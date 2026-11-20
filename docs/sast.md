# Etapa 3 — SAST de PHP e React

Integração: `scripts/security/sast.py`, `security/sast-policy.json` e job **SAST (PHP and React)** no workflow `Security`. O gate final exige esse job, Secret Detection, ambos os SCA e os testes de política. IaC foi integrada na [etapa 4](iac.md); DAST continua pendente.

## Ferramenta, regras e cobertura

Semgrep **Community Edition 1.186.0**, imagem oficial fixada por digest em `security/tools.json`. Requer Docker, Git, Bash e Python 3.9+ no host; nenhum serviço pago, token Semgrep, pacote Python adicional no host ou instalação de PHP/Node é necessário.

São **89 regras** de PHP genérico, Doctrine, Symfony, JavaScript/browser e React, selecionadas da revisão `a5ad1714f00c9f7fde980cab0ea1d6dc6d414fd2` de `semgrep/semgrep-rules`. Incluem padrões de SQL injection, execução de comandos/código, inclusão de arquivos, desserialização, XSS, redirects, criptografia e configuração insegura em código. A seleção precedeu a avaliação dos resultados; não foi reduzida para aprovar a aplicação.

`security/semgrep/provenance.json` fixa caminhos, hashes individuais, hash do arquivo de origem e hash do conjunto convertido. No primeiro uso, o integrador baixa a revisão oficial por HTTPS, verifica esses hashes e converte YAML para JSON no container. Somente os IDs recebem prefixos com o caminho original para evitar colisões; padrões e metadados permanecem iguais. As regras ficam no cache ignorado `artifacts/security/semgrep-cache/`, não nos artifacts publicados pelo workflow. Elas não são redistribuídas no repositório/ZIP, respeitando a licença indicada em `security/semgrep/LICENSE`; a procedência reproduzível fica versionada. Falha de obtenção ou integridade bloqueia.

Depois de obter as regras e a imagem, o scanner funciona **sem rede**, sem métricas e sem login. Recebe uma cópia somente dos arquivos com extensões `.php`, `.js`, `.jsx`, `.mjs`, `.cjs`, `.ts` e `.tsx` rastreados ou novos não ignorados pelo Git. Na versão inicial desta etapa: **27 arquivos**, incluindo `src`, `assets`, PHP de configuração/migrações/testes/infraestrutura e `webpack.config.mjs`. `inventory.json` identifica cada alvo e seu hash. Arquivos removidos da árvore de trabalho não integram o alvo atual; o histórico é escopo do Secret Detection.

`vendor/`, `node_modules/`, `var/`, `public/build/` e `artifacts/` ficam fora desse SAST. Templates Twig, CSS, YAML, scripts sem as extensões listadas e código de terceiros não recebem cobertura deste conjunto. `bin/console`, por exemplo, é um bootstrap sem extensão. SCA cobre advisories dos lockfiles; não substitui análise do código de terceiros.

Os arquivos selecionados são passados explicitamente ao scanner, inclusive os testes que ele excluiria por padrão. O integrador não copia `.semgrepignore`/`.gitignore` para o alvo e desativa supressões `nosemgrep`. Compara os arquivos reportados com o inventário; divergência, parsing parcial, timeout ou regras puladas impedem aprovação. O motor CE tem análise limitada a funções/arquivos; **não comprova fluxos completos entre Controller, Repository e React**, nem detecta todas as falhas de autorização ou lógica. Ausência de alertas não comprova segurança.

## Política e achado da aplicação

`ERROR`/`WARNING` com confiança `HIGH`/`MEDIUM` bloqueiam; confiança baixa ou severidade `INFO` geram revisão visível. Metadados desconhecidos bloqueiam. Erro de execução/análise gera saída 2; violação gera 1; análise válida sem bloqueantes gera 0. Não há exceções SAST. A justificativa contextual está em `security/POLICY.md`.

A análise real inicial retornou **um alerta de revisão, nenhum bloqueante**:

| Achado | Avaliação | Tratamento |
|---|---|---|
| `php.lang.security.unlink-use.unlink-use`, `tests/functional.php:43`, WARNING/LOW, CWE-22 | A regra identifica `unlink()` com argumento não literal. `$stateFile` é construído a partir de `dirname(__DIR__)` e do sufixo fixo `/var/test-persistence.json`; nenhuma entrada HTTP/CLI escolhe o caminho. Não se confirma a hipótese de exclusão arbitrária controlada por usuário: falso positivo para path traversal neste fluxo. O script também exige banco descartável. | Manter código e alerta `review`, sem `nosemgrep`, exceção ou remoção da regra. Reavaliar se a origem do caminho mudar. |

O SAST não encontrou uma vulnerabilidade bloqueante espontânea adequada à demonstração. Portanto, o ciclo abaixo usa **casos intencionais isolados**, permitidos pelo enunciado. Não são apresentados como vulnerabilidades encontradas em Pacientes ACME; não houve correção de segurança no código da aplicação nesta etapa.

## Detectar → bloquear → corrigir → revalidar

`scripts/security/sast_demo.py` contém duas versões pequenas de exemplos, copiadas para repositório temporário sem servidor/banco. Esse código é apenas analisado, nunca executado:

| Exemplo | Antes: achado bloqueante | Correção e resultado |
|---|---|---|
| PHP | `$_GET['name']` concatenado em SQL; regra `tainted-sql-string`, ERROR/MEDIUM, CWE-89. Se executado nesse formato, dados poderiam alterar a consulta. | SQL com placeholder `:name` e parâmetros separados por `prepare`/`execute`; achado desaparece. |
| JSX | Propriedade `name` chega a `dangerouslySetInnerHTML`; regra `react-dangerouslysetinnerhtml`, WARNING/MEDIUM, CWE-79. HTML fornecido externamente poderia ser interpretado no navegador. | Renderização como texto React, `<div>{name}</div>`; achado desaparece. |

As versões antes/depois usam **a mesma imagem, as mesmas 89 regras e a mesma política**, com os mesmos dois caminhos de arquivo. Fontes, diff, inventários e hashes acompanham os relatórios. O modo operacional usa PHP sintaticamente inválido: o scanner real retorna erro de parsing e o integrador reprova como `operational_error`, nunca como zero vulnerabilidades.

Comandos na raiz (a sessão antiga do grupo Docker pode precisar de `sg docker -c 'COMANDO'`):

```bash
scripts/security/sast
python3 scripts/security/sast_demo.py sast-fixture --output artifacts/security/sast-discovery-fixture
# saída 1 esperada: dois achados bloqueantes
python3 scripts/security/sast_demo.py sast-corrected --output artifacts/security/sast-corrected
# saída 0 esperada: mesmos arquivos corrigidos, mesmas regras/política
python3 scripts/security/sast_demo.py sast-operational-failure --output artifacts/security/sast-operational
# saída 2 esperada: análise inválida por erro de parsing
python3 -m unittest discover -s tests/security -v
```

Não usar `|| true` na etapa de análise para transformar as falhas esperadas em aprovação. Os testes automatizados, por sua vez, verificam explicitamente os códigos esperados: sucesso do job de testes significa que os controles se comportaram corretamente, não que o cenário vulnerável foi aprovado.

## Evidências no GitHub Actions

Após enviar o commit desta etapa, selecionar **Actions → Security → Run workflow** na mesma branch/versão:

| `scenario` | SAST real da aplicação | Demonstração adicional | Gate esperado |
|---|---|---|---|
| `normal` | Válido, um `review`, zero bloqueantes | Nenhuma | Aprova, se as outras categorias aprovarem |
| `sast-fixture` | Sempre executado | Dois bloqueantes no alvo isolado | Reprova |
| `sast-corrected` | Sempre executado | Zero achados nos exemplos corrigidos | Aprova, se as outras categorias aprovarem |
| `sast-operational-failure` | Sempre executado | Erro de parsing no alvo isolado | Reprova |

Baixar o artifact **`sast-<run_id>-<attempt>`** de cada execução antes dos 14 dias de retenção. Contém `result.json` (decisão, validade, commit, cenário, ferramenta, hashes e achados), `inventory.json`, `semgrep.json` (JSON real) e `scanner.log`. Nas demonstrações, inclui também `source.json` e `correction.diff`. `security-controls-…` guarda evidências do teste automatizado antes/depois. Relatórios SAST podem conter trechos de código; revisar antes da entrega.

No relatório, registrar commit e URL/ID de cada execução, identificar a simulação e comparar `rules_sha256`/`policy_sha256` entre `sast-fixture` e `sast-corrected`. A correção está nos exemplos, não em uma alteração das regras. Não é preciso inventar dois commits de correção da aplicação: as execuções distintas sobre fontes diferentes e o diff preservam o ciclo. O caso real SCA já dispõe de commits separados antes/depois.

O responsável acompanha o repositório privado no próprio navegador. As confirmações recebidas estão registradas abaixo; distinguir essa confirmação do responsável de inspeção direta pelo Codex ao escrever o relatório.

## Validações locais e fontes

Na implementação: download com cache vazio e hashes válidos; análise dos 27 arquivos; dois bloqueios nos exemplos; aprovação após correção; falha real de parsing; 23 testes de política (7 SAST, 9 SCA e 7 Secret Detection) aprovados; workflow validado com actionlint. Testes também verificam resistência a supressões, cache modificado, alvo vazio, symlink, runtime indisponível e relatórios incoerentes. Não foi necessário alterar dependências da aplicação nem seus fluxos HTTP.

- [Semgrep CE e limites por linguagem](https://semgrep.dev/docs/semgrep-ce-languages).
- [Opções e códigos de saída](https://semgrep.dev/docs/cli-reference).
- [Revisão das regras usadas](https://github.com/semgrep/semgrep-rules/tree/a5ad1714f00c9f7fde980cab0ea1d6dc6d414fd2).
- [Licença das regras](https://semgrep.dev/legal/rules-license/).

Seleção, integração, análise e testes desenvolvidos com apoio do OpenAI Codex. O estudante deve revisar as decisões e usar evidências selecionadas no relatório, preservando a autoria e a origem das regras.

## Confirmação das execuções no Actions

Em 20/11/2026, Jonatan confirmou as execuções do commit `3c27aa3064e65f55c3c55226e3e40db33e9a5e28`: `normal` e `sast-corrected` aprovaram; `sast-fixture` e `sast-operational-failure` reprovaram conforme esperado. Resultado informado pelo responsável após inspeção no próprio navegador, não por acesso direto do Codex ao Actions. Guardar as URLs/IDs e os artifacts dessas execuções como evidência do relatório.
