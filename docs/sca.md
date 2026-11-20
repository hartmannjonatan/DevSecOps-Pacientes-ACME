# Etapa 2 — SCA de Composer e npm

Implementação: `scripts/security/sca.py`, `security/sca-policy.json` e matriz `sca` no workflow `Security`. Usa Composer **2.11.2** e npm **11.19.1**, com Node **24.22.3**, em imagens oficiais fixadas pelos mesmos digests usados no Dockerfile da aplicação. Não instala PHP, Composer ou Node no host; requer Docker, Git, Bash e Python 3.9+.

## Comandos

```bash
scripts/security/sca                       # analisa ambos; continua para coletar o outro se um falhar
scripts/security/sca --ecosystem composer
scripts/security/sca --ecosystem npm
python3 -m unittest discover -s tests/security -v
scripts/security/sca --ecosystem npm --offline-demo --output artifacts/security/sca-demo  # falha esperada: 2
```

Na sessão sem grupo Docker atualizado, envolva o comando com `sg docker -c 'COMANDO'`. Saídas: **0** análise válida sem violação bloqueante, **1** violação da política, **2** falha operacional. No modo `all`, falha operacional prevalece sobre violação. Cada ecossistema mantém seu próprio resultado.

A análise copia somente manifesto e lockfile para diretório temporário. Composer valida o lock e executa `audit --locked --format=json --no-plugins --no-scripts --abandoned=report`. npm valida a consistência com `ci --dry-run --ignore-scripts --install-links=true` e audita com `--package-lock-only --include=dev --include=optional --include=peer --audit-level=low`. O limiar do npm serve para conferir a coerência do retorno; a decisão final usa a política contextual do projeto. Overrides de auditoria e fontes Composer customizadas não são aceitos silenciosamente.

Nenhum `audit fix`, `--force`, `--ignore-platform-reqs` ou atualização automática integra o CI. O dry-run não instala nem executa pacotes. No build real, Composer continua precedendo npm para disponibilizar `vendor/symfony/ux-react/assets`; a análise por lock não precisa dessa instalação. A compatibilidade de plataforma e o funcionamento final continuam sendo verificados pelo build/testes funcionais, não apenas pelo SCA.

## Cobertura e artefatos

Em `artifacts/security/sca/composer/` e `npm/`:

- `result.json`: validade, decisão, commit, cenário, hashes de entrada/política/ferramentas, versões dos scanners, achados com versões/escopo/cadeia de advisories.
- `audit.json`: resposta JSON da auditoria real. Pode conter erro do serviço; sua presença isolada não significa análise válida.
- `inventory.json`: dependências resolvidas, diretas/transitivas e runtime/desenvolvimento.
- `validation.log`: resultado da validação de consistência manifesto/lock.

No Actions, baixar os artifacts **`sca-composer-…`** e **`sca-npm-…`**, retidos por 14 dias. Sem filtro por paths, ambos executam em push/PR/execução manual. Não é necessário cadastrar segredos adicionais no GitHub. Os nomes/versões das dependências são enviados aos serviços públicos de advisories do Packagist e npm; credenciais, `.env.local` e banco não são montados.

O inventário inicial contém **126 pacotes PHP** (91 de runtime e 35 de desenvolvimento) e **316 entradas npm**. Dependências locais como `@symfony/ux-react` são identificadas explicitamente; sua resolução vem de `symfony/ux-react` no Composer. Não se presume cobertura de advisories próprios para o conteúdo de um pacote `file:`: o SAST próprio desta etapa não analisa o conteúdo de `vendor/`/`node_modules/`; essa limitação permanece explícita. Bibliotecas presentes no bundle e ferramentas de build integram o inventário, mesmo quando uma vulnerabilidade não é alcançável no fluxo atual.

As bases de advisories mudam: lockfiles fixam versões dos pacotes, não os alertas futuros. Estes comandos não analisam pacotes do sistema operacional da imagem, não provam explorabilidade e não detectam todas as ameaças de supply chain. Não há alegação de ausência absoluta de vulnerabilidades.

## Achados reais antes da correção

Composer: consulta válida sem advisories ou pacotes abandonados na rodada inicial. npm: dois pacotes afetados, `react-router` e `react-router-dom` **6.30.6**, associados aos mesmos dois advisories; o segundo pacote aparece por depender do primeiro. Não são quatro vulnerabilidades distintas.

| Advisory | Evidência e contexto | Decisão |
|---|---|---|
| [GHSA-wrjc-x8rr-h8h6 / CVE-2026-53669](https://github.com/advisories/GHSA-wrjc-x8rr-h8h6) | Versão instalada na faixa afetada `>=6.0.0 <7.18.0`. Redirecionamento externo inesperado quando navegação recebe caminhos controlados pelo atacante. Os `Link` atuais usam `/`, `/create` e `/edit/` + ID inteiro; não há entrada de URL livre. Não foi demonstrada exploração no fluxo atual. | Atualizar a dependência de runtime, eliminando a versão afetada e o risco de reutilizar a API vulnerável em alterações futuras. |
| [GHSA-337j-9hxr-rhxg / CVE-2026-53666](https://github.com/advisories/GHSA-337j-9hxr-rhxg) | Versão instalada na faixa afetada `>=6.4.0 <7.18.0`. O advisory exclui modo declarativo e exige SSR/hidratação específica. `assets/app.js` usa `createRoot` + `BrowserRouter`, sem SSR/hydrateRoot: achado confirmado na dependência, **não aplicável ao modo atual**. | Resolver na mesma atualização, sem registrar exceção nem chamar o achado de falso positivo. |

Os dois registros npm bloquearam por serem moderados em runtime segundo a política. A integração foi registrada em `ea1daf505088011c17be6b726f117fd23ba3ad69`. A correção está em `9f77e54ef573808906dcef34416bfc6ad4c5dbbc`: `react-router`/`react-router-dom` 6.30.6 → 7.18.6, mantendo o scanner e `security/sca-policy.json` inalterados. Os relatórios anteriores estão em `artifacts/security/sca-before/` localmente e nos artifacts da execução do primeiro commit.

## Validação e GitHub Actions

1. Conferir no primeiro commit SCA: `SCA (composer)` aprovado, `SCA (npm)` e `Security gate` reprovados por política, com relatórios válidos.
2. Após o commit da atualização do Router, conferir ambos os jobs SCA e `Security gate` aprovados. Comparar hashes da política e versões/lockfiles antes e depois.
3. Executar **Run workflow → scenario `sca-operational-failure`**. A análise normal continua presente; a demonstração adicional roda npm audit sem acesso à rede, em diretório temporário. Esperado: `analysis_valid: false`, `operational_error`, saída 2 e gate final reprovado. Não há simulação de “zero vulnerabilidades”.
4. Executar `normal` novamente. Os três cenários anteriores de Secret Detection continuam disponíveis e preservam seu comportamento.

O responsável prefere acompanhar o repositório privado no próprio navegador. Por isso, diferenciar os resultados locais observados dos resultados do Actions que ele confirmar, guardando links/commits das execuções.

Os testes unitários usam a resposta npm real anterior à correção e exemplos explicitamente sintéticos para exercitar interpretação, metadados, escopo, limites, exceções e erros. Não são a fonte dos resultados do scanner no CI. A indisponibilidade do registro também deve ser validada com o comando real de demonstração.

## Fontes e autoria

- [Composer Audit e validação](https://getcomposer.org/doc/03-cli.md#audit).
- [npm audit: lockfile, retorno e metavulnerabilidades](https://docs.npmjs.com/cli/v11/commands/npm-audit/).
- [React Router: migração v6 → v7](https://github.com/remix-run/react-router/blob/v7/docs/upgrading/v6.md).
- Advisories oficiais vinculados na tabela acima.

Integração, análise e testes preparados com apoio do OpenAI Codex, sujeitos à revisão e compreensão pelo estudante. SAST foi integrado na [etapa 3](sast.md); IaC foi integrada na [etapa 4](iac.md); DAST permanece para a próxima etapa.

## Registro da revalidação

Em 20/11/2026, Jonatan confirmou no próprio navegador: o pipeline do primeiro commit reprovou SCA npm por Router/Router DOM; após a atualização, a interface funcionou e o pipeline aprovou. Essa confirmação do responsável é distinta da inspeção direta do Actions pelo Codex. Guardar os links/IDs e artifacts dessas execuções para o relatório.

Localmente, a atualização passou pelo build, testes HTTP/CRUD e persistência após reiniciar app/MySQL. A auditoria posterior consultou 126 pacotes PHP e 317 entradas npm, sem advisories nessa consulta. Hash da política preservada: `ddbe650026a933fe211b7c271389e065581caa597dcc00bdd4a0f944fd41cc2b`. Esses resultados são datados; futuras consultas podem trazer novos alertas.
