# DAST — ZAP e aplicação descartável

## Execução e cobertura

`scripts/security/dast` constrói o Dockerfile efetivamente usado, cria um projeto aleatório `acme-dast-<id>`, espera MySQL/aplicação saudáveis e executa os testes HTTP existentes. Cada execução tem volume novo, sem vínculo com `acme-local` ou `acme-test`. O Compose adicional retira as portas publicadas e usa rede interna sem saída externa. Não há parâmetro para apontar a varredura a outra aplicação. Requer Compose **2.24.4+** (`!reset`), Docker, Bash, Git e Python 3.9+ no host.

ZAP **2.17.0**, fixado em `security/tools.json` por digest, inicia dentro de um container sem root, sem Docker socket e com API de controle apenas no loopback. Add-ons vêm da mesma imagem; sem instalação/atualização durante a análise. O script Python usa a API oficial para configurar e consultar o scanner; não simula seus achados.

1. O tráfego de teste passa pelo proxy ZAP: `/health`, HTML/assets e os nove métodos/endpoints do OpenAPI. São conferidos cadastro 201, consulta/listagem, edição persistida, pesquisa, disponibilidade de CPF, mudança de status, exclusão, 404 e entrada inválida 422.
2. São criados registros fictícios distintos para consulta, edição e exclusão. `openapi-seeded.json` substitui IDs e exemplos de CPF/formulário; o scanner importa esse contrato. Cadastro/edição/pesquisa usam formulários, não JSON.
3. Scan ativo no contexto restrito `http://app:8080/`: XSS refletido 40012, SQL injection 40018 e CRLF injection 40003, força Low/limiar Medium. As regras passivas habilitadas na imagem também analisam o tráfego, inclusive interface e assets.
4. O integrador exige scan 100%, cada regra ativa concluída com requisições enviadas, fila passiva zero, nove operações funcionais bem-sucedidas e mensagens **da varredura ativa** nos formulários de criação, edição e pesquisa. IDs, métodos, caminhos e respostas ficam em `coverage.json`; requisições/respostas do preflight em `preflight-http.json`.
5. A política bloqueia risco Medium/High com confiança Medium/High/Confirmed. Low/Informational ou confiança Low ficam para revisão; nenhuma exceção/supressão. Relatório ausente/inválido, alcance insuficiente e erros operacionais bloqueiam. Saídas 0/1/2 significam aprovação/violação/falha operacional.
6. Coleta logs e remove somente os containers, rede, imagem local e volume do identificador criado nessa execução, mesmo após falha. Não usa `prune`. Falha de limpeza também reprova. Cancelamento abrupto do processo/host pode impedir esse `finally`; no runner GitHub o ambiente é efêmero. Para limpeza local interrompida, identificar primeiro o projeto exato em `result.json`/nomes `acme-dast-*`, sem remover projetos locais ou de testes.

## Comandos e cenários

```bash
scripts/security/dast
scripts/security/dast --scenario dast-fixture
scripts/security/dast --scenario dast-corrected
scripts/security/dast --scenario dast-operational-failure
python3 -m unittest discover -s tests/security -v
```

Cada comando gera um diretório novo `artifacts/security/dast-<data>-<id>`. `--output CAMINHO` permite especificá-lo, mas recusa diretório não vazio para impedir evidência antiga confundida com resultado novo. Não é necessário executar `scripts/configure`, manter o ambiente local ligado ou preparar banco manualmente.

No Actions → **Security → Run workflow**, usar `normal`, `dast-fixture`, `dast-corrected`, `dast-operational-failure`:

| Cenário | Mudança isolada | Resultado esperado |
|---|---|---|
| normal | Aplicação atual | Aprova se todas as categorias aprovarem |
| dast-fixture | Monta a configuração Apache anterior, sem cabeçalhos, apenas no projeto novo | Reprova por CSP/anti-clickjacking ausentes |
| dast-corrected | Usa Apache atual | Aprova com a mesma política/regras |
| dast-operational-failure | Para sua aplicação após prontidão/testes; ZAP tenta acessá-la de fato | Reprova como análise inválida, não como aplicação segura |

Todos os cenários do workflow executam primeiro a análise normal. Os adicionais repetem a execução em outro projeto novo; não alteram a aplicação local nem desativam controles do gate. O resultado negativo da demonstração reprova job e gate. O job de testes unitários verifica contratos do integrador; os cenários DAST usam scanner, HTTP e banco reais.

## Registro do ciclo real

Em 21/11/2026, antes da correção dos cabeçalhos, a análise válida da aplicação (`artifacts/security/dast-before`) retornou **1 / policy_violation**: 9 operações bem-sucedidas, 590 mensagens ativas, 2 achados bloqueantes (10020 e 10038), 41 instâncias para revisão (versão do servidor, ausência de nosniff e identificação de SPA). Os três scanners ativos terminaram sem alertas de injeção. O banco/ambiente temporário foi removido corretamente. Não se demonstrou exploração de clickjacking/XSS: o achado é ausência verificável dessas proteções.

Política SHA256 `7a1d4b29f89692a3cef482b4e3c2fda414342d2292428be9c822be28af73f171`; executor ZAP SHA256 `a06263d7126709f9f722d7e04207b9cecab32d8d5975d31c543ee508376cf1fb`. A configuração sem cabeçalhos fica conservada na fixture para repetir o bloqueio sem enfraquecer a aplicação atual.

## Evidências e limites

Artifact `dast-<run_id>-<attempt>`: `result.json`, `alerts.json` nativo, `zap-report.html`, `coverage.json`, `preflight-http.json`, `addons.json`, contrato e fixtures usados, logs de build/startup/teste/scanner/serviços/limpeza. Retenção de 14 dias. Guardar antes do vencimento os relatórios selecionados e URLs/IDs de execuções para o relatório acadêmico; contagens de instâncias não são quantidades de vulnerabilidades distintas.

`result.json` identifica commit, árvore modificada, imagem da aplicação, versão/digest ZAP e hashes de política, executor, Dockerfile e OpenAPI. Comparar `scanner_image`, `policy_sha256` e `runner_sha256` entre bloqueio e correção. O repositório privado é acompanhado por Jonatan no próprio navegador: resultados locais não são alegados como comprovação do gate remoto.

Cobertura limitada: scan ativo com três regras, sem Ajax Spider/navegador dentro do ZAP; não cobre todo o JavaScript executado, XSS no DOM, todos os estados, controle de acesso ou TLS. DELETE pode invalidar seu ID nos ataques posteriores; o fluxo funcional anterior comprova seu sucesso e o relatório conserva respostas negativas. API sem autenticação/autorização, apropriada apenas a esta demonstração com dados fictícios. Uma execução verde não certifica segurança nem adequação para dados reais.

## Fontes e autoria

- [ZAP 2.17.0](https://github.com/zaproxy/zaproxy/releases/tag/v2.17.0).
- [API oficial: Active Scan, mensagens e OpenAPI](https://www.zaproxy.org/docs/api/).
- [ZAP API Scan: importação e limitações](https://www.zaproxy.org/docs/docker/api-scan/). Esta integração usa a API diretamente, com cobertura adicional do fluxo e da interface; não usa os códigos de saída do script `zap-api-scan.py`.
- [CSP ausente](https://www.zaproxy.org/docs/alerts/10038/) e [proteção contra clickjacking](https://www.zaproxy.org/docs/alerts/10020/).

Integração, política contextual, correções e documentação com apoio do OpenAI Codex. Scanner/regras pertencem ao projeto ZAP.
