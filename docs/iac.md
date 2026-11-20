# Etapa 4 — IaC Scanning do Dockerfile

Implementação: `scripts/security/iac.py`, `security/iac-policy.json`, regras locais em `security/checkov/` e job **IaC (Dockerfile)**. O `Security gate` exige sucesso desta análise, Secret Detection, ambos os SCA, SAST e testes da política. DAST ainda será implementado.

## Ferramenta e alvo efetivo

**Checkov 3.4.6**, imagem oficial `bridgecrew/checkov` fixada por digest em `security/tools.json`. Suas regras nativas ficam incluídas nessa imagem; não há download de regras mutáveis durante a análise. Requer Docker, Git, Bash e Python 3.9+ no host. Nenhum pacote adicional foi instalado no host e nenhum token/serviço pago é necessário.

O scanner roda sem rede, sem capabilities, com `no-new-privileges`, UID/GID do usuário e entrada somente para leitura. Recebe apenas uma cópia de `Dockerfile`, `compose.yaml` e regras locais; não recebe `.env.local`, credenciais, socket Docker, `.checkov.yaml` do projeto ou baseline. `--skip-download` evita consulta à plataforma Prisma; a decisão usa IDs e contexto, pois severidades oficiais não são fornecidas nessa execução offline.

O **Dockerfile inteiro** é analisado, inclusive comandos dos estágios de build. Uma verificação auxiliar lê `compose.yaml` sem resolver variáveis/arquivos de ambiente e exige `services.app.build.context: .`, Dockerfile padrão e `target: app` como estágio final. `build-context.json` registra esse vínculo e os cinco estágios atuais: `php-base`, `tooling`, `dependencies`, `assets`, `app`. Alterações nesse contrato exigem revisão do escopo, em vez de continuar analisando um Dockerfile sem relação com a execução.

**Compose não recebe uma análise geral de segurança nesta etapa.** A verificação auxiliar confirma somente o alvo de build. Bind em loopback, capabilities, volumes, permissões dos arquivos, entrypoint e configuração MySQL não são certificados pelo resultado Checkov. Não há análise de CVEs dos pacotes do sistema operacional, resolução de imagens herdadas ou comprovação de que comandos de healthcheck funcionam apenas por leitura estática.

## Regras e política contextual

As regras nativas analisam exposição de SSH, usuário, healthcheck, instruções de build, imagens, caminhos, TLS, assinaturas de pacotes e outras práticas. A política versiona 31 IDs: 28 nativos e três locais; regras condicionais só geram registros quando há instruções aplicáveis. No Dockerfile atual foram **93 avaliações aprovadas, correspondentes a 29 IDs distintos**, zero falhas, zero supressões e zero erros de parsing. Não são 93 regras diferentes.

As três regras locais complementam limitações verificadas no código do Checkov:

| Regra | Controle |
|---|---|
| `CKV_ACME_DOCKER_1` | USER explícito no estágio final `app`, recusando root, UID 0 (inclusive `0:0`) e valores dinâmicos não verificáveis. Um USER em estágio anterior não satisfaz o controle. |
| `CKV_ACME_DOCKER_2` | HEALTHCHECK ativo no estágio final `app`; `NONE` e instrução presente apenas no build não satisfazem o controle. |
| `CKV_ACME_DOCKER_3` | SHA256 literal nas imagens externas de FROM e COPY --from. Aliases e índices válidos de estágios anteriores são permitidos. |

Na versão fixada, `CKV_DOCKER_8` compara o último USER com a string `root`; `CKV_DOCKER_2/3` verificam presença das instruções no arquivo. Por isso, sozinhas não garantem usuário não root e healthcheck ativo no estágio correto. Os testes exercitam especificamente UID 0, NONE e controles deslocados para o build.

O uso de root para instalar extensões e configurar Apache no **build** é distinto do usuário do processo que atende HTTP. Exige-se USER não root no estágio final; não se exige healthcheck nos estágios de compilação. A identidade de uma imagem por digest não comprova ausência de vulnerabilidades ou existência da imagem no registro. Nomes de usuário não são resolvidos contra `/etc/passwd` da imagem pelo scanner; a inspeção do UID efetivo complementa essa limitação.

Bloqueiam: as três regras locais; `CKV_DOCKER_1,2,3,5,7,8,10,11`; e `CKV2_DOCKER_1` a `17`. `CKV_DOCKER_4,6,9` (ADD, MAINTAINER, apt) geram `review`, pois exigem análise contextual, não prova automática de exploração. Achado desconhecido bloqueia. Os motivos ficam no JSON da política e no relatório; não há exceções IaC. Uma tentativa de supressão inline gera análise incompleta e reprovação, em vez de ocultar o controle.

Saídas do integrador: **0** análise válida sem bloqueantes; **1** violação; **2** falha operacional. Ele verifica estrutura e contagens do JSON, código nativo, versão, alvo, parsing, supressões e execução das regras obrigatórias. Se uma regra local não carregar, o resultado não pode aprovar silenciosamente. O relatório distingue código nativo do scanner e decisão final.

## Achados e ciclo de demonstração

O Dockerfile real **não apresentou achados** nessa rodada. Os controles existentes vieram da etapa inicial: USER www-data, healthcheck SQL da aplicação, imagens fixadas e instalação/configuração no build. Não foi necessário alterar o Dockerfile nem os fluxos da aplicação para aprovar IaC.

A demonstração usa **cópias intencionalmente modificadas do Dockerfile real**, em repositório temporário. Nunca são construídas nem executadas. Não se trata de descoberta espontânea na aplicação:

| Antes, somente na cópia isolada | Impacto se usado na aplicação | Correção |
|---|---|---|
| `USER root` | Um comprometimento do processo HTTP ocorreria com privilégios root no container; isso não implica automaticamente acesso root ao host. | Restaurar `USER www-data`. |
| `HEALTHCHECK NONE` | O container perde a verificação configurada de prontidão; processo iniciado não garante acesso ao banco ou operação correta da aplicação. | Restaurar a instrução que executa `php docker/healthcheck.php`. |

São **duas condições inseguras e três registros bloqueantes**: `CKV_DOCKER_8`, `CKV_ACME_DOCKER_1` e `CKV_ACME_DOCKER_2`. O caso corrigido restaura o Dockerfile real e aprova. Imagem, regras nativas/locais e política permanecem iguais; o artifact contém fontes e diff para comparação.

Em `iac-operational-failure`, o alvo temporário contém texto sem instruções Dockerfile válidas. O Checkov 3.4.6 retorna nativamente **0**, com `resource_count: 0` e nenhuma avaliação. O integrador rejeita esse resultado como análise inválida e retorna **2**. É uma demonstração concreta de por que “scanner retornou zero” não basta para aprovar o pipeline.

## Comandos e GitHub Actions

Na raiz do clone; se a sessão ainda não herdou o grupo Docker, usar `sg docker -c 'COMANDO'`:

```bash
scripts/security/iac
python3 scripts/security/iac_demo.py iac-fixture --output artifacts/security/iac-fixture
# saída 1 esperada: duas condições inseguras, três achados bloqueantes
python3 scripts/security/iac_demo.py iac-corrected --output artifacts/security/iac-corrected
# saída 0 esperada: controles restaurados, mesmas regras/política
python3 scripts/security/iac_demo.py iac-operational-failure --output artifacts/security/iac-operational
# saída 2 esperada: nenhuma análise válida do alvo
python3 -m unittest discover -s tests/security -v
```

No Actions → **Security → Run workflow**, usando a mesma versão:

| Scenario | Gate esperado |
|---|---|
| `normal` | Aprova, se as demais categorias aprovarem |
| `iac-fixture` | Reprova por política |
| `iac-corrected` | Aprova, se as demais categorias aprovarem |
| `iac-operational-failure` | Reprova por análise inválida |

Todos os cenários analisam primeiro o Dockerfile real. A demonstração é uma etapa adicional e sua falha reprova o job/gate; não há `continue-on-error` nem `soft-fail`. Sucesso do job de testes significa que os controles responderam como esperado, não que a configuração insegura foi aprovada.

Artifacts **`iac-<run_id>-<attempt>`**, retidos por 14 dias: `result.json` (validade, decisão, achados, commit e hashes), `checkov.json` (relatório nativo completo), `scanner.log`, `inventory.json`, `build-context.json` e `context.log` quando produzidos. Nos cenários adicionais: `source.json` e `correction.diff`. Erros podem impedir alguns arquivos; `result.json` identifica o impedimento. O artifact `security-controls-…` também guarda o antes/depois dos testes.

Guardar URLs/IDs das execuções e comparar `scanner_image`, `policy_sha256` e `local_checks_sha256` entre os dois casos. O registro das entradas identifica o que mudou. Esses exemplos não exigem dois commits que enfraqueçam a aplicação: as execuções separadas e o diff demonstram a correção isolada. O caso real de SCA já conserva commits separados.

## Validação e limites das evidências

Validação local: scanner real no Dockerfile atual; demonstrações antes/depois e falha operacional; testes de supressões, cobertura de regras, alvo Compose divergente, usuário numérico, healthcheck de estágio anterior, imagem sem digest, relatórios incoerentes e runtime/alvo indisponíveis. A suíte das quatro categorias contém **32 testes**, incluindo nove IaC. Workflow validado com actionlint.

Também foi inspecionada a execução existente: app local e de teste com `Config.User=www-data`, healthcheck `php docker/healthcheck.php`, estado saudável e UID/GID efetivo 33 no container de teste. Esses dados complementam a análise estática de infraestrutura, mas não significam que o job IaC constrói ou executa containers da aplicação. Os comandos de build/testes funcionais já existentes continuam em `scripts/test-env`; as cópias vulneráveis nunca são usadas por eles. Nenhum banco/volume foi removido ou modificado nesta etapa.

O responsável acompanha o repositório privado no próprio navegador. Resultados do Actions desta etapa permanecem esperados até sua confirmação; as evidências locais não substituem a comprovação do gate remoto.

## Fontes e autoria

- [Checkov: análise de Dockerfiles](https://www.checkov.io/7.Scan%20Examples/Dockerfile.html).
- [Índice oficial de regras](https://www.checkov.io/5.Policy%20Index/dockerfile.html).
- [CLI e funcionamento de skip-download](https://www.checkov.io/2.Basics/CLI%20Command%20Reference.html).
- [Código do Checkov](https://github.com/bridgecrewio/checkov); a imagem fixada conserva exatamente a implementação usada, mesmo que a documentação evolua.

Integração, regras locais, análise e testes desenvolvidos com apoio do OpenAI Codex. Regras nativas são do Checkov; decisões contextuais e complementos locais pertencem a esta adaptação acadêmica. DAST é a próxima categoria pendente.
