# Política de segurança — versão 4

Escopo: demonstração acadêmica Pacientes ACME, com dados fictícios, executada localmente e no CI. Objetivo: decidir a aprovação com evidências válidas, mantendo resultados de segurança separados de erros de execução. Esta versão aplica **Secret Detection, SCA, SAST e IaC**; DAST ainda não está implementado e não é declarado aprovado.

## Decisão de Secret Detection e composição do gate

| Condição | Resultado | Saída do script |
|---|---|---|
| Duas análises válidas (arquivos e histórico), nenhum achado sem exceção vigente | `pass` | 0 |
| Pelo menos um achado sem exceção específica vigente | `policy_violation` | 1 |
| Docker/scanner indisponível, timeout, configuração inválida, histórico raso, relatório ausente/malformado ou incompatível com o código de saída | `operational_error` | 2 |
| Exceção expirada, incompleta ou duplicada | `operational_error`: revisão obrigatória | 2 |

Gitleaks não oferece uma classificação uniforme de severidade para todos os segredos. Uma credencial detectada e ainda não avaliada é potencialmente utilizável: **todo achado não excepcionado bloqueia**, inclusive no histórico. O tratamento depende do contexto; não se presume que um token seja inofensivo porque está antigo ou não aparece mais no arquivo atual.

`Security gate` exige sucesso dos jobs `Secret Detection`, **ambas as entradas da matriz SCA (Composer/npm)**, `SAST (PHP and React)`, `IaC (Dockerfile)` e `Security policy tests`, executa mesmo se outro job falhar e reprova também para `failure`, `cancelled` ou `skipped`. A matriz não cancela o outro ecossistema quando um falha. Não há `continue-on-error`, baseline automática, `|| true` para aprovar o scanner nem exceção de falha operacional. A coleta de artefatos pode ocorrer depois da falha e não transforma o job em sucesso. Falha de upload também impede aprovação.

## Exceções de Secret Detection

O registro executável é `security/secret-exceptions.json`. Nesta etapa, exceções são admitidas apenas para **achados históricos exatos**: fingerprint contém commit, arquivo, regra e linha. Arquivos atuais e novos commits não herdam a exceção. O achado permanece visível no resultado com `accepted_exception`; o scanner continua detectando-o.

Cada entrada exige classificação, justificativa contextual, risco restante, controles compensatórios, responsável, condição de revisão e data de expiração. A data é inclusiva; a execução seguinte ao vencimento bloqueia até revisão. Alterações desse registro e das regras devem ser revisadas pelo responsável pelo projeto. Não se deve prorrogar uma exceção apenas para obter um resultado verde.

Única exceção inicial: APP_SECRET no commit `c6d0667af8d0d6a05b7d3e32fb13c2c1d9c39def`, `.env`, linha 23, regra `symfony-app-secret`. Jonatan confirmou em 20/11/2026 uso exclusivo em demonstração acadêmica com dados fictícios. A configuração local atual possui outra chave não versionada. A exposição histórica é confirmada e o risco é aceito apenas nesse contexto até **26/11/2026**; não é falso positivo e não constitui o caso obrigatório de correção. Reutilização ou publicação da aplicação exige revisão. Não há alegação de revogação em outros ambientes.

Se uma credencial real for encontrada: interromper aprovação, identificar seu uso e responsável, revogar/rotacionar no serviço apropriado, removê-la do código atual e revalidar. Apagar uma linha ou um commit não revoga uma credencial. A eventual permanência de um segredo já revogado no histórico requer evidência e exceção específica; reescrita do Git não é automática.

## Política SCA

Configuração executável: `security/sca-policy.json`. Os comandos consultam os serviços públicos de advisories, usando os lockfiles completos e ferramentas fixadas. A análise inclui dependências diretas, transitivas e de desenvolvimento; não executa scripts de pacotes nem altera suas versões. Inventários registram nome, versão exata, origem, caminho e escopo. A consistência manifesto/lock é verificada antes da auditoria.

| Condição sem exceção específica | Decisão |
|---|---|
| Vulnerabilidade em dependência de runtime com severidade moderada, alta ou crítica | Bloqueia |
| Vulnerabilidade em dependência de desenvolvimento/build com severidade alta ou crítica | Bloqueia |
| Severidade desconhecida | Bloqueia até análise |
| Severidade inferior ao limiar do escopo ou pacote abandonado | Mantém alerta `review`; não bloqueia automaticamente |
| Ferramenta/registro inacessível, JSON inválido, inventário inconsistente, lock desatualizado ou divergência entre saída e relatório | Falha operacional, bloqueia |

Justificativa contextual: bibliotecas de runtime são distribuídas no backend/bundle acessível pela aplicação. Dependências exclusivamente de desenvolvimento ficam fora do runtime final; seu limiar inicial é maior, mas continuam analisadas porque o build é uma superfície de ataque. A classificação usa as marcações do lockfile, não uma prova automática de explorabilidade. Um pacote compartilhado com runtime recebe o limiar mais restritivo. Esta distinção não torna vulnerabilidades de build inofensivas; achados abaixo do limiar exigem revisão antes da conclusão do relatório, e sua prioridade pode ser elevada após análise.

Metavulnerabilidades npm (por exemplo, `react-router-dom` afetado por depender de `react-router`) conservam a cadeia e os IDs dos advisories; não são apresentadas como novos CVEs independentes. Pacote abandonado indica manutenção, não necessariamente uma vulnerabilidade. Novas categorias não vazias do Composer que o integrador ainda não reconhece causam falha operacional, nunca aprovação silenciosa.

Exceções SCA, se necessárias, devem identificar **ecossistema + pacote + versão exata + advisory**, com justificativa, classificação, risco, controles, responsável e vencimento. Todos os advisories/versões de um achado precisam estar cobertos; versões novas e pacotes pais não herdam a exceção. Exceções expiradas/incompletas reprovam. O registro começa vazio: os avisos do Router foram tratados pela atualização pontual da dependência, sem relaxar a política.

Os dois advisories iniciais do Router são moderados e estão em dependências de runtime; portanto bloqueiam enquanto não forem corrigidos ou excepcionados. A análise de aplicabilidade em `docs/sca.md` distingue versão afetada de exploração demonstrada. Optou-se por corrigir a dependência em vez de manter uma exceção, inclusive para o advisory SSR não aplicável ao modo atual.

## Política SAST

Configuração executável: `security/sast-policy.json`. Semgrep CE 1.186.0 analisa o código PHP/JavaScript/JSX/TypeScript próprio, incluindo configuração em código, migrações, build e testes. As 89 regras selecionadas de PHP, Doctrine, Symfony, JavaScript/browser e React são identificadas por revisão e hashes em `security/semgrep/provenance.json`. O guia `docs/sast.md` descreve limites e obtenção das regras. Não há upload do código para um serviço SAST.

| Evidência da regra | Decisão |
|---|---|
| Severidade `ERROR` ou `WARNING`, confiança `HIGH` ou `MEDIUM` | Bloqueia para correção ou análise específica |
| Confiança `LOW`, ou severidade `INFO` | Mantém `review`, exige análise documentada; não bloqueia automaticamente |
| Severidade/confiança desconhecida | Bloqueia até revisão |
| Scanner indisponível, download/hash inválido, relatório inválido, parsing incompleto, timeout, regra pulada ou arquivo selecionado não analisado | Falha operacional, bloqueia |

A confiança é a estimativa da regra, não comprovação automática de explorabilidade. O contexto de dados HTTP no backend e de dados da API no navegador justifica impedir padrões de injeção com confiança média/alta. Regras genéricas de auditoria com confiança baixa exigem inspeção antes de alterar código funcional; o alerta de `unlink` em `tests/functional.php` foi revisado e não recebe dados do usuário. O relatório mantém esse alerta. Não existe exceção SAST nem supressão por `nosemgrep`; o registro de exceções deve permanecer vazio até haver implementação e revisão de um mecanismo específico. Alterações nas regras/política requerem revalidação dos controles.

Saídas do integrador: 0 = análise válida sem bloqueantes (pode haver `review`), 1 = violação, 2 = erro operacional. O scanner nativo pode retornar 1 por um alerta de revisão e o integrador retornar 0: isso aplica a política explícita e não mascara uma falha de execução. A validade do JSON, cobertura e coerência com o retorno nativo são verificadas antes dessa decisão.

## Política IaC

Configuração executável: `security/iac-policy.json`; scanner Checkov 3.4.6 com regras nativas incluídas na imagem fixada, mais três regras locais em `security/checkov/`. Alvo de segurança: o Dockerfile completo. `compose.yaml` é usado somente para confirmar `app.build.context: .`, Dockerfile e target `app` final; não é apresentado como cobertura de todas as configurações Compose.

A execução offline não fornece severidades oficiais de plataforma. A decisão é **por ID e contexto**, sem inventar classificações do fornecedor:

| Regra/condição | Decisão e motivo |
|---|---|
| `CKV_DOCKER_1,2,3,5,7,8,10,11` | Bloqueia: exposição SSH, ausência de usuário/healthcheck, uso de root, atualização separada da instalação, tag latest/ausente, diretório relativo ou aliases conflitantes são incompatíveis com a política desta aplicação. |
| `CKV2_DOCKER_1` a `CKV2_DOCKER_17` | Bloqueia práticas de build como sudo, desativação TLS/assinaturas e uso de chpasswd. Inspecionar a regra específica no relatório, sem confundir essas práticas com um CVE confirmado. |
| `CKV_DOCKER_4,6,9` | `review`: ADD, MAINTAINER e uso de apt exigem avaliação, mas não comprovam exploração isoladamente; os alertas permanecem visíveis. |
| `CKV_ACME_DOCKER_1` | Bloqueia se o estágio final app não declarar usuário não root explicitamente; considera UID 0 e não confunde USER do build com runtime. |
| `CKV_ACME_DOCKER_2` | Bloqueia healthcheck ausente/desativado no estágio final; presença de HEALTHCHECK NONE não basta. |
| `CKV_ACME_DOCKER_3` | Bloqueia imagem externa sem SHA256 em FROM ou COPY --from; aliases de estágios locais são permitidos. |
| Regra desconhecida com achado | Bloqueia até revisão. |
| Scanner/alvo indisponível, relatório incoerente, parsing incompleto, supressões, regras obrigatórias ausentes ou divergência no alvo Compose | Falha operacional, bloqueia; nunca tratar como zero falhas. |

O uso de root durante instalações e configuração no build não equivale à execução HTTP como root. A política requer não root explicitamente no estágio final `app`; não exige USER nem HEALTHCHECK em todos os estágios intermediários. USER herdado de imagem externa, mesmo potencialmente seguro, não satisfaz a declaração explícita exigida aqui. TLS/assinaturas e digests continuam verificados no build. O digest garante identidade da imagem, não ausência de vulnerabilidades.

Saídas do integrador: 0 = válido sem bloqueantes, 1 = violação, 2 = falha operacional. Registros de aprovação/falha podem se repetir por instrução: quantidade de avaliações não é quantidade de regras distintas. Não há exceção IaC, `soft-fail`, baseline ou supressão local permitida. Adicionar uma exceção requer implementar escopo/revisão/testes; o registro atual deve permanecer vazio.

## Evolução para as outras categorias

As decisões abaixo orientam as próximas etapas; seus controles ainda serão implementados e demonstrados:

- DAST: exigir prontidão, alcance real dos endpoints e resultado válido. Definir regras bloqueantes a partir de risco/confiança e contexto; respostas 404/500 ou scanner iniciado não comprovam cobertura.
- Para todas: erro operacional bloqueia por padrão, exceções são específicas e revisáveis, e nenhum scanner pode ser omitido para aprovar o trabalho completo.

## Evidências e avaliação

Registrar commit, versão/digest da ferramenta, hash da configuração, alvos, validade da análise, achados, decisão e limitações. Os relatórios de Secret Detection não incluem valor do segredo, trecho original, e-mail do autor ou mensagem de commit. O JSON SAST pode incluir trechos de código; revisar os artifacts antes da entrega acadêmica. O runner usa somente `contents: read`, sem credenciais da aplicação; as actions e o scanner estão fixados por SHA/digest.

O teste sintético isolado exercita detectar → bloquear → remover o literal não commitado → revalidar com as mesmas regras. A demonstração manual `secret-fixture` deve reprovar **o workflow inteiro**. `operational-failure` usa uma configuração TOML inválida no scanner real e deve reprovar como falha operacional. Não são descobertas espontâneas na aplicação. As execuções reais do GitHub precisam ser guardadas como evidências; testes locais não substituem essa comprovação.

Em SCA, preservar a execução bloqueada com Router 6.30.6 e a execução posterior à correção, identificando commits, hashes de lockfiles e o mesmo hash da política. O cenário `sca-operational-failure` retira a rede apenas da auditoria npm real: deve gerar `operational_error` e reprovar o resultado final. Fixtures de respostas usadas em testes unitários não substituem as consultas reais dos jobs SCA.

Pipeline reprovado e impedimento de merge são controles diferentes. Para impedir merge, configurar uma regra da branch exigindo `Security gate` e revisão das alterações de workflow/política, quando disponível no plano do repositório. Sem isso, o CI reprova, mas quem tem permissão ainda pode enviar alterações diretamente.

Em SAST, os cenários isolados `sast-fixture` e `sast-corrected` preservam regras/política e registram fontes/diff. O primeiro deve reprovar o gate por SQL injection e XSS; o segundo deve aprovar. `sast-operational-failure` introduz PHP inválido somente no alvo temporário e deve reprovar como análise incompleta. A aplicação real é analisada em todos os cenários.

Em IaC, comparar `iac-fixture` e `iac-corrected`: são cópias isoladas do Dockerfile, com root/healthcheck desativado e posterior restauração. Nunca são construídas/executadas. A análise real permanece obrigatória em todos os cenários. `iac-operational-failure` usa alvo inválido e deve reprovar como análise inválida. Guardar hashes de política, regras locais, imagem e entradas.
