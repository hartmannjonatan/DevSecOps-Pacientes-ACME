# Política de segurança — versão 2

Escopo: demonstração acadêmica Pacientes ACME, com dados fictícios, executada localmente e no CI. Objetivo: decidir a aprovação com evidências válidas, mantendo resultados de segurança separados de erros de execução. Esta versão aplica **Secret Detection e SCA**; SAST, IaC e DAST ainda não estão implementados e não são declarados aprovados.

## Decisão atual, efetivamente automatizada

| Condição | Resultado | Saída do script |
|---|---|---|
| Duas análises válidas (arquivos e histórico), nenhum achado sem exceção vigente | `pass` | 0 |
| Pelo menos um achado sem exceção específica vigente | `policy_violation` | 1 |
| Docker/scanner indisponível, timeout, configuração inválida, histórico raso, relatório ausente/malformado ou incompatível com o código de saída | `operational_error` | 2 |
| Exceção expirada, incompleta ou duplicada | `operational_error`: revisão obrigatória | 2 |

Gitleaks não oferece uma classificação uniforme de severidade para todos os segredos. Uma credencial detectada e ainda não avaliada é potencialmente utilizável: **todo achado não excepcionado bloqueia**, inclusive no histórico. O tratamento depende do contexto; não se presume que um token seja inofensivo porque está antigo ou não aparece mais no arquivo atual.

`Security gate` exige sucesso dos jobs `Secret Detection`, **ambas as entradas da matriz SCA (Composer/npm)** e `Security policy tests`, executa mesmo se outro job falhar e reprova também para `failure`, `cancelled` ou `skipped`. A matriz não cancela o outro ecossistema quando um falha. Não há `continue-on-error`, baseline automática, `|| true` para aprovar o scanner nem exceção de falha operacional. A coleta de artefatos pode ocorrer depois da falha e não transforma o job em sucesso. Falha de upload também impede aprovação.

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

Exceções SCA, se necessárias, devem identificar **ecossistema + pacote + versão exata + advisory**, com justificativa, classificação, risco, controles, responsável e vencimento. Todos os advisories/versões de um achado precisam estar cobertos; versões novas e pacotes pais não herdam a exceção. Exceções expiradas/incompletas reprovam. O registro começa vazio: os avisos do Router serão tratados pela atualização pontual da dependência, sem relaxar a política.

Os dois advisories iniciais do Router são moderados e estão em dependências de runtime; portanto bloqueiam enquanto não forem corrigidos ou excepcionados. A análise de aplicabilidade em `docs/sca.md` distingue versão afetada de exploração demonstrada. Optou-se por corrigir a dependência em vez de manter uma exceção, inclusive para o advisory SSR não aplicável ao modo atual.

## Evolução para as outras categorias

As decisões abaixo orientam as próximas etapas; seus controles ainda serão implementados e demonstrados:

- SAST: avaliar evidência e fluxo de dados das regras habilitadas. Regras bloqueantes e critérios de confiança serão versionados junto da integração, após verificar sua cobertura PHP/JSX.
- IaC: avaliar privilégios e condições inseguras no estágio de execução e no build. Identificar explicitamente as regras bloqueantes e as justificativas contextuais.
- DAST: exigir prontidão, alcance real dos endpoints e resultado válido. Definir regras bloqueantes a partir de risco/confiança e contexto; respostas 404/500 ou scanner iniciado não comprovam cobertura.
- Para todas: erro operacional bloqueia por padrão, exceções são específicas e revisáveis, e nenhum scanner pode ser omitido para aprovar o trabalho completo.

## Evidências e avaliação

Registrar commit, versão/digest da ferramenta, hash da configuração, alvos, validade da análise, achados, decisão e limitações. Os relatórios publicáveis não incluem valor do segredo, trecho original, e-mail do autor ou mensagem de commit. O runner usa somente `contents: read`, sem credenciais da aplicação; as actions e o scanner estão fixados por SHA/digest.

O teste sintético isolado exercita detectar → bloquear → remover o literal não commitado → revalidar com as mesmas regras. A demonstração manual `secret-fixture` deve reprovar **o workflow inteiro**. `operational-failure` usa uma configuração TOML inválida no scanner real e deve reprovar como falha operacional. Não são descobertas espontâneas na aplicação. As execuções reais do GitHub precisam ser guardadas como evidências; testes locais não substituem essa comprovação.

Em SCA, preservar a execução bloqueada com Router 6.30.6 e a execução posterior à correção, identificando commits, hashes de lockfiles e o mesmo hash da política. O cenário `sca-operational-failure` retira a rede apenas da auditoria npm real: deve gerar `operational_error` e reprovar o resultado final. Fixtures de respostas usadas em testes unitários não substituem as consultas reais dos jobs SCA.

Pipeline reprovado e impedimento de merge são controles diferentes. Para impedir merge, configurar uma regra da branch exigindo `Security gate` e revisão das alterações de workflow/política, quando disponível no plano do repositório. Sem isso, o CI reprova, mas quem tem permissão ainda pode enviar alterações diretamente.
