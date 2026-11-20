# Pacientes ACME — base para DevSecOps

Demonstração local de cadastro, consulta, edição, pesquisa, ativação/inativação e exclusão de pacientes **fictícios**. React → API Symfony/Doctrine → MySQL. Apache serve a interface, os assets compilados e a API na mesma origem; não há serviço externo obrigatório.

Origem: [Pacientes-ACME](https://github.com/hartmannjonatan/Pacientes-ACME), base `7ca2ee4`; esta cópia tem remoto `DevSecOps-Pacientes-ACME`. As adaptações de execução, dependências, validação, testes e documentação foram implementadas com apoio do **OpenAI Codex**. [Registro das adaptações e fontes](docs/preparacao.md).

## Ambiente e inicialização

Host: Docker Engine funcionando, Compose com `up --wait`, Bash e OpenSSL. Validado em Ubuntu 26.04, Docker 29.10.0 e Compose 5.8.0. PHP 8.4.27, Composer 2.11.2, Node 24.22.3/npm 11.19.1, Symfony 7.4.23 LTS, Doctrine ORM 3.8/DBAL 4.6, MySQL 8.4.13, React 18.3.1 e Encore 7.2.1 ficam **nos containers**. Imagens fixadas por digest; dependências resolvidas em `composer.lock` e `package-lock.json` (somente npm).

No Ubuntu, se Docker faltar: `bash scripts/install-docker-ubuntu.sh` (requer sudo). Depois de adicionar seu usuário ao grupo docker, entre novamente na sessão; esse grupo concede acesso administrativo. Nesta máquina foi necessário instalar `util-linux-extra` e usar `sg docker -c 'COMANDO'` até renovar a sessão.

Na raiz do clone:

```bash
scripts/configure
scripts/dev build
scripts/dev up -d --wait --wait-timeout 180
```

Acesse **http://127.0.0.1:8080**. `scripts/configure` gera `.env.local` com permissões restritas e credenciais aleatórias; preserva um arquivo existente. `.env.example` descreve `APP_PORT`, `APP_SECRET`, `DB_NAME`, `DB_USER`, `DB_PASSWORD` e `DB_ROOT_PASSWORD`. Use valores alfanuméricos/hexadecimais nas senhas da URL; não versione o arquivo local. Alterar a senha no arquivo não altera usuários de um volume MySQL já inicializado.

Compose cria o banco e seu usuário próprio, aguarda uma consulta SQL autenticada e inicia a aplicação. O entrypoint aguarda o banco, aplica migrações e prepara o cache; `/health` só retorna 200 quando consegue consultar a tabela. Apache/PHP executam como `www-data`, na porta interna 8080, com cache/logs graváveis. O banco não publica porta no host. `APP_ENV=prod` desativa o debug, mas esta configuração continua sendo uma **demonstração local**, não implantação de produção.

```bash
scripts/dev logs --no-color --tail=100
scripts/dev stop                             # preserva containers e dados
scripts/dev up -d --wait --wait-timeout 180  # inicia novamente
scripts/dev down                             # remove containers/rede; preserva o volume
```

Os dados locais ficam em `acme-local_db-data`. **Não acrescente `--volumes` ao comando local**, salvo se realmente quiser apagá-los. Migrações são automáticas e idempotentes; não use `doctrine:schema:update --force`.

Preserve também `.env.local` ao remover containers/imagens. Se esse arquivo for recriado com outras senhas e o volume antigo continuar existindo, MySQL retorna `Access denied` e o banco fica `unhealthy`. Restaure as credenciais originais ou recupere as senhas do banco com backup prévio; não apague o volume para corrigir autenticação. `scripts/configure` impede gerar novas credenciais quando encontra esse volume sem o arquivo local.

## Testes e comandos reutilizáveis no CI

O projeto Compose fixo `acme-test`, porta **8081**, banco `acme_test` e volume `acme-test_db-data` são exclusivamente descartáveis. Usa a mesma imagem e configuração de produção, com credenciais públicas de teste em `tests/compose.env`.

```bash
scripts/test-env all         # build, prontidão, testes HTTP e persistência após reinício
scripts/test-env seed        # registros fictícios e OpenAPI com IDs reais para futuro DAST
scripts/test-env logs        # logs dos dois serviços
scripts/test-env clean       # apaga SOMENTE containers/rede/volume do projeto acme-test
```

Também existem `build`, `up`, `wait`, `migrate`, `test`, `persistence` e `stop`, executáveis separadamente. Não rode duas instâncias de `all` ao mesmo tempo no mesmo host. Os testes devolvem saída diferente de zero ao falhar; `all` coleta `artifacts/test-failure.log` e preserva o ambiente para inspeção. No CI, use `clean` em uma etapa final executada mesmo após falha.

A suíte verifica HTML/assets, rotas da SPA, cadastro por formulário, leitura persistida, listagem, edição, pesquisa, status, exclusão, duplicidade, entradas inválidas e 404. A persistência é comparada antes/depois de parar e iniciar aplicação e MySQL. O teste se recusa a alterar outro banco. A interface também foi conferida no navegador; essa conferência não integra a suíte HTTP.

## API e próxima etapa

Contrato: [docs/openapi.json](docs/openapi.json). Cadastro/edição/pesquisa recebem `application/x-www-form-urlencoded` ou `multipart/form-data`, **não JSON**. Datas: `AAAA-MM-DD`. Criação retorna 201 e o registro com ID; erros de entrada retornam 422, CPF duplicado 409 e registro ausente 404. Alteração de status usa POST.

`seed` grava `artifacts/dast-fixtures.json` e `artifacts/openapi-seeded.json`, com IDs distintos para consulta, edição e exclusão. O futuro ZAP poderá acessar `http://app:8080` pela rede `acme-test_default`. Recrie fixtures entre análises destrutivas; importar OpenAPI não garante cobertura de sequências com estado.

CI: Secret Detection nos arquivos/histórico, SCA dos lockfiles PHP/JS, SAST do código PHP/JSX e IaC do Dockerfile, com [política de bloqueio](security/POLICY.md), relatórios e testes de falha. Execute `scripts/security/scan`, `scripts/security/sca`, `scripts/security/sast`, `scripts/security/iac` e `python3 -m unittest discover -s tests/security -v` (Docker, Git e Python 3.9+). Guias: [Secret Detection](docs/secret-detection.md), [SCA, achados e revalidação](docs/sca.md), [SAST](docs/sast.md) e [IaC, cobertura e demonstrações](docs/iac.md). A exceção histórica de segredo vence em **26/11/2026** e exige revisão. DAST ainda será implementado.

Não há autenticação/autorização nem validação dos dígitos verificadores de CPF; use somente dados fictícios e mantenha o bind em loopback. Os testes funcionais e a análise de segredos não certificam segurança.

Problemas encontrados e corrigidos: migrações duplicadas, configuração antiga de Doctrine, variáveis ausentes no Apache e preset React de desenvolvimento no bundle de produção. Se aparecer `permission denied` no socket Docker, renove a sessão do grupo; se a prontidão falhar, consulte `logs`. Migração com CPFs duplicados preexistentes interrompe sem apagar registros: a revisão é manual. Detalhes e resultados em [docs/preparacao.md](docs/preparacao.md).
