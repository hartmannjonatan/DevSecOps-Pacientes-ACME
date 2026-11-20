# Preparação da aplicação — 19–20/11/2026

## Escopo e proveniência

Aplicação reutilizada de https://github.com/hartmannjonatan/Pacientes-ACME, base local `7ca2ee4`. O remoto desta cópia é `git@github.com:hartmannjonatan/DevSecOps-Pacientes-ACME.git`. O Git estava limpo no início e não havia AGENTS.md aplicável. A preparação é registrada em um commit próprio, a pedido do estudante, sem reescrever o histórico anterior.

O enunciado e os slides da INE5429 foram consultados como referência de requisitos. Nesta etapa foi preparada a aplicação e sua automação funcional; as cinco categorias de scanners, política de bloqueio, exceções e relatório crítico acadêmico permanecem para a próxima etapa.

OpenAI Codex foi usado para inspecionar o código e ambiente, consultar documentação oficial, atualizar dependências/configuração, escrever containerização, corrigir API e integração React, implementar testes/OpenAPI e executar validações. A arquitetura e os fluxos do projeto original foram preservados; o estudante deve revisar e compreender as alterações antes de incorporá-las ao relatório.

## Decisões e versões

| Componente | Base original | Preparação |
|---|---|---|
| Symfony Framework | 6.0.16 | 7.4.23 LTS |
| PHP | requisito >=8.0.2 | 8.4.27; requisito >=8.4 |
| Doctrine ORM / DBAL | 2.14.0 / 3.5.2 | 3.8.0 / 4.6.0 |
| DoctrineBundle | 2.7.2 | 2.19.4 |
| UX React PHP | 2.6.1 | 2.36.0 |
| EncoreBundle PHP | 1.16.0 | 2.4.3 |
| React / React DOM | 18.2.0 | 18.3.1 |
| Encore / Webpack CLI | 4.2.0 / 4.10.0 | 7.2.1 / 7.3.1 |
| Webpack / Babel core | 5.75.0 / 7.20.7 | 5.112.2 / 8.1.2 |
| Stimulus bridge | 3.2.1 | 4.0.2 |
| Axios | 1.2.1 | 1.21.1 |
| Bootstrap / React Router | 5.2.3 / 6.6.1 | 5.3.9 / 6.30.6 |
| PHPUnit (desenvolvimento) | 9.5.27 | 11.5.58 |
| MySQL | URL indicava 5.7 | 8.4.13 LTS |

Symfony 7.4 estende o horizonte LTS até novembro de 2029. PHP 8.4 permite os lazy objects nativos do Doctrine. SensioFrameworkExtraBundle/annotations legados foram removidos e as rotas passaram a atributos nativos. Doctrine recebeu mapeamento explícito e índices compatíveis com o transport Messenger atual. As versões completas e transitivas estão nos lockfiles.

Encore foi atualizado preservando o bundler, com configuração ESM assíncrona e Babel 8. A ponte Stimulus antiga usava uma API interna removida no Webpack atual; 4.0.2 resolveu a compilação. O preset React agora configura explicitamente o modo de produção (evita `jsxDEV is not a function`). React permaneceu na major 18 e Router na major 6. A árvore npm foi regenerada após conflito de peers opcionais antigos, sem `--force`, `--legacy-peer-deps` ou requisitos de plataforma ignorados.

A dependência local UX React é copiada de `vendor` após Composer. `.npmrc` usa `install-links=true` para empacotar seus assets em vez de incluir dependências de desenvolvimento internas do pacote vinculado. Bibliotecas importadas pela aplicação ficam em `dependencies`; o build instala também `devDependencies`. Yarn foi removido após confirmar uso exclusivo de npm. Não se instalou PHP/Composer/Node/MySQL no host.

## Correções funcionais e infraestrutura

- API preserva os caminhos principais, recebe formulários, valida tipos/tamanhos, datas representáveis pelo MySQL, sexo e CPF com 11 dígitos; devolve erros observáveis em vez de 500 para entradas inválidas. Não valida dígitos verificadores de CPF.
- Criação retorna objeto/ID (201); pesquisa retorna lista plana com o mesmo formato da listagem; datas são ISO. React foi ajustado junto com o contrato. Campos controlados, submissão de formulário, tratamento de erro e renderização de status foram corrigidos.
- Troca de status usa POST; GET não modifica registros. CPF único é garantido no banco, inclusive sob concorrência. Migração interrompe caso já existam duplicados, sem excluir dados.
- Duas migrações históricas repetiam a criação das mesmas tabelas. Seus IDs foram mantidos como operações vazias; a primeira continua criando o esquema. Uma nova migração cria o índice único e outra atualiza índices do Messenger. A reversão das versões duplicadas não remove tabelas.
- Dockerfile multistage usa imagens oficiais fixadas por digest, Composer antes de npm, instalação por lock e assets incorporados à imagem. Apache/PHP roda como UID 33, com capabilities removidas e `no-new-privileges`. Banco possui usuário próprio e volume persistente, sem porta publicada.
- `variables_order=EGPCS` faz Apache respeitar as variáveis dos containers como o console PHP; o padrão do php.ini de produção antes fazia HTTP usar os valores de fallback do `.env`.
- Prontidão verifica SQL autenticado, migrações e consulta HTTP à tabela real. Não depende de um `sleep` fixo. As tentativas de conexão têm prazo limitado.
- Ambientes local e descartável usam projetos, bancos e volumes distintos. Limpeza nunca executa `docker system prune` nem remove volumes de outros projetos.
- Após remoção dos containers e recriação de `.env.local`, o volume local existente manteve as senhas antigas e ficou `unhealthy`. Em 20/11 foi feito backup frio verificado e recuperação das credenciais em container temporário sem rede; o registro existente foi preservado. `scripts/configure` agora recusa gerar credenciais se encontrar o volume local sem `.env.local`. O backup e as credenciais permanecem fora do Git.

## Host

Ubuntu 26.04.1 LTS. Docker Engine 29.10.0, Compose 5.8.0, Buildx, containerd/runc e util-linux-extra foram instalados com autenticação sudo fornecida pelo usuário. A sessão do agente não podia fornecer essa senha. O daemon foi verificado; `sg docker -c '…'` foi usado porque a sessão existente ainda não herdara o grupo docker. Bash/OpenSSL são necessários aos scripts locais; dependências da aplicação ficaram nos containers.

## Validação

A suíte HTTP em `tests/functional.php` usa a aplicação real e MySQL. `scripts/test-env all` constrói, aguarda saúde, verifica o contrato e compara um registro após parar/iniciar os dois containers. `scripts/test-env clean` é a limpeza explícita do ambiente descartável; a inicialização seguinte executa as migrações sobre um volume novo.

Os resultados finais estão registrados em `artifacts/validation.log`, `artifacts/platform.log` e `artifacts/schema.log` (arquivos locais ignorados pelo Git). O diretório pode ser coletado como artefato no futuro CI; nenhum workflow vazio foi criado.

No navegador integrado, foram verificados a renderização, o carregamento de um registro por ID, sua edição por formulário multipart e a pesquisa pelo nome alterado, sem erros JavaScript na rodada final. Evidência local: `artifacts/interface-validada.png`. O cadastro e a exclusão estão cobertos pela suíte HTTP; a conferência visual não é uma suíte de navegador automatizada.

As validações de Composer e plataforma, lint do container Symfony/YAML, esquema Doctrine, build Encore, CRUD/pesquisa/status, casos inválidos/404, prontidão e persistência devem ser distinguidas da análise de segurança. Avisos de depreciação internos do DoctrineBundle/DBAL não foram silenciados. A instalação npm reportou dois avisos moderados; sua aplicabilidade e tratamento pertencem à próxima etapa de SCA, sem alegação de ausência de vulnerabilidades.

Resultados finais confirmados: build e suite HTTP aprovados; persistência aprovada; esquema Doctrine sincronizado; inicialização a partir de volume vazio aprovada (`artifacts/clean-start.log`); banco indisponível produz HTTP 503 e teste com saída 1 (`artifacts/failure-check.log`). O ciclo local `stop`/`up` e `down`/`up` preserva o volume. Processo da aplicação verificado como UID 33; Node 24.22.3. Nenhum teste desta etapa constitui execução das cinco categorias de scanners.

## Limitações e próximo pipeline

Demonstração sem autenticação/autorização, HTTPS, paginação ou isolamento entre usuários. Bind somente em loopback, uso exclusivo de dados fictícios. Não adequada a pacientes reais ou exposição pública. O ambiente `prod` indica configuração Symfony sem debug, não aprovação para produção.

`docs/openapi.json` descreve os endpoints e formatos reais. `scripts/test-env seed` cria fixtures distintas e `artifacts/openapi-seeded.json` substitui IDs de exemplo. O scanner pode usar a rede `acme-test_default` e `http://app:8080`; o host acessa 8081. Chamadas de edição/exclusão exigem controlar a ordem e repor registros. Isso prepara a cobertura, não comprova execução de ZAP.

Próxima etapa: Gitleaks deve analisar arquivos e histórico (o APP_SECRET histórico não foi apagado do Git); SCA deve incluir os dois lockfiles e dependências frontend de build; SAST deve analisar PHP e JSX; IaC deve analisar o Dockerfile efetivamente usado; DAST deve alcançar as operações documentadas. Política, bloqueio, falha operacional, exceções e ciclo detectar→bloquear→corrigir→revalidar ainda serão implementados.

Os digests fixam as imagens-base, mas apt utiliza os repositórios Debian vigentes: há reprodutibilidade funcional e de dependências da aplicação, não uma garantia de imagem idêntica byte a byte em builds futuros. Atualizações de imagens/locks devem ser deliberadas e revalidadas.

## Fontes oficiais consultadas

- [Symfony 7.4 LTS e suporte](https://symfony.com/releases/7.4)
- [Symfony 6.4 e suporte](https://symfony.com/releases/6.4)
- [Atualização do Encore](https://github.com/symfony/webpack-encore/blob/main/UPGRADE.md)
- [Babel com Encore](https://symfony.com/doc/current/frontend/encore/babel.html)
- [Releases Node.js](https://nodejs.org/en/about/previous-releases)
- [Docker Engine no Ubuntu](https://docs.docker.com/engine/install/ubuntu/)
