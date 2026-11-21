# Pacientes ACME — DevSecOps

Aplicação acadêmica de cadastro, consulta, edição, pesquisa, ativação/inativação e exclusão de pacientes fictícios: **React → API Symfony/Doctrine → MySQL**. Apache serve interface e API na mesma origem. Não há autenticação/autorização; use apenas dados fictícios em ambiente local.

Origem: [Pacientes-ACME](https://github.com/hartmannjonatan/Pacientes-ACME), base `7ca2ee4`. Esta cópia recebeu atualização de dependências, Docker, validação, testes e pipeline com apoio do **OpenAI Codex**. [Adaptações e versões](docs/preparacao.md).

## Executar com Docker

Host: Docker Engine funcionando, Compose **2.24.4+**, Bash e OpenSSL; Git/Python 3.9+ para os scanners locais. Validado em Ubuntu 26.04, Docker 29.10 e Compose 5.8. PHP 8.4, Composer 2, Node 24/npm 11 e MySQL 8.4 ficam nos containers; Symfony 7.4 LTS, React 18 e Encore 7 usam os lockfiles Composer/npm. Imagens fixadas por digest.

Na raiz do clone:

```bash
scripts/configure
scripts/dev build
scripts/dev up -d --wait --wait-timeout 180
```

Acesse **http://127.0.0.1:8080**. A configuração gera `.env.local` com credenciais aleatórias; variáveis descritas em [.env.example](.env.example). Não versione esse arquivo. O banco possui usuário próprio, volume persistente e nenhuma porta pública. A inicialização aguarda prontidão, aplica migrações e prepara o cache automaticamente. Aplicação executa como `www-data`.

```bash
scripts/dev logs --no-color --tail=100
scripts/dev stop                            # mantém dados
scripts/dev up -d --wait --wait-timeout 180 # inicia novamente
scripts/dev down                            # remove containers/rede; mantém dados
```

**Preserve `.env.local` e `acme-local_db-data`.** Acrescentar `--volumes` ao `down` apaga o banco. Se houver `Access denied`/banco `unhealthy`, confira as credenciais originais: alterar o arquivo não altera senhas de um volume existente. Permissão negada no socket Docker: renove a sessão após entrar no grupo `docker`; nesta máquina, `sg docker -c 'COMANDO'` permite usar o grupo sem reiniciar a sessão.

## Testar

```bash
scripts/test-env all    # build, HTML/assets, CRUD, validação e persistência após reinício
scripts/test-env logs
scripts/test-env clean  # apaga somente o ambiente descartável acme-test (porta 8081)
scripts/security/dast  # constrói, testa, analisa com ZAP e limpa seu próprio ambiente
```

DAST cria um projeto `acme-dast-<id>` novo, sem portas publicadas; não usa os bancos local/teste. Seu relatório fica em `artifacts/security/dast-*`. Contrato: [OpenAPI](docs/openapi.json); criação/edição/pesquisa recebem **formulários**, não JSON. IDs fictícios válidos são preparados automaticamente para o ZAP.

## Pipeline DevSecOps

[Security](.github/workflows/security.yml) roda em push, pull request e execução manual. [Política contextual](security/POLICY.md): análise incompleta/erro operacional bloqueia; alerts e decisões permanecem nos artifacts por **14 dias**.

| Job | Análise/controle |
|---|---|
| Secret Detection | Gitleaks: arquivos e histórico Git |
| SCA (composer), SCA (npm) | Dependências dos dois lockfiles, incluindo desenvolvimento |
| SAST (PHP and React) | Semgrep: código próprio PHP/JS/JSX |
| IaC (Dockerfile) | Checkov + regras locais: Dockerfile realmente utilizado |
| DAST (ZAP and disposable app) | API/interface em execução, cobertura HTTP, scan passivo e ativo |
| Security policy tests | Testes de decisão, bloqueio, correção e erros dos integradores |
| Security gate | Exige sucesso de todos os anteriores |

Em **Actions → Security → Run workflow → scenario**:

| Cenário | Resultado esperado do gate |
|---|---|
| `normal` | Aprova se todas as análises aprovarem |
| `secret-fixture` | Reprova por segredo sintético |
| `operational-failure`, `sca-operational-failure` | Reprova por erro de Gitleaks/auditoria npm |
| `sast-fixture`, `iac-fixture`, `dast-fixture` | Reprova pelo achado demonstrado na categoria |
| `sast-corrected`, `iac-corrected`, `dast-corrected` | Aprova após correção, com os mesmos controles |
| `sast-operational-failure`, `iac-operational-failure`, `dast-operational-failure` | Reprova por análise inválida/alvo indisponível |

Os cenários adicionais preservam a análise normal obrigatória e usam alvos isolados. O caso real SCA conserva os commits com Router vulnerável e atualizado; DAST conserva o bloqueio por cabeçalhos ausentes e sua correção. Guias/evidências: [segredos](docs/secret-detection.md), [SCA](docs/sca.md), [SAST](docs/sast.md), [IaC](docs/iac.md), [DAST](docs/dast.md). Os guias incluem os comandos individuais dos scanners; suíte de controles: `python3 -m unittest discover -s tests/security -v`.

A exceção do segredo acadêmico histórico vence em **26/11/2026** e exige revisão. Gate verde não certifica segurança; DAST não cobre todos os ataques/estados. Impedir merge exige configurar proteção de branch para `Security gate`. O relatório acadêmico detalhará achados, correções, limitações e execuções confirmadas no Actions.
