# Etapa 1 — política e Secret Detection

Implementação: `.github/workflows/security.yml`, `security/`, `scripts/security/` e `tests/security/`. Política: [security/POLICY.md](../security/POLICY.md). Ferramenta: Gitleaks **8.30.1**, CLI oficial em container, sem depender da action Gitleaks ou de tokens de serviços externos.

## Executar localmente

Pré-requisitos: Docker funcionando, Git, Bash e Python 3.9+ (biblioteca padrão; nenhum pacote pip). Nesta máquina, Python 3 já estava instalado. Não é necessário subir a aplicação/MySQL para Secret Detection.

```bash
scripts/security/scan
python3 -m unittest discover -s tests/security -v
```

Se a sessão não herdou o grupo Docker: `sg docker -c 'scripts/security/scan'`. O script devolve 0 para aprovação, 1 para violação da política e 2 para falha operacional. Resultado: `artifacts/security/secrets/result.json`. As versões/digests vêm de `security/tools.json`; a primeira execução pode baixar a imagem. A análise em si acontece sem rede, com mounts de entrada somente leitura.

Escopo dos arquivos: todos os versionados existentes e os ainda não versionados que o Git não ignora. Arquivos versionados continuam incluídos mesmo se corresponderem a `.gitignore`. `.env.local`, dependências instaladas, backups e artefatos ignorados não integram esse alvo; no CI eles não são necessários. O snapshot inclui dotfiles. O histórico é copiado para um repositório temporário completo, sem depender do caminho externo de `.git` desta cópia/submódulo, e analisado com `--all --full-history`. Commits inacessíveis por refs não são cobertos. Histórico raso é recusado. Submódulos internos e links simbólicos exigem tratamento explícito e geram erro, em vez de serem silenciosamente omitidos.

As regras padrão permanecem habilitadas e há uma regra explícita para APP_SECRET hexadecimal. Não se usam baselines nem exclusões amplas de `.env`; comentários `gitleaks:allow` e arquivos `.gitleaksignore` não desativam o controle. As heurísticas e exclusões próprias das regras padrão ainda limitam a detecção; ausência de alertas não prova ausência de segredos.

## Configurar no GitHub

1. Enviar o commit com esta etapa ao remoto `origin`. O workflow roda em `push`, `pull_request` e execução manual; não possui filtro de caminhos que dispense a análise. `fetch-depth: 0` disponibiliza o histórico completo ao job do scanner.
2. Em **Actions**, abrir o workflow **Security** e verificar os jobs `Secret Detection`, `Security policy tests` e `Security gate`. Se Actions estiver desativado por configuração do repositório/organização, habilitar sua execução em **Settings → Actions → General**. O workflow não requer cadastrar `APP_SECRET`, senha do MySQL, PAT ou `GITLEAKS_LICENSE` nos Secrets.
3. Baixar os artefatos `secret-detection-…` e `security-controls-…`. Guardar o link da execução, commit, resultado final e relatórios selecionados para o trabalho. A retenção solicitada é de 14 dias.
4. Na branch padrão, usar **Run workflow**, cenário `secret-fixture`. A aplicação real continua sendo analisada; adicionalmente, um repositório temporário recebe um valor fictício sem conta associada. O job do scanner e `Security gate` devem falhar. O artefato da demonstração deve indicar `policy_violation`.
5. Repetir com `operational-failure`. Uma configuração inválida é entregue ao Gitleaks real em uma cópia temporária. O resultado deve ser `operational_error`, e o workflow final também deve reprovar.
6. Executar novamente com `normal`. O cenário artificial não é aplicado, mas scanner, regras e testes permanecem ativos. Conferir aprovação e preservar as três execuções distintas. A exceção histórica segue aparecendo no relatório.

O botão manual depende de o workflow existir na branch padrão. A demonstração usa um input `choice` validado pelo script, passado por variável de ambiente. Ela não altera nem introduz segredos no histórico da aplicação. As execuções vermelhas intencionais são evidências esperadas; não devem ser “corrigidas” com `continue-on-error`.

Para exigir aprovação antes de merge, configurar em **Settings → Rules → Rulesets** (ou proteção de branch) uma regra para a branch padrão que exija o check **Security gate**. Disponibilidade depende do plano e da visibilidade do repositório. Isso é adicional ao bloqueio do resultado do pipeline e não é feito automaticamente por este workflow.

## Demonstrar localmente

```bash
python3 scripts/security/demo.py secret-fixture       # saída esperada: 1
python3 scripts/security/demo.py operational-failure  # saída esperada: 2
```

Esses comandos terminam com falha de propósito. O relatório da última demonstração fica em `artifacts/security/demo/result.json`; use `--output CAMINHO` para guardar execuções separadas. A suíte automatizada verifica o ciclo limpo → bloqueado → corrigido, compara hashes das regras antes/depois, verifica ausência do valor sensível no resultado e salva evidências em `artifacts/security/controls/`.

Também testa: segredo removido do arquivo mas presente no histórico; exceção por fingerprint que não libera o mesmo valor em arquivo atual; tentativa de ignorar por comentário/arquivo; runtime indisponível; configuração inválida no scanner real; relatório ausente, malformado ou contraditório; exceção expirada/incompleta.

## Achado real e próximos passos

O APP_SECRET histórico foi detectado antes de cadastrar a exceção. Seu uso acadêmico foi confirmado pelo responsável e o tratamento está descrito integralmente na política. A exceção **vence em 26/11/2026**: após essa data, a aprovação é interrompida até revisão. A correção da aplicação atual e a aceitação do histórico são decisões distintas; essa exceção não é apresentada como eliminação da exposição histórica.

SCA foi acrescentado na [etapa 2](sca.md); a aprovação final agora exige também os dois ecossistemas dessa análise. SAST, IaC e DAST ainda não estão implementados. O relatório acadêmico deve distinguir os testes sintéticos, o achado histórico real e as execuções efetivamente observadas no GitHub. Implementação e testes desta etapa receberam apoio do OpenAI Codex; as fontes oficiais abaixo orientaram as escolhas.

## Fontes

- [Gitleaks: CLI, configuração, histórico, redaction e códigos de saída](https://github.com/gitleaks/gitleaks/tree/v8.30.1).
- [GitHub Actions: sintaxe de workflows](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax).
- [GitHub Actions: permissões mínimas e fixação por SHA](https://docs.github.com/en/actions/reference/security/secure-use).
