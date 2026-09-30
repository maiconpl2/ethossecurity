# EthosSecurity — guia técnico de uso

<a href="USAGE.pt-BR.md"><kbd>Português (Brasil)</kbd></a> &nbsp; <a href="USAGE.en.md"><kbd>English</kbd></a>

[Voltar à apresentação](../README.md)

## Instalação

Requisitos: Python 3.11 ou superior, scanners escolhidos instalados separadamente e Git para instalação direta do repositório. Repositórios privados exigem acesso autorizado.

```sh
python -m venv .venv
```

Ative o ambiente conforme seu sistema:

```sh
# Windows PowerShell
.venv\Scripts\Activate.ps1
# Linux/macOS
source .venv/bin/activate
```

Na raiz da fonte distribuída:

```sh
python -m pip install .
ethos-sec --help
```

Ou instale o arquivo `.whl` fornecido com `python -m pip install /caminho/ethossecurity-0.1.0-py3-none-any.whl`.

Para instalar a versão publicada pelo GitHub:

```sh
python -m pip install "git+https://github.com/maiconpl2/ethossecurity.git@v0.1.0"
```

Prefira uma versão ou commit revisado. Não inclua tokens na URL. Instalar o EthosSecurity não instala os scanners.

## Prepare o projeto e execute

```sh
ethos-sec init /caminho/absoluto/do/projeto --adapter openai
ethos-sec scan /caminho/do/projeto --profile full-scan --output reports/security.json
```

No `init`, escolha `anthropic` ou `antigravity` para os outros clientes. O comando exporta quatro skills, `ethossecurity.yaml` e um fragmento MCP em `.ethossecurity/`, sem sobrescrever arquivos existentes. Reutilize esses arquivos nas próximas análises. Mescle o fragmento nas configurações do cliente e recarregue-o; o comando não registra o servidor automaticamente.

Perfis disponíveis: `bug-hunter`, `app-security`, `infra-security` e `full-scan`. A configuração é lida de `ethossecurity.yaml` na raiz do projeto, quando presente. Para indicar uma configuração confiável explicitamente:

```sh
ethos-sec scan /caminho/do/projeto --config /caminho/confiavel/ethossecurity.yaml --output reports/security.json
```

## Prepare as ferramentas

O padrão habilita Semgrep, Trivy, Gitleaks e OSV-Scanner. CodeQL e ZAP exigem preparação e habilitação explícitas. O perfil determina quais ferramentas habilitadas são aplicáveis.

| Ferramenta | Preparação e alcance desta versão |
|---|---|
| [Semgrep](https://semgrep.dev/docs/getting-started/) | CLI no PATH; duas regras locais iniciais, com cobertura limitada |
| [CodeQL](https://docs.github.com/en/code-security/codeql-cli) | Database e query suite preparados; informar `codeql_database`, `codeql_queries` e habilitar `codeql`. Observe os termos de uso da ferramenta |
| [Trivy](https://trivy.dev/) | CLI no PATH; análise do filesystem para dependências e configurações. Downloads de bases podem exigir rede |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | CLI 8.x no PATH; varredura dos arquivos atuais, com omissão dos valores de credenciais |
| [OSV-Scanner](https://google.github.io/osv-scanner/) | CLI 2.x no PATH; análise de dependências. Consultas podem enviar metadados de pacotes |
| [OWASP ZAP](https://www.zaproxy.org/docs/docker/baseline-scan/) | Runtime de `zap-baseline.py` preparado; configurar `zap_target`, a URL exata em `authorized_targets` e habilitar `zap` |

Use ZAP somente em alvos autorizados de teste. Baseline faz navegação e análise passiva; não substitui testes de autorização ou lógica de negócio. A ferramenta, a rede e o alcance de navegação precisam ser configurados adequadamente pelo operador.

## Conecte seu assistente

Para executar o servidor local:

```sh
ethos-sec mcp --root /caminho/absoluto/do/projeto --config /caminho/confiavel/ethossecurity.yaml
```

Configure esse comando no cliente ou use o fragmento gerado por `init`. Ele aponta para o ambiente Python usado na instalação; preserve esse ambiente.

- **OpenAI/Codex:** mescle `.ethossecurity/openai.toml` na configuração MCP do cliente.
- **Claude/Anthropic:** mescle `.ethossecurity/anthropic.json` na configuração MCP apropriada. Claude Code usa `.mcp.json`; outros clientes podem ter localização diferente.
- **Antigravity:** mescle `.ethossecurity/antigravity.json` na configuração MCP acessível pelo cliente.
- **ChatGPT:** quando houver suporte local a STDIO, use o comando local. Uso remoto/hospedado exige servidor acessível, autenticação e configuração adicional; não há serviço público hospedado nesta entrega.

Após recarregar o cliente, confira `security_profiles` e execute `security_scan` com o perfil escolhido. As configurações foram preparadas; as conexões reais nos produtos ainda não foram homologadas.

O modo `--http` escuta em localhost e exige um gateway com TLS e autenticação para exposição externa. Não exponha o servidor diretamente. Use uma configuração controlada pelo operador.

## Leia os resultados

O JSON inclui `executions`, `findings`, `complete`, `policy_failed` e `policy_unknown`. `complete` se refere às ferramentas habilitadas e aplicáveis, não à cobertura de todos os controles de segurança.

Cada finding contém gravidade, confiança, CWE/OWASP quando informados, arquivo/linha ou endpoint, evidência, impacto, explorabilidade, recomendação, patch sugerido, origem e estado de validação. Dados não determinados permanecem desconhecidos ou vazios. Alertas começam como `unvalidated`; uma regra acionada não é uma vulnerabilidade confirmada. Patches não são gerados ou aplicados automaticamente.

| Código de saída | Interpretação |
|---|---|
| `0` | Ferramentas solicitadas concluídas e nenhum finding atingiu o limite configurado |
| `1` | Execução concluída com findings que atingiram o limite |
| `2` | Entrada inválida, execução incompleta ou gravidade desconhecida que requer triagem |

Ferramentas indisponíveis, falhas e análises parciais são registradas. Confirme o contexto, reproduza os riscos com dados de teste e valide as correções. Ausência de alertas não comprova ausência de problemas.

Importe também um relatório externo compatível:

```sh
ethos-sec import codeql reports/codeql.sarif --output reports/normalized.json
ethos-sec import trivy reports/image.json --output reports/image-normalized.json
```

## Operação e automação

O workflow GitHub Actions incluído testa, empacota e demonstra uma análise com Semgrep. Ele ainda não foi executado no GitHub e não publica pacotes automaticamente.

Analise somente projetos autorizados. Repositórios não confiáveis devem ser processados em ambiente isolado, sem credenciais de produção. Revise os relatórios antes de compartilhá-los: caminhos, endpoints e metadados também podem ser sensíveis.
