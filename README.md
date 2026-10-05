# EthosSecurity

## Criando seu próprio software com IA? Coloque a segurança no seu processo.

**Use o EthosSecurity para ajudar a encontrar bugs, investigar vulnerabilidades e revisar riscos antes de colocar seu projeto em uso.**

<a href="README.md"><kbd>Português (Brasil)</kbd></a> &nbsp; <a href="README.en.md"><kbd>English</kbd></a>

[**Quero revisar meu projeto →**](#comecar) · [Conheça as frentes de análise](#produto) · [Guia técnico](#guia-tecnico)

A IA permite transformar uma ideia em software com mais rapidez. Junto com cada nova funcionalidade, surgem decisões sobre permissões, dados, credenciais e funcionamento do sistema. Essas decisões também precisam de revisão.

O EthosSecurity ajuda você a organizar essa etapa: reunir sinais de problemas, entender onde investigar e conduzir a revisão com mais clareza. Uma ferramenta de apoio para quem está criando um aplicativo, um SaaS, um sistema interno ou um produto para clientes.

<a id="produto"></a>

## Seu software precisa de atenção em três frentes

Não é preciso dominar todos os nomes técnicos para entender as perguntas que importam:

| Frente | A pergunta que você precisa fazer | Como o EthosSecurity ajuda |
|---|---|---|
| **Funcionamento — Bug Hunter** | Uma mudança pode quebrar algo que já funcionava? | Orienta a investigação de bugs, regressões, erros de lógica e exceções |
| **Aplicação — Application Security** | Alguém pode acessar dados ou ações que não deveria? | Orienta a revisão de acesso, permissões, separação entre clientes e tratamento das informações recebidas |
| **Infraestrutura — Infrastructure Security** | Uma credencial exposta, dependência vulnerável ou configuração pode colocar o projeto em risco? | Reúne verificações de dependências, segredos e configurações nos arquivos do projeto |

Quer começar com uma visão mais ampla? O **Full Scan** reúne as verificações habilitadas e organiza a revisão das três frentes.

As frentes combinam verificações por ferramentas com revisão orientada. A cobertura automática depende das regras, do ambiente e das ferramentas configuradas. Permissões de negócio e isolamento entre clientes precisam de validação contextual.

## Leve uma rotina de revisão para o seu desenvolvimento com IA

- **Escolha o foco.** Investigue uma mudança ou faça uma avaliação mais ampla.
- **Reúna os alertas.** Consulte a origem, a localização e a gravidade informada de cada achado.
- **Direcione a correção.** Use as evidências e orientações para decidir o que investigar e testar.
- **Enxergue as lacunas.** Saiba quais verificações não puderam ser executadas.
- **Reutilize em outros projetos.** Mantenha uma rotina de análise conforme seu software evolui.

O EthosSecurity não aplica alterações ao código automaticamente. As decisões de correção e liberação continuam sob revisão de quem desenvolve e opera o projeto.

## Recursos de análise reunidos em um só fluxo

O EthosSecurity organiza ferramentas de análise de código, dependências, credenciais e aplicações. Há integrações de execução e leitura de relatórios para **Semgrep, CodeQL, Trivy, Gitleaks, OSV-Scanner e OWASP ZAP**, ativadas conforme a configuração e a finalidade da revisão.

Também há configurações de conexão preparadas para **OpenAI/ChatGPT/Codex, Claude/Anthropic e Google Antigravity**. A instalação assistida prepara a conexão local, e seu assistente ajuda a investigar e explicar os resultados.

A instalação assistida prepara Semgrep, Trivy, Gitleaks e OSV-Scanner; CodeQL e ZAP exigem preparação adicional. As ferramentas externas têm seus próprios termos. O EthosSecurity não inclui assinaturas de modelos de IA nem seleciona ou executa modelos automaticamente. As marcas citadas identificam ferramentas e ambientes de integração; não indicam parceria, aprovação ou certificação desses fornecedores.

## Do projeto ao próximo passo

**Escolha o projeto → prepare as ferramentas → execute a análise → valide os achados → teste as correções.**

O resultado é um relatório que pode ser lido por ferramentas e assistentes, com alertas e o estado das verificações. Ele ajuda a conduzir a investigação; cada alerta ainda precisa ser confirmado no contexto do projeto.

<a id="comecar"></a>

## Comece dentro do assistente que você já utiliza

Abra seu projeto no **Codex, Claude Code ou Google Antigravity** e envie:

> Instale o EthosSecurity deste link no meu projeto: https://github.com/maiconpl2/ethossecurity. Leia INSTALL.md, prepare a integração compatível com este assistente e faça a primeira análise. Explique os resultados em português, incluindo o que não foi verificado. Preserve meu código e minhas configurações existentes.

Seu assistente cuida da preparação; você acompanha e aceita as permissões necessárias. Ele precisa ter acesso ao projeto, executar ferramentas e baixar dependências. A conexão pode exigir reabrir o projeto ou aceitar a integração no assistente.

[**Ver como começar →**](docs/START.pt-BR.md) · [Ambientes e testes realizados](docs/COMPATIBILITY.md)

### No Claude Code, instale como plugin

Adicione o marketplace uma única vez e escolha as skills que deseja. O motor de análise é instalado automaticamente com qualquer uma delas.

```text
/plugin marketplace add maiconpl2/ethossecurity
/plugin install full-scan@ethossecurity
```

| Plugin | O que adiciona |
|---|---|
| `ethossecurity` | Motor de análise (MCP), incluído automaticamente |
| `bug-hunter` | Revisão de bugs e falhas de lógica |
| `app-security` | Autenticação, autorização, isolamento entre clientes, injeções e exposição de dados |
| `infra-security` | Dependências vulneráveis, credenciais expostas e configurações |
| `full-scan` | Análise completa; inclui as três skills acima |

Depois, em qualquer projeto aberto no Claude Code, peça: *"faça uma análise de segurança deste projeto"*. Não é preciso indicar a pasta: o plugin analisa o projeto da sessão. Na primeira análise, o Claude prepara os scanners em `~/.ethossecurity`, uma única vez por computador. Os relatórios ficam em `~/.ethossecurity/reports/` e o projeto analisado não é alterado. Requer o [uv](https://docs.astral.sh/uv/) instalado.

## Disponibilidade atual

**Versão 0.2.0 — instalação assistida em validação.** A nova entrada prepara ferramentas em uma pasta isolada, registra MCP e quatro skills no projeto e gera relatórios locais em JSON e HTML. Os formatos de configuração de Codex, Claude Code e Antigravity foram testados para preservar outras integrações e permitir repetição. Veja os testes reais e as limitações em [compatibilidade](docs/COMPATIBILITY.md).

**Versão 0.3.0 — plugin do Claude Code e regras ampliadas.** O Claude Code passa a ter um marketplace próprio, com o motor de análise e uma skill por plugin, para que cada pessoa escolha o que instalar. As regras iniciais do Semgrep passaram de 2 para 75, cobrindo injeção de comando, SQL e código, path traversal, SSRF, XSS, CORS, TLS desativado, JWT, segredos com valor padrão no código, GitHub Actions e regras do Firebase em Python, JavaScript e TypeScript. Cada regra tem casos vulneráveis e seguros verificados automaticamente na integração contínua.

As regras iniciais de código têm cobertura limitada. Configuração gerada não significa conexão homologada em todos os produtos. Chat sem acesso ao projeto e execução de ferramentas não instala o EthosSecurity por receber um link. Não há serviço público hospedado, correção automática ou garantia de segurança.

## Experimente no seu projeto

- **Uso pessoal e não comercial:** gratuito conforme a [licença PolyForm Noncommercial](licenses/PolyForm-Noncommercial-1.0.0.md), incluindo os demais usos permitidos por ela.
- **Avaliação empresarial:** 30 dias corridos para avaliar em desenvolvimento ou teste. Leia as [condições de avaliação](EVALUATION.md).
- **Uso comercial contínuo, produção ou serviço a clientes:** obtenha uma licença comercial escrita antes desse uso. [Solicitar autorização comercial →](https://github.com/maiconpl2/ethossecurity/issues/new?template=licensing.yml)

O prazo começa no primeiro uso empresarial de avaliação; reinstalação ou atualização não o reinicia. Nesta versão, o controle é pelas condições de uso, sem ativação ou bloqueio automático. Não há compra, renovação ou cobrança automática ao final do teste.

<a id="guia-tecnico"></a>

## Guia técnico

<details>
<summary><strong>Instalação, execução e conexão com seu assistente</strong></summary>

O [guia técnico completo](docs/USAGE.pt-BR.md) explica requisitos, instalação, configuração de scanners, conexão com assistentes e leitura dos resultados.

Exemplo após a instalação e a preparação das ferramentas:

```sh
ethos-sec scan /caminho/do/projeto --profile full-scan --output reports/security.json
```

Perfis disponíveis: `bug-hunter`, `app-security`, `infra-security` e `full-scan`. Ferramentas ausentes, falhas e análises parciais são informadas no relatório; não são apresentadas como análise bem-sucedida.

</details>

## Uso responsável e limites da análise

O EthosSecurity é uma ferramenta de apoio à identificação e investigação de falhas. Seus resultados podem conter falsos positivos e deixar de identificar vulnerabilidades. A ausência de alertas não comprova segurança, conformidade ou ausência de problemas; a ferramenta não substitui testes, revisão especializada ou outras medidas de proteção.

O usuário deve analisar somente sistemas que possui ou está autorizado a avaliar, configurar o ambiente adequadamente, proteger dados e credenciais e validar os resultados e as correções antes de aplicá-los ou colocar o software em produção.

As decisões de uso, alteração e implantação cabem ao usuário. Este aviso não afasta garantias legais, direitos do consumidor ou responsabilidades que não possam ser excluídas pela legislação aplicável. O alcance das permissões gratuitas está descrito em [LICENSE](LICENSE) e nas [condições de avaliação](EVALUATION.md). Uma licença comercial deve especificar seu escopo, validade técnica, suporte e condições; este aviso não substitui esses termos.
