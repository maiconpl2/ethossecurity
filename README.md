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

Também há configurações de conexão preparadas para **OpenAI/ChatGPT/Codex, Claude/Anthropic e Google Antigravity**. Você pode usar o EthosSecurity diretamente pelo terminal e preparar a conexão com seu assistente para apoiar a interpretação dos resultados.

As ferramentas externas são instaladas separadamente e têm seus próprios termos. O EthosSecurity não inclui assinaturas de modelos de IA nem seleciona ou executa modelos automaticamente. As marcas citadas identificam ferramentas e ambientes de integração; não indicam parceria, aprovação ou certificação desses fornecedores.

## Do projeto ao próximo passo

**Escolha o projeto → prepare as ferramentas → execute a análise → valide os achados → teste as correções.**

O resultado é um relatório que pode ser lido por ferramentas e assistentes, com alertas e o estado das verificações. Ele ajuda a conduzir a investigação; cada alerta ainda precisa ser confirmado no contexto do projeto.

<a id="comecar"></a>

## Comece pela revisão do seu projeto

Você não precisa começar por uma auditoria completa. Escolha a frente que corresponde à sua necessidade e siga a preparação indicada no guia.

[**Abrir o guia e preparar minha primeira análise →**](docs/USAGE.pt-BR.md)

Se você não trabalha com comandos, peça apoio técnico para a instalação inicial, a configuração das ferramentas e a interpretação dos resultados.

## Disponibilidade atual

**Versão inicial 0.1.0.** O pacote local, a comunicação MCP e execuções reais do Gitleaks e do Semgrep foram verificados; dez testes automatizados passaram. A instalação diretamente pelo GitHub e o pipeline de testes, empacotamento e análise passaram nas verificações. As regras iniciais têm cobertura limitada. Execução real do CodeQL, Trivy, OSV-Scanner e ZAP, além das conexões nos produtos citados, ainda precisa de homologação.

O produto não oferece atualmente painel gráfico, correção automática ou serviço público hospedado. O uso em ChatGPT remoto exige configuração de acesso adicional. O código é público. O uso não comercial segue a licença incluída; empresas podem avaliar por 30 dias, nas condições abaixo. Uso comercial fora da avaliação exige licença separada. Preços e planos comerciais ainda serão definidos.

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
