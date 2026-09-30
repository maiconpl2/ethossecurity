# EthosSecurity

## Building your own software with AI? Make security part of your process.

**Use EthosSecurity to help find bugs, investigate vulnerabilities and review risks before putting your project into use.**

<a href="README.md"><kbd>Português (Brasil)</kbd></a> &nbsp; <a href="README.en.md"><kbd>English</kbd></a>

[**Review my project →**](#get-started) · [Explore the review areas](#product) · [Technical guide](#technical-guide)

AI helps turn an idea into software faster. Each new feature also introduces decisions about permissions, data, credentials and system behavior. Those decisions need review too.

EthosSecurity helps organize that work: gather signals of problems, identify where to investigate and guide your review with greater clarity. A supporting tool for people building an app, a SaaS product, an internal system or software for clients.

<a id="product"></a>

## Three areas of your software need attention

You do not need to know every technical term to understand the questions that matter:

| Area | The question you need to ask | How EthosSecurity helps |
|---|---|---|
| **Behavior — Bug Hunter** | Could a change break something that already worked? | Guides investigation of bugs, regressions, logic errors and exception handling |
| **Application — Application Security** | Could someone access data or actions they should not? | Guides review of access, permissions, separation between customers and handling of incoming information |
| **Infrastructure — Infrastructure Security** | Could an exposed credential, vulnerable dependency or configuration put the project at risk? | Brings together dependency, secret and configuration checks on project files |

Want to start with a broader view? **Full Scan** brings together enabled checks and organizes review across all three areas.

These areas combine tool-based checks with guided review. Automated coverage depends on rules, the environment and configured tools. Business permissions and isolation between customers require contextual validation.

## Bring a review routine to your AI development workflow

- **Choose your focus.** Investigate a change or run a broader assessment.
- **Gather the alerts.** Inspect each finding's source, location and reported severity.
- **Guide remediation.** Use evidence and recommendations to decide what to investigate and test.
- **See the gaps.** Know which checks could not run.
- **Reuse it across projects.** Maintain an assessment routine as your software evolves.

EthosSecurity does not automatically change your code. Remediation and release decisions remain subject to review by the people developing and operating the project.

## Analysis resources in one workflow

EthosSecurity organizes tools for code, dependency, credential and application analysis. Execution and report-reading integrations are provided for **Semgrep, CodeQL, Trivy, Gitleaks, OSV-Scanner and OWASP ZAP**, enabled according to configuration and review purpose.

Connection configurations are also prepared for **OpenAI/ChatGPT/Codex, Claude/Anthropic and Google Antigravity**. Use EthosSecurity directly from the terminal and prepare a connection to your assistant to help interpret results.

External tools are installed separately and have their own terms. EthosSecurity does not include AI model subscriptions or automatically select or execute models. The listed brands identify tools and integration environments; they do not indicate partnership, endorsement or certification by those providers.

## From your project to your next step

**Choose the project → prepare the tools → run the assessment → validate findings → test fixes.**

The result is a report for tools and assistants, with alerts and check status. It helps guide investigation; each alert still needs confirmation in the project's context.

<a id="get-started"></a>

## Start by reviewing your project

You do not have to begin with a full audit. Choose the review area that fits your needs and follow the preparation steps in the guide.

[**Open the guide and prepare my first assessment →**](docs/USAGE.en.md)

If you do not work with terminal commands, ask for technical help with initial installation, scanner configuration and result interpretation.

## Current availability

**Initial version 0.1.0.** The local package, MCP communication and real Gitleaks and Semgrep runs were verified; ten automated tests passed. Direct GitHub installation and the test, build and scan pipeline passed verification. Starter rules provide limited coverage. Real execution of CodeQL, Trivy, OSV-Scanner and ZAP, plus live connections in the listed products, still requires acceptance testing.

The product currently provides no graphical dashboard, automatic remediation or hosted public service. Remote ChatGPT usage requires additional access setup. The source is public. Noncommercial use follows the included license; businesses may evaluate it for 30 days under the conditions below. Commercial use outside evaluation requires a separate license. Commercial pricing and plans remain to be defined.

## Try it on your project

- **Personal and noncommercial use:** free under the [PolyForm Noncommercial license](licenses/PolyForm-Noncommercial-1.0.0.md), including other uses permitted by that license.
- **Business evaluation:** 30 consecutive calendar days for evaluation in development or test environments. Read the [evaluation terms](EVALUATION.en.md).
- **Continuing commercial use, production or services for clients:** obtain a written commercial license before such use. [Request commercial permission →](https://github.com/maiconpl2/ethossecurity/issues/new?template=licensing.yml)

The period starts with the first business evaluation use; reinstalling or updating does not restart it. This version relies on usage terms, with no automatic activation or blocking. There is no automatic purchase, renewal or charge after evaluation.

<a id="technical-guide"></a>

## Technical guide

<details>
<summary><strong>Installation, execution and assistant connections</strong></summary>

The [complete technical guide](docs/USAGE.en.md) covers requirements, installation, scanner configuration, assistant connections and result interpretation.

Example after installation and scanner preparation:

```sh
ethos-sec scan /path/to/project --profile full-scan --output reports/security.json
```

Available profiles: `bug-hunter`, `app-security`, `infra-security` and `full-scan`. Missing tools, failures and partial assessments are reported; they are not presented as successful assessments.

</details>

## Responsible use and assessment limitations

EthosSecurity supports the identification and investigation of defects. Its results may include false positives and may miss vulnerabilities. No alerts does not prove security, compliance or the absence of problems; the tool does not replace testing, specialist review or other protective measures.

Users must assess only systems they own or are authorized to evaluate, configure the environment appropriately, protect data and credentials, and validate findings and fixes before applying them or putting software into production.

Usage, modification and deployment decisions remain with the user. This notice does not exclude statutory warranties, consumer rights or liabilities that applicable law does not allow to be excluded. Free usage permissions are described in [LICENSE](LICENSE) and the [evaluation terms](EVALUATION.en.md). A commercial license must specify scope, technical validity, support and commercial conditions; this notice does not replace those terms.
