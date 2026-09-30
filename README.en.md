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

Assisted installation prepares Semgrep, Trivy, Gitleaks and OSV-Scanner; CodeQL and ZAP need additional preparation. External tools have their own terms. EthosSecurity does not include AI model subscriptions or automatically select or execute models. The listed brands identify tools and integration environments; they do not indicate partnership, endorsement or certification by those providers.

## From your project to your next step

**Choose the project → prepare the tools → run the assessment → validate findings → test fixes.**

The result is a report for tools and assistants, with alerts and check status. It helps guide investigation; each alert still needs confirmation in the project's context.

<a id="get-started"></a>

## Start inside the assistant you already use

Open your project in **Codex, Claude Code or Google Antigravity** and send:

> Install EthosSecurity from this link in my project: https://github.com/maiconpl2/ethossecurity. Read INSTALL.md, prepare the integration compatible with this assistant, and run the first scan. Explain the results in English, including what was not checked. Preserve my code and existing configuration.

Your assistant handles preparation; follow along and accept the required permissions. It needs project access, tool execution and permitted dependency downloads. Loading the connection may require reopening the project or accepting the integration in your assistant.

[**See how to start →**](docs/START.en.md) · [Compatibility and completed tests](docs/COMPATIBILITY.md)

### In Claude Code, install it as a plugin

Add the marketplace once and choose the skills you want. The analysis engine is installed automatically with any of them.

```text
/plugin marketplace add maiconpl2/ethossecurity
/plugin install full-scan@ethossecurity
```

| Plugin | What it adds |
|---|---|
| `ethossecurity` | Analysis engine (MCP), included automatically |
| `bug-hunter` | Bug and logic-flaw review |
| `app-security` | Authentication, authorization, tenant isolation, injection and data exposure |
| `infra-security` | Vulnerable dependencies, exposed credentials and configuration |
| `full-scan` | Complete review; includes the three skills above |

Then, in any project open in Claude Code, ask: *"run a security review of this project"*. No folder selection is needed: the plugin scans the session's project. On the first scan, Claude prepares the scanners in `~/.ethossecurity`, once per computer. Reports go to `~/.ethossecurity/reports/` and the scanned project is not modified. Requires [uv](https://docs.astral.sh/uv/).

## Availability

**Version 0.2.0 — assisted installation under validation.** The new entrypoint prepares isolated tools, registers project MCP and four skills, and produces local JSON/HTML reports. Configuration formats for Codex, Claude Code and Antigravity were tested for preservation of other integrations and repeated setup. See actual tests and limitations in [compatibility](docs/COMPATIBILITY.md).

Starter code rules have limited coverage. Generated configuration does not mean all product connections have been qualified. A conversation without project access and tool execution cannot install EthosSecurity merely by receiving a link. There is no public hosted service, automatic remediation or security guarantee.

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
