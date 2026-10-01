# Compatibility and validation

This page separates what the installer prepares from what has been observed in an actual client. Validation date: **2026-09-30**. This is an initial assisted-installation release, not universal support for every AI chat.

## Prepared integrations

| Client | Prepared format | Status |
|---|---|---|
| OpenAI Codex | Project MCP TOML, four skills, optional native plugin bundle | Codex CLI discovered the connection; Codex app-server loaded four skills and discovered both MCP tools; a real scan passed through MCP stdio. Desktop user flow remains to be evaluated |
| Anthropic Claude Code | Project MCP JSON, four skills, optional native plugin bundle | Claude Code 2.1.285 validated the plugin, discovered project MCP and reported Connected after explicit authorization in the isolated test. Interactive review and desktop flow remain to be evaluated |
| Google Antigravity IDE/CLI | Project MCP JSON and four skills | Antigravity CLI 1.0.14 validated the native bundle, processing four skills and one MCP definition. A live MCP session and interactive IDE flow remain to be evaluated |

The core is independent of model provider. Integration depends on the host application's capabilities, permissions and version. Installing into one project does not implicitly configure other projects or modify global accounts. The installer does not obtain or supply AI subscriptions/API keys.

## Platforms

Pinned binary releases are supplied for Windows x64, Linux x64, macOS Intel and macOS Apple Silicon. Semgrep is installed separately in an isolated Python environment. The assistant needs a working Python 3.11–3.14 runtime. Unavailable binaries or failed preparation are reported as gaps. Native macOS installation has not been tested here.

## Reproducible verification

- Unit tests cover all three configuration formats, existing integration preservation, conflicting connections, repeated setup, checksum rejection, managed binary changes, bounded archive extraction, escaped HTML and incomplete scan reporting.
- The smoke tests use synthetic fixtures and compare project source bytes before and after setup/analysis. They do not run project builds, exploit systems or contact a live ZAP target.
- On Windows x64, pinned Semgrep 1.178.0, Trivy 0.74.0, Gitleaks 8.30.1 and OSV-Scanner 2.6.0 were installed automatically and all four ran successfully against synthetic code, credentials, a dependency manifest and a Dockerfile. The injected credential was omitted from the consolidated report.
- Codex validation used an isolated test configuration and no model calls. CLI configuration discovery, app-server skill loading and MCP tool discovery were observed; a separate MCP SDK connection executed the code scan. This does not cover every Codex desktop/cloud permission or reload flow.
- The public v0.2.0 bootstrap and wheel were downloaded directly from GitHub into a fresh Windows x64 project. All four tools prepared and ran; an existing third-party MCP entry and the synthetic project source were preserved. Repeated preparation reused the installation. Unknown advisory severity kept exit code 2, correctly requiring triage even though enabled scanner executions completed.
- [GitHub CI run 36773697142](https://github.com/maiconpl2/ethossecurity/actions/runs/36773697142) passed unit tests/build, repository Semgrep analysis and a fresh assisted installation on Linux x64. The Linux smoke test ran all four scanners, tested all three configuration adapters, preserved source and omitted the planted credential.
- Claude Code's native validator passed with a non-blocking author-attribution warning. The normal initial connection was Pending approval. Only the isolated test process was then given explicit authorization for EthosSecurity; the native client reported Connected. No personal account setup or model call was used. Antigravity's validator processed the native bundle without installing it into the user's global plugin registry.
- Real scanner execution and package/release tests are recorded in the release notes once complete. Tests against the MCP Python SDK establish protocol behavior; they do not prove a client's user interface loaded the tools.

## Claude Code plugin marketplace (v0.3.0)

Validation date: **2026-10-01**, Windows x64, Claude Code 2.1.284.

- `claude plugin validate` passed for `.claude-plugin/marketplace.json`. Installing `full-scan@ethossecurity` pulled its four dependencies (`ethossecurity`, `bug-hunter`, `app-security`, `infra-security`) automatically.
- `claude plugin details` reported the intended inventory: the `ethossecurity` engine has one MCP server and no skills; each skill plugin has exactly one skill and no MCP server.
- `claude mcp list`, run inside a project, reported `plugin:ethossecurity:ethossecurity` as Connected. Over MCP stdio with the plugin's exact command, `security_setup` prepared the four pinned scanners in `~/.ethossecurity/` and `security_scan` completed against a synthetic project without modifying it; the planted credential was omitted from the report.
- Fixed during validation: under MCP on Windows, Semgrep preparation hung because `ensurepip` inherited the server's stdin pipe; Gitleaks ignored an entire project whose parent folder was named `.ethossecurity`; Semgrep wrote non-UTF-8 reports for paths with accented characters.
- Semgrep starter rules: 72 rules for Python, JavaScript/TypeScript, GitHub Actions and Firebase rules, each with annotated vulnerable (`ruleid`) and safe (`ok`) fixtures run by `semgrep --test` in CI. A synthetic vulnerable app produced the expected findings for every planted issue; a real 67-file project scanned in about 7 seconds with one alert to review. Intra-file taint only (Semgrep OSS): flows through helper functions in other files are not followed.

## Official integration references

- [Codex MCP](https://developers.openai.com/codex/mcp) and [plugin packaging](https://developers.openai.com/plugins/build/plugins).
- [Claude Code MCP](https://code.claude.com/docs/en/mcp) and [plugins](https://code.claude.com/docs/en/plugins).
- [Google Antigravity MCP](https://antigravity.google/docs/mcp) and [agent skills](https://antigravity.google/docs/skills).

Cloud or browser chat surfaces may require a remotely hosted service, product registration or extra permissions. Such a service is outside this local installer. Tool installation cannot be promised solely from the model's brand.
