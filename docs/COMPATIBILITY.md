# Compatibility and validation

This page separates what the installer prepares from what has been observed in an actual client. Validation date: **2026-09-30**. This is an initial assisted-installation release, not universal support for every AI chat.

## Prepared integrations

| Client | Prepared format | Status |
|---|---|---|
| OpenAI Codex | Project MCP TOML, four skills, optional native plugin bundle | Codex CLI discovered the connection; Codex app-server loaded four skills and discovered both MCP tools; a real scan passed through MCP stdio. Desktop user flow remains to be evaluated |
| Anthropic Claude Code | Project MCP JSON, four skills, optional native plugin bundle | Automated configuration preservation/idempotency tests passed; live client loading under validation |
| Google Antigravity IDE/CLI | Project MCP JSON and four skills | Automated configuration preservation/idempotency tests passed; live client loading under validation |

The core is independent of model provider. Integration depends on the host application's capabilities, permissions and version. Installing into one project does not implicitly configure other projects or modify global accounts. The installer does not obtain or supply AI subscriptions/API keys.

## Platforms

Pinned binary releases are supplied for Windows x64, Linux x64, macOS Intel and macOS Apple Silicon. Semgrep is installed separately in an isolated Python environment. The assistant needs a working Python 3.11–3.14 runtime. Unavailable binaries or failed preparation are reported as gaps. Native macOS installation has not been tested here.

## Reproducible verification

- Unit tests cover all three configuration formats, existing integration preservation, conflicting connections, repeated setup, checksum rejection, managed binary changes, bounded archive extraction, escaped HTML and incomplete scan reporting.
- The smoke tests use synthetic fixtures and compare project source bytes before and after setup/analysis. They do not run project builds, exploit systems or contact a live ZAP target.
- On Windows x64, pinned Semgrep 1.178.0, Trivy 0.74.0, Gitleaks 8.30.1 and OSV-Scanner 2.6.0 were installed automatically and all four ran successfully against synthetic code, credentials, a dependency manifest and a Dockerfile. The injected credential was omitted from the consolidated report.
- Codex validation used an isolated test configuration and no model calls. CLI configuration discovery, app-server skill loading and MCP tool discovery were observed; a separate MCP SDK connection executed the code scan. This does not cover every Codex desktop/cloud permission or reload flow.
- Real scanner execution and package/release tests are recorded in the release notes once complete. Tests against the MCP Python SDK establish protocol behavior; they do not prove a client's user interface loaded the tools.

## Official integration references

- [Codex MCP](https://developers.openai.com/codex/mcp) and [plugin packaging](https://developers.openai.com/plugins/build/plugins).
- [Claude Code MCP](https://code.claude.com/docs/en/mcp) and [plugins](https://code.claude.com/docs/en/plugins).
- [Google Antigravity MCP](https://antigravity.google/docs/mcp) and [agent skills](https://antigravity.google/docs/skills).

Cloud or browser chat surfaces may require a remotely hosted service, product registration or extra permissions. Such a service is outside this local installer. Tool installation cannot be promised solely from the model's brand.
