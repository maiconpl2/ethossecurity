# Assisted installation architecture

One repository link leads to `INSTALL.md`. The host agent identifies its own client, the authorized workspace and a compatible Python runtime, retrieves the pinned release bootstrap, and executes preparation under host permissions. No model-provider API is called by the installer or scanners.

`bootstrap.py` verifies the pinned EthosSecurity wheel and installs it into `.ethossecurity/runtime/`. `ethos-sec start` provisions the pinned local tools, registers project MCP and skills, scans local files, and exports JSON plus script-free HTML. Publisher binary checksums live in packaged `assets/tools.json`; only the requested executable member is copied from each verified archive. Semgrep uses a separate environment with its pinned PyPI version.

Client adapters preserve other MCP connections, back up configuration before adding entries, and refuse conflicting existing EthosSecurity entries. Registration is project-local. The native plugin export is separate from host activation. Project trust, connection permissions and reloads remain controlled by the client.

Managed tools and reports are excluded from scanner targets. OSV dependency resolution and build-based call analysis are disabled during onboarding. CodeQL and ZAP are excluded from the first scan even if an advanced project configuration enables them. Later explicit scans retain the operator's advanced configuration and target allowlist.

The common MCP server keeps a fixed operator workspace and exposes `security_profiles` and `security_scan`. Tool callers cannot supply arbitrary paths, executable names or shell commands. The installed runtime paths are operator-controlled local state; do not import or trust a third party's `.ethossecurity` directory. Reports are local and findings remain unvalidated until reproduction or a complete source trace supports confirmation.

The host agent performs the contextual investigation using the four skills. The CLI reports scanner evidence and coverage; it does not perform autonomous model reviews or generate/apply patches. Remote web-chat integrations would need a separately operated authenticated service and are not implemented by this local bootstrap.
