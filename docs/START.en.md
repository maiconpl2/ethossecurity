# Start inside the AI assistant you already use

[Português (Brasil)](START.pt-BR.md) · [English](START.en.md)

**Open your project in Codex, Claude Code or Google Antigravity and send this message:**

> Install EthosSecurity from this link in my project: https://github.com/maiconpl2/ethossecurity. Read INSTALL.md, prepare the integration compatible with this assistant, and run the first scan. Explain the results in English, including what was not checked. Preserve my code and existing configuration.

Follow the preparation and accept any permissions your assistant requests. It handles the commands and configuration.

## What you get

- Tools prepared in a separate project directory.
- Four review workflows: bugs, application security, infrastructure and a combined review.
- A first local report showing alerts and the status of each check.
- Your assistant's explanation of what to investigate and how to validate the next steps.

After installation, ask: **“Use EthosSecurity to review changes in this project and prioritize risks that need investigation.”** Loading the connection may require reopening the project or accepting a permission in your assistant.

## What must be available

Your assistant needs project access, tool execution and permission to download dependencies. A conversation-only chat cannot install tools on a computer simply by receiving a link. If access is missing, it should explain what needs to be enabled.

This experience is under validation. See [compatibility and completed tests](COMPATIBILITY.md). Generated configuration does not mean every product integration has been qualified.

EthosSecurity helps investigate risks; it does not guarantee secure software. Alerts need validation and some controls require contextual review. [License terms](../LICENSE) include noncommercial use and a [30-day business evaluation](../EVALUATION.en.md), under their respective conditions.
