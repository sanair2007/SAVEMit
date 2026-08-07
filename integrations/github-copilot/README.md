# SAVEMit for GitHub Copilot

GitHub Copilot connects to SAVEMit as a local MCP server rather than through a plugin manifest. Install the SAVEMit command once, then choose the configuration file that matches your Copilot client.

## Prerequisites

Install SAVEMit from this repository and make sure its Python scripts directory is on `PATH`:

```powershell
py -3 -m pip install "git+https://github.com/sanair2007/SAVEMit.git"
```

SAVEMit also requires Syft, Docker Desktop, and network access to OSV. Docker Desktop must be running before an investigation reaches validation.

## Copilot in VS Code

Copy `vscode-mcp.json` to `.vscode/mcp.json` in the repository you want Copilot to analyse. Open that file and start the `savemit-security` server with the VS Code CodeLens control. Then use Copilot Chat in Agent mode.

## Copilot CLI

Copy `copilot-cli-mcp.json` to `.mcp.json` in the repository you want Copilot to analyse, then start Copilot CLI from that repository. Confirm folder trust when prompted.

Alternatively, register the server for your user account:

```powershell
copilot mcp add savemit-security -- savemit-mcp
```

## Suggested prompt

```text
Use SAVEMit to investigate dependency vulnerabilities in this repository. Wait for validation, then summarize only remediation options that are safe for developer review. Do not edit or merge files.
```
