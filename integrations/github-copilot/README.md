# SAVEMit for GitHub Copilot

GitHub Copilot uses SAVEMit as a local MCP server, not as a GitHub App or repository-writing plugin. The complete requirements, installation, removal, policy workflow, and troubleshooting instructions are in the [SAVEMit getting-started guide](../../docs/getting-started.md).

Quick setup:

1. Install the core: `py -3 -m pip install "git+https://github.com/sanair2007/SAVEMit.git"`.
2. Copy `vscode-mcp.json` to a target project's `.vscode/mcp.json`, or copy `copilot-cli-mcp.json` to its `.mcp.json`.
3. Start the configured server and use Copilot in Agent mode.

Suggested prompt:

```text
Use SAVEMit to investigate dependency vulnerabilities in this repository. Wait for it to finish, call get_policy_decision before recommending any upgrade, and treat POLICY_BLOCKED and REVIEW_REQUIRED as hard review gates. Only summarize changes that are policy-permitted and whose validation passed. Do not edit, commit, or merge files.
```
