# SAVEMit
Semi-Autonomous Vulnerability Evaluation and Mitigation

## Antigravity GitHub plugin

This repository is also a self-contained Antigravity plugin. Install it from the repository root with Antigravity's plugin command, then the Python bootstrap creates its own local environment on first use. On Windows it uses the `py -3` launcher. It requires Python 3.10+, Syft, Docker Desktop, and network access to OSV.

The plugin exposes `savemit-security` MCP tools and never edits the target repository during validation.

## Codex and GitHub Copilot

SAVEMit exposes the same local stdio MCP server to other coding agents:

- **Codex:** [the Codex plugin package](integrations/codex/savemit-security/) provides the SAVEMit workflow skill and MCP configuration. Install the core command first:

  ```powershell
  py -3 -m pip install "git+https://github.com/sanair2007/SAVEMit.git"
  ```

  Then add the local plugin directory to your Codex plugin setup. It starts the installed `savemit-mcp` command.

- **GitHub Copilot:** [the Copilot integration](integrations/github-copilot/) contains ready-to-copy MCP configuration for VS Code and Copilot CLI, plus exact setup instructions. Copilot treats SAVEMit as a local MCP server, not a GitHub App or a repository-writing integration.

All integrations are read-only with respect to the repository being analysed: they investigate, plan, and validate, but never create commits, branches, pull requests, or merges.

## Demo repositories

Use the `savemit-security` MCP tools to scan these local repositories by passing their absolute paths to `start_investigation`.

| Repository | Expected outcome |
| --- | --- |
| `customer-portal` | Docker validation passes. The repository deliberately has no Dockerfile: SAVEMit uses its own temporary `node:22-alpine` validation container. |
| `breaking-upgrade` | A proposed dependency update causes a compatibility test to fail. SAVEMit must not change the original repository or create a pull request. |
| `unsupported-python-service` | Scanner stops before analysis because this prototype supports Node/npm only. No patch is attempted. |
| `unreachable-dependency` | A dependency has no static import evidence, so its policy priority is lowered for review. |
| `transitive-dependency` | A vulnerable package is treated as transitive; the plan asks for a parent dependency update. |
| `tests-not-defined` | No `npm test` command exists, so the result is `NOT_VALIDATED`. |
| `policy-blocked-upgrade` | Repository policy forbids the upgrade, producing `POLICY_BLOCKED`. |
| `no-fix-available` | No approved fixed version is available, producing `MANUAL_REMEDIATION_REQUIRED`. |
| `docker-unavailable` | A simulated validation-host failure produces `VALIDATION_INFRASTRUCTURE_FAILED`. |

The `no-fix-available`, `transitive-dependency`, and `docker-unavailable` repositories use `.savemit-demo.json` solely to make their demonstration outcome deterministic. Normal repositories do not use this file.
