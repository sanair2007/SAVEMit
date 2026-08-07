# SAVEMit: installation and integration guide

This guide describes the first release of SAVEMit as it exists today: a **local stdio MCP server** for analysing a local Node/npm repository. It is intended for a developer's machine, not as a hosted multi-user service.

## 1. System requirements

### Required for every installation

| Requirement | Why it is needed | How to check |
| --- | --- | --- |
| Python 3.10 or later | Runs SAVEMit and installs its Python dependencies. | `python --version` or, on Windows, `py -3 --version` |
| pip | Installs `fastmcp` and `httpx` from `pyproject.toml`. | `python -m pip --version` |
| Syft on `PATH` | Produces the SBOM used for dependency discovery. | `syft version` |
| Docker Engine running | Performs isolated installation and test validation. Docker Desktop is suitable on Windows/macOS. | `docker version` must show both Client and Server sections. |
| Network access | Queries OSV and pulls Docker's `node:22-alpine` image on first validation. | Your normal internet connection is sufficient. |

Install Syft and Docker using the official installation instructions for your operating system. SAVEMit does not bundle either tool.

### Target-repository requirements

- The repository must be a readable local directory.
- It must contain `package.json`; this version supports Node/npm only.
- A host installation of Node or npm is **not required** for validation. SAVEMit runs npm in Docker.
- A repository with `scripts.test` can be validated. Without one, SAVEMit returns `NOT_VALIDATED` rather than claiming success.
- Docker creates temporary validation files outside the scanned repository and does not modify the original checkout.

### Not required

- A GitHub token, GitHub App, or Git server
- A Dockerfile in the repository under inspection
- A local Node/npm installation
- An AI model API key for SAVEMit itself

## 2. Install SAVEMit

### A. Antigravity plugin

The repository root is an Antigravity plugin. It carries its own MCP configuration and a bootstrap script that creates a private Python virtual environment the first time the plugin is used.

1. Ensure the requirements above are installed. On Windows, the plugin starts Python with `py -3`.
2. Install directly from GitHub:

   ```powershell
   agy plugin install https://github.com/sanair2007/SAVEMit.git
   ```

3. Confirm installation:

   ```powershell
   agy plugin list
   ```

4. Restart Antigravity if it was already open, then ask it:

   ```text
   Use SAVEMit to investigate dependency vulnerabilities in this repository.
   ```

On first use, expect a short one-time setup while Python creates `.savemit-plugin-venv` and installs the SAVEMit package. The MCP server writes setup diagnostics to stderr, never to the MCP protocol stream.

#### Uninstall Antigravity

```powershell
agy plugin uninstall savemit-security
```

This removes the plugin registration. If Antigravity leaves its plugin cache behind, remove it only through Antigravity's plugin/cache management UI or its documented cache command; do not delete unrelated plugin directories manually.

### B. Codex plugin

The Codex package is a repository marketplace in `integrations/codex`. Its plugin intentionally reuses the standalone SAVEMit server instead of duplicating the security pipeline.

1. Install the standalone command:

   ```powershell
   py -3 -m pip install "git+https://github.com/sanair2007/SAVEMit.git"
   ```

2. Confirm that the command is discoverable in a new terminal:

   ```powershell
   savemit-mcp
   ```

   Stop it with `Ctrl+C` after confirming it starts. Do not leave it running: a stdio MCP host starts it itself.

3. Register the marketplace from a clone of this repository:

   ```powershell
   codex plugin marketplace add C:\path\to\SAVEMit\integrations\codex
   ```

4. In Codex's Plugins view, install **SAVEMit Security** from the **SAVEMit** marketplace. The plugin points Codex at the installed `savemit-mcp` command. Once installed, use the prompt shown in the [agent workflow](#agent-workflow-and-policy-gates) section.

#### Uninstall Codex

1. Remove or disable **SAVEMit Security** in Codex's plugin management UI.
2. Remove the marketplace registration if it is no longer needed:

   ```powershell
   codex plugin marketplace remove savemit
   ```

3. Remove the standalone core if no other MCP client needs it:

   ```powershell
   py -3 -m pip uninstall savemit-mcp
   ```

If you only remove the Codex plugin, the standalone MCP command remains available for Copilot or another agent.

### C. Standalone MCP server

Use this route for GitHub Copilot, Claude Code, Cursor, Windsurf, a custom MCP client, or a local application that supports stdio MCP.

1. Install SAVEMit:

   ```powershell
   py -3 -m pip install "git+https://github.com/sanair2007/SAVEMit.git"
   ```

2. Confirm the server command exists:

   ```powershell
   savemit-mcp
   ```

   Stop it with `Ctrl+C`. The command is normally launched by the host, not manually.

3. Add this configuration to the MCP host's local-server configuration file:

   ```json
   {
     "mcpServers": {
       "savemit-security": {
         "command": "savemit-mcp",
         "args": []
       }
     }
   }
   ```

The exact top-level key varies by host. For example, VS Code uses `servers`, while Copilot CLI uses `mcpServers` with `"type": "local"`.

#### GitHub Copilot

- **VS Code:** Copy `integrations/github-copilot/vscode-mcp.json` to the target repository as `.vscode/mcp.json`, then start the server from that file.
- **Copilot CLI:** Copy `integrations/github-copilot/copilot-cli-mcp.json` to the target repository as `.mcp.json`, or register it for your account:

  ```powershell
  copilot mcp add savemit-security -- savemit-mcp
  ```

The Copilot templates and a short prompt are also available in [the Copilot integration folder](../integrations/github-copilot/README.md).

#### Uninstall a standalone MCP setup

1. Remove the `savemit-security` MCP-server entry from the host configuration. For Copilot CLI, use:

   ```powershell
   copilot mcp remove savemit-security
   ```

2. Uninstall the Python package if it is no longer used:

   ```powershell
   py -3 -m pip uninstall savemit-mcp
   ```

3. Restart the MCP host so it forgets the old server definition.

## 3. Agent workflow and policy gates

### Repository policy manifest

Place an optional `.savemit-policy.json` in the target repository to express team rules. Unknown fields or invalid values stop the investigation early rather than being silently ignored.

```json
{
  "blocked_packages": ["legacy-package"],
  "minimum_priority": "HIGH",
  "allow_major_upgrades": false
}
```

| Field | Default | Effect |
| --- | --- | --- |
| `blocked_packages` | `[]` | Packages that SAVEMit must never propose for an automated upgrade. |
| `minimum_priority` | `"LOW"` | Only findings at or above this priority may be planned automatically. |
| `allow_major_upgrades` | `true` | When false, a planned major-version upgrade becomes `POLICY_BLOCKED`. |

Every MCP client should follow this sequence:

1. Call `start_investigation` with an absolute repository path.
2. Poll `get_investigation` until its status is no longer `QUEUED` or `RUNNING`.
3. Call `get_policy_decision` before discussing an upgrade.
4. If needed, call `get_findings` for vulnerability evidence and `get_validation_log` for failure context.
5. Call `get_report` for the final, portable structured result.

| Policy result | Required agent behavior |
| --- | --- |
| `PENDING` | Wait for the scan to finish. |
| `NO_REMEDIATION` | Do not invent an upgrade. Explain that SAVEMit has no planned dependency change. |
| `POLICY_BLOCKED` | Do not propose an automated patch for blocked packages. Explain the policy reason and request developer review. |
| `REVIEW_REQUIRED` | Do not present an automated remediation. Explain why a human decision is needed. |
| `APPROVED_FOR_REVIEW` | Policy allows discussion only. Check validation before presenting the upgrade. |

Validation statuses are a separate gate. A remediation is validated only when `validation.status` is `PASSED`. `TESTS_FAILED`, `PATCH_NOT_APPLICABLE`, `NOT_VALIDATED`, `NO_IMPROVEMENT`, `MANUAL_REMEDIATION_REQUIRED`, and `VALIDATION_INFRASTRUCTURE_FAILED` must be reported as review states, not successes.

Recommended prompt for any coding agent:

```text
Use SAVEMit to investigate dependency vulnerabilities in this repository. Wait for it to finish, call get_policy_decision before recommending any upgrade, and treat POLICY_BLOCKED and REVIEW_REQUIRED as hard review gates. Only summarize changes that are policy-permitted and whose validation passed. Do not edit, commit, or merge files.
```

## 4. Integrate the core into another project

### Preferred: integrate through MCP

Any product that can launch a local stdio MCP server can use SAVEMit. Install `savemit-mcp`, add the local-server configuration shown above, and have the host implement the workflow and policy gates in the preceding section. This is the supported integration boundary because the server owns the stable tool contract.

To add support for a new coding agent, create a small integration folder containing:

1. The host's MCP configuration pointing to `savemit-mcp`.
2. Agent instructions requiring `get_policy_decision` before upgrade recommendations.
3. Installation and removal instructions for that host.

Do not copy the Python agents or call their internal classes from a host integration. That would couple the host to implementation details instead of the MCP contract.

### Direct Python use

The Python package can be imported by another local Python application, but this is not yet a formal stable SDK. If you choose this route, pin the SAVEMit version and treat `app.coordinator.InvestigationCoordinator` and `app.models.InvestigationCase` as internal APIs that may change.

The stable boundary is documented in the [MCP tool reference](mcp-reference.md).

### Hosted or shared deployments

This release runs over stdio and assumes it can access a local repository, Docker daemon, Syft executable, and temporary workspace. A shared, remote deployment would need a job queue, persistent case storage, an authenticated HTTP MCP transport, per-job workspaces, and isolation rules. Those pieces are not part of the current prototype.

## 5. Troubleshooting

| Symptom | Likely cause and fix |
| --- | --- |
| `syft` is not found | Install Syft and reopen the terminal/agent so its `PATH` is refreshed. |
| Docker says it cannot connect to the daemon | Start Docker Desktop and wait until `docker version` shows a Server section. |
| `savemit-mcp` is not recognized | Reopen the terminal after pip installation. On Windows, ensure Python's Scripts directory is on `PATH`; alternatively configure the MCP host with the full path to `savemit-mcp.exe`. |
| First validation is slow | Docker may be pulling `node:22-alpine` for the first time. |
| `NOT_VALIDATED` | Add an npm `test` script if you want SAVEMit to execute tests. |
| Unsupported repository | This version requires `package.json` and supports Node/npm only. |
| OSV lookup fails | Check network access and retry later; SAVEMit needs OSV connectivity for vulnerability intelligence. |

## Security model

SAVEMit reads the target repository, copies it to a temporary validation workspace, and runs validation there. It does not alter the original repository. However, install and test commands execute code from the copied repository in Docker; review untrusted repositories carefully and keep Docker updated.

See the full [security model and limitations](security.md).
