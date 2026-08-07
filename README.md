# SAVEMit

**S**emi-**A**utonomous **V**ulnerability **E**valuation and **Mit**igation for Node/npm projects.

SAVEMit is a local Model Context Protocol (MCP) server for coding agents. It scans a repository, produces an SBOM, checks dependency vulnerabilities, ranks findings with a deterministic policy engine, proposes dependency upgrades, and validates eligible upgrades in an isolated Docker container.

It is deliberately a decision-support tool: SAVEMit never edits the repository it scans, creates commits, opens pull requests, or merges code. Your AI agent and developer remain responsible for making changes.

## What it supports

- Node/npm repositories containing `package.json`
- Local repositories on the same machine as the MCP host
- Vulnerability evidence from OSV
- SBOM generation using Syft, with a `package.json` fallback
- Docker-based validation using the `node:22-alpine` image
- Policy and validation gates before an agent may recommend an upgrade

It does not currently support Python, Java, Go, container-image scanning, remote MCP hosting, automatic patches, or pull-request creation.

## Choose an installation

| Use case | Install path |
| --- | --- |
| Antigravity | Install this repository as an Antigravity plugin. |
| Codex | Install the standalone core, then install the bundled SAVEMit Codex marketplace plugin. |
| GitHub Copilot | Install the standalone core and add an MCP configuration. |
| Another MCP-capable agent or application | Run the standalone `savemit-mcp` command through its local stdio MCP configuration. |

Start with the detailed [getting-started guide](docs/getting-started.md). It includes prerequisites, installation, removal, policy behavior, troubleshooting, and integration guidance.

The [MCP tool reference](docs/mcp-reference.md) documents every tool and response status. The [security model](docs/security.md) describes the Docker boundary and current deployment limitations.

## How an investigation works

```text
Repository scan → SBOM → OSV vulnerability lookup → static reachability
       → policy decision → remediation plan → isolated Docker validation → result
```

The exposed MCP workflow is:

1. `start_investigation(repository_path)`
2. Poll `get_investigation(case_id)` until it is no longer `QUEUED` or `RUNNING`.
3. Call `get_policy_decision(case_id)` before recommending an upgrade.
4. Use `get_findings(case_id)` for supporting evidence and `get_validation_log(case_id)` for failed or incomplete validation.
5. Use `get_report(case_id)` to retrieve the final structured report when the case reaches `Report Generation`.

`POLICY_BLOCKED` and `REVIEW_REQUIRED` are hard review gates. `APPROVED_FOR_REVIEW` only means policy permits discussion of the change; the agent must still require a `PASSED` validation result before presenting it as a validated remediation.

## Demo repositories

The included `reference-repos` folder demonstrates common outcomes:

| Repository | Expected outcome |
| --- | --- |
| `customer-portal` | Docker validation passes. No repository Dockerfile is needed. |
| `breaking-upgrade` | Tests fail after the proposed upgrade. |
| `unsupported-python-service` | Stops early because this prototype supports Node/npm only. |
| `unreachable-dependency` | Priority is lowered because no static import is found. |
| `transitive-dependency` | Requires a parent dependency update. |
| `tests-not-defined` | Returns `NOT_VALIDATED`. |
| `policy-blocked-upgrade` | Returns `POLICY_BLOCKED`. |
| `no-fix-available` | Returns `MANUAL_REMEDIATION_REQUIRED`. |
| `docker-unavailable` | Returns `VALIDATION_INFRASTRUCTURE_FAILED`. |

The `no-fix-available`, `transitive-dependency`, and `docker-unavailable` demos use `.savemit-demo.json` solely to make their outcomes deterministic. Normal repositories do not use that file.
