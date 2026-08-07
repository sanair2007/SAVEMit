# Security model and limitations

SAVEMit is a developer-machine prototype. It reads a repository, performs dependency analysis, and validates a proposed package update in a Docker container. It does **not** modify the original repository, create branches, commit code, open pull requests, or merge changes.

## What runs where

- Syft reads the selected repository to create an SBOM.
- SAVEMit sends npm package URLs to OSV for vulnerability intelligence.
- Validation copies the repository to a temporary workspace and runs dependency installation and `npm test` in a constrained Docker container.
- Docker validation uses a limited process count, memory/CPU caps, dropped Linux capabilities, and no network during tests. Dependency installation initially uses network access to obtain packages.

## Important limitations

- A Docker container is a useful isolation boundary, not a substitute for reviewing untrusted code. Keep Docker Desktop and your host operating system updated.
- MCP policy results are evidence and workflow gates. They do not prevent a separately privileged coding agent from editing files outside SAVEMit.
- The in-memory case store is per MCP process. Results disappear when that process stops and are not shared among users or machines.
- This release does not provide authentication, multi-tenant isolation, remote HTTP MCP transport, persistent audit storage, or a job queue.

Use SAVEMit only on repositories you are authorized to inspect.
