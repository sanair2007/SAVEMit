---
name: savemit-security
description: Investigate npm dependency vulnerabilities with SAVEMit before suggesting upgrades.
---

# SAVEMit Security

Use the `savemit-security` MCP tools before recommending npm dependency upgrades.

1. Call `start_investigation` with the repository's absolute local path.
2. Poll `get_investigation` until the case is no longer `QUEUED` or `RUNNING`.
3. Use `get_findings` for detailed evidence and `get_validation_log` when validation did not pass.
4. Treat `TESTS_FAILED`, `NOT_VALIDATED`, `POLICY_BLOCKED`, `MANUAL_REMEDIATION_REQUIRED`, and `VALIDATION_INFRASTRUCTURE_FAILED` as review states. Do not claim the repository is fixed.
5. When validation is `PASSED`, present the package changes for developer review. Never merge code automatically.
