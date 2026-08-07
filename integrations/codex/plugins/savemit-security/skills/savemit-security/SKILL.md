---
name: savemit-security
description: Investigate npm dependency vulnerabilities with SAVEMit before suggesting upgrades.
---

# SAVEMit Security

Use the `savemit-security` MCP tools before recommending npm dependency upgrades.

1. Call `start_investigation` with the repository's absolute local path.
2. Poll `get_investigation` until the case is no longer `QUEUED` or `RUNNING`.
3. Call `get_policy_decision` before recommending any dependency upgrade. Treat its result as authoritative.
4. When `policy_status` is `POLICY_BLOCKED` or `REVIEW_REQUIRED`, do not propose an automated patch. Explain the reason and request developer review.
5. Use `get_findings` for detailed evidence and `get_validation_log` when validation did not pass.
6. Treat `TESTS_FAILED`, `NOT_VALIDATED`, `MANUAL_REMEDIATION_REQUIRED`, and `VALIDATION_INFRASTRUCTURE_FAILED` as review states. Do not claim the repository is fixed.
7. Use `get_report` to retrieve the final structured result when the investigation reaches Report Generation.
8. Only when policy permits the action and validation is `PASSED`, present the package changes for developer review. Never merge code automatically.
