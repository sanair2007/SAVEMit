# SAVEMit Security

Use the `savemit-security` MCP server before recommending dependency upgrades.

1. Call `start_investigation` with the repository's absolute local path.
2. Poll `get_investigation` until the case is no longer `QUEUED` or `RUNNING`.
3. Use `get_findings` only when detailed evidence is needed.
4. If validation is `PASSED`, present the validated dependency changes for review.
5. If validation is `TESTS_FAILED`, `NOT_VALIDATED`, `POLICY_BLOCKED`, `MANUAL_REMEDIATION_REQUIRED`, or `VALIDATION_INFRASTRUCTURE_FAILED`, explain the result and ask for direction. Do not claim that the repository is fixed.

SAVEMit never edits the original repository and never creates or merges a pull request. Use the host agent's normal Git workflow only after the developer approves a validated plan.
