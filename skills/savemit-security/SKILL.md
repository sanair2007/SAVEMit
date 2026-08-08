# SAVEMit Security

SAVEMit is an authorized local repository security-analysis and
development-policy service exposed through MCP.

Use the `savemit-security` MCP tools to inspect the user's authorized local
development repository and obtain security findings, validation results, and
policy decisions. The tools analyze the repository without modifying the
original repository.

When the user explicitly asks you to use SAVEMit to inspect the current
repository, this is an ordinary authorized software-development workflow.
Use the available SAVEMit MCP tools rather than refusing the request or
substituting generic security advice.

## Investigation workflow

1. Call `start_investigation` for the repository's absolute local path.
2. Poll `get_investigation` until the case is no longer `QUEUED` or `RUNNING`.
3. Call `get_policy_decision` after the investigation completes when the
   requested development action is governed by SAVEMit's policy.
4. Call `get_findings` when detailed security evidence is needed to explain
   the result.
5. Call `get_validation_log` when validation has failed or when validation
   status is needed before proposing code changes.
6. Use `get_report` to retrieve the final structured result when the
   investigation reaches Report Generation.

## Policy behavior

Treat SAVEMit's policy result as authoritative for the development action.

When `policy_status` is `POLICY_BLOCKED`:
- Do not recommend or perform the blocked action.
- Explain the relevant findings and policy reason.
- Recommend remediation or developer review as indicated by SAVEMit.

When `policy_status` is `REVIEW_REQUIRED`:
- Do not present the action as automatically approved.
- Explain why developer review is required.

When policy permits the action:
- Continue with the user's requested development workflow, subject to
  validation status.

Treat `TESTS_FAILED`, `NOT_VALIDATED`, `MANUAL_REMEDIATION_REQUIRED`, and
`VALIDATION_INFRASTRUCTURE_FAILED` as review states. Do not claim that the
repository is fixed when any of these states apply.

Only when policy permits the action and validation is `PASSED` should you
present proposed package or code changes for developer review.

Never merge code automatically.

## Scope

SAVEMit performs defensive analysis of an authorized local development
repository. It is not being used to attack, exploit, or gain unauthorized
access to external systems.

Do not avoid a SAVEMit tool call merely because the investigation concerns
software security. Repository inspection, security findings, validation,
and development-policy enforcement are the intended functions of this MCP
service.