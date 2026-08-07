# MCP tool reference

SAVEMit runs as a local **stdio MCP server** named `savemit-security`. Its tool results are JSON strings so they are easy for both humans and coding agents to inspect.

## `start_investigation`

Starts a background investigation. The path must be absolute (or resolvable to an absolute path) and point to a local Node/npm repository.

```json
{
  "repository_path": "C:\\work\\customer-portal"
}
```

Response:

```json
{
  "case_id": "a generated UUID",
  "status": "QUEUED",
  "message": "Investigation started. Poll get_investigation with this case_id."
}
```

## `get_investigation`

Returns compact progress and the remediation/validation state.

```json
{
  "case_id": "...",
  "status": "PASSED",
  "stage": "Report Generation",
  "vulnerability_count": 2,
  "policy_manifest": {
    "blocked_packages": [],
    "minimum_priority": "LOW",
    "allow_major_upgrades": true
  },
  "remediation_plan": [],
  "validation": { "status": "PASSED" }
}
```

Poll while status is `QUEUED` or `RUNNING`. A failed pipeline has status `FAILED` and an `error` field.

## `get_policy_decision`

Returns the policy gate. Call this before an agent recommends any dependency change.

```json
{
  "case_id": "...",
  "policy_status": "POLICY_BLOCKED",
  "requires_human_review": true,
  "allowed_actions": [],
  "blocked_actions": [
    {
      "package": "axios",
      "outcome": "POLICY_BLOCKED",
      "reason": "Repository policy prohibits this automated upgrade."
    }
  ],
  "review_actions": []
}
```

| `policy_status` | Meaning |
| --- | --- |
| `PENDING` | Investigation is not complete. |
| `NO_REMEDIATION` | No upgrade was planned. |
| `POLICY_BLOCKED` | One or more upgrades violate `.savemit-policy.json`; do not propose them automatically. |
| `REVIEW_REQUIRED` | A remediation needs a human decision, for example a transitive dependency or no fixed version. |
| `APPROVED_FOR_REVIEW` | Policy permits discussion; successful validation is still required. |

## `get_findings`

Returns advisory evidence, affected packages, fixed versions, reachability evidence, and per-finding policy ranking. Use it to support an explanation rather than to decide whether a change is allowed.

## `get_validation_log`

Returns validation status, command/test failure context, pipeline history, and any terminal error. Use it whenever validation is not `PASSED`.

## `get_report`

Returns the final structured report generated after the pipeline completes. It contains the report schema version, timestamp, repository, policy manifest/summary, remediation plan, and validation outcome.

## MCP resource

`savemit://cases/{case_id}/summary` returns the same compact result as `get_investigation` for clients that prefer MCP resources.
