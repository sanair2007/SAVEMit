"""Local stdio MCP server that exposes SAVEMit's existing investigation pipeline."""

import json
import logging
import threading
import uuid
from pathlib import Path

from fastmcp import FastMCP

from app.coordinator.coordinator import InvestigationCoordinator
from app.models.investigation_case import InvestigationCase


logging.basicConfig(level=logging.INFO)
mcp = FastMCP("SAVEMit Security")


class InvestigationStore:
    """Small in-memory store for local MCP sessions.

    A deployed version can replace this with a database and job queue without
    changing the tool contracts.
    """

    def __init__(self):
        self._cases = {}
        self._lock = threading.Lock()

    def create(self, repository_path):
        case = InvestigationCase(
            id=str(uuid.uuid4()),
            repository=str(Path(repository_path).expanduser().resolve()),
            status="QUEUED",
        )
        with self._lock:
            self._cases[case.id] = case
        return case

    def get(self, case_id):
        with self._lock:
            return self._cases.get(case_id)

    def run(self, case_id):
        case = self.get(case_id)
        if case is None:
            return

        case.status = "RUNNING"
        try:
            InvestigationCoordinator().run(case)
        except (RuntimeError, ValueError) as error:
            case.status = "FAILED"
            case.stage = "Failed"
            case.metadata["error"] = str(error)
            case.history.append({
                "agent": "SAVEMit MCP",
                "stage": case.stage,
                "status": "Failed",
                "error": str(error),
            })


store = InvestigationStore()


def _case_summary(case):
    threat_intel = case.metadata.get("threat_intel", {})
    return {
        "case_id": case.id,
        "repository": case.repository,
        "status": case.status,
        "stage": case.stage,
        "vulnerability_count": threat_intel.get("vulnerability_count", 0),
        "priority_summary": case.metadata.get("policy", {}).get("summary", {}),
        "policy_manifest": case.metadata.get("policy_manifest", {}),
        "remediation_plan": case.metadata.get("remediation_plan", []),
        "validation": case.metadata.get("validation", {}),
        "error": case.metadata.get("error"),
    }


def _result(case):
    return json.dumps(_case_summary(case), indent=2)


def _policy_decision(case):
    """Build a small, model-oriented policy gate from pipeline evidence."""
    if case.status in {"QUEUED", "RUNNING", "PENDING"}:
        return {
            "case_id": case.id,
            "policy_status": "PENDING",
            "requires_human_review": True,
            "allowed_actions": [],
            "blocked_actions": [],
            "policy_manifest": case.metadata.get("policy_manifest", {}),
            "message": "Wait for the investigation to finish before using policy evidence.",
        }

    plans = case.metadata.get("remediation_plan", [])
    if not plans:
        return {
            "case_id": case.id,
            "policy_status": "NO_REMEDIATION",
            "requires_human_review": False,
            "allowed_actions": [],
            "blocked_actions": [],
            "policy_summary": case.metadata.get("policy", {}).get("summary", {}),
            "policy_manifest": case.metadata.get("policy_manifest", {}),
            "message": "No dependency upgrade was planned for this investigation.",
        }

    allowed_actions = []
    blocked_actions = []
    review_actions = []
    for plan in plans:
        action = {
            "package": plan.get("package"),
            "current_version": plan.get("current_version"),
            "recommended_version": plan.get("recommended_version"),
            "priority": plan.get("highest_priority"),
            "outcome": plan.get("outcome"),
            "reason": plan.get("action"),
        }
        if plan.get("outcome") == "READY_FOR_VALIDATION":
            allowed_actions.append(action)
        elif plan.get("outcome") == "POLICY_BLOCKED":
            blocked_actions.append(action)
        else:
            review_actions.append(action)

    if blocked_actions:
        policy_status = "POLICY_BLOCKED"
        message = "Repository policy blocks one or more automated upgrades. Do not propose a patch for those packages."
    elif review_actions:
        policy_status = "REVIEW_REQUIRED"
        message = "At least one remediation needs developer review before it can be proposed."
    else:
        policy_status = "APPROVED_FOR_REVIEW"
        message = "The policy allows these upgrades to be presented for developer review; validation remains a separate gate."

    return {
        "case_id": case.id,
        "policy_status": policy_status,
        "requires_human_review": bool(blocked_actions or review_actions),
        "allowed_actions": allowed_actions,
        "blocked_actions": blocked_actions,
        "review_actions": review_actions,
        "policy_summary": case.metadata.get("policy", {}).get("summary", {}),
        "policy_manifest": case.metadata.get("policy_manifest", {}),
        "message": message,
    }


@mcp.tool()
def start_investigation(repository_path: str) -> str:
    """Start an isolated SAVEMit scan of a local Node/npm repository.

    The original repository is never edited. Use get_investigation to poll the
    case after this returns.
    """
    path = Path(repository_path).expanduser().resolve()
    if not path.is_dir():
        raise ValueError("repository_path must be an existing local directory.")

    case = store.create(path)
    thread = threading.Thread(target=store.run, args=(case.id,), daemon=True)
    thread.start()
    return json.dumps({
        "case_id": case.id,
        "status": case.status,
        "message": "Investigation started. Poll get_investigation with this case_id.",
    })


@mcp.tool()
def get_investigation(case_id: str) -> str:
    """Return the compact status, remediation plan, and validation outcome for a case."""
    case = store.get(case_id)
    if case is None:
        raise ValueError("Unknown case_id. Start an investigation first.")
    return _result(case)


@mcp.tool()
def get_findings(case_id: str) -> str:
    """Return detailed vulnerability evidence for an investigation after it has completed."""
    case = store.get(case_id)
    if case is None:
        raise ValueError("Unknown case_id. Start an investigation first.")
    return json.dumps({
        "case_id": case.id,
        "status": case.status,
        "findings": case.metadata.get("threat_intel", {}).get("vulnerabilities", []),
    }, indent=2)


@mcp.tool()
def get_policy_decision(case_id: str) -> str:
    """Return the authoritative policy gate before recommending a dependency upgrade.

    Call this after the investigation finishes. Do not propose an automated
    patch when policy_status is POLICY_BLOCKED or REVIEW_REQUIRED.
    """
    case = store.get(case_id)
    if case is None:
        raise ValueError("Unknown case_id. Start an investigation first.")
    return json.dumps(_policy_decision(case), indent=2)


@mcp.tool()
def get_validation_log(case_id: str) -> str:
    """Return validation status and failure context for a case; use this before suggesting code changes."""
    case = store.get(case_id)
    if case is None:
        raise ValueError("Unknown case_id. Start an investigation first.")
    return json.dumps({
        "case_id": case.id,
        "status": case.status,
        "validation": case.metadata.get("validation", {}),
        "error": case.metadata.get("error"),
        "history": case.history,
    }, indent=2)


@mcp.tool()
def get_report(case_id: str) -> str:
    """Return the final structured SAVEMit report after an investigation completes."""
    case = store.get(case_id)
    if case is None:
        raise ValueError("Unknown case_id. Start an investigation first.")
    report = case.metadata.get("report")
    if report is None:
        raise ValueError("Report is not ready. Wait for the investigation to complete.")
    return json.dumps(report, indent=2)


@mcp.resource("savemit://cases/{case_id}/summary")
def case_summary_resource(case_id: str) -> str:
    """Read a compact investigation result as an MCP resource."""
    return get_investigation(case_id)


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
