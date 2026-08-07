from app.agents.base_agent import BaseAgent
from datetime import datetime, timezone
import logging


class ReportGenerator(BaseAgent):
    def execute(self, case):
        logging.getLogger(__name__).info("Report Generation")

        report = {
            "schema_version": "1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "case_id": case.id,
            "repository": case.repository,
            "status": case.status,
            "vulnerability_count": case.metadata.get("threat_intel", {}).get(
                "vulnerability_count", 0
            ),
            "policy": {
                "manifest": case.metadata.get("policy_manifest", {}),
                "summary": case.metadata.get("policy", {}).get("summary", {}),
            },
            "remediation_plan": case.metadata.get("remediation_plan", []),
            "validation": case.metadata.get("validation", {}),
        }
        case.metadata["report"] = report

        case.stage = "Report Generation"
        if case.status in {"PENDING", "COMPLETED"}:
            case.status = "COMPLETED"
        case.history.append({
            "agent": "Report Generator",
            "stage": case.stage,
            "status": "Completed",
            "report_schema_version": report["schema_version"],
        })
        return case
