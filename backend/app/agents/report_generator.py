from app.agents.base_agent import BaseAgent
import logging


class ReportGenerator(BaseAgent):
    def execute(self, case):
        logging.getLogger(__name__).info("Report Generation")

        case.stage = "Report Generation"
        if case.status in {"PENDING", "COMPLETED"}:
            case.status = "COMPLETED"
        case.history.append({
            "agent": "Report Generator",
            "stage": case.stage,
            "status": "Completed"
        })
        return case
