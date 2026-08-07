from app.agents.base_agent import BaseAgent


class ReportGenerator(BaseAgent):
    def execute(self, case):
        print("Report Generation")

        case.stage = "Report Generation"
        case.status = "COMPLETED"
        case.history.append({
            "agent": "Report Generator",
            "stage": case.stage,
            "status": "Completed"
        })
        return case
