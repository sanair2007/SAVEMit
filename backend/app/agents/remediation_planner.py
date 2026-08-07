from app.agents.base_agent import BaseAgent


class RemediationPlanner(BaseAgent):
    def execute(self, case):
        print("Remediation Planning")

        case.stage = "Remediation Planning"
        case.history.append({
            "agent": "Remediation Planner",
            "stage": case.stage,
            "status": "Completed"
        })
        return case
