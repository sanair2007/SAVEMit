from app.agents.base_agent import BaseAgent


class ValidationAgent(BaseAgent):
    def execute(self, case):
        print("Validation")

        case.stage = "Validation"
        case.history.append({
            "agent": "Validation Agent",
            "stage": case.stage,
            "status": "Completed"
        })
        return case
