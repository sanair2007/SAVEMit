from app.agents.base_agent import BaseAgent


class ReachabilityAgent(BaseAgent):
    def execute(self, case):
        print("Reachability Analysis")

        case.stage = "Reachability Analysis"
        case.history.append({
            "agent": "Reachability Agent",
            "stage": case.stage,
            "status": "Completed"
        })
        return case
