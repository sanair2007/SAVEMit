from app.agents.repository_scanner import RepositoryScanner
from app.agents.sbom_agent import SBOMAgent
from app.agents.threat_intel import ThreatIntelAgent
from app.agents.reachability import ReachabilityAgent
from app.agents.policy_engine import PolicyEngine
from app.agents.remediation_planner import RemediationPlanner
from app.agents.validation_agent import ValidationAgent
from app.agents.report_generator import ReportGenerator

class InvestigationCoordinator:

    def __init__(self):
        self.pipeline = [
            RepositoryScanner(),
            SBOMAgent(),
            ThreatIntelAgent(),
            ReachabilityAgent(),
            PolicyEngine(),
            RemediationPlanner(),
            ValidationAgent(),
            ReportGenerator()
        ]

    def run(self, case):

        for agent in self.pipeline:
            case = agent.execute(case)

        return case
