import json
import tempfile
import unittest
from pathlib import Path

from app.agents.policy_engine import PolicyEngine
from app.agents.remediation_planner import RemediationPlanner
from app.agents.report_generator import ReportGenerator
from app.agents.repository_scanner import RepositoryScanner
from app.mcp.server import _policy_decision
from app.models.investigation_case import InvestigationCase


HIGH_CVSS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def finding(package="example-package", current_version="1.2.3", fixed_version="2.0.0"):
    return {
        "id": "CVE-TEST-0001",
        "severity": [{"type": "CVSS_V3", "score": HIGH_CVSS}],
        "affected_packages": [
            {
                "package": package,
                "version": current_version,
                "purl": f"pkg:npm/{package}@{current_version}",
            }
        ],
        "fixed_versions": [fixed_version],
        "advisory_ids": ["GHSA-test"],
        "reachability": {"reachable": True, "evidence": []},
    }


class PolicyManifestTests(unittest.TestCase):
    def test_scanner_loads_policy_manifest(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository = Path(temporary_directory)
            (repository / "package.json").write_text("{}", encoding="utf-8")
            (repository / ".savemit-policy.json").write_text(
                json.dumps(
                    {
                        "blocked_packages": ["axios"],
                        "minimum_priority": "HIGH",
                        "allow_major_upgrades": False,
                    }
                ),
                encoding="utf-8",
            )
            case = InvestigationCase(id="scanner-test", repository=str(repository))

            RepositoryScanner().execute(case)

            self.assertEqual(case.metadata["policy_manifest"]["blocked_packages"], ["axios"])
            self.assertEqual(case.metadata["policy_manifest"]["minimum_priority"], "HIGH")
            self.assertFalse(case.metadata["policy_manifest"]["allow_major_upgrades"])

    def test_blocked_package_is_not_planned_for_automation(self):
        case = InvestigationCase(id="blocked-test", repository="repository")
        case.findings = [finding(package="axios")]
        case.metadata = {
            "policy_manifest": {
                "blocked_packages": ["axios"],
                "minimum_priority": "LOW",
                "allow_major_upgrades": True,
            },
            "threat_intel": {},
        }

        PolicyEngine().execute(case)
        RemediationPlanner().execute(case)

        plan = case.metadata["remediation_plan"][0]
        self.assertEqual(plan["outcome"], "POLICY_BLOCKED")
        self.assertIsNone(plan["recommended_version"])

    def test_major_upgrade_can_be_blocked_by_manifest(self):
        case = InvestigationCase(id="major-test", repository="repository")
        case.findings = [finding()]
        case.metadata = {
            "policy_manifest": {
                "blocked_packages": [],
                "minimum_priority": "LOW",
                "allow_major_upgrades": False,
            },
            "threat_intel": {},
        }

        PolicyEngine().execute(case)
        RemediationPlanner().execute(case)

        plan = case.metadata["remediation_plan"][0]
        self.assertEqual(plan["outcome"], "POLICY_BLOCKED")
        self.assertIn("major-version", plan["action"])


class ReportTests(unittest.TestCase):
    def test_report_generator_creates_structured_report(self):
        case = InvestigationCase(id="report-test", repository="repository", status="PASSED")
        case.metadata = {
            "policy_manifest": {"blocked_packages": []},
            "policy": {"summary": {"critical": 1}},
            "threat_intel": {"vulnerability_count": 1},
            "remediation_plan": [{"package": "example-package"}],
            "validation": {"status": "PASSED"},
        }

        ReportGenerator().execute(case)

        report = case.metadata["report"]
        self.assertEqual(report["schema_version"], "1.0")
        self.assertEqual(report["case_id"], "report-test")
        self.assertEqual(report["validation"]["status"], "PASSED")

    def test_policy_decision_exposes_blocked_actions(self):
        case = InvestigationCase(id="decision-test", repository="repository", status="POLICY_BLOCKED")
        case.metadata = {
            "policy_manifest": {"blocked_packages": ["axios"]},
            "policy": {"summary": {"high": 1}},
            "remediation_plan": [
                {
                    "package": "axios",
                    "current_version": "1.0.0",
                    "recommended_version": None,
                    "highest_priority": "HIGH",
                    "outcome": "POLICY_BLOCKED",
                    "action": "Repository policy prohibits this automated upgrade.",
                }
            ],
        }

        decision = _policy_decision(case)

        self.assertEqual(decision["policy_status"], "POLICY_BLOCKED")
        self.assertEqual(decision["blocked_actions"][0]["package"], "axios")


if __name__ == "__main__":
    unittest.main()
