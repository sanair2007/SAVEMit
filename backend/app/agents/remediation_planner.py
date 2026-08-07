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
import re
import logging

from app.agents.base_agent import BaseAgent


class RemediationPlanner(BaseAgent):
    PRIORITY_ORDER = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "UNKNOWN": 4,
    }

    @staticmethod
    def _version_key(version):
        match = re.match(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?", version)
        if not match:
            return None
        return tuple(int(part or 0) for part in match.groups())

    def _recommended_version(self, fixed_versions):
        version_pairs = [
            (self._version_key(version), version)
            for version in fixed_versions
            if self._version_key(version) is not None
        ]
        if not version_pairs:
            return None
        return max(version_pairs, key=lambda pair: pair[0])[1]

    def execute(self, case):
        logging.getLogger(__name__).info("Remediation Planning")

        plans = {}
        for finding in case.findings:
            for package in finding["affected_packages"]:
                package_name = package["package"]
                plan = plans.setdefault(
                    package_name,
                    {
                        "package": package_name,
                        "current_version": package["version"],
                        "purl": package["purl"],
                        "fixed_versions": [],
                        "vulnerability_ids": [],
                        "highest_priority": finding["policy"]["priority"],
                    },
                )

                for fixed_version in finding.get("fixed_versions", []):
                    if fixed_version not in plan["fixed_versions"]:
                        plan["fixed_versions"].append(fixed_version)
                for vulnerability_id in finding["advisory_ids"]:
                    if vulnerability_id not in plan["vulnerability_ids"]:
                        plan["vulnerability_ids"].append(vulnerability_id)

                if self.PRIORITY_ORDER[finding["policy"]["priority"]] < self.PRIORITY_ORDER[plan["highest_priority"]]:
                    plan["highest_priority"] = finding["policy"]["priority"]

        demo = case.metadata.get("demo", {})
        no_fix_packages = set(demo.get("no_fix_packages", []))
        transitive_dependencies = demo.get("transitive_dependencies", {})
        remediation_plan = []
        for plan in plans.values():
            blocked = any(
                finding["policy"].get("blocked")
                for finding in case.findings
                if any(package["package"] == plan["package"] for package in finding["affected_packages"])
            )
            plan["recommended_version"] = (
                None
                if plan["package"] in no_fix_packages or blocked
                else self._recommended_version(plan["fixed_versions"])
            )
            if plan["package"] in transitive_dependencies:
                plan["outcome"] = "MANUAL_REMEDIATION_REQUIRED"
                plan["recommended_version"] = None
                plan["action"] = (
                    "Update the parent dependency "
                    f"'{transitive_dependencies[plan['package']]}' manually; "
                    "the vulnerable package is transitive."
                )
            elif blocked:
                plan["outcome"] = "POLICY_BLOCKED"
                plan["action"] = "Repository policy prohibits this automated upgrade."
            elif plan["package"] in no_fix_packages or not plan["recommended_version"]:
                plan["outcome"] = "MANUAL_REMEDIATION_REQUIRED"
                plan["action"] = "No approved fixed version is available; review the advisory manually."
            else:
                plan["outcome"] = "READY_FOR_VALIDATION"
                plan["action"] = f"Upgrade {plan['package']} to {plan['recommended_version']} or later."
            remediation_plan.append(plan)

        remediation_plan.sort(
            key=lambda plan: (
                self.PRIORITY_ORDER[plan["highest_priority"]],
                plan["package"],
            )
        )
        case.metadata["remediation_plan"] = remediation_plan
        case.stage = "Remediation Planning"
        case.history.append({
            "agent": "Remediation Planner",
            "stage": case.stage,
            "status": "Completed",
            "packages_with_plans": len(remediation_plan),
        })

        return case
