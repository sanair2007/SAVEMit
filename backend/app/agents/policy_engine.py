from app.agents.base_agent import BaseAgent


class PolicyEngine(BaseAgent):
    def execute(self, case):
        print("Policy Evaluation")

        case.stage = "Policy Evaluation"
        case.history.append({
            "agent": "Policy Engine",
            "stage": case.stage,
            "status": "Completed"
        })
        return case
import math
import logging

from app.agents.base_agent import BaseAgent


class PolicyEngine(BaseAgent):
    PRIORITY_ORDER = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "UNKNOWN": 4,
    }

    @staticmethod
    def _parse_vector(vector):
        return {
            key: value
            for key, value in (
                metric.split(":", 1)
                for metric in vector.split("/")[1:]
                if ":" in metric
            )
        }

    @staticmethod
    def _round_up(score):
        return math.ceil((score - 1e-10) * 10) / 10

    def _cvss_v3_score(self, severity):
        vector = next(
            (
                entry.get("score")
                for entry in severity
                if entry.get("type") == "CVSS_V3"
            ),
            None,
        )
        if not vector:
            return None, None

        metrics = self._parse_vector(vector)
        try:
            attack_vector = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics["AV"]]
            attack_complexity = {"L": 0.77, "H": 0.44}[metrics["AC"]]
            user_interaction = {"N": 0.85, "R": 0.62}[metrics["UI"]]
            scope = metrics["S"]
            privileges_required = {
                "U": {"N": 0.85, "L": 0.62, "H": 0.27},
                "C": {"N": 0.85, "L": 0.68, "H": 0.5},
            }[scope][metrics["PR"]]
            impact_weights = {"H": 0.56, "L": 0.22, "N": 0.0}
            confidentiality = impact_weights[metrics["C"]]
            integrity = impact_weights[metrics["I"]]
            availability = impact_weights[metrics["A"]]
        except KeyError:
            return None, vector

        impact_subscore = 1 - (
            (1 - confidentiality) * (1 - integrity) * (1 - availability)
        )
        if impact_subscore <= 0:
            return 0.0, vector

        if scope == "U":
            impact = 6.42 * impact_subscore
        else:
            impact = (
                7.52 * (impact_subscore - 0.029)
                - 3.25 * ((impact_subscore - 0.02) ** 15)
            )

        exploitability = (
            8.22 * attack_vector * attack_complexity * privileges_required * user_interaction
        )
        score = impact + exploitability
        if scope == "C":
            score *= 1.08

        return self._round_up(min(score, 10)), vector

    def _cvss_v4_priority(self, severity):
        vector = next(
            (
                entry.get("score")
                for entry in severity
                if entry.get("type") == "CVSS_V4"
            ),
            None,
        )
        if not vector:
            return "UNKNOWN", None

        metrics = self._parse_vector(vector)
        high_impacts = sum(
            metrics.get(metric) == "H"
            for metric in ("VC", "VI", "VA", "SC", "SI", "SA")
        )
        remotely_exploitable = metrics.get("AV") == "N"
        unauthenticated = metrics.get("PR") == "N"

        if remotely_exploitable and unauthenticated and high_impacts >= 2:
            return "CRITICAL", vector
        if high_impacts >= 2 or (remotely_exploitable and high_impacts >= 1):
            return "HIGH", vector
        if high_impacts >= 1:
            return "MEDIUM", vector
        return "LOW", vector

    @staticmethod
    def _priority_for_score(score):
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        return "LOW"

    def _deprioritize(self, priority):
        priorities = list(self.PRIORITY_ORDER)
        return priorities[min(priorities.index(priority) + 1, len(priorities) - 1)]

    def _evaluate_finding(self, finding):
        severity = finding.get("severity", [])
        cvss_score, vector = self._cvss_v3_score(severity)

        if cvss_score is not None:
            policy = {
                "priority": self._priority_for_score(cvss_score),
                "cvss_score": cvss_score,
                "policy_basis": "CVSS v3 base score",
                "cvss_vector": vector,
            }
        else:
            priority, vector = self._cvss_v4_priority(severity)
            policy = {
                "priority": priority,
                "cvss_score": None,
                "policy_basis": "CVSS v4 exposure-and-impact fallback",
                "cvss_vector": vector,
            }

        reachable = finding.get("reachability", {}).get("reachable")
        package_names = {
            package["package"] for package in finding.get("affected_packages", [])
        }
        blocked_packages = set(finding.get("demo", {}).get("blocked_packages", []))
        if not reachable:
            policy["priority"] = self._deprioritize(policy["priority"])
        policy["reachability_status"] = (
            "REACHABLE" if reachable else "REVIEW - no static import found"
        )
        policy["recommended_action"] = (
            "Prioritize remediation; vulnerable package is statically imported."
            if reachable
            else "Review before remediation; no static import was found."
        )
        policy["blocked"] = bool(package_names & blocked_packages)
        if policy["blocked"]:
            policy["recommended_action"] = "Blocked by repository policy; do not create an automated patch."
        return policy

    def execute(self, case):
        logging.getLogger(__name__).info("Policy Evaluation")

        findings = case.findings
        demo = case.metadata.get("demo", {})
        for finding in findings:
            finding["demo"] = demo
            finding["policy"] = self._evaluate_finding(finding)
            finding.pop("demo", None)

        findings.sort(
            key=lambda finding: (
                self.PRIORITY_ORDER[finding["policy"]["priority"]],
                -(finding["policy"]["cvss_score"] or 0),
                finding["id"],
            )
        )

        summary = {
            priority.lower(): sum(
                finding["policy"]["priority"] == priority for finding in findings
            )
            for priority in self.PRIORITY_ORDER
        }
        case.metadata["policy"] = {
            "summary": summary,
            "prioritized_findings": findings,
        }
        case.metadata["threat_intel"]["vulnerabilities"] = findings
        case.stage = "Policy Evaluation"
        case.history.append({
            "agent": "Policy Engine",
            "stage": case.stage,
            "status": "Completed",
            "priority_summary": summary,
        })

        return case
