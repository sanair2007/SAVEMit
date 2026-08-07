from app.agents.base_agent import BaseAgent

import json
import logging
import os
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

from app.agents.base_agent import BaseAgent
from app.agents.repository_scanner import RepositoryScanner
from app.agents.sbom_agent import SBOMAgent
from app.agents.threat_intel import ThreatIntelAgent
from app.models.investigation_case import InvestigationCase


class ValidationAgent(BaseAgent):
    DOCKER_IMAGE = "node:22-alpine"

    @staticmethod
    def _docker(command, timeout=60):
        try:
            return subprocess.run(
                command,
                capture_output=True,
                check=False,
                text=True,
                timeout=timeout,
                encoding="utf-8",
                errors="replace",
            )
        except subprocess.TimeoutExpired as error:
            raise RuntimeError("Docker validation timed out.") from error

    def _create_container(self, name, command, volume, network):
        docker_command = [
            "docker",
            "create",
            "--name",
            name,
            "--cap-drop",
            "ALL",
            "--pids-limit",
            "128",
            "--memory",
            "512m",
            "--cpus",
            "1",
            "--workdir",
            "/workspace",
            "--mount",
            f"type=volume,source={volume},target=/workspace",
            "--network",
            network,
        ]
        docker_command.extend([ValidationAgent.DOCKER_IMAGE, *command])
        result = self._docker(docker_command)
        if result.returncode != 0:
            raise RuntimeError(f"Docker container setup failed: {result.stderr.strip()}")
        return name

    def _start_container(self, name, timeout):
        return self._docker(["docker", "start", "-a", name], timeout=timeout)

    def _copy_to_container(self, workspace, name):
        result = self._docker(["docker", "cp", f"{workspace}{os.sep}.", f"{name}:/workspace"])
        if result.returncode != 0:
            raise RuntimeError(f"Unable to copy validation files into Docker: {result.stderr.strip()}")

    def _copy_from_container(self, name, workspace):
        result = self._docker(["docker", "cp", f"{name}:/workspace/.", str(workspace)])
        if result.returncode != 0:
            raise RuntimeError(f"Unable to copy validation files from Docker: {result.stderr.strip()}")

    @staticmethod
    def _command_error(result):
        return result.stderr.strip() or result.stdout.strip() or "No command output available."

    @staticmethod
    def _apply_upgrades(workspace, remediation_plan):
        package_path = Path(workspace) / "package.json"
        package_data = json.loads(package_path.read_text(encoding="utf-8"))

        applied_upgrades = []
        for plan in remediation_plan:
            target_version = plan.get("recommended_version")
            if not target_version:
                continue

            for dependency_group in ("dependencies", "devDependencies"):
                dependencies = package_data.get(dependency_group, {})
                if plan["package"] not in dependencies:
                    continue

                current_version = dependencies[plan["package"]]
                dependencies[plan["package"]] = target_version
                applied_upgrades.append(
                    f"{plan['package']}: {current_version} -> {target_version}"
                )

        if not applied_upgrades:
            raise RuntimeError("No remediation upgrades could be applied to package.json.")

        package_path.write_text(
            json.dumps(package_data, indent=2) + "\n",
            encoding="utf-8",
        )
        return applied_upgrades

    @staticmethod
    def _scan_patched_repository(repository_path, case_id):
        validation_case = InvestigationCase(id=f"{case_id}-validation", repository=repository_path)
        for agent in (RepositoryScanner(), SBOMAgent(), ThreatIntelAgent()):
            validation_case = agent.execute(validation_case)
        return validation_case

    @staticmethod
    def _record(case, status, reason, **details):
        validation = {"status": status, "reason": reason, "tests_passed": False, **details}
        case.metadata["validation"] = validation
        case.status = status
        case.stage = "Validation"
        case.history.append({
            "agent": "Validation Agent",
            "stage": case.stage,
            "status": "Completed",
            "validation_status": status,
            "reason": reason,
        })
        return case

    def execute(self, case):
        logging.getLogger(__name__).info("Validation")

        repository_path = case.metadata.get("repository_path")
        remediation_plan = case.metadata.get("remediation_plan", [])
        if not repository_path:
            raise ValueError("Validation requires a repository path.")
        if not remediation_plan:
            return self._record(case, "NO_REMEDIATION", "No vulnerable dependencies need an update.")

        demo = case.metadata.get("demo", {})
        plan_outcomes = {plan.get("outcome") for plan in remediation_plan}
        if "POLICY_BLOCKED" in plan_outcomes:
            return self._record(case, "POLICY_BLOCKED", "Repository policy prohibited an automated dependency update.")
        if "MANUAL_REMEDIATION_REQUIRED" in plan_outcomes:
            return self._record(case, "MANUAL_REMEDIATION_REQUIRED", "At least one remediation requires human review.")
        if demo.get("simulate_docker_failure"):
            return self._record(case, "VALIDATION_INFRASTRUCTURE_FAILED", "Demo simulates an unavailable Docker validation environment.")
        package_data = json.loads((Path(repository_path) / "package.json").read_text(encoding="utf-8"))
        if not package_data.get("scripts", {}).get("test"):
            return self._record(case, "NOT_VALIDATED", "The repository does not define an npm test script.")
        if not shutil.which("docker"):
            return self._record(case, "VALIDATION_INFRASTRUCTURE_FAILED", "Docker is required for remediation validation.")

        validation_root = Path(repository_path).parents[1] / "data" / "validation"
        validation_root.mkdir(parents=True, exist_ok=True)

        with tempfile.TemporaryDirectory(
            prefix="savemit-validation-",
            dir=validation_root,
        ) as temporary_directory:
            workspace = Path(temporary_directory) / "repository"
            shutil.copytree(
                repository_path,
                workspace,
                ignore=shutil.ignore_patterns(".git", "node_modules"),
            )
            applied_upgrades = self._apply_upgrades(workspace, remediation_plan)

            volume = f"savemit-validation-{uuid.uuid4().hex}"
            containers = []
            volume_created = self._docker(["docker", "volume", "create", volume])
            if volume_created.returncode != 0:
                raise RuntimeError(f"Docker volume setup failed: {volume_created.stderr.strip()}")

            try:
                install_container = self._create_container(
                    f"{volume}-install",
                    ["sh", "-c", "npm install --package-lock-only --ignore-scripts && npm ci --ignore-scripts"],
                    volume,
                    "bridge",
                )
                containers.append(install_container)
                self._copy_to_container(workspace, install_container)
                install = self._start_container(install_container, timeout=600)
                if install.returncode != 0:
                    return self._record(case, "PATCH_NOT_APPLICABLE", self._command_error(install))

                test_container = self._create_container(
                    f"{volume}-test",
                    ["npm", "test"],
                    volume,
                    "none",
                )
                containers.append(test_container)
                tests = self._start_container(test_container, timeout=120)
                if tests.returncode != 0:
                    return self._record(case, "TESTS_FAILED", self._command_error(tests), validated_upgrades=applied_upgrades)

                self._copy_from_container(test_container, workspace)
                patched_case = self._scan_patched_repository(str(workspace), case.id)
                before_count = case.metadata["threat_intel"]["vulnerability_count"]
                after_count = patched_case.metadata["threat_intel"]["vulnerability_count"]
            finally:
                for container in containers:
                    self._docker(["docker", "rm", "-f", container])
                self._docker(["docker", "volume", "rm", "-f", volume])

        validation = {
            "status": "PASSED" if after_count < before_count else "NO_IMPROVEMENT",
            "tests_passed": True,
            "before_vulnerabilities": before_count,
            "after_vulnerabilities": after_count,
            "removed_vulnerabilities": before_count - after_count,
            "validated_upgrades": applied_upgrades,
        }
        case.metadata["validation"] = validation
        case.status = validation["status"]
        case.stage = "Validation"
        case.history.append({
            "agent": "Validation Agent",
            "stage": case.stage,
            "status": "Completed",
            "validation_status": validation["status"],
            "removed_vulnerabilities": validation["removed_vulnerabilities"],
        })
        return case
