import json
import shutil
import subprocess

from app.agents.base_agent import BaseAgent


class SBOMAgent(BaseAgent):

    def execute(self, case):
        print("SBOM Agent")

        repository_path = case.metadata.get("repository_path")
        if not repository_path:
            raise ValueError("SBOM generation requires a repository path.")

        syft_path = shutil.which("syft")
        if not syft_path:
            raise RuntimeError(
                "Syft is not installed or is not available on PATH. "
                "Install it with: winget install Anchore.Syft"
            )

        try:
            result = subprocess.run(
                [
                    syft_path,
                    "scan",
                    f"dir:{repository_path}",
                    "--quiet",
                    "--exclude",
                    "**/.git/**",
                    "--exclude",
                    "**/.venv/**",
                    "-o",
                    "cyclonedx-json",
                ],
                capture_output=True,
                check=False,
                timeout=120,
            )
        except subprocess.TimeoutExpired as error:
            raise RuntimeError("Syft scan timed out after 120 seconds.") from error

        if result.returncode != 0:
            error_message = result.stderr.decode("utf-8", errors="replace").strip()
            error_message = error_message or "Unknown Syft error"
            raise RuntimeError(f"Syft scan failed: {error_message}")

        try:
            sbom = json.loads(result.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RuntimeError("Syft returned invalid CycloneDX JSON.") from error

        package_count = len(sbom.get("components", []))
        case.metadata["sbom"] = sbom
        case.metadata["sbom_package_count"] = package_count
        case.stage = "SBOM Generation"

        case.history.append({
            "agent": "SBOM Agent",
            "stage": case.stage,
            "status": "Completed",
            "package_count": package_count
        })

        return case
