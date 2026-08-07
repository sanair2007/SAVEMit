import json
import logging
import shutil
import subprocess
from pathlib import Path

from app.agents.base_agent import BaseAgent


class SBOMAgent(BaseAgent):

    @staticmethod
    def _manifest_components(repository_path):
        """Build a minimal direct-dependency SBOM when no lockfile is available."""
        package_path = Path(repository_path) / "package.json"
        package_data = json.loads(package_path.read_text(encoding="utf-8"))
        components = []
        for dependency_group in ("dependencies", "devDependencies"):
            for name, declared_version in package_data.get(dependency_group, {}).items():
                version = str(declared_version).lstrip("^~v")
                if not version or not version[0].isdigit():
                    continue
                encoded_name = name.replace("@", "%40", 1) if name.startswith("@") else name
                components.append({
                    "type": "library",
                    "name": name,
                    "version": version,
                    "purl": f"pkg:npm/{encoded_name}@{version}",
                    "properties": [{"name": "savemit:source", "value": "package.json"}],
                })
        return components

    def execute(self, case):
        logging.getLogger(__name__).info("SBOM Agent")

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

        npm_components = [
            component
            for component in sbom.get("components", [])
            if component.get("purl", "").startswith("pkg:npm/")
        ]
        sbom_source = "syft"
        if not npm_components:
            npm_components = self._manifest_components(repository_path)
            sbom_source = "package.json fallback"
        if not npm_components:
            raise RuntimeError("No npm dependencies were found in Syft output or package.json.")

        sbom["components"] = npm_components
        package_count = len(npm_components)
        case.metadata["sbom"] = sbom
        case.metadata["sbom_package_count"] = package_count
        case.metadata["sbom_source"] = sbom_source
        case.stage = "SBOM Generation"

        case.history.append({
            "agent": "SBOM Agent",
            "stage": case.stage,
            "status": "Completed",
            "package_count": package_count,
            "source": sbom_source,
        })

        return case
