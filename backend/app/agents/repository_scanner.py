import json
import logging
from pathlib import Path

from app.agents.base_agent import BaseAgent

class RepositoryScanner(BaseAgent):

    DEFAULT_POLICY = {
        "blocked_packages": [],
        "minimum_priority": "LOW",
        "allow_major_upgrades": True,
    }

    @classmethod
    def _load_policy_manifest(cls, repository_path):
        policy_path = repository_path / ".savemit-policy.json"
        if not policy_path.is_file():
            return cls.DEFAULT_POLICY.copy(), None

        try:
            policy = json.loads(policy_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError(f"Invalid .savemit-policy.json: {error}") from error

        if not isinstance(policy, dict):
            raise ValueError(".savemit-policy.json must contain a JSON object.")

        unsupported = set(policy) - set(cls.DEFAULT_POLICY)
        if unsupported:
            raise ValueError(
                ".savemit-policy.json contains unsupported fields: "
                + ", ".join(sorted(unsupported))
            )

        normalized = cls.DEFAULT_POLICY | policy
        blocked_packages = normalized["blocked_packages"]
        if not isinstance(blocked_packages, list) or not all(
            isinstance(package, str) and package.strip() for package in blocked_packages
        ):
            raise ValueError("policy.blocked_packages must be an array of package names.")
        normalized["blocked_packages"] = sorted(set(blocked_packages))

        minimum_priority = normalized["minimum_priority"]
        if minimum_priority not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            raise ValueError(
                "policy.minimum_priority must be CRITICAL, HIGH, MEDIUM, or LOW."
            )
        if not isinstance(normalized["allow_major_upgrades"], bool):
            raise ValueError("policy.allow_major_upgrades must be true or false.")

        return normalized, str(policy_path)

    def execute(self, case):
        logging.getLogger(__name__).info("Repository Scanner")

        repository_path = Path(case.repository).expanduser().resolve()
        if not repository_path.is_dir():
            raise ValueError(
                f"Repository path does not exist or is not a directory: {repository_path}"
            )

        if not (repository_path / "package.json").is_file():
            raise ValueError(
                "SAVEMit currently analyzes Node.js repositories. "
                f"No package.json was found in: {repository_path}"
            )

        case.metadata["repository_path"] = str(repository_path)
        case.metadata["ecosystem"] = "npm"
        policy, policy_path = self._load_policy_manifest(repository_path)
        case.metadata["policy_manifest"] = policy
        case.metadata["policy_manifest_path"] = policy_path
        demo_config_path = repository_path / ".savemit-demo.json"
        if demo_config_path.is_file():
            case.metadata["demo"] = json.loads(demo_config_path.read_text(encoding="utf-8"))
        case.stage = "Repository Scan"

        case.history.append({
            "agent": "Repository Scanner",
            "stage": case.stage,
            "status": "Completed",
            "repository_path": str(repository_path),
            "policy_manifest_path": policy_path,
        })

        return case
