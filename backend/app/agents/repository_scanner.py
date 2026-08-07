import json
from pathlib import Path

from app.agents.base_agent import BaseAgent

class RepositoryScanner(BaseAgent):

    def execute(self, case):
        print("Repository Scanner")

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
        demo_config_path = repository_path / ".savemit-demo.json"
        if demo_config_path.is_file():
            case.metadata["demo"] = json.loads(demo_config_path.read_text(encoding="utf-8"))
        case.stage = "Repository Scan"

        case.history.append({
            "agent": "Repository Scanner",
            "stage": case.stage,
            "status": "Completed",
            "repository_path": str(repository_path)
        })

        return case
