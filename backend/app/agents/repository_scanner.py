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

        case.metadata["repository_path"] = str(repository_path)
        case.stage = "Repository Scan"

        case.history.append({
            "agent": "Repository Scanner",
            "stage": case.stage,
            "status": "Completed",
            "repository_path": str(repository_path)
        })

        return case
