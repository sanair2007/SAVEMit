import os

import httpx


class GitHubPullRequestClient:
    API_URL = "https://api.github.com"

    def __init__(self, owner, repository, token):
        self.owner = owner
        self.repository = repository
        self.token = token

    @classmethod
    def from_environment(cls):
        token = os.getenv("SAVEMIT_GITHUB_TOKEN")
        owner = os.getenv("SAVEMIT_GITHUB_OWNER")
        repository = os.getenv("SAVEMIT_GITHUB_REPOSITORY")

        if not token:
            raise RuntimeError("SAVEMIT_GITHUB_TOKEN is required to create a pull request.")
        if not owner or not repository:
            raise RuntimeError(
                "SAVEMIT_GITHUB_OWNER and SAVEMIT_GITHUB_REPOSITORY are required."
            )

        return cls(owner, repository, token)

    def create_pull_request(self, title, body, head_branch, base_branch):
        url = f"{self.API_URL}/repos/{self.owner}/{self.repository}/pulls"
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.token}",
            "X-GitHub-Api-Version": "2026-03-10",
        }
        payload = {
            "title": title,
            "body": body,
            "head": head_branch,
            "base": base_branch,
        }

        try:
            response = httpx.post(url, headers=headers, json=payload, timeout=30.0)
            response.raise_for_status()
        except httpx.HTTPError as error:
            raise RuntimeError(f"GitHub pull request creation failed: {error}") from error

        pull_request = response.json()
        return {
            "number": pull_request["number"],
            "url": pull_request["html_url"],
            "state": pull_request["state"],
        }
