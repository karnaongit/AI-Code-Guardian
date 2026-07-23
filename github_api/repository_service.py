from github_api.github_client import GitHubClient


class RepositoryService:

    def __init__(self):
        self.client = GitHubClient()

    def get_repository_details(self, repo_name: str):

        repo = self.client.get_repository(repo_name)

        return {
            "name": repo.name,
            "owner": repo.owner.login,
            "description": repo.description,
            "language": repo.language,
            "stars": repo.stargazers_count,
            "forks": repo.forks_count,
            "branch": repo.default_branch,
            "updated": str(repo.updated_at)
        }