from github import Github
from dotenv import load_dotenv
import os

load_dotenv()


class GitHubClient:

    def __init__(self):

        token = os.getenv("GITHUB_TOKEN")

        if token:
            self.github = Github(token)
        else:
            self.github = Github()

    def get_repository(self, repo_name):
        return self.github.get_repo(repo_name)