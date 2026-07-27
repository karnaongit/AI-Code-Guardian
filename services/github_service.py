from github_api.repository_service import RepositoryService
from github_api.file_service import FileService


class GitHubService:

    def __init__(self):
        self.repository_service = RepositoryService()
        self.file_service = FileService()

    def get_repository(self, repo_name: str):
        return self.repository_service.get_repository_details(repo_name)

    def get_python_files(self, repo_name: str):
        return self.file_service.get_python_files(repo_name)

    def get_file_content(self, download_url: str):
        return self.file_service.get_file_content(download_url)