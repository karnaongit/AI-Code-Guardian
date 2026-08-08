from github_api.repository_service import RepositoryService
from github_api.file_service import FileService


class GitHubService:

    def __init__(self):
        self.repository_service = RepositoryService()
        self.file_service = FileService()

    def get_repository(self, repo_name: str):
        return self.repository_service.get_repository_details(repo_name)

    def download_and_extract(self, repo_name: str, extract_path: str):
        self.file_service.download_and_extract(repo_name, extract_path)

    def get_source_files(self, workspace_path: str):
        return self.file_service.get_source_files(workspace_path)

    def get_file_content(self, local_path: str):
        return self.file_service.get_file_content(local_path)

    def get_file_from_github(self, repo_name: str, file_path: str):
        return self.file_service.get_file_from_github(repo_name, file_path)