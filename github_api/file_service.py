import requests
from github_api.github_client import GitHubClient


class FileService:

    def __init__(self):
        self.client = GitHubClient()

    def get_python_files(self, repo_name):

        repo = self.client.get_repository(repo_name)

        contents = repo.get_contents("")

        python_files = []

        while contents:

            item = contents.pop(0)

            if item.type == "dir":
                contents.extend(repo.get_contents(item.path))

            elif item.path.endswith(".py"):

                python_files.append(
                    {
                        "name": item.name,
                        "path": item.path,
                        "download_url": item.download_url,
                    }
                )

        return python_files

    def get_file_content(self, download_url):

        response = requests.get(download_url)

        if response.status_code == 200:
            return response.text

        return ""