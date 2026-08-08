import os
import zipfile
import tempfile
import requests
from pathlib import Path
from typing import List, Dict

from github_api.github_client import GitHubClient

SUPPORTED_EXTENSIONS = {
    ".py",
    ".java",
    ".js",
    ".jsx",
    ".ts",
    ".cpp",
    ".c",
    ".h",
    ".hpp",
    ".cs",
    ".go",
    ".rs",
    ".php",
    ".kt",
    ".swift",
}

class FileService:

    def __init__(self):
        self.client = GitHubClient()

    def download_and_extract(self, repo_name: str, extract_path: str) -> None:
        """Downloads the repository zipball and extracts it to extract_path."""
        repo = self.client.get_repository(repo_name)
        zip_url = repo.get_archive_link('zipball')
        
        response = requests.get(zip_url, stream=True)
        response.raise_for_status()

        zip_path = os.path.join(extract_path, "repo.zip")
        with open(zip_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
                
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_path)
            
        os.remove(zip_path)

    def get_source_files(self, workspace_path: str) -> List[Dict]:
        """Enumerates source files recursively from the local workspace."""
        source_files = []
        workspace_dir = Path(workspace_path)
        
        for file_path in workspace_dir.rglob("*"):
            if file_path.is_file():
                extension = file_path.suffix.lower()
                if extension in SUPPORTED_EXTENSIONS:
                    # Keep paths relative to workspace for consistency in findings
                    rel_path = str(file_path.relative_to(workspace_dir))
                    # The zip extraction typically creates a top-level folder like owner-repo-sha
                    # rel_path will include that top-level folder, which is fine.
                    source_files.append(
                        {
                            "name": file_path.name,
                            "path": rel_path,
                            "local_path": str(file_path),
                            "extension": extension,
                        }
                    )

        return source_files

    def get_file_content(self, local_path: str) -> str:
        """Reads file content directly from local disk."""
        try:
            with open(local_path, "r", encoding="utf-8") as f:
                return f.read()
        except UnicodeDecodeError:
            # Fallback for some files that might not be utf-8
            try:
                with open(local_path, "r", encoding="latin-1") as f:
                    return f.read()
            except Exception:
                return ""
        except Exception:
            return ""

    def get_file_from_github(self, repo_name: str, file_path: str) -> str:
        """Fetches a single file's content directly from GitHub API."""
        try:
            repo = self.client.get_repository(repo_name)
            
            # Extract the actual file path by removing the zip top-level folder if present
            # e.g., 'owner-repo-sha1/path/to/file.py' -> 'path/to/file.py'
            parts = file_path.replace('\\', '/').split('/')
            
            # The top level folder from GitHub zipballs is typically owner-repo-sha
            # Let's do a case-insensitive check
            prefix_pattern = f"{repo.owner.login}-{repo.name}".lower()
            
            if len(parts) > 1 and parts[0].lower().startswith(prefix_pattern):
                actual_path = '/'.join(parts[1:])
            elif len(parts) > 1 and parts[0].count('-') >= 2:
                # Fallback: if it has multiple dashes, it's highly likely the zip folder root
                actual_path = '/'.join(parts[1:])
            else:
                actual_path = file_path
                
            file_content = repo.get_contents(actual_path)
            if isinstance(file_content, list):
                return "" # It's a directory
            return file_content.decoded_content.decode('utf-8')
        except Exception as e:
            print(f"Error fetching {file_path} from GitHub: {e}")
            return ""