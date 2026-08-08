from fastapi import APIRouter
from pydantic import BaseModel

from services.github_service import GitHubService

router = APIRouter(
    prefix="/github",
    tags=["GitHub"]
)

service = GitHubService()


class RepositoryRequest(BaseModel):
    repository_url: str


@router.post("/repository")
def repository_details(request: RepositoryRequest):

    repo_name = request.repository_url.replace(
        "https://github.com/",
        ""
    ).strip()

    repo = service.get_repository(repo_name)

    files = service.get_python_files(repo_name)

    return {
        "repository": repo,
        "total_files": len(files),
        "files": files
    }