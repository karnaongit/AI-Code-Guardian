from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from services.analysis_service import AnalysisService


router = APIRouter(
    prefix="/analysis",
    tags=["Analysis"]
)


service = AnalysisService()


class RepositoryRequest(BaseModel):
    repo_name: str


@router.get("/")
def health():

    return {
        "message": "Analysis API Working"
    }


@router.post("/repository")
def analyze_repository(request: RepositoryRequest):

    try:

        result = service.analyze_repository(
            request.repo_name
        )

        return result

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=str(e)
        )