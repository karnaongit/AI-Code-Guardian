from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import traceback
from ai.assistant import AIAssistant

from services.analysis_service import AnalysisService

router = APIRouter(
    prefix="/analysis",
    tags=["Analysis"]
)

service = AnalysisService()
assistant = AIAssistant()

class RepositoryRequest(BaseModel):
    repo_name: str

class ChatRequest(BaseModel):
    question: str


@router.post("/repository")
def analyze_repository(request: RepositoryRequest):
    try:
        
        
        report = service.analyze_repository(request.repo_name)

        assistant.attach_scan(
            scan_report=report,
            repo_root=request.repo_name,
        )

        return report



    except Exception as e:
        traceback.print_exc()   # <-- ADD THIS
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )
        
@router.post("/chat")
def chat(request: ChatRequest):
    try:
        response = assistant.ask(request.question)

        return {
            "answer": response.answer,
            "citations": response.citations,
            "grounded": response.grounded,
            "latency_ms": response.latency_ms,
        }

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )