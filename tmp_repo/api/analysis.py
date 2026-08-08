from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import traceback
import logging
from typing import Optional
from ai.assistant import AIAssistant
from services.analysis_service import AnalysisService
from ai.models import InvestigationAction, InvestigationSession

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/analysis",
    tags=["Analysis"]
)

service = AnalysisService()
assistant = AIAssistant()

# In-memory store for investigation sessions
active_sessions: dict[str, InvestigationSession] = {}

class RepositoryRequest(BaseModel):
    repo_name: str

class ChatRequest(BaseModel):
    question: str
    repo_name: Optional[str] = None
    finding_id: Optional[str] = None

class FileRequest(BaseModel):
    repo_name: str
    file_path: str

class InvestigateRequest(BaseModel):
    finding_id: str
    repo_name: str

class ActionRequest(BaseModel):
    session_id: str
    action: InvestigationAction
    repo_name: str
    finding_id: str
    question: Optional[str] = None # For free-text chat if we decide to pass it

@router.post("/file")
def get_file(request: FileRequest):
    try:
        repo_name = request.repo_name
        if "github.com/" in repo_name:
            repo_name = repo_name.split("github.com/")[-1]
        repo_name = repo_name.replace(".git", "").strip("/")
        
        content = service.github.get_file_from_github(repo_name, request.file_path)
        return {"content": content}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/repository")
def analyze_repository(request: RepositoryRequest):
    try:
        repo_name = request.repo_name
        if "github.com/" in repo_name:
            repo_name = repo_name.split("github.com/")[-1]
        repo_name = repo_name.replace(".git", "").strip("/")
        
        report = service.analyze_repository(repo_name)

        assistant.attach_scan(
            scan_report=report,
            repo_root=repo_name,
        )

        response_report = {k: v for k, v in report.items() if k != "graph"}
        return response_report

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )

@router.post("/investigate")
def investigate(request: InvestigateRequest):
    try:
        graph = assistant.pipeline._scan_report.get("graph")
        if not graph:
            raise ValueError("No repository scanned. Please scan first.")
            
        from scanner.intelligence.investigation_service import InvestigationService
        inv_service = InvestigationService(graph)
        session = inv_service.investigate(request.finding_id, request.repo_name)
        active_sessions[session.session_id] = session
        
        # We need to return dict so FastAPI can serialize dataclasses properly
        import dataclasses
        return dataclasses.asdict(session)
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/action")
def take_action(request: ActionRequest):
    try:
        session = active_sessions.get(request.session_id)
        if not session:
            # Reconstruct session if lost in memory
            graph = assistant.pipeline._scan_report.get("graph")
            if not graph:
                raise ValueError("No repository scanned. Please scan first.")
            from scanner.intelligence.investigation_service import InvestigationService
            inv_service = InvestigationService(graph)
            session = inv_service.investigate(request.finding_id, request.repo_name)
            active_sessions[session.session_id] = session
            
        if request.repo_name:
            safe_repo_name = request.repo_name.replace("/", "_")
            assistant.pipeline.set_retriever_index(safe_repo_name)

        # Let the assistant handle the structured action
        result = assistant.take_action(session, request.action, request.question)
        
        import dataclasses
        return dataclasses.asdict(result)
        
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))