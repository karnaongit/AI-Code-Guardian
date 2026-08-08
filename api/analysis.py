from fastapi import APIRouter, HTTPException, UploadFile, File
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
    workspace_id: Optional[str] = None

@router.post("/file")
def get_file(request: FileRequest):
    try:
        repo_name = request.repo_name
        if repo_name.startswith("local/"):
            # It's a local zip extraction, so the file might be gone, but wait...
            # We can't easily fetch it from github. 
            # We must either persist the extraction or fallback.
            # But the requirement states: "Do not create a separate ZIP-specific scanner or analysis architecture."
            # Wait, if we need the file for the UI, we must persist it or we can't show it.
            # I will temporarily support reading from temp_dir if it's still there. But it's random tempdir!
            # Let's fix that by extracting ZIP to a known deterministic directory based on repo_name.
            import os
            # Use ~/.gemini/ai_code_guardian_workspaces/repo_name
            workspace_root = os.path.expanduser("~/.gemini/ai_code_guardian_workspaces")
            target_file = os.path.join(workspace_root, repo_name.replace("local/", ""), request.file_path)
            if os.path.exists(target_file):
                with open(target_file, "r", encoding="utf-8") as f:
                    return {"content": f.read()}
            return {"content": "File content not available offline."}
            
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

import tempfile
import os
import zipfile
import shutil

@router.post("/repository/zip")
def analyze_local_zip(file: UploadFile = File(...)):
    if not file.filename.endswith('.zip'):
        raise HTTPException(status_code=400, detail="Only .zip files are supported")
        
    repo_name = file.filename.replace(".zip", "")
    workspace_root = os.path.expanduser("~/.gemini/ai_code_guardian_workspaces")
    extract_dir = os.path.join(workspace_root, repo_name)
    os.makedirs(extract_dir, exist_ok=True)
    zip_path = os.path.join(extract_dir, "upload.zip")
    
    try:
        # Save uploaded file
        with open(zip_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
            
        # Securely extract
        with zipfile.ZipFile(zip_path, 'r') as zf:
            for member in zf.infolist():
                # Check for absolute paths or path traversal
                if member.filename.startswith('/') or '..' in member.filename:
                    raise HTTPException(status_code=400, detail="Unsafe zip file detected: Path traversal")
                
                target_path = os.path.abspath(os.path.join(extract_dir, member.filename))
                if not target_path.startswith(os.path.abspath(extract_dir)):
                    raise HTTPException(status_code=400, detail="Unsafe zip file detected: Path traversal")
                    
                zf.extract(member, extract_dir)
                
        # We need to find the root directory of the source code.
        # Often ZIPs contain a single top-level directory.
        extracted_items = [item for item in os.listdir(extract_dir) if item != "upload.zip"]
        source_dir = extract_dir
        if len(extracted_items) == 1:
            single_item_path = os.path.join(extract_dir, extracted_items[0])
            if os.path.isdir(single_item_path):
                source_dir = single_item_path
        
        # Analyze
        report = service.analyze_repository(repo_name=f"local/{repo_name}", extracted_dir=source_dir)
        
        assistant.attach_scan(
            scan_report=report,
            repo_root=f"local/{repo_name}",
        )
        
        response_report = {k: v for k, v in report.items() if k != "graph"}
        return response_report
        
    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        # Clean up the zip file, but keep the extracted directory if it's used by vector store?
        # The vector store copies what it needs into its index.
        # But wait, does semantic resolver or RAG need the files later?
        # The frontend calls /analysis/file to view file content!
        # Oh, /analysis/file delegates to GitHubService.
        pass

@router.post("/investigate")
def investigate(request: InvestigateRequest):
    try:
        if not assistant.pipeline._scan_report:
            raise HTTPException(status_code=400, detail="No repository scanned on this worker. Please scan first.")
        graph = assistant.pipeline._scan_report.get("graph")
        if not graph:
            raise HTTPException(status_code=400, detail="No repository graph available. Please scan first.")
            
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
            if not assistant.pipeline._scan_report:
                raise HTTPException(status_code=400, detail="Session expired and no repository context available on this worker. Please rescan the repository.")
            graph = assistant.pipeline._scan_report.get("graph")
            if not graph:
                raise HTTPException(status_code=400, detail="No repository graph available to reconstruct session. Please rescan.")
            from scanner.intelligence.investigation_service import InvestigationService
            inv_service = InvestigationService(graph)
            session = inv_service.investigate(request.finding_id, request.repo_name)
            active_sessions[session.session_id] = session
            
        if request.repo_name:
            safe_repo_name = request.repo_name.replace("/", "_")
            assistant.pipeline.set_retriever_index(safe_repo_name)

        # Let the assistant handle the structured action
        result = assistant.take_action(session, request.action, request.question, workspace_id=request.workspace_id)
        
        import dataclasses
        return dataclasses.asdict(result)
        
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))