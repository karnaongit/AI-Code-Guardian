"""
Scans API Endpoint
==================
Triggers and retrieves repository security scans wrapping `guardian.core.pipeline`.
"""
from __future__ import annotations

import asyncio
import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, BackgroundTasks, File, Form, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field
import git

from guardian.core.pipeline import ScanPipeline
from guardian.reasoning.tools import register_scan_context
from guardian.workspace.manager import RepositoryManager

router = APIRouter(prefix="/scans", tags=["scans"])

# In-memory scan store (syncs with DB when available)
_SCANS_STORE: Dict[str, Dict[str, Any]] = {}


class ScanRequest(BaseModel):
    source_type: Optional[str] = Field("local", description="Source type: 'local', 'zip', or 'github'.")
    target_path: Optional[str] = Field(None, description="Path to repository or directory to scan.")
    repo_url: Optional[str] = Field(None, description="GitHub repository URL to clone and scan.")
    url: Optional[str] = Field(None, description="Generic URL or path parameter.")
    scan_mode: str = Field("precision", description="Scan mode: 'precision' or 'recall'.")
    enable_ai: bool = Field(False, description="Enable Nemotron AI contextual reasoning.")
    requirements: Optional[List[str]] = Field(None, description="Optional requirements file paths.")


class ScanResponse(BaseModel):
    scan_id: str
    target: str
    scan_mode: str
    status: str
    files_scanned: int
    duration_seconds: float
    total_findings: int
    funnel_metrics: Dict[str, int]
    by_severity: Dict[str, int]
    by_category: Dict[str, int]


import logging
logger = logging.getLogger("guardian.api.scans")

def generate_repo_overview(scan_result: Dict[str, Any], scan_dir: str) -> Dict[str, Any]:
    profile = scan_result.get("repository", {})
    discovery = scan_result.get("discovery", {})
    ust_summary = scan_result.get("ust", {})
    domain_info = scan_result.get("business_domain", {})
    
    raw_langs = profile.get("languages") or ust_summary.get("languages") or ["Python"]
    if isinstance(raw_langs, dict):
        primary_languages = list(raw_langs.keys())
    elif isinstance(raw_langs, (set, tuple, list)):
        primary_languages = [str(x) for x in raw_langs]
    else:
        primary_languages = [str(raw_langs)]
        
    raw_frameworks = profile.get("frameworks") or []
    if isinstance(raw_frameworks, (set, tuple, list)):
        frameworks = [str(x) for x in raw_frameworks]
    else:
        frameworks = [str(raw_frameworks)]
        
    total_files = discovery.get("source_files", 0) + discovery.get("manifest_files", 0) + discovery.get("infrastructure_files", 0)
    if total_files == 0:
        total_files = scan_result.get("scan", {}).get("files_scanned", 0)
        
    domain_name = (domain_info.get("domain") if isinstance(domain_info, dict) else "") or "software"
    lang_str = ", ".join(primary_languages[:3]) if primary_languages else "Python"
    summary = f"This repository is a {domain_name} codebase containing {total_files} scanned files primarily written in {lang_str}."
    
    return {
        "repo_name": Path(scan_dir).name,
        "repo_path": str(scan_dir),
        "primary_languages": primary_languages,
        "frameworks_detected": frameworks,
        "total_files_scanned": total_files,
        "summary": summary
    }

def _run_pipeline_scan(scan_dir: str, enable_ai: bool, scan_mode: str, requirements: Optional[List[str]] = None) -> Dict[str, Any]:
    pipeline = ScanPipeline()
    pipeline.config.enable_ai = enable_ai
    result = pipeline.scan(
        repo_root=str(scan_dir),
        business_requirements=requirements,
    )
    result["scan_mode"] = scan_mode
    result["target"] = str(scan_dir)
    
    repo_overview = generate_repo_overview(result, str(scan_dir))
    result["repo_overview"] = repo_overview

    scan_id = f"scan_{len(_SCANS_STORE) + 1}"
    _SCANS_STORE[scan_id] = result
    
    findings = result.get("scan", {}).get("findings", [])
    register_scan_context(findings, repo_overview=repo_overview)

    return {
        "status": "success",
        "scan_id": scan_id,
        "message": "Scan completed successfully.",
        "result": result
    }

@router.post("", response_model=Dict[str, Any])
async def trigger_scan(request: ScanRequest):
    try:
        source_type = (request.source_type or "local").lower()
        target_input = (request.url or request.repo_url or request.target_path or "").strip()

        if not target_input:
            raise HTTPException(status_code=400, detail="Must provide target_path, repo_url, or url.")

        scan_dir = ""
        from guardian.discovery.github_service import is_github_url, GitHubService

        if source_type == "github" or is_github_url(target_input):
            try:
                gh = GitHubService()
                fetched_path = gh.fetch_repository(target_input)
                scan_dir = str(fetched_path)
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Failed to clone repository: {str(e)}")
        elif source_type == "zip" or target_input.endswith(".zip"):
            try:
                repo_mgr = RepositoryManager()
                repo_info = repo_mgr.extract_zip_repository(target_input, filename=Path(target_input).name)
                scan_dir = repo_info["repo_path"]
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Failed to extract ZIP repository: {str(e)}")
        else:
            scan_dir = target_input
            path = Path(scan_dir)
            if not path.exists():
                raise HTTPException(status_code=400, detail=f"Target path '{scan_dir}' does not exist.")

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            lambda: _run_pipeline_scan(
                scan_dir=scan_dir,
                enable_ai=request.enable_ai,
                scan_mode=request.scan_mode,
                requirements=request.requirements
            )
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Scan execution error: {str(e)}")


@router.post("/upload", response_model=Dict[str, Any])
async def upload_and_scan(
    file: UploadFile = File(...),
    scan_mode: str = Form("precision"),
    enable_ai: bool = Form(False)
):
    """Upload a ZIP archive file and trigger security scan."""
    try:
        if not file.filename.endswith(".zip"):
            raise HTTPException(status_code=400, detail="Only .zip files are supported for upload.")

        contents = await file.read()
        repo_mgr = RepositoryManager()
        repo_info = repo_mgr.extract_zip_repository(contents, filename=file.filename)
        scan_dir = repo_info["repo_path"]

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            lambda: _run_pipeline_scan(
                scan_dir=scan_dir,
                enable_ai=enable_ai,
                scan_mode=scan_mode
            )
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Upload scan failed: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Upload scan failed: {str(e)}")


@router.get("", response_model=List[Dict[str, Any]])
async def list_scans():
    return [{"scan_id": k, **v} for k, v in _SCANS_STORE.items()]


@router.get("/{scan_id}", response_model=Dict[str, Any])
async def get_scan(scan_id: str):
    if scan_id not in _SCANS_STORE:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")
    return _SCANS_STORE[scan_id]
