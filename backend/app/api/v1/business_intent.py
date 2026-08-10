"""
FastAPI Router for Business Intent Engine API
=============================================
Provides REST endpoints:
  POST /api/business-intent/analyze
  POST /api/v1/business-intent/analyze
  GET  /api/v1/business-intent/docs
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Body
from guardian.intent.engine import BusinessIntentEngine
from guardian.intent.ingestion.document_loader import DocumentLoader, get_business_docs_dir

logger = logging.getLogger("guardian.api.business_intent")

router = APIRouter(tags=["business-intent"])


@router.post("/api/business-intent/analyze")
@router.post("/business-intent/analyze")
async def analyze_business_intent(payload: dict[str, Any] = Body(default={})):
    """Runs the Business Intent Engine against uploaded documents in /data/business_docs/."""
    try:
        findings = payload.get("findings", [])
        target_path = payload.get("target_path") or payload.get("repo_path")
        engine = BusinessIntentEngine()
        result = engine.run(scan_findings=findings, target_dir=target_path)
        return result
    except Exception as e:
        logger.error(f"Error executing business intent analysis: {e}", exc_info=True)
        return {
            "status": "ERROR",
            "message": str(e),
            "alignment_score": 0.0,
            "total_rules": 0,
            "matched": 0,
            "violated": 0,
            "partial": 0,
            "findings": []
        }


@router.get("/api/business-intent/docs")
@router.get("/business-intent/docs")
async def list_business_docs():
    """List all documents currently in the /data/business_docs/ folder."""
    try:
        loader = DocumentLoader()
        docs = loader.list_documents()
        docs_dir = get_business_docs_dir()
        return {
            "folder_path": str(docs_dir),
            "count": len(docs),
            "files": docs
        }
    except Exception as e:
        return {
            "folder_path": "/data/business_docs/",
            "count": 0,
            "files": [],
            "error": str(e)
        }


from fastapi import File, UploadFile

@router.post("/api/business-intent/upload")
@router.post("/business-intent/upload")
async def upload_business_doc(file: UploadFile = File(...)):
    """Upload a business requirement document directly into /data/business_docs/."""
    try:
        docs_dir = get_business_docs_dir()
        file_path = docs_dir / file.filename
        content = await file.read()
        file_path.write_bytes(content)
        logger.info(f"Successfully uploaded business doc {file.filename} to {file_path}")

        # List updated docs
        loader = DocumentLoader()
        docs = loader.list_documents()

        return {
            "status": "SUCCESS",
            "filename": file.filename,
            "message": f"Successfully uploaded {file.filename} to {docs_dir}",
            "files": [d["filename"] for d in docs]
        }
    except Exception as e:
        logger.error(f"Failed to upload business doc {file.filename}: {e}", exc_info=True)
        return {
            "status": "ERROR",
            "message": f"Failed to upload document: {str(e)}"
        }


@router.delete("/api/business-intent/docs/{filename}")
@router.delete("/business-intent/docs/{filename}")
async def delete_business_doc(filename: str):
    """Delete a specific business requirement document from /data/business_docs/."""
    try:
        docs_dir = get_business_docs_dir()
        file_path = docs_dir / filename
        if not file_path.exists():
            return {
                "status": "NOT_FOUND",
                "message": f"Document {filename} not found in {docs_dir}"
            }

        file_path.unlink()
        logger.info(f"Successfully deleted business doc {filename} from {docs_dir}")

        loader = DocumentLoader()
        docs = loader.list_documents()

        return {
            "status": "SUCCESS",
            "filename": filename,
            "message": f"Successfully deleted {filename}",
            "files": [d["filename"] for d in docs]
        }
    except Exception as e:
        logger.error(f"Failed to delete business doc {filename}: {e}", exc_info=True)
        return {
            "status": "ERROR",
            "message": f"Failed to delete document: {str(e)}"
        }


@router.delete("/api/business-intent/docs")
@router.delete("/business-intent/docs")
async def delete_all_business_docs():
    """Delete all business requirement documents from /data/business_docs/."""
    try:
        docs_dir = get_business_docs_dir()
        deleted_files = []
        if docs_dir.exists():
            for f in docs_dir.iterdir():
                if f.is_file():
                    f.unlink()
                    deleted_files.append(f.name)

        logger.info(f"Successfully cleared all business docs ({len(deleted_files)} deleted) from {docs_dir}")

        return {
            "status": "SUCCESS",
            "message": f"Successfully deleted {len(deleted_files)} document(s)",
            "deleted_files": deleted_files,
            "files": []
        }
    except Exception as e:
        logger.error(f"Failed to delete all business docs: {e}", exc_info=True)
        return {
            "status": "ERROR",
            "message": f"Failed to clear documents: {str(e)}"
        }


