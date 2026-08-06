"""
Requirements API Endpoint
=========================
Retrieves the validation matrix and compliance verdicts from the most recent scan.
"""
from typing import Any, Dict, List
from fastapi import APIRouter, HTTPException

from backend.app.api.v1.scans import _SCANS_STORE

router = APIRouter(prefix="/requirements", tags=["requirements"])

@router.get("", response_model=Dict[str, Any])
async def get_latest_requirements():
    """Retrieve the requirement coverage from the latest scan."""
    if not _SCANS_STORE:
        return {"status": "no_scans", "alignment_score": 0.0, "verdicts": []}
    
    # Get the latest scan
    latest_scan_id = list(_SCANS_STORE.keys())[-1]
    scan_data = _SCANS_STORE[latest_scan_id]
    
    bi_data = scan_data.get("business_intent")
    if not bi_data:
        return {"status": "no_requirements", "alignment_score": 0.0, "verdicts": []}
    
    return {
        "status": bi_data.get("status", "unknown"),
        "alignment_score": bi_data.get("alignment_score", 0.0),
        "policies": bi_data.get("policies", {}),
        "verdicts": bi_data.get("verdicts", []),
        "documents": bi_data.get("documents", [])
    }

@router.get("/{scan_id}", response_model=Dict[str, Any])
async def get_requirements_by_scan(scan_id: str):
    """Retrieve requirement coverage for a specific scan."""
    if scan_id not in _SCANS_STORE:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")
        
    scan_data = _SCANS_STORE[scan_id]
    bi_data = scan_data.get("business_intent")
    
    if not bi_data:
        return {"status": "no_requirements", "alignment_score": 0.0, "verdicts": []}
        
    return {
        "status": bi_data.get("status", "unknown"),
        "alignment_score": bi_data.get("alignment_score", 0.0),
        "policies": bi_data.get("policies", {}),
        "verdicts": bi_data.get("verdicts", []),
        "documents": bi_data.get("documents", [])
    }
