from typing import Any, Dict
from fastapi import APIRouter
from backend.app.api.v1.scans import _SCANS_STORE
from guardian.reasoning.tools import _ACTIVE_FINDINGS

router = APIRouter(prefix="/analytics", tags=["analytics"])

@router.get("/severity", response_model=Dict[str, Dict[str, int]])
async def get_severity_analytics():
    by_severity = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    by_category = {}
    
    for f in _ACTIVE_FINDINGS.values():
        item = f.to_dict() if hasattr(f, "to_dict") else dict(f)
        
        # Severity
        sev = item.get("severity", "Info")
        # Normalize casing
        sev = sev.capitalize() if sev else "Info"
        if sev not in by_severity:
            by_severity[sev] = 0
        by_severity[sev] += 1
        
        # Category
        cat = item.get("category", "Uncategorized")
        if cat not in by_category:
            by_category[cat] = 0
        by_category[cat] += 1
        
    return {
        "by_severity": by_severity,
        "by_category": by_category
    }

@router.get("/trends", response_model=Dict[str, list])
async def get_score_trends():
    trends = []
    
    for scan_id, scan_data in _SCANS_STORE.items():
        risk_data = scan_data.get("risk", {})
        scan_info = scan_data.get("scan", {})
        
        sec_score = risk_data.get("security_score", 0.0)
        risk_score = risk_data.get("overall_risk_score", 0.0)
        
        # Mock timestamp if not present, just for trend line
        timestamp = scan_info.get("timestamp", "2023-01-01T00:00:00Z")
        
        trends.append({
            "scan_id": scan_id,
            "security_score": sec_score,
            "risk_score": risk_score,
            "timestamp": timestamp
        })
        
    return {"trends": trends}
