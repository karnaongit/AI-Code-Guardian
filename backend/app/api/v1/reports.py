"""
Reports API Endpoint
====================
Provides report rendering, formatting, and file download capabilities (JSON, SARIF, HTML, CSV, PDF, ZIP).
"""
from __future__ import annotations

import io
import json
import zipfile
from datetime import datetime
from typing import Any, Dict, Optional
from fastapi import APIRouter, HTTPException, Query, Response
from fastapi.responses import StreamingResponse

from guardian.core.registry import load_builtin_plugins
from guardian.reasoning.tools import _ACTIVE_FINDINGS
from backend.app.api.v1.scans import _SCANS_STORE

router = APIRouter(prefix="/reports", tags=["reports"])


def _get_latest_report() -> Dict[str, Any]:
    if not _SCANS_STORE:
        return {
            "scan": {
                "target": "Sample Repository",
                "files_scanned": 12,
                "total_findings": len(_ACTIVE_FINDINGS),
                "by_severity": {"Critical": 1, "High": 2, "Medium": 3},
                "by_category": {"SQL Injection": 1, "Weak Crypto": 2},
                "findings": [f.to_dict() if hasattr(f, "to_dict") else dict(f) for f in _ACTIVE_FINDINGS.values()],
            },
            "unified_risk": {
                "security_score": 78.5,
                "alignment_score": 90.0,
                "quantum_readiness_score": 85.0,
                "dependency_risk_score": 95.0,
                "overall_risk_score": 82.0,
                "merge_decision": "Warn",
                "dimensions": {
                    "weights": {"security": 0.4, "alignment": 0.3, "quantum": 0.2, "dependencies": 0.1},
                    "security": 78.5, "alignment": 90.0, "quantum": 85.0, "dependencies": 95.0,
                }
            },
            "quantum": {
                "readiness_score": 85.0,
                "total_occurrences": 3,
                "total_algorithms": 2,
                "unresolved_call_sites": 0,
                "entries": [
                    {
                        "algorithm": "MD5",
                        "status": "classically_broken",
                        "occurrences": 2,
                        "operations": ["Hashing"],
                        "files": ["utils/crypto.py"],
                        "migration_target": "SHA-256",
                        "nist_standard": "FIPS 180-4",
                        "rationale": "MD5 is collision-broken",
                    }
                ]
            },
            "business_intent": {
                "status": "analyzed",
                "alignment_score": 90.0,
                "policies": {"checkable": 4, "policies": []},
                "documents": ["SRS.md"],
                "verdicts": [
                    {
                        "verdict": "COMPLIANT",
                        "policy": "Manager approval for high refunds",
                        "requirement": "Refunds above 50,000 require manager approval",
                        "implementations": [{"file": "services/payment.py", "line": 42, "function": "processRefund"}]
                    }
                ]
            }
        }
    latest_key = list(_SCANS_STORE.keys())[-1]
    return _SCANS_STORE[latest_key]


@router.get("/summary", response_model=Dict[str, Any])
async def get_report_summary():
    try:
        return _get_latest_report()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate report summary: {str(e)}")


@router.get("/download")
async def download_report(
    format: str = Query("json", description="Format: json, sarif, html, csv, pdf, zip")
):
    report = _get_latest_report()
    registry = load_builtin_plugins()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    if format.lower() == "zip":
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            root = f"acg_scan_{ts}"
            zf.writestr(f"{root}/full_report.json", json.dumps(report, indent=2, default=str))
            for fmt in ("csv", "sarif", "html"):
                reporter = registry.reporter(fmt)
                if reporter:
                    try:
                        zf.writestr(f"{root}/guardian_report{reporter.file_extension}", reporter.render(report))
                    except Exception:
                        pass
        buf.seek(0)
        return StreamingResponse(
            buf,
            media_type="application/zip",
            headers={"Content-Disposition": f"attachment; filename=acg_scan_{ts}.zip"}
        )

    reporter = registry.reporter(format.lower())
    if not reporter and format.lower() != "json":
        raise HTTPException(status_code=400, detail=f"Unsupported format '{format}'.")

    if format.lower() == "json":
        content = json.dumps(report, indent=2, default=str)
        ext = ".json"
        media = "application/json"
    else:
        content = reporter.render(report)
        ext = reporter.file_extension
        media = "application/octet-stream"

    return Response(
        content=content,
        media_type=media,
        headers={"Content-Disposition": f"attachment; filename=guardian_report_{ts}{ext}"}
    )
