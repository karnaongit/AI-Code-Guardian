"""
Files API Endpoint
==================
Provides repository file tree and raw file content retrieval for the IDE Code Viewer.
"""
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query
from backend.app.api.v1.scans import _SCANS_STORE

router = APIRouter(prefix="/files", tags=["files"])

def build_file_tree(repo_root: Path, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    # Build a lookup for vulnerable files
    vuln_map = {}
    for f in findings:
        file_path = f.get("file", "").replace("\\", "/")
        if not file_path:
            continue
        if file_path not in vuln_map:
            vuln_map[file_path] = {"count": 0, "max_severity": "INFO"}
        vuln_map[file_path]["count"] += 1
        
        # Determine max severity
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        curr_sev = f.get("severity", "INFO").upper()
        max_sev = vuln_map[file_path]["max_severity"]
        if severity_order.get(curr_sev, 0) > severity_order.get(max_sev, 0):
            vuln_map[file_path]["max_severity"] = curr_sev

    def get_node(path: Path) -> Dict[str, Any]:
        rel_path = path.relative_to(repo_root).as_posix()
        node = {
            "name": path.name,
            "path": rel_path,
            "type": "directory" if path.is_dir() else "file",
            "has_vulnerabilities": False,
            "vulnerability_count": 0,
            "max_severity": None,
        }
        
        if path.is_dir():
            children = []
            dir_vuln_count = 0
            dir_max_sev = "INFO"
            severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
            
            for child in path.iterdir():
                # Skip common hidden/build dirs
                if child.name in {".git", ".venv", "__pycache__", "node_modules", ".next"}:
                    continue
                child_node = get_node(child)
                children.append(child_node)
                
                if child_node["has_vulnerabilities"]:
                    node["has_vulnerabilities"] = True
                    dir_vuln_count += child_node["vulnerability_count"]
                    if severity_order.get(child_node["max_severity"], 0) > severity_order.get(dir_max_sev, 0):
                        dir_max_sev = child_node["max_severity"]
            
            node["children"] = sorted(children, key=lambda x: (x["type"] != "directory", x["name"].lower()))
            node["vulnerability_count"] = dir_vuln_count
            node["max_severity"] = dir_max_sev if node["has_vulnerabilities"] else None
        else:
            if rel_path in vuln_map:
                node["has_vulnerabilities"] = True
                node["vulnerability_count"] = vuln_map[rel_path]["count"]
                node["max_severity"] = vuln_map[rel_path]["max_severity"]
                
        return node

    return get_node(repo_root)


@router.get("/tree")
async def get_file_tree(scan_id: str = Query(..., description="ID of the scan")):
    if scan_id not in _SCANS_STORE:
        raise HTTPException(status_code=404, detail="Scan not found.")
    
    scan_data = _SCANS_STORE[scan_id]
    target_dir = scan_data.get("target") or scan_data.get("scan", {}).get("target") or scan_data.get("repository", {}).get("root")
    if not target_dir or not os.path.exists(target_dir):
        # Fallback to empty tree if repo root is no longer available
        return {"name": "root", "path": "", "type": "directory", "children": []}
        
    findings = scan_data.get("scan", {}).get("findings", [])
    tree = build_file_tree(Path(target_dir), findings)
    return tree


@router.get("/content")
async def get_file_content(
    scan_id: str = Query(..., description="ID of the scan"),
    path: str = Query(..., description="Relative file path")
):
    if scan_id not in _SCANS_STORE:
        raise HTTPException(status_code=404, detail="Scan not found.")
        
    scan_data = _SCANS_STORE[scan_id]
    target_dir = scan_data.get("target") or scan_data.get("scan", {}).get("target") or scan_data.get("repository", {}).get("root")
    if not target_dir or not os.path.exists(target_dir):
        raise HTTPException(status_code=404, detail="Repository root not found.")
        
    repo_root = Path(target_dir).resolve()
    file_path = (repo_root / path).resolve()

    if not str(file_path).startswith(str(repo_root)):
        raise HTTPException(status_code=403, detail="Access denied: Path outside repository boundary.")

    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=404, detail=f"File '{path}' not found.")
        
    try:
        content = file_path.read_text(encoding="utf-8")
        return {"content": content}
    except UnicodeDecodeError:
        return {"content": "// Binary file or unsupported encoding"}


import hashlib

def transform_ust_to_react_flow(scan_data: Dict[str, Any], max_depth: int = 3) -> Dict[str, Any]:
    """Flattens hierarchical USTNode structures into React Flow nodes and edges with max depth limiting."""
    nodes = []
    edges = []
    
    target_dir = scan_data.get("target") or scan_data.get("scan", {}).get("target") or "repository"
    repo_name = Path(target_dir).name or "Repository Root"
    findings = scan_data.get("scan", {}).get("findings", [])
    
    # 1. Root Node (Depth 0)
    root_id = "root-repo"
    nodes.append({
        "id": root_id,
        "type": "folder",
        "data": {
            "label": repo_name,
            "path": "/",
            "riskScore": 75 if findings else 0,
        }
    })
    
    if max_depth <= 0:
        return {"nodes": nodes, "edges": edges}

    # Extract UST files
    ust_files = scan_data.get("ust", {}).get("files", {})
    vuln_files = {}
    for f in findings:
        f_path = (f.get("file") or f.get("file_path") or "").replace("\\", "/")
        if f_path:
            vuln_files.setdefault(f_path, []).append(f)

    # Process files
    for f_path, file_data in ust_files.items():
        rel_path = f_path.replace("\\", "/")
        file_id = f"file-{hashlib.md5(rel_path.encode()).hexdigest()[:8]}"
        
        file_findings = vuln_files.get(rel_path, [])
        risk_score = min(100, len(file_findings) * 30) if file_findings else 0
        
        # Depth 1: File Node
        nodes.append({
            "id": file_id,
            "type": "file",
            "data": {
                "label": Path(rel_path).name,
                "path": rel_path,
                "language": Path(rel_path).suffix.lstrip("."),
                "riskScore": risk_score,
                "findings": file_findings,
            }
        })
        edges.append({
            "id": f"e-{root_id}-{file_id}",
            "source": root_id,
            "target": file_id,
            "label": "contains"
        })

        if max_depth >= 2:
            ast_nodes = file_data.get("nodes", []) if isinstance(file_data, dict) else getattr(file_data, "nodes", [])
            for idx, n in enumerate(ast_nodes[:15]):
                n_dict = n.to_dict() if hasattr(n, "to_dict") else (n if isinstance(n, dict) else {})
                n_type = str(n_dict.get("type", "unknown")).lower()
                n_name = n_dict.get("name") or n_dict.get("symbol") or f"element_{idx}"
                
                react_type = "function" if "func" in n_type or "call" in n_type else ("class" if "class" in n_type else "module")
                child_id = f"{file_id}-node-{idx}"
                
                nodes.append({
                    "id": child_id,
                    "type": react_type,
                    "data": {
                        "label": f"{n_type.capitalize()}: {n_name}",
                        "path": f"{rel_path}:{n_dict.get('span', {}).get('start_line', 1)}",
                        "riskScore": 20 if n_dict.get("security_tags") else 0,
                    }
                })
                edges.append({
                    "id": f"e-{file_id}-{child_id}",
                    "source": file_id,
                    "target": child_id,
                    "label": n_type
                })
                
                # Depth 3: Finding Node attached to AST element
                if max_depth >= 3 and file_findings and idx < len(file_findings):
                    f_item = file_findings[idx]
                    finding_id = f"finding-{child_id}-{idx}"
                    nodes.append({
                        "id": finding_id,
                        "type": "finding",
                        "data": {
                            "label": f"{f_item.get('category', 'Issue')} ({f_item.get('cwe', 'CWE')})",
                            "path": f"{f_item.get('file')}:{f_item.get('line', 1)}",
                            "severity": (f_item.get('severity') or 'high').lower(),
                            "reason": f_item.get('description') or f_item.get('reason'),
                        }
                    })
                    edges.append({
                        "id": f"e-{child_id}-{finding_id}",
                        "source": child_id,
                        "target": finding_id,
                        "label": "vulnerability"
                    })

    return {"nodes": nodes, "edges": edges}


@router.get("/ast")
async def get_ast_graph(
    scan_id: str = Query(..., description="ID of the scan"),
    max_depth: int = Query(3, ge=1, le=5, description="Maximum tree depth for visualization")
):
    """Retrieves Universal Syntax Tree topology transformed into React Flow graph nodes and edges."""
    if scan_id not in _SCANS_STORE:
        raise HTTPException(status_code=404, detail="Scan not found.")
        
    scan_data = _SCANS_STORE[scan_id]
    graph_payload = transform_ust_to_react_flow(scan_data, max_depth=max_depth)
    return graph_payload
