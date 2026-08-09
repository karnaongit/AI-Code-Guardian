"""
Unit & API Integration Tests for Phase 5: AST Topology Endpoint & React Flow Mind Map
========================================================================================
Tests AST to React Flow transformation, max-depth tree pruning, and GET /api/v1/files/ast endpoint.
"""
import pytest
from pathlib import Path
from backend.app.api.v1.files import transform_ust_to_react_flow, _SCANS_STORE


def test_transform_ust_to_react_flow_structure():
    """Verifies that transform_ust_to_react_flow generates valid React Flow nodes and edges."""
    mock_scan_data = {
        "target": "/mock/repo/project",
        "scan": {
            "findings": [
                {
                    "finding_id": "F1",
                    "file": "auth.py",
                    "line": 42,
                    "severity": "CRITICAL",
                    "category": "Hardcoded Secret",
                    "cwe": "CWE-798",
                    "description": "Hardcoded AWS secret key discovered in auth.py"
                }
            ]
        },
        "ust": {
            "files": {
                "auth.py": {
                    "nodes": [
                        {
                            "type": "function",
                            "name": "login_user",
                            "symbol": "auth.login_user",
                            "span": {"start_line": 10, "start_column": 0, "end_line": 25, "end_column": 0},
                            "security_tags": ["auth"]
                        }
                    ]
                }
            }
        }
    }

    graph = transform_ust_to_react_flow(mock_scan_data, max_depth=3)

    assert "nodes" in graph
    assert "edges" in graph
    
    node_types = [n["type"] for n in graph["nodes"]]
    assert "folder" in node_types   # Root node
    assert "file" in node_types     # auth.py
    assert "function" in node_types # login_user function
    assert "finding" in node_types  # F1 finding node

    # Verify edge connectivity
    edge_sources = [e["source"] for e in graph["edges"]]
    assert "root-repo" in edge_sources


def test_ast_depth_pruning():
    """Verifies that max_depth limits child AST node depth."""
    mock_scan_data = {
        "target": "/mock/repo/project",
        "scan": {"findings": []},
        "ust": {
            "files": {
                "main.py": {
                    "nodes": [
                        {"type": "function", "name": "main_fn", "span": {"start_line": 1}}
                    ]
                }
            }
        }
    }

    # Depth 1: Root & File node only
    depth1_graph = transform_ust_to_react_flow(mock_scan_data, max_depth=1)
    assert len(depth1_graph["nodes"]) == 2  # Root + file

    # Depth 3: Includes function node
    depth3_graph = transform_ust_to_react_flow(mock_scan_data, max_depth=3)
    assert len(depth3_graph["nodes"]) == 3  # Root + file + function


from fastapi.testclient import TestClient
from backend.app.main import app

def test_ast_api_endpoint():
    """Tests GET /api/v1/files/ast FastAPI endpoint."""
    scan_id = "test_ast_scan_1"
    _SCANS_STORE[scan_id] = {
        "target": "/tmp/test_ast_repo",
        "scan": {"findings": []},
        "ust": {
            "files": {
                "app.py": {
                    "nodes": [{"type": "module", "name": "app", "span": {"start_line": 1}}]
                }
            }
        }
    }

    client = TestClient(app)
    res = client.get(f"/api/v1/files/ast?scan_id={scan_id}&max_depth=3")
    assert res.status_code == 200
    
    data = res.json()
    assert "nodes" in data
    assert "edges" in data
    assert len(data["nodes"]) >= 2
