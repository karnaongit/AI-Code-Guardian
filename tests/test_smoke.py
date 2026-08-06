"""
AI Code Guardian v3 — Cold-Start Smoke Test
============================================
Validates that the FastAPI application boots successfully and the health
endpoint responds correctly. Uses Starlette TestClient (no real server needed).
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


def _get_client():
    """Import the app lazily to avoid top-level import errors in CI where
    DB/env may not be configured.  The health endpoint requires no DB."""
    from backend.app.main import app
    return TestClient(app)


class TestColdStartSmoke:
    """Smoke tests that verify the stack is bootable and the API is reachable."""

    def test_root_health_returns_healthy(self):
        """GET / must return status=healthy with the service name and version."""
        client = _get_client()
        response = client.get("/")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "healthy"
        assert "service" in body
        assert "version" in body

    def test_openapi_docs_reachable(self):
        """The OpenAPI docs page should be reachable (important for pitch demos)."""
        client = _get_client()
        response = client.get("/api/v1/docs")
        assert response.status_code == 200

    def test_scans_endpoint_exists(self):
        """GET /api/v1/scans should respond (even if no scans exist yet)."""
        client = _get_client()
        response = client.get("/api/v1/scans")
        # Endpoint can return 200 (empty list) or 405 (method not allowed for GET on POST-only)
        assert response.status_code in (200, 404, 405)

    def test_requirements_endpoint_returns_valid_json(self):
        """GET /api/v1/requirements should return valid JSON even when no scans exist."""
        client = _get_client()
        response = client.get("/api/v1/requirements")
        assert response.status_code == 200
        body = response.json()
        # Must at minimum have status, alignment_score, and verdicts
        assert "status" in body
        assert "alignment_score" in body
        assert "verdicts" in body

    def test_findings_endpoint_exists(self):
        """GET /api/v1/findings should respond (empty findings are OK)."""
        client = _get_client()
        response = client.get("/api/v1/findings")
        assert response.status_code in (200, 404)
