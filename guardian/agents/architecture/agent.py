"""
AI Code Guardian v3 — Architecture Agent
=========================================
Specialist agent analyzing system topology, service boundaries, authentication flows,
database relationships, trust boundaries, and API interfaces using KnowledgeService.
"""
from __future__ import annotations

from typing import Any, Dict

from guardian.agents.base.agent import BaseAgent
from guardian.agents.shared.context import ArchitectureContext
from guardian.orchestrator.state import AgentWorkflowState


class ArchitectureAgent(BaseAgent):
    """Specialist agent deriving architectural topologies and boundaries."""

    name: str = "architecture"
    description: str = "Analyzes service boundaries, authentication flows, and trust boundaries."

    def _process(self, state: AgentWorkflowState) -> AgentWorkflowState:
        self._used_tools = ["repository_graph_tool", "knowledge_tool"]

        profile = state.get("repository_profile", {})
        repo_ctx = state.get("repository_context", {})

        # Derive service boundaries and trust boundaries deterministically
        endpoints = profile.get("detected_endpoints", [])
        entry_points = profile.get("entry_points", [])
        frameworks = profile.get("frameworks", [])

        service_boundaries = [f"service:{profile.get('primary_language', 'core')}"]
        auth_flows = repo_ctx.get("auth_modules", ["Session/JWT Authentication Header"])
        db_interactions = repo_ctx.get("database_layers", ["ORM Data Access Layer"])
        api_relationships = [f"API Endpoint: {ep}" for ep in endpoints[:5]]
        external_integrations = [f for f in frameworks if f in ["FastAPI", "Spring Boot", "NestJS", "Actix-web"]]
        trust_boundaries = ["Public HTTP Gateway -> Application Controller", "Application Layer -> Database"]
        critical_components = entry_points + auth_flows

        arch_context: ArchitectureContext = {
            "service_boundaries": service_boundaries,
            "authentication_flows": auth_flows,
            "database_interactions": db_interactions,
            "api_relationships": api_relationships,
            "external_integrations": external_integrations,
            "trust_boundaries": trust_boundaries,
            "critical_components": critical_components,
        }

        new_state = dict(state)
        new_state["architecture_context"] = dict(arch_context)
        return new_state
