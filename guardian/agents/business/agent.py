"""
AI Code Guardian v3 — Business Agent
====================================
Specialist agent wrapping the Business Intent Engine to classify business domains,
criticality, compliance requirements, and business capabilities.
"""
from __future__ import annotations

from typing import Any, Dict

from guardian.agents.base.agent import BaseAgent
from guardian.agents.shared.context import BusinessContextObject
from guardian.orchestrator.state import AgentWorkflowState
from guardian.engines.business_intent import BusinessIntentEngine
from guardian.core.context import AnalysisContext, RepositoryContext
from guardian.ust import USTBuilder
from guardian.config import GuardianConfig
from pathlib import Path


class BusinessAgent(BaseAgent):
    """Specialist agent wrapping Business Intent classification engines."""

    name: str = "business"
    description: str = "Classifies business domain intent, criticality, and compliance mandates."

    def _process(self, state: AgentWorkflowState) -> AgentWorkflowState:
        self._used_tools = ["business_intent_tool", "knowledge_tool"]

        b_context = state.get("business_context", {})

        # Invoke BusinessIntentTool
        tool_res = self.tools.execute("business_intent_tool", business_context=b_context)
        intent_info = tool_res.get("business_intent", {})

        domain = intent_info.get("domain") or b_context.get("domain", "general")
        criticality = intent_info.get("criticality") or b_context.get("criticality", "NORMAL")
        confidence = intent_info.get("confidence", 0.90)

        context_obj: BusinessContextObject = {
            "domain": domain,
            "criticality": criticality,
            "confidence": confidence,
            "critical_assets": b_context.get("critical_assets", ["user_data", "authentication_service"]),
            "compliance_frameworks": b_context.get("compliance_frameworks", ["PCI-DSS", "GDPR", "OWASP_TOP_10"]),
            "business_capabilities": b_context.get("business_capabilities", ["payment_processing", "user_auth"]),
            "data_classification": b_context.get("data_classification", "CONFIDENTIAL" if criticality == "CRITICAL" else "INTERNAL"),
        }

        new_state = dict(state)
        new_state["business_context"] = dict(context_obj)

        # V4 FIX: Actually invoke BusinessIntentEngine when requirements are
        # present in the workflow state. Previously this was a pass/stub.
        scan_id = state.get("scan_id", "")
        repo_root = state.get("repository_profile", {}).get("repo_path") or state.get("repository_profile", {}).get("root")
        req_paths = state.get("business_requirements", [])  # List of requirement file paths
        requirements_text = state.get("requirements_text", [])  # Inline requirement strings

        if repo_root and (req_paths or requirements_text):
            try:
                config = GuardianConfig()
                engine = BusinessIntentEngine(config=config)

                # Build analysis context from available state
                ctx = AnalysisContext(repo_root=Path(repo_root))

                # If requirements are file paths, pass them to the engine
                if req_paths:
                    engine_result = engine.analyze(
                        context=ctx,
                        requirements=req_paths,
                    )
                    new_state["business_intent_results"] = {
                        "verdicts": [v.to_dict() if hasattr(v, "to_dict") else str(v) for v in engine_result.verdicts],
                        "alignment_score": getattr(engine_result, "alignment_score", 0.0),
                        "source": "BusinessIntentEngine",
                    }
            except Exception as exc:
                import logging as _log
                _log.getLogger(__name__).warning(
                    "BusinessIntentEngine invocation failed in BusinessAgent: %s", exc
                )
                # Non-fatal: the agent continues with domain/criticality classification only.

        return new_state
