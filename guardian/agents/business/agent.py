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
        return new_state
