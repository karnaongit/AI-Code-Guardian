"""
AI Code Guardian v3 — Threat Simulation Agent
==============================================
Simulates realistic attacker behavior by evaluating reachability, exploitability,
and attack chains directly grounded in deterministic findings and evidence IDs.
NEVER fabricates vulnerabilities.
"""
from __future__ import annotations

from typing import Any, Dict, List

from guardian.agents.base.agent import BaseAgent
from guardian.agents.shared.context import ThreatContext
from guardian.orchestrator.state import AgentWorkflowState


class ThreatSimulationAgent(BaseAgent):
    """Specialist agent modeling attack paths and exploitability grounded in findings."""

    name: str = "threat_simulation"
    description: str = "Simulates attack paths, privilege escalation, and reachability grounded in evidence."

    def _process(self, state: AgentWorkflowState) -> AgentWorkflowState:
        self._used_tools = ["knowledge_tool", "evidence_tool"]

        findings = state.get("findings", [])
        evidence = state.get("evidence", [])
        repo_ctx = state.get("repository_context", {})
        arch_ctx = state.get("architecture_context", {})
        biz_ctx = state.get("business_context", {})

        attack_paths: List[Dict[str, Any]] = []
        max_exploitability = 0.0

        for f in findings:
            f_id = f.get("finding_id", "")
            rule_id = f.get("rule_id", "")
            ev_id = f.get("evidence_id", "")
            file_path = f.get("file_path", "")
            sev = f.get("severity", "MEDIUM").upper()

            # Determine reachability & exploitability deterministically
            is_entry_point = any(file_path.endswith(ep) for ep in repo_ctx.get("entry_points", [])) or "api" in file_path.lower()
            exploitability = 0.95 if (sev == "CRITICAL" and is_entry_point) else (0.80 if is_entry_point else 0.50)
            if exploitability > max_exploitability:
                max_exploitability = exploitability

            path_obj = {
                "finding_id": f_id,
                "evidence_id": ev_id,
                "title": f"Attack Chain via {rule_id} in {file_path}",
                "entry_point": file_path if is_entry_point else repo_ctx.get("public_apis", ["/api"])[0] if repo_ctx.get("public_apis") else "main.py",
                "target_file": file_path,
                "exploitability": exploitability,
                "reachability": "DIRECT" if is_entry_point else "INDIRECT",
                "attack_vector": "HTTP/API Request" if is_entry_point else "Internal Subroutine",
            }
            attack_paths.append(path_obj)

        has_auth_bypass = any("auth" in f.get("rule_id", "").lower() for f in findings)
        has_secret_exposure = any("secret" in f.get("rule_id", "").lower() for f in findings)

        threat_ctx: ThreatContext = {
            "exploitability": max_exploitability,
            "reachability": 0.90 if any(p["reachability"] == "DIRECT" for p in attack_paths) else 0.60,
            "attack_paths": attack_paths,
            "privilege_escalation_risk": "HIGH" if has_auth_bypass else "LOW",
            "lateral_movement_risk": "MEDIUM" if len(arch_ctx.get("service_boundaries", [])) > 1 else "LOW",
            "auth_bypass_risk": "HIGH" if has_auth_bypass else "LOW",
            "data_exposure_risk": "HIGH" if has_secret_exposure else "LOW",
            "business_impact": "CRITICAL" if biz_ctx.get("criticality") == "CRITICAL" and max_exploitability >= 0.8 else "HIGH" if max_exploitability >= 0.8 else "MODERATE",
        }

        new_state = dict(state)
        new_state["threat_context"] = dict(threat_ctx)
        new_state["attack_paths"] = attack_paths
        new_state["exploitability"] = max_exploitability
        return new_state
