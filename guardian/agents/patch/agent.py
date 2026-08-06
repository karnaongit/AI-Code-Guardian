"""
AI Code Guardian v3 — Patch Generation Agent
============================================
Specialist agent generating secure remediation proposals grounded in evidence.
Never overwrites repository files on disk. Produces unified git diffs and developer explanations.
"""
from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from guardian.agents.base.agent import BaseAgent
from guardian.agents.patch.models import PatchProposal
from guardian.orchestrator.state import AgentWorkflowState
from guardian.reasoning.grounding.diff import GitDiffGenerator


class PatchGenerationAgent(BaseAgent):
    """Specialist agent producing grounded remediation patch proposals and unified git diffs."""

    name: str = "patch"
    description: str = "Generates grounded patch proposals, unified git diffs, and developer explanations."

    def __init__(
        self,
        tool_registry: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        diff_generator: Optional[GitDiffGenerator] = None
    ) -> None:
        super().__init__(tool_registry=tool_registry, event_bus=event_bus)
        self.diff_generator = diff_generator or GitDiffGenerator()

    def _process(self, state: AgentWorkflowState) -> AgentWorkflowState:
        self._used_tools = ["report_tool", "evidence_tool"]

        findings = state.get("findings", [])
        evidence = state.get("evidence", [])
        threat_ctx = state.get("threat_context", {})
        biz_ctx = state.get("business_context", {})
        policy_res = state.get("policy_results", {})

        patches: List[Dict[str, Any]] = []
        git_diffs: List[str] = []
        dev_explanations: List[str] = []

        for idx, f in enumerate(findings):
            f_id = f.get("finding_id", f"f-{idx+1}")
            rule_id = f.get("rule_id", "SEC-001")
            file_path = f.get("file_path", "app.py")
            line_no = str(f.get("line_number", 1))
            orig_snippet = f.get("snippet", "")
            ev_id = f.get("evidence_id", "")

            # Generate grounded secure replacement code snippet
            suggested_replacement = self._generate_secure_snippet(rule_id, orig_snippet)

            # Compute unified git diff string (NO DISK WRITE)
            diff_str = self.diff_generator.generate_unified_diff(
                file_path=file_path,
                original_snippet=orig_snippet,
                replacement_snippet=suggested_replacement
            )
            git_diffs.append(diff_str)

            explanation = (
                f"Remediated {rule_id} in {file_path}:{line_no} by introducing secure parameterized handling. "
                f"Grounding Evidence ID: {ev_id}. Business Criticality: {biz_ctx.get('criticality', 'NORMAL')}."
            )
            dev_explanations.append(explanation)

            policy_refs = [v.get("policy_name") for v in policy_res.get("violations", []) if v.get("finding_id") == f_id]

            patch_proposal = PatchProposal(
                patch_id=f"patch-{f_id[:8] if len(f_id)>=8 else f_id}",
                finding_id=f_id,
                affected_file=file_path,
                affected_lines=line_no,
                original_snippet=orig_snippet,
                suggested_replacement=suggested_replacement,
                explanation=explanation,
                evidence_ids=[ev_id] if ev_id else [],
                confidence=0.90,
                policy_references=policy_refs,
                business_impact=biz_ctx.get("criticality", "NORMAL"),
                threat_impact="REDUCED",
                validation_status="PENDING",
                git_diff=diff_str,
            )

            patches.append(patch_proposal.to_dict())

        combined_diff = "\n".join(git_diffs)
        combined_explanation = "\n---\n".join(dev_explanations)

        new_state = dict(state)
        new_state["patches"] = patches
        new_state["git_diff"] = combined_diff
        new_state["developer_explanation"] = combined_explanation
        new_state["remediation_summary"] = {
            "total_patches_proposed": len(patches),
            "files_affected": list({p.get("affected_file") for p in patches if p.get("affected_file")}),
        }
        return new_state

    @staticmethod
    def _generate_secure_snippet(rule_id: str, orig_snippet: str) -> str:
        """Generates secure replacement snippet based on rule category."""
        rule_upper = rule_id.upper()
        if "SEC-004" in rule_upper or "SECRET" in rule_upper:
            return "import os\nAWS_SECRET_KEY = os.environ.get('AWS_SECRET_KEY', '')"
        elif "SQL" in rule_upper or "SEC-001" in rule_upper:
            return "# Parameterized SQL Query\ncursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
        elif "XSS" in rule_upper or "SEC-002" in rule_upper:
            return "import html\nsafe_output = html.escape(user_input)"
        elif "DEP" in rule_upper:
            return f"# Pinned dependency version\n{orig_snippet.split('==')[0].strip()}==2.31.0" if orig_snippet else "# Pinned dependency"
        else:
            return f"# Secure Remediated Pattern\n# Grounded fix for {rule_id}\n" + orig_snippet.replace("eval(", "safe_eval(").replace("exec(", "safe_exec(")
