"""
LLM Layer — Security Prompt Builder (spec §4, §5)
=================================================
Builds the structured security-analysis prompt from all available
evidence, and enforces context compression.

Context compression (spec §5): repositories are never sent wholesale.
The builder accepts only pre-selected, high-signal material — AST facts,
the specific functions containing findings, imports, security sinks,
retrieved standards, and business intent — then applies a hard character
budget with proportional truncation so the most important sections
survive when the budget binds.

This is distinct from `guardian.ai.prompt_builder`, which builds
conversational RAG prompts for the chatbot. Both are prompt builders;
this one produces the analysis prompt whose answer the parser turns into
a `SecurityAnalysis`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

SYSTEM_PROMPT = """\
You are AI Code Guardian, an enterprise application security analyst.

You verify static-analysis findings, explain their business impact, and \
produce secure remediations.

EVIDENCE RULE (absolute)
------------------------
Analyse ONLY the code and context provided in this message. Never invent \
file names, line numbers, function names, CWE identifiers, or findings \
that are not supported by the provided evidence. If evidence is \
insufficient to judge a finding, set its status to "needs_manual_review" \
and say why. Reporting uncertainty is correct behaviour; fabricating \
detail is a critical failure.

OUTPUT RULE
-----------
Respond with a single JSON object and nothing else. No prose before or \
after, no markdown fences. Schema:

{
  "summary": "one-paragraph overview",
  "findings": [
    {"rule_id": "", "status": "confirmed|false_positive|needs_manual_review",
     "reasoning": "", "confidence": 0.0}
  ],
  "severity": "Critical|High|Medium|Low|Info",
  "confidence": 0.0,
  "business_impact": "",
  "technical_explanation": "",
  "recommendation": "",
  "secure_code": "",
  "owasp": "",
  "nist": "",
  "rmf": "",
  "cwe": ""
}
"""


@dataclass
class SecurityPromptContext:
    """Everything the analysis prompt may draw on. All fields optional —
    the builder emits only the sections that carry content."""
    code_chunk: str = ""
    language: str = ""
    framework: str = ""
    file_path: str = ""

    business_requirement: str = ""
    business_intent: str = ""
    business_policies: list[str] = field(default_factory=list)

    detected_vulnerabilities: list[dict] = field(default_factory=list)
    ast_analysis: str = ""
    call_graph: str = ""
    security_sinks: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)

    owasp_rules: list[str] = field(default_factory=list)
    nist_controls: list[str] = field(default_factory=list)
    rmf_controls: list[str] = field(default_factory=list)
    related_chunks: list[str] = field(default_factory=list)


class SecurityPromptBuilder:
    """Assembles system+user messages under a hard context budget."""

    #: Section budget share when truncation is required. Code and findings
    #: are the irreducible core; retrieved standards compress first.
    _PRIORITY = ("code", "vulnerabilities", "requirement", "ast",
                 "standards", "related")

    def __init__(self, max_context_chars: int = 12_000):
        self.max_context_chars = max_context_chars

    def build(self, ctx: SecurityPromptContext) -> list[dict]:
        sections = self._sections(ctx)
        user = self._assemble(sections)
        return [{"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user}]

    # ------------------------------------------------------------------
    def _sections(self, ctx: SecurityPromptContext) -> dict[str, str]:
        out: dict[str, str] = {}

        meta = []
        if ctx.file_path:
            meta.append(f"File: {ctx.file_path}")
        if ctx.language:
            meta.append(f"Language: {ctx.language}")
        if ctx.framework:
            meta.append(f"Framework: {ctx.framework}")
        if meta:
            out["meta"] = "\n".join(meta)

        if ctx.business_requirement or ctx.business_intent or ctx.business_policies:
            parts = []
            if ctx.business_requirement:
                parts.append(ctx.business_requirement)
            if ctx.business_intent:
                parts.append(f"Detected business domain: {ctx.business_intent}")
            if ctx.business_policies:
                parts.append("Applicable policies:\n" +
                             "\n".join(f"- {p}" for p in ctx.business_policies))
            out["requirement"] = "\n".join(parts)

        if ctx.detected_vulnerabilities:
            lines = []
            for v in ctx.detected_vulnerabilities:
                lines.append(
                    f"- [{v.get('severity', '?')}] {v.get('rule_id', '?')} "
                    f"{v.get('category', '')} at "
                    f"{v.get('file', '?')}:{v.get('line', '?')}\n"
                    f"  code: {str(v.get('snippet', ''))[:160]}\n"
                    f"  scanner recommendation: {str(v.get('recommendation', ''))[:160]}")
            out["vulnerabilities"] = "\n".join(lines)

        ast_parts = []
        if ctx.ast_analysis:
            ast_parts.append(ctx.ast_analysis)
        if ctx.imports:
            ast_parts.append("Imports: " + ", ".join(ctx.imports[:40]))
        if ctx.security_sinks:
            ast_parts.append("Security sinks reached: " + ", ".join(ctx.security_sinks[:20]))
        if ctx.call_graph:
            ast_parts.append("Call graph:\n" + ctx.call_graph)
        if ast_parts:
            out["ast"] = "\n".join(ast_parts)

        std_parts = []
        if ctx.owasp_rules:
            std_parts.append("OWASP:\n" + "\n".join(f"- {r}" for r in ctx.owasp_rules))
        if ctx.nist_controls:
            std_parts.append("NIST:\n" + "\n".join(f"- {r}" for r in ctx.nist_controls))
        if ctx.rmf_controls:
            std_parts.append("RMF:\n" + "\n".join(f"- {r}" for r in ctx.rmf_controls))
        if std_parts:
            out["standards"] = "\n\n".join(std_parts)

        if ctx.related_chunks:
            out["related"] = "\n---\n".join(ctx.related_chunks)

        if ctx.code_chunk:
            fence = ctx.language.lower() if ctx.language else ""
            out["code"] = f"```{fence}\n{ctx.code_chunk}\n```"
        return out

    def _assemble(self, sections: dict[str, str]) -> str:
        sections = self._compress(sections)
        titles = {
            "meta": "Context",
            "requirement": "Business Requirement",
            "vulnerabilities": "Detected Vulnerabilities (from static analysis)",
            "ast": "AST / Data-Flow Analysis",
            "standards": "Relevant Standards",
            "related": "Related Code Chunks",
            "code": "Code",
        }
        blocks = []
        for key in ("meta", "requirement", "vulnerabilities", "ast",
                    "standards", "related", "code"):
            if sections.get(key):
                blocks.append(f"{titles[key]}:\n{sections[key]}")
        blocks.append(
            "Tasks:\n"
            "1. Verify each detected finding (confirmed / false_positive / "
            "needs_manual_review) with reasoning.\n"
            "2. Explain the business impact in terms of the stated requirement.\n"
            "3. Provide secure remediation guidance.\n"
            "4. Generate corrected secure code.\n"
            "5. Assign an overall confidence score (0.0-1.0).\n\n"
            "Respond with the JSON object only.")
        return "\n\n".join(blocks)

    def _compress(self, sections: dict[str, str]) -> dict[str, str]:
        """Enforce the character budget, dropping/truncating lowest-priority
        sections first (spec §5)."""
        total = sum(len(v) for v in sections.values())
        if total <= self.max_context_chars:
            return sections
        out = dict(sections)
        for key in reversed(self._PRIORITY):
            if key not in out:
                continue
            total = sum(len(v) for v in out.values())
            if total <= self.max_context_chars:
                break
            excess = total - self.max_context_chars
            current = out[key]
            if len(current) <= excess:
                # never drop code or findings entirely — truncate to a stub
                if key in ("code", "vulnerabilities"):
                    out[key] = current[: max(400, len(current) - excess)] + "\n... [truncated]"
                else:
                    del out[key]
            else:
                out[key] = current[: len(current) - excess] + "\n... [truncated]"
        return out
