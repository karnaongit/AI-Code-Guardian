"""
AI Vulnerability Verifier & False Positive Triage Engine
========================================================
Takes deterministic scan findings and verifies their exploitability and context
using NVIDIA Nemotron reasoning. Redacts secrets via guardrails before transmission.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from guardian.core.models import Finding
from guardian.llm.config import LLMConfig
from guardian.llm.factory import create_llm
from guardian.llm.guardrails import LLMGuardrails

log = logging.getLogger(__name__)


class AIFindingVerifier:
    def __init__(self, config: Optional[LLMConfig] = None) -> None:
        self.config = config or LLMConfig.from_env()
        self.guardrails = LLMGuardrails()

    def verify_findings(self, repo_root: Path, findings: List[Finding]) -> List[Finding]:
        """Run AI verification pass over high/critical findings to triage false positives."""
        if not self.config.api_key:
            log.info("NVIDIA_API_KEY not configured — skipping AI verification pass.")
            return findings

        llm = create_llm(self.config)
        verified: List[Finding] = []

        for finding in findings:
            if finding.severity not in ("High", "Critical"):
                verified.append(finding)
                continue

            # Read code snippet window
            file_path = repo_root / finding.file
            context = self._get_context_window(file_path, finding.line)

            # Redact secrets before sending to LLM
            clean_context, _ = self.guardrails.redact_outbound_text(context)

            prompt = (
                f"You are a Senior Application Security Engineer. Analyze this potential vulnerability:\n\n"
                f"Rule ID: {finding.rule_id}\n"
                f"Category: {finding.category}\n"
                f"Severity: {finding.severity}\n"
                f"File: {finding.file} (Line {finding.line})\n"
                f"Snippet: {finding.snippet}\n\n"
                f"Code Context:\n```\n{clean_context}\n```\n\n"
                f"Determine if this is a True Positive or False Positive.\n"
                f"Respond ONLY in valid JSON format:\n"
                f'{{"verdict": "true_positive"|"false_positive", "confidence": <0.0-1.0>, "explanation": "<reason>"}}'
            )

            try:
                response = llm.complete(prompt)
                res = json.loads(response.text)
                verdict = res.get("verdict", "true_positive")
                explanation = res.get("explanation", "")
                conf = float(res.get("confidence", finding.confidence))

                if verdict == "false_positive" and conf >= 0.7:
                    log.info("AI suppressed false positive finding %s in %s", finding.rule_id, finding.file)
                    finding.confidence = 0.1
                    finding.recommendation += f" [AI Triage: Suppressed as False Positive ({explanation})]"
                else:
                    finding.confidence = min(1.0, conf + 0.1)
                    if explanation:
                        finding.recommendation += f" [AI Verified: {explanation}]"

            except Exception as e:
                log.debug("AI verification pass skipped for %s: %s", finding.rule_id, e)

            verified.append(finding)

        return verified

    def _get_context_window(self, file_path: Path, line_no: int, window: int = 10) -> str:
        if not file_path.exists():
            return ""
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            start = max(0, line_no - window - 1)
            end = min(len(lines), line_no + window)
            return "\n".join(lines[start:end])
        except OSError:
            return ""
