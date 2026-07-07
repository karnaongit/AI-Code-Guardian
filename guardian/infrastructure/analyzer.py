"""Infrastructure Analyzer — Analyzer plugin applying the IaC rule
catalog to every infrastructure file discovered by the walker."""
from __future__ import annotations

from pathlib import Path
from typing import Iterable

from guardian.core.models import Finding
from guardian.core.registry import register_analyzer
from guardian.infrastructure.rules import RULES


@register_analyzer
class InfrastructureAnalyzer:
    name = "infrastructure"

    def analyze(self, repo_root: Path, files: Iterable[Path]) -> list[Finding]:
        findings: list[Finding] = []
        for fp in files:
            applicable = [r for r in RULES if r.applies(fp)]
            if not applicable:
                continue
            try:
                text = fp.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            try:
                label = str(fp.relative_to(repo_root))
            except ValueError:
                label = str(fp)
            for lineno, line in enumerate(text.splitlines(), 1):
                for rule in applicable:
                    if rule.pattern.search(line):
                        findings.append(Finding(
                            category=rule.category, severity=rule.severity,
                            rule_id=rule.rule_id, file=label, line=lineno,
                            snippet=line.strip()[:200],
                            recommendation=rule.recommendation, confidence=0.7,
                        ))
        return findings
