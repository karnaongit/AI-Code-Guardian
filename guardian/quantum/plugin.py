"""
Quantum Readiness — Analyzer adapter.

Wraps the existing quantum engine (13 crypto families, NIST FIPS
203/204/205 mapping, CBOM builder, readiness scorer — all ported intact
from v1) behind the cross-cutting Analyzer contract so the pipeline can
run it like any other analyzer, repository-agnostic.

The full CBOM + readiness score remain available via `last_cbom` /
`last_summary` for the reporting layer; findings emitted here are the
per-usage vulnerabilities in the common Finding schema. This module
performs static risk assessment only — future quantum risk is clearly
separated from present-day weaknesses via the threat-level → severity
mapping below.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable, Optional

from guardian.core.models import Finding
from guardian.core.registry import register_analyzer
from guardian.quantum.detector import QuantumDetector
from guardian.quantum.inventory import CryptoInventoryBuilder
from guardian.quantum.mapper import MigrationMapper

# QuantumThreat level -> Finding severity. "Broken today" (MD5/SHA-1/DES)
# is a present vulnerability; Shor-vulnerable asymmetric crypto is a
# future-migration priority, reported one notch lower.
_THREAT_TO_SEVERITY = {
    "BROKEN": "Critical",
    "CRITICAL": "High",
    "HIGH": "Medium",
    "MEDIUM": "Low",
    "LOW": "Info",
}

_SCANNABLE = {".java", ".py", ".js", ".ts", ".go", ".cs", ".rb", ".php", ".kt", ".scala", ".c", ".cpp"}


@register_analyzer
class QuantumReadinessAnalyzer:
    name = "quantum"

    def __init__(self) -> None:
        self._detector = QuantumDetector()
        self._cbom_builder = CryptoInventoryBuilder()
        self._mapper = MigrationMapper()
        self.last_cbom = None
        self.last_summary: Optional[dict] = None

    def analyze(self, repo_root: Path, files: Iterable[Path]) -> list[Finding]:
        usages = []
        for fp in files:
            if fp.suffix.lower() not in _SCANNABLE:
                continue
            try:
                usages.extend(self._detector.scan_file(fp))
            except OSError:
                continue

        self.last_cbom = self._cbom_builder.build(usages, target=str(repo_root))
        try:
            self.last_summary = self._cbom_builder.summary(self.last_cbom)
        except Exception:  # summary is reporting sugar; never fail the scan
            self.last_summary = None

        findings: list[Finding] = []
        for u in usages:
            threat = getattr(u.threat_level, "name", str(u.threat_level)).upper()
            severity = _THREAT_TO_SEVERITY.get(threat, "Medium")
            mig = self._mapper.get_recommendation(u.algorithm)
            rec = (f"Replace with {mig.replacement_algorithm} ({mig.nist_standard}). {mig.rationale}"
                   if mig else
                   f"Migrate {u.algorithm} to a NIST PQC standard (FIPS 203/204/205) or stronger classical primitive.")
            try:
                label = str(Path(u.file).resolve().relative_to(Path(repo_root).resolve()))
            except (ValueError, OSError):
                label = u.file
            findings.append(Finding(
                category="Quantum-Vulnerable Cryptography",
                severity=severity,
                rule_id=f"QNT-{u.algorithm.replace('/', '-').replace(' ', '')}",
                file=label,
                line=u.line,
                snippet=u.snippet[:200],
                recommendation=str(rec)[:300],
                confidence=0.85,
            ))
        return findings
