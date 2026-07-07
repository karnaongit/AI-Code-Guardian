"""
AI Code Guardian 2.0 — Scan Pipeline Orchestrator
=================================================
The single place where the end-to-end flow lives:

    discover files -> detect repository profile -> language plugins
    -> dependency analysis -> infrastructure analysis -> quantum
    -> business-domain classification -> risk scoring -> report dict

The pipeline knows nothing about any specific language, analyzer, or
repository — it iterates over whatever the Registry provides, driven by
GuardianConfig toggles. The AI layer (RAG/Ollama) attaches *after* this
deterministic pipeline: it enriches results, never gates them.
"""
from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Optional

from guardian.config import GuardianConfig
from guardian.core.models import Finding, ScanResult
from guardian.core.registry import Registry, default_registry, load_builtin_plugins
from guardian.core.risk import compute_risk_report
from guardian.discovery.file_walker import DiscoveredFiles, FileWalker
from guardian.discovery.repo_detector import RepositoryDetector, RepositoryProfile
from guardian.intent.classifier import DomainClassifier, DomainVerdict

log = logging.getLogger(__name__)


class ScanPipeline:
    def __init__(self, config: Optional[GuardianConfig] = None,
                 registry: Optional[Registry] = None):
        self.config = config or GuardianConfig()
        self.registry = registry or load_builtin_plugins() or default_registry

    # ------------------------------------------------------------------
    def scan(self, repo_root: str | Path,
             alignment_score: Optional[float] = None) -> dict:
        """Run the full pipeline over a repository. Returns the aggregate
        report dict consumed by every Reporter and the dashboard."""
        t0 = time.time()
        repo_root = Path(repo_root)
        cfg = self.config

        # 1. Discovery ---------------------------------------------------
        walker = FileWalker(cfg)
        discovered: DiscoveredFiles = walker.discover(
            repo_root, source_extensions=self.registry.supported_extensions)
        log.info("discovered %d source / %d manifest / %d infra files",
                 len(discovered.source), len(discovered.manifests),
                 len(discovered.infrastructure))

        # 2. Repository profile -------------------------------------------
        profile: RepositoryProfile = RepositoryDetector().detect(
            repo_root, discovered.all_files)

        # 3. Language plugin scans ----------------------------------------
        findings: list[Finding] = []
        files_scanned = 0
        for fp in discovered.source:
            plugin = self.registry.language_for(fp.suffix)
            if plugin is None:
                continue
            try:
                text = fp.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            try:
                label = str(fp.relative_to(repo_root))
            except ValueError:
                label = str(fp)
            findings.extend(plugin.scan_source(text, label))
            files_scanned += 1

        # 4. Cross-cutting analyzers ---------------------------------------
        analyzer_results: dict[str, int] = {}
        toggles = {
            "dependencies": cfg.enable_dependencies,
            "infrastructure": cfg.enable_infrastructure,
            "quantum": cfg.enable_quantum,
        }
        analyzer_inputs = {
            "dependencies": discovered.manifests,
            "infrastructure": discovered.infrastructure,
            "quantum": discovered.source,
        }
        quantum_summary = None
        for name, analyzer in self.registry.analyzers.items():
            if not toggles.get(name, True):
                continue
            try:
                extra = analyzer.analyze(repo_root, analyzer_inputs.get(name, discovered.all_files))
            except Exception as exc:  # noqa: BLE001 — one analyzer must never kill a scan
                log.error("analyzer %s failed: %s", name, exc)
                continue
            findings.extend(extra)
            analyzer_results[name] = len(extra)
            if name == "quantum":
                quantum_summary = getattr(analyzer, "last_summary", None)

        # 5. Deduplicate on stable finding_id -------------------------------
        deduped: dict[str, Finding] = {f.finding_id: f for f in findings}
        findings = list(deduped.values())

        # 6. Business-domain classification ---------------------------------
        verdict: Optional[DomainVerdict] = None
        if cfg.enable_intent:
            try:
                verdict = DomainClassifier().classify(repo_root, discovered.all_files)
            except Exception as exc:  # noqa: BLE001
                log.error("intent classification failed: %s", exc)

        # 7. Risk scoring ----------------------------------------------------
        result = ScanResult(target=str(repo_root),
                            files_scanned=files_scanned, findings=findings)
        result.finish()
        risk = compute_risk_report(
            result,
            alignment_score=(alignment_score if alignment_score is not None
                             else cfg.alignment_score_default))

        # 8. Aggregate report -------------------------------------------------
        return {
            "tool": {"name": "AI Code Guardian", "version": "2.0.0"},
            "repository": profile.to_dict(),
            "scan": result.to_dict(),
            "risk": risk.to_dict(),
            "analyzers": analyzer_results,
            "quantum_summary": quantum_summary,
            "business_domain": verdict.to_dict() if verdict else None,
            "discovery": {
                "source_files": len(discovered.source),
                "manifest_files": len(discovered.manifests),
                "infrastructure_files": len(discovered.infrastructure),
                "doc_files": len(discovered.docs),
                "truncated": discovered.truncated,
            },
            "duration_seconds": round(time.time() - t0, 3),
        }
