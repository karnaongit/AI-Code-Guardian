"""
AI Code Guardian 2.0 — Scan Pipeline Orchestrator
=================================================
The single place the end-to-end flow lives:

    Repository
      -> Discovery                 (discovery/file_walker, repo_detector)
      -> Language detection        (ust/parsers)
      -> Tree-sitter parsing       (ust/parsers)
      -> UST normalization         (ust/builder)
      -> Static engines            (engines/*, legacy plugins & analyzers)
      -> Shared evidence store     (evidence/store)
      -> Relevant evidence         (reasoning/context)
      -> RAG retrieval             (reasoning/knowledge)
      -> Nemotron reasoning        (reasoning/gateway)
      -> Evidence validation       (reasoning/validation)
      -> Unified risk              (core/unified_risk)
      -> Report dict               (consumed by every Reporter + dashboard)

The pipeline knows nothing about any specific language, engine or
repository — it iterates over what the registry and engine list provide,
driven by GuardianConfig toggles.

Failure policy: every stage is contained. A missing grammar, a failing
engine, an unreachable Nemotron endpoint or a broken RAG index degrades
that stage only, is recorded in `report["errors"]`, and the scan returns
partial results rather than raising.
"""
from __future__ import annotations

import logging
import tempfile
import time
from dataclasses import replace
from pathlib import Path
from typing import Any, Optional

from guardian.config import GuardianConfig
from guardian.core.context import AnalysisContext, RepositoryContext
from guardian.core.models import Finding, ScanResult
from guardian.core.registry import Registry, default_registry, load_builtin_plugins
from guardian.core.risk import compute_risk_report
from guardian.core.unified_risk import compute_unified_risk
from guardian.discovery.file_walker import DiscoveredFiles, FileWalker
from guardian.discovery.repo_detector import RepositoryDetector, RepositoryProfile
from guardian.engines.base import run_engine
from guardian.engines.business_intent import BusinessIntentEngine
from guardian.engines.quantum import QuantumReadinessEngine
from guardian.engines.security import SecurityEngine
from guardian.intent.classifier import DomainClassifier, DomainVerdict
from guardian.ust import USTBuilder, parsers

log = logging.getLogger(__name__)

TOOL_VERSION = "2.1.0"


class ScanPipeline:
    def __init__(self, config: Optional[GuardianConfig] = None,
                 registry: Optional[Registry] = None,
                 *, reasoning_service=None, knowledge_retriever=None):
        self.config = config or GuardianConfig()
        self.registry = registry or load_builtin_plugins() or default_registry
        self._reasoning_service = reasoning_service
        self._knowledge_retriever = knowledge_retriever

    # ------------------------------------------------------------------
    def scan(self, repo_root: str | Path,
             alignment_score: Optional[float] = None,
             business_requirements: Optional[list[str | Path]] = None) -> dict:
        """Run the full pipeline. Returns the aggregate report dict."""
        t0 = time.time()
        cfg = self.config

        repo_root = self._resolve_target(repo_root)
        if cfg.enable_sandbox:
            return self._scan_in_sandbox(
                repo_root,
                alignment_score=alignment_score,
                business_requirements=business_requirements,
                started_at=t0,
            )

        # 1. Discovery ---------------------------------------------------
        walker = FileWalker(cfg)
        source_extensions = self.registry.supported_extensions | parsers.supported_extensions()
        discovered: DiscoveredFiles = walker.discover(
            repo_root, source_extensions=source_extensions)
        log.info("discovered %d source / %d manifest / %d infra files",
                 len(discovered.source), len(discovered.manifests),
                 len(discovered.infrastructure))

        # 2. Repository profile -------------------------------------------
        profile: RepositoryProfile = RepositoryDetector().detect(
            repo_root, discovered.all_files)

        repository = RepositoryContext(
            root=repo_root,
            source_files=discovered.source,
            manifest_files=discovered.manifests,
            infrastructure_files=discovered.infrastructure,
            doc_files=discovered.docs,
            other_files=discovered.other,
            profile=profile,
            truncated=discovered.truncated,
        )
        context = AnalysisContext(repository=repository, config=cfg)
        context.business_requirements = [Path(p) for p in (business_requirements or [])]

        # 3. UST construction ---------------------------------------------
        try:
            context.ust = USTBuilder().build_repository(repo_root, discovered.source)
        except Exception as exc:  # noqa: BLE001 — never let parsing kill a scan
            log.error("UST construction failed: %s", exc)
            context.record_error("ust", exc)

        knowledge_output = self._build_knowledge_context(
            repo_root=repo_root,
            profile=profile,
            discovered=discovered,
            ust_files=list(context.ust),
            context=context,
        )

        # 4. Deterministic engines -----------------------------------------
        engine_stats: dict[str, Any] = {}
        for engine in self._engines():
            result = run_engine(engine, context)
            context.add_findings(result.findings)
            engine_stats[engine.name] = {
                "findings": len(result.findings),
                "evidence": len(result.evidence),
                "duration_seconds": result.duration_seconds,
                "error": result.error,
            }

        # 5. Legacy language plugins + analyzers ----------------------------
        # Kept deliberately: their pattern sets still cover constructs the
        # UST engines do not, and they are the fallback when no grammar is
        # available. Overlapping detections are merged in step 6.
        legacy_findings, files_scanned = self._run_legacy_plugins(context, discovered)
        context.add_findings(legacy_findings)
        analyzer_findings, analyzer_stats = self._run_legacy_analyzers(
            context, discovered, repo_root)
        context.add_findings(analyzer_findings)

        # 6. Merge overlapping findings -------------------------------------
        context.findings = _merge_findings(context.findings)

        # 7. Business-domain classification ----------------------------------
        verdict: Optional[DomainVerdict] = None
        if cfg.enable_intent:
            try:
                verdict = DomainClassifier().classify(repo_root, discovered.all_files)
            except Exception as exc:  # noqa: BLE001
                log.error("intent classification failed: %s", exc)
                context.record_error("domain_classifier", exc)

        # 8. Risk scoring ------------------------------------------------------
        result = ScanResult(target=str(repo_root),
                            files_scanned=max(files_scanned, len(context.ust)),
                            findings=context.findings)
        result.finish()

        business_output = context.output("business_intent") or {}
        effective_alignment = _effective_alignment(
            alignment_score, business_output, cfg.alignment_score_default)
        cbom = context.output("quantum")
        quantum_readiness = cbom.readiness_score() if cbom is not None else 100.0

        unified = compute_unified_risk(
            result,
            evidence_store=context.evidence,
            alignment_score=effective_alignment,
            quantum_readiness=quantum_readiness,
            business_domain=verdict.domain if verdict else "",
            dependency_findings=analyzer_stats.get("dependencies", 0),
            quantum_gate=cfg.enable_quantum_gate,
        )
        # Preserved unchanged for existing consumers of report["risk"].
        legacy_risk = compute_risk_report(
            result, alignment_score=effective_alignment,
            quantum_gate=cfg.enable_quantum_gate)

        # 9. Aggregate report ----------------------------------------------------
        return {
            "tool": {"name": "AI Code Guardian", "version": TOOL_VERSION},
            "repository": profile.to_dict(),
            "scan": result.to_dict(),
            "risk": legacy_risk.to_dict(),
            "unified_risk": unified.to_dict(),
            "ust": context.ust.summary(),
            "evidence": context.evidence.summary(),
            "evidence_items": [e.to_dict() for e in context.evidence],
            "engines": engine_stats,
            "analyzers": analyzer_stats,
            "quantum": cbom.to_dict() if cbom is not None else None,
            "quantum_summary": _quantum_summary(cbom),
            "business_intent": business_output or None,
            "business_domain": verdict.to_dict() if verdict else None,
            "knowledge": knowledge_output,
            "ai": self._ai_status(),
            "discovery": {
                "source_files": len(discovered.source),
                "manifest_files": len(discovered.manifests),
                "infrastructure_files": len(discovered.infrastructure),
                "doc_files": len(discovered.docs),
                "truncated": discovered.truncated,
                "parsers": parsers.availability(),
            },
            "errors": context.errors,
            "sandbox": {"enabled": False},
            "duration_seconds": round(time.time() - t0, 3),
        }

    def _scan_in_sandbox(
        self,
        repo_root: Path,
        *,
        alignment_score: Optional[float],
        business_requirements: Optional[list[str | Path]],
        started_at: float,
    ) -> dict:
        """Run the normal pipeline against an isolated repository copy."""
        from guardian.sandbox import DockerSandboxRunner

        runner = DockerSandboxRunner()
        original_root = Path(repo_root).resolve()

        with tempfile.TemporaryDirectory(prefix="acg_scan_workspace_") as tmpdir:
            isolated_root = runner.prepare_isolated_workspace(original_root, base_dir=Path(tmpdir))
            isolated_requirements = _remap_paths_for_sandbox(
                business_requirements or [], original_root, isolated_root
            )

            sandboxed_config = replace(self.config, enable_sandbox=False)
            sandboxed_pipeline = ScanPipeline(
                sandboxed_config,
                self.registry,
                reasoning_service=self._reasoning_service,
                knowledge_retriever=self._knowledge_retriever,
            )
            report = sandboxed_pipeline.scan(
                isolated_root,
                alignment_score=alignment_score,
                business_requirements=isolated_requirements,
            )

        _rewrite_sandbox_paths(report, isolated_root, original_root)
        report["sandbox"] = {
            "enabled": True,
            "mode": "isolated_workspace",
            "original_root": str(original_root),
            "read_only_source": True,
            "network_disabled": runner.config.network_disabled,
            "workspace_retained": False,
        }
        report["repository"]["root"] = str(original_root)
        report["scan"]["target"] = str(original_root)
        report["duration_seconds"] = round(time.time() - started_at, 3)
        return report

    def _build_knowledge_context(
        self,
        *,
        repo_root: Path,
        profile: RepositoryProfile,
        discovered: DiscoveredFiles,
        ust_files: list,
        context: AnalysisContext,
    ) -> dict:
        """Optionally build Phase 2 graph/vector knowledge for scan output."""
        if not self.config.enable_knowledge:
            return {"enabled": False}

        try:
            from guardian.knowledge.services.knowledge_service import KnowledgeService

            service = KnowledgeService()
            repo_id = Path(repo_root).resolve().name
            graph_counts = service.build_repository_graph(repo_root, profile, ust_files)
            documents = _documents_for_knowledge_index(context, discovered, repo_root)
            doc_ids = service.index_documents(documents, category="repository_docs", repo_id=repo_id) if documents else []
            endpoints = service.get_endpoints()
            architecture = service.get_architecture_context(repo_id)
            service.close()

            return {
                "enabled": True,
                "graph": graph_counts,
                "documents_indexed": len(doc_ids),
                "document_ids": doc_ids[:25],
                "endpoints": endpoints[:25],
                "architecture": architecture,
                "backend": {
                    "vector_store": "qdrant_or_memory",
                    "graph_store": "neo4j_or_memory",
                },
            }
        except Exception as exc:  # noqa: BLE001
            log.error("knowledge layer failed: %s", exc)
            context.record_error("knowledge", exc)
            return {"enabled": True, "error": str(exc)}

    # ------------------------------------------------------------------
    # Stages
    # ------------------------------------------------------------------
    @staticmethod
    def _resolve_target(repo_root: str | Path) -> Path:
        from guardian.discovery.github_service import GitHubService, is_github_url
        target = str(repo_root)
        if is_github_url(target):
            log.info("fetching GitHub repository: %s", target)
            return GitHubService().fetch_repository(target)
        return Path(repo_root)

    def _engines(self) -> list:
        """Build the engine list for this scan, honouring config toggles."""
        service = self.reasoning_service
        knowledge = self.knowledge_retriever
        use_llm = bool(self.config.enable_ai)

        engines: list = [SecurityEngine()]
        if self.config.enable_quantum:
            engines.append(QuantumReadinessEngine(
                reasoning_service=service, knowledge_retriever=knowledge,
                use_llm=use_llm))
        if self.config.enable_intent:
            engines.append(BusinessIntentEngine(
                reasoning_service=service, knowledge_retriever=knowledge,
                use_llm=use_llm))
        return engines

    @property
    def reasoning_service(self):
        """Lazily construct the shared Nemotron service (never raises)."""
        if self._reasoning_service is None and self.config.enable_ai:
            try:
                from guardian.reasoning.gateway import NemotronReasoningService
                self._reasoning_service = NemotronReasoningService()
            except Exception as exc:  # noqa: BLE001
                log.warning("could not build reasoning service: %s", exc)
        return self._reasoning_service

    @property
    def knowledge_retriever(self):
        if self._knowledge_retriever is None and self.config.enable_ai:
            try:
                from guardian.reasoning.knowledge import build_default_retriever
                self._knowledge_retriever = build_default_retriever()
            except Exception as exc:  # noqa: BLE001
                log.warning("could not build knowledge retriever: %s", exc)
        return self._knowledge_retriever

    def _run_legacy_plugins(self, context: AnalysisContext,
                            discovered: DiscoveredFiles) -> tuple[list[Finding], int]:
        findings: list[Finding] = []
        files_scanned = 0
        for fp in discovered.source:
            plugin = self.registry.language_for(fp.suffix)
            if plugin is None:
                continue
            text = context.repository.read(fp)
            if not text:
                continue
            label = context.repository.relative(fp)
            try:
                produced = plugin.scan_source(text, label)
            except Exception as exc:  # noqa: BLE001 — one plugin, one file
                log.debug("plugin %s failed on %s: %s", plugin.name, label, exc)
                context.record_error(f"plugin:{plugin.name}", exc)
                continue
            for finding in produced:
                if not finding.engine:
                    finding.engine = f"legacy:{plugin.name}"
                if not finding.language:
                    finding.language = plugin.name
            findings.extend(produced)
            files_scanned += 1
        return findings, files_scanned

    def _run_legacy_analyzers(self, context: AnalysisContext,
                              discovered: DiscoveredFiles,
                              repo_root: Path) -> tuple[list[Finding], dict[str, int]]:
        cfg = self.config
        toggles = {
            "dependencies": cfg.enable_dependencies,
            "infrastructure": cfg.enable_infrastructure,
            # The UST quantum engine owns this lens now; the regex analyzer
            # stays registered as a fallback but must not double-report.
            "quantum": False,
        }
        inputs = {
            "dependencies": discovered.manifests,
            "infrastructure": discovered.infrastructure,
            "quantum": discovered.source,
        }

        findings: list[Finding] = []
        stats: dict[str, int] = {}
        for name, analyzer in self.registry.analyzers.items():
            if not toggles.get(name, True):
                continue
            try:
                produced = analyzer.analyze(repo_root, inputs.get(name, discovered.all_files))
            except Exception as exc:  # noqa: BLE001 — one analyzer must never kill a scan
                log.error("analyzer %s failed: %s", name, exc)
                context.record_error(f"analyzer:{name}", exc)
                continue
            for finding in produced:
                if not finding.engine:
                    finding.engine = f"analyzer:{name}"
            findings.extend(produced)
            stats[name] = len(produced)
            self._publish_analyzer_evidence(context, name, produced)
        return findings, stats

    @staticmethod
    def _publish_analyzer_evidence(context: AnalysisContext, analyzer: str,
                                   findings: list[Finding]) -> None:
        """Bring legacy analyzer output into the shared evidence store so it
        can be selected for reasoning and cited like everything else."""
        from guardian.evidence.models import Evidence, EvidenceType

        type_map = {
            "dependencies": EvidenceType.VULNERABLE_DEPENDENCY,
            "infrastructure": EvidenceType.IAC_MISCONFIGURATION,
            "quantum": EvidenceType.CRYPTO_USAGE,
        }
        evidence_type = type_map.get(analyzer, EvidenceType.OTHER)
        for finding in findings:
            item = context.evidence.add(Evidence(
                type=evidence_type,
                source=f"analyzer:{analyzer}",
                file=finding.file, line=finding.line,
                language=finding.language,
                symbol=finding.function or finding.rule_id or "",
                operation=finding.category,
                description=finding.reason or finding.recommendation[:200],
                snippet=finding.snippet,
                confidence=finding.confidence,
                severity_hint=finding.severity,
                tags=[analyzer, finding.category],
                metadata={"rule_id": finding.rule_id,
                          "package": _package_of(finding)},
            ))
            if item.id and item.id not in finding.evidence_ids:
                finding.evidence_ids.append(item.id)

    def _ai_status(self) -> dict:
        service = self._reasoning_service
        if service is None:
            return {"enabled": bool(self.config.enable_ai), "configured": False,
                    "reason": ("AI layer disabled in configuration"
                               if not self.config.enable_ai
                               else "reasoning service unavailable")}
        status = service.health()
        status["enabled"] = bool(self.config.enable_ai)
        if self._knowledge_retriever is not None:
            status["knowledge"] = self._knowledge_retriever.backend_status
        return status


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _merge_findings(findings: list[Finding]) -> list[Finding]:
    """Collapse findings that describe the same issue at the same place.

    The UST engines and the legacy pattern plugins legitimately overlap.
    Keep the better-evidenced detection — deterministic over contextual,
    then evidence-backed, then higher confidence — and union the evidence
    IDs so nothing that was observed is lost.
    """
    best: dict[tuple, Finding] = {}
    for finding in findings:
        key = (finding.file, finding.line, finding.category)
        existing = best.get(key)
        if existing is None:
            best[key] = finding
            continue
        best[key] = _absorb(existing, finding)

    return _merge_adjacent(sorted(best.values(),
                                  key=lambda f: (f.file, f.category, f.line)))


def _merge_adjacent(findings: list[Finding], window: int = 3) -> list[Finding]:
    """Second pass: collapse the same issue reported a line or two apart.

    A UST engine anchors an injection finding on the sink call while a
    regex plugin anchors it on the line that builds the string. Both are
    the same defect, and reporting it twice double-counts it in the risk
    score. Only merges when the two are within `window` lines and at least
    one lacks supporting evidence — genuinely distinct findings of the
    same category in the same function are both evidenced and survive.
    """
    merged: list[Finding] = []
    for finding in findings:
        previous = merged[-1] if merged else None
        if (previous is not None
                and previous.file == finding.file
                and previous.category == finding.category
                and abs(previous.line - finding.line) <= window
                and not (previous.evidence_ids and finding.evidence_ids)):
            merged[-1] = _absorb(previous, finding)
            continue
        merged.append(finding)
    return sorted(merged, key=lambda f: (f.file, f.line, f.category))


def _absorb(a: Finding, b: Finding) -> Finding:
    """Keep the stronger finding, carrying over what the weaker one knew."""
    keeper, loser = _preferred(a, b)
    keeper.evidence_ids = list(dict.fromkeys(keeper.evidence_ids + loser.evidence_ids))
    if not keeper.reason and loser.reason:
        keeper.reason = loser.reason
    if not keeper.function and loser.function:
        keeper.function = loser.function
    if not keeper.language and loser.language:
        keeper.language = loser.language
    return keeper


def _preferred(a: Finding, b: Finding) -> tuple[Finding, Finding]:
    def rank(f: Finding) -> tuple:
        return (f.source == "DETERMINISTIC", bool(f.evidence_ids), f.confidence)
    return (a, b) if rank(a) >= rank(b) else (b, a)


def _effective_alignment(explicit: Optional[float], business_output: dict,
                         default: float) -> float:
    """Explicit override wins; then a measured alignment score; then default."""
    if explicit is not None:
        return explicit
    measured = (business_output or {}).get("alignment_score")
    if isinstance(measured, (int, float)):
        return float(measured)
    return default


def _remap_paths_for_sandbox(
    paths: list[str | Path],
    original_root: Path,
    isolated_root: Path,
) -> list[Path]:
    """Map requirement files inside the source repo to their isolated copies."""
    remapped: list[Path] = []
    for raw_path in paths:
        path = Path(raw_path)
        candidate = path if path.is_absolute() else original_root / path
        try:
            relative = candidate.resolve().relative_to(original_root)
        except (OSError, ValueError):
            remapped.append(path)
            continue
        remapped.append(isolated_root / relative)
    return remapped


def _rewrite_sandbox_paths(value: Any, isolated_root: Path, original_root: Path) -> Any:
    """Replace temporary sandbox root strings in a report with the source root."""
    isolated_candidates = sorted(
        {str(isolated_root), str(isolated_root.resolve())},
        key=len,
        reverse=True,
    )
    original = str(original_root.resolve())

    if isinstance(value, dict):
        for key, child in list(value.items()):
            value[key] = _rewrite_sandbox_paths(child, isolated_root, original_root)
        return value
    if isinstance(value, list):
        for idx, child in enumerate(value):
            value[idx] = _rewrite_sandbox_paths(child, isolated_root, original_root)
        return value
    if isinstance(value, str):
        for isolated in isolated_candidates:
            if value == isolated:
                return original
            if value.startswith(isolated + "/"):
                return original + value[len(isolated):]
    return value


def _documents_for_knowledge_index(
    context: AnalysisContext,
    discovered: DiscoveredFiles,
    repo_root: Path,
    *,
    max_docs: int = 50,
    max_chars: int = 12_000,
) -> list[dict[str, Any]]:
    """Collect bounded text documents for Phase 2 semantic indexing."""
    docs: list[dict[str, Any]] = []
    seen: set[Path] = set()
    candidates = list(discovered.docs) + list(context.business_requirements)

    for path in candidates:
        p = Path(path)
        try:
            resolved = p.resolve()
        except OSError:
            resolved = p
        if resolved in seen:
            continue
        seen.add(resolved)

        suffix = p.suffix.lower()
        if suffix not in {".md", ".txt", ".rst", ".json", ".yaml", ".yml"}:
            continue

        text = context.repository.read(p).strip()
        if not text:
            continue

        rel = context.repository.relative(p)
        docs.append({
            "id": f"doc:{rel}",
            "content": text[:max_chars],
            "metadata": {
                "path": rel,
                "source": "repository_document",
                "root": str(repo_root),
            },
        })
        if len(docs) >= max_docs:
            break

    return docs


def _quantum_summary(cbom) -> Optional[dict]:
    """Compact summary preserved for existing report/dashboard consumers."""
    if cbom is None:
        return None
    by_family: dict[str, int] = {}
    by_threat: dict[str, int] = {}
    for entry in cbom.entries:
        family = entry.classification.family.value
        by_family[family] = by_family.get(family, 0) + entry.occurrences
        threat = entry.classification.threat.value
        by_threat[threat] = by_threat.get(threat, 0) + entry.occurrences
    return {
        "target": cbom.target,
        "readiness_score": cbom.readiness_score(),
        "total_crypto_usages": cbom.total_occurrences,
        "by_family": by_family,
        "by_threat": by_threat,
        "quantum_vulnerable_algorithms": [e.algorithm for e in cbom.quantum_vulnerable],
        "post_quantum_algorithms": [e.algorithm for e in cbom.post_quantum],
        "unresolved_call_sites": cbom.unresolved_call_sites,
    }


def _package_of(finding: Finding) -> str:
    """Best-effort package name from a dependency finding's snippet."""
    snippet = (finding.snippet or "").strip()
    for separator in ("==", "@", ":", " "):
        if separator in snippet:
            return snippet.split(separator, 1)[0].strip().lower()
    return snippet.lower()[:80]
