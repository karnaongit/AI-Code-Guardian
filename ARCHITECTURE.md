# AI Code Guardian 2.0 — Architecture

## Design goal
Eliminate every repository-specific assumption from v1 and restructure the
platform so it can scan **any repository** through a plugin-driven,
configuration-driven pipeline. All v1 engines are preserved — they now live
behind stable contracts instead of being wired directly to each other.

## Layout

```
guardian/
├── config.py               Configuration (YAML + defaults). Single source of truth.
├── cli.py / __main__.py    `python -m guardian scan|detect|intent <path>`
├── core/
│   ├── models.py           Finding / ScanResult / Severity (v1 schema, unchanged —
│   │                       stable SHA-1 finding IDs, flat to_dict contract)
│   ├── interfaces.py       LanguagePlugin / Analyzer / Reporter / IntentClassifier protocols
│   ├── registry.py         Plugin registry + @register_* decorators
│   ├── pipeline.py         Orchestrator: discovery → detection → plugins →
│   │                       analyzers → dedup → intent → risk → report dict
│   └── risk.py             CRS risk scorer (v1, unchanged)
├── discovery/
│   ├── file_walker.py      Recursive discovery: ignore list, symlink-cycle
│   │                       safety, size caps, 200k-file cap, file classification
│   └── repo_detector.py    Language %, frameworks, build tools, architecture
│                           shape, monorepo detection — manifest-driven
├── scanner/
│   ├── _engine.py          v1 SecurityRuleEngine, intact (entropy-filtered
│   │                       secrets, Python AST taint pass, Java regex bridge)
│   ├── base.py             EngineBackedPlugin adapter
│   ├── java/  python/      Plugins wrapping the proven v1 detectors
│   ├── javascript/         New starter plugin (proves zero-pipeline-change extension)
│   └── common/secrets.py   Shared entropy gate (threshold 2.8)
├── dependencies/
│   ├── parsers.py          requirements.txt / package(.lock).json / pom.xml / go.mod
│   └── analyzer.py         Inventory + unpinned-version findings; OSV CVE
│                           cross-reference via existing threat_intel collectors
├── infrastructure/
│   ├── rules.py            Data-driven IaC catalog (Docker, Compose, K8s,
│   │                       Terraform, CI pipelines)
│   └── analyzer.py         Applies catalog to discovered infra files
├── intent/
│   ├── domains.py          14-domain vocabulary taxonomy (data-driven)
│   ├── classifier.py       Evidence-weighted domain classifier with
│   │                       confidence, alternatives, evidence, reasoning
│   └── legacy/             v1 requirement-alignment engine (Jira/Excel user
│                           stories ↔ code), unchanged and complementary
├── quantum/                v1 engine intact (13 families, FIPS 203/204/205,
│   └── plugin.py           CBOM) + new Analyzer adapter
├── threat_intel/           v1 NVD / CISA KEV / OSV collectors, 24h cache, intact
├── ai/                     v1 Ollama + RAG + CodeBERT assistant, intact
│                           (off by default: config.enable_ai)
└── reporting/              JSON · SARIF 2.1.0 · self-contained HTML
```

## Key decisions

1. **Contracts over rewrites.** The v1 detectors were validated against a
   real 3-MLoC banking codebase; they are wrapped, not rewritten. The
   `LanguagePlugin` contract means the planned Tree-sitter migration
   changes plugin internals only.
2. **Registry-driven pipeline.** `pipeline.py` never names a language or
   analyzer. Adding Go support = one module with `@register_language`.
3. **Deterministic core, AI enrichment.** The scan pipeline is fully
   functional offline with no models. The Ollama/RAG layer (ported in
   `guardian/ai/`) attaches on top for explanation, false-positive triage,
   and chat — it never gates results.
4. **Two intent engines, two questions.** `intent/classifier.py` answers
   *"what domain is this repository?"* (repo-agnostic, evidence-based);
   `intent/legacy/` answers *"does this code match the stated
   requirements?"* (user-story alignment). Both feed reporting.
5. **Graceful degradation everywhere.** Analyzer failure, network failure,
   unparsable files, and oversized repos degrade to partial results with
   logs — never to a dead scan.

## Roadmap markers in code
Search for `TODO(...-roadmap)`:
- `plugin-roadmap`  — Tree-sitter UAST rules per language, DOM-XSS taint for JS
- `deps-roadmap`    — Cargo.lock / Gemfile.lock / composer.lock / go.sum parsers
- `iac-roadmap`     — structural YAML/HCL parsing for K8s + Terraform
- `intent-roadmap`  — optional Ollama re-ranking of domain candidates
- `report-roadmap`  — PDF/CSV export, charts, compliance overview

## Backward compatibility
- `python main.py scan <path>` still works (delegates to the new CLI).
- `Finding.to_dict()` output is byte-compatible with v1 → the Streamlit
  dashboard and Day-7 risk scorer consume it unchanged.
- All 44 v1 tests pass unmodified apart from import paths.
