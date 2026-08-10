# AI Code Guardian — Complete Project Structure

This document is the canonical reference for **every folder and file** in the project: what it is, what feature it belongs to, and how it connects to the rest of the system.

---

## Table of Contents
1. [Architecture Overview](#architecture-overview)
2. [Root Directory](#root-directory)
3. [Core Engine — `guardian/`](#core-engine--guardian)
4. [REST API Backend — `backend/`](#rest-api-backend--backend)
5. [Web Frontend — `frontend/`](#web-frontend--frontend)
6. [Configuration & Static Data](#configuration--static-data)
7. [Tests](#tests)
8. [Runtime Storage & Workspaces](#runtime-storage--workspaces)
9. [Quick Command Reference](#quick-command-reference)

---

## Architecture Overview

```
CLI Entry (main.py)
        │
        ▼
 guardian/core/pipeline.py          ◄─── FastAPI Backend (backend/)
        │                                      ▲
        ├── guardian/discovery/                │
        │   ├── file_walker.py                 │  Web Frontend (frontend/)
        │   └── repo_detector.py               │  http://localhost:3000
        │                                      │
        ├── guardian/ust/                      │
        │   └── parsers.py (tree-sitter)       │
        │                                      │
        ├── guardian/scanner/                  │
        ├── guardian/engines/                  │
        │   ├── security.py                    │
        │   ├── quantum.py                     │
        │   └── business_intent.py             │
        │                                      │
        ├── guardian/dependencies/             │
        ├── guardian/infrastructure/           │
        │                                      │
        ├── guardian/evidence/store.py         │
        │                                      │
        ├── guardian/reasoning/                │
        │   ├── context.py                     │
        │   ├── knowledge.py (RAG)             │
        │   ├── gateway.py (Nemotron AI)       │
        │   └── validation.py (guardrails)     │
        │                                      │
        ├── guardian/core/unified_risk.py      │
        │                                      │
        └── guardian/reporting/   ─────────────┘
            guardian/dashboard/
```

---

## Root Directory

```
AI_feature/
├── main.py                    ← CLI entry point
├── dashboard_preview.py       ← Generates standalone HTML dashboard preview
├── dashboard_preview.html     ← Pre-rendered static dashboard (open in browser)
├── docker-compose.yml         ← Docker Compose for running all services together
├── pyproject.toml             ← Python package metadata, dependencies, build config
├── requirements.txt           ← Core Python dependencies
├── requirements_ai.txt        ← AI/ML/LLM additional dependencies
├── structure.md               ← This file — project directory reference
├── Architecture.md            ← Engine architecture blueprint
├── END_TO_END_SYSTEM_DESIGN.md← Full system design documentation
├── config/                    ← YAML config files
├── data/                      ← Static knowledge base and rules
├── docs/                      ← Detailed phase documentation
├── phases/                    ← Phase migration docs
├── reports/                   ← Generated scan output reports (auto-created)
├── .acg_workspaces/           ← Runtime: cloned repos, ZIP extracts, history.json
├── guardian/                  ← Core scan engine (Python package)
├── backend/                   ← FastAPI REST API server
├── frontend/                  ← Next.js 14 web dashboard
└── tests/                     ← Pytest test suite
```

| File | Purpose |
| :--- | :--- |
| `main.py` | Backward-compatible CLI entry. `python main.py scan <path>` delegates to `guardian.cli.main()`. |
| `dashboard_preview.py` | Self-contained script that writes a single-file HTML security dashboard preview to `dashboard_preview.html`. |
| `docker-compose.yml` | Brings up the FastAPI backend, Redis cache, and PostgreSQL in containers together. |
| `pyproject.toml` | Declares the `guardian` package, its extras (`[ust]`, `[ai]`), and the `guardian` CLI entrypoint. |
| `requirements.txt` | FastAPI, uvicorn, tree-sitter, pytest, and all core dependencies. |
| `requirements_ai.txt` | NVIDIA Nemotron SDK, LangChain, sentence-transformers, Qdrant client, CodeBERT. |

---

## Core Engine — `guardian/`

The `guardian` Python package is the heart of the project. All security scanning, AI reasoning, and report generation happens here.

---

### `guardian/config.py`
Global `GuardianConfig` dataclass holding all feature flags and tuneable settings:
- `enable_sandbox` — run scan inside isolated workspace/container
- `enable_ai` — activate NVIDIA Nemotron contextual reasoning
- `enable_knowledge` — build code knowledge graph and vector index
- `alignment_score` — minimum business requirement alignment threshold

---

### `guardian/cli.py`
**Feature: CLI Terminal Interface**

Command-line argument parser and dispatcher used by `main.py` and `python -m guardian`:

| Sub-command | What it does |
| :--- | :--- |
| `scan <path>` | Full pipeline scan — discovery, UST parsing, engines, AI reasoning, reports |
| `detect <path>` | Quick repository profile only (language, frameworks, endpoints) |
| `intent <path>` | Business domain classification only |
| `parsers` | Show Tree-sitter grammar availability per language |

---

### `guardian/core/` — Pipeline Orchestration & Risk Scoring

**Feature: Full Scan Pipeline**

| File | Purpose |
| :--- | :--- |
| `pipeline.py` | `ScanPipeline` class — the main driver that runs every stage in order: discovery → UST parsing → engines → evidence → AI reasoning → risk scoring → reporting. Also contains `_scan_in_sandbox()` for isolated Docker workspace scans. |
| `unified_risk.py` | Combines security, quantum readiness, and business alignment sub-scores into the final overall risk score (0–100) and merge decision (`Warn`, `Block`, `Approved`). |
| `registry.py` | Plugin and rule registry — loads built-in detection rule plugins that the pipeline consumes. |

---

### `guardian/discovery/` — Repository Profiling & Entry Point Detection

**Feature: Repository Discovery & Profiling**

| File | Purpose |
| :--- | :--- |
| `file_walker.py` | High-performance recursive directory crawler. Filters out `.git`, `node_modules`, `__pycache__`, binary files, and lock files. Returns only analysable source files. |
| `repo_detector.py` | Inspects manifests (`package.json`, `pyproject.toml`, `pom.xml`, etc.) to detect: primary language, frameworks (FastAPI, Next.js, Spring, React), build tools, architecture patterns (monorepo, cloud-native), API endpoints, and security markers (JWT, OAuth2, Vault). |
| `github_service.py` | Fetches repository metadata and file trees from the GitHub REST API, used when scanning remote repos or PRs. |

---

### `guardian/ust/` — Unified Syntax Tree (AST Parsing)

**Feature: Multi-language Code Parsing (Tree-sitter)**

All supported languages are parsed into a common `USTNode` structure so the detection engines are language-agnostic.

| File | Purpose |
| :--- | :--- |
| `parsers.py` | Tree-sitter parser manager. Loads grammars for Python, Java, JavaScript, TypeScript/TSX, and Rust. Falls back gracefully when a grammar is missing. |
| `builder.py` | Constructs the full `USTNode` tree from a Tree-sitter parse tree, attaching source positions, types, and children. |
| `models.py` | `USTNode` dataclass — the common intermediate representation every engine reads. |
| `tagging.py` | Tags UST nodes with semantic roles: entry points, authorization gates, injection sinks, crypto primitives, public API routes. |
| `dataflow.py` | Tracks taint flow between nodes — traces user-controlled data from source to sink across function boundaries. |
| `fallback.py` | Regex/AST-based fallback parser for languages without a Tree-sitter grammar. |
| `languages/base.py` | Base normaliser class all language normalisers inherit from. |
| `languages/python_lang.py` | Python-specific UST normalisation rules. |
| `languages/java_lang.py` | Java-specific UST normalisation rules. |
| `languages/javascript_lang.py` | JavaScript/TypeScript UST normalisation rules. |
| `languages/rust_lang.py` | Rust UST normalisation rules. |

---

### `guardian/scanner/` — Per-language Scan Rules

**Feature: Language-specific Vulnerability Detection**

| File / Directory | Purpose |
| :--- | :--- |
| `_engine.py` | Core rule-matching engine driving all language scanners. Applies rule patterns to UST nodes. |
| `base.py` | Abstract `BaseScanner` class all language scanners extend. |
| `python/` | Python-specific vulnerability detection rules (eval injection, pickle deserialization, path traversal). |
| `java/` | Java-specific rules (XXE, deserialization, JNDI injection). |
| `javascript/` | JS/TS rules (prototype pollution, XSS sinks, dangerouslySetInnerHTML). |
| `rust/` | Rust-specific unsafe block and FFI boundary analysis. |
| `common/` | Language-agnostic rules (hardcoded secrets, weak crypto, SSRF patterns). |

---

### `guardian/engines/` — Deterministic Detection Engines

**Feature: Security & Compliance Scanning**

These engines run on UST nodes and produce structured `Evidence` items — no AI involved, fully deterministic.

| File | Purpose |
| :--- | :--- |
| `base.py` | `BaseEngine` abstract class. All engines implement `run(ust_nodes) → List[Evidence]`. |
| `security.py` | **Security Engine** — 30+ CWE-mapped detection rules: SQL Injection (CWE-89), XSS (CWE-79), Hardcoded Secrets (CWE-798), Insecure TLS/Certificate Validation (CWE-295), Command Injection (CWE-78), Path Traversal (CWE-22), Insecure Deserialization (CWE-502), CORS misconfiguration, and more. |
| `quantum.py` | **Post-Quantum Cryptography Engine** — Detects legacy cryptographic algorithms (RSA, ECC, DSA, AES-128, SHA-1, MD5) and scores quantum readiness. Flags code that will break under Shor's / Grover's algorithms. |
| `business_intent.py` | **Business Alignment Engine** — Compares code behaviour against supplied business requirement documents (txt/md/pdf/docx/xlsx/csv/yaml/json). Computes alignment score and flags deviations. |

---

### `guardian/quantum/` — Post-Quantum Cryptography Classification

**Feature: Quantum Readiness Assessment**

Provides deeper classification beyond the quantum engine.

| File | Purpose |
| :--- | :--- |
| `detector.py` | Pattern-based crypto algorithm detector scanning for use of deprecated ciphers in code. |
| `classification.py` | Maps detected algorithms to NIST PQC migration categories (Harvest Now Decrypt Later, near-term risk, safe). |
| `mapper.py` | Maps CWE findings to PQC threat level (L0–L3) and recommended replacement algorithms (CRYSTALS-Kyber, CRYSTALS-Dilithium, SPHINCS+). |
| `scorer.py` | Computes the quantum readiness score (0–100) factoring in asset criticality and cipher usage. |
| `inventory.py` | Builds a full cryptographic asset inventory for the repository. |
| `plugin.py` | Plugin adapter integrating the quantum module into the main scan pipeline. |
| `models.py` | `CryptoFinding`, `QuantumRisk` dataclasses. |

---

### `guardian/dependencies/` — Dependency Vulnerability Scanning

**Feature: Dependency & Supply Chain Analysis**

| File | Purpose |
| :--- | :--- |
| `parsers.py` | Parses `requirements.txt`, `package.json`, `pom.xml`, `Cargo.toml`, `go.mod` to extract declared dependencies and versions. |
| `analyzer.py` | Checks extracted dependencies against known vulnerability databases and flags outdated or CVE-affected packages. |

---

### `guardian/infrastructure/` — Infrastructure-as-Code Analysis

**Feature: IaC Security Scanning**

| File | Purpose |
| :--- | :--- |
| `analyzer.py` | Scans Dockerfile, `docker-compose.yml`, Kubernetes YAML, Terraform, and GitHub Actions workflows for misconfigurations (privileged containers, exposed ports, missing resource limits, insecure environment variables). |
| `rules.py` | IaC-specific rule definitions (CIS Benchmarks, Docker security best practices). |

---

### `guardian/evidence/` — Evidence Store

**Feature: Evidence-grounded Findings (Anti-hallucination)**

Every finding is backed by a stable evidence ID (e.g. `E12`). The AI layer is only allowed to reference evidence IDs that actually exist in the store.

| File | Purpose |
| :--- | :--- |
| `store.py` | `EvidenceStore` — append-only in-memory store collecting evidence items from all engines during a scan. Assigns stable IDs. |
| `models.py` | `Evidence`, `FindingItem` dataclasses with fields: file, line, CWE, severity, confidence, code snippet. |
| `correlation.py` | Groups and de-duplicates related evidence items across engines (e.g. same hardcoded secret found by two rules). |

---

### `guardian/reasoning/` — NVIDIA Nemotron AI Reasoning & RAG

**Feature: AI-powered Contextual Reasoning**

| File | Purpose |
| :--- | :--- |
| `gateway.py` | Communicates with the NVIDIA Nemotron LLM API. Sends structured prompts, receives JSON-schema-validated responses, enforces token budget. |
| `context.py` | Selects the most relevant evidence items for the AI's context window, avoiding token overflow. |
| `knowledge.py` | RAG retrieval layer — queries the OWASP/NIST/PQC knowledge vector index and injects relevant guidance into prompts. |
| `validation.py` | **Anti-hallucination guardrails** — validates every AI claim against real evidence IDs. Rejects (not downgrades) any AI statement citing non-existent or contradicting evidence. |
| `schemas.py` | Pydantic schemas for structured AI response validation (`ReasoningResponse`, `AIFinding`, `RemediationSuggestion`). |
| `tools.py` | Function-calling tool definitions for Nemotron tool use mode (query evidence, lookup CWE, fetch knowledge). |
| `grounding/` | Additional grounding utilities for aligning AI outputs to code facts. |

---

### `guardian/llm/` — LLM Abstraction Layer

**Feature: Multi-model LLM Support**

| File | Purpose |
| :--- | :--- |
| `nemotron.py` | NVIDIA Nemotron-specific client (streaming, function-calling, retries). |
| `base.py` | Abstract `BaseLLM` interface — swap any model by implementing this. |
| `factory.py` | LLM factory — instantiates the correct LLM client from config. |
| `config.py` | LLM configuration (model name, temperature, max tokens, API base URL). |
| `prompt_builder.py` | Constructs structured prompts from evidence, RAG context, and persona templates. |
| `personas.py` | AI persona definitions (Security Analyst, PR Reviewer, Remediation Expert). |
| `guardrails.py` | Output guardrail checks applied to raw LLM responses before returning to pipeline. |
| `parser.py` | Parses raw LLM text/JSON outputs into structured Python objects. |
| `verifier.py` | Secondary verification pass checking AI suggestions against static analysis truth. |
| `prompts/` | Jinja2 prompt template files for each reasoning task. |
| `patch_prompts/` | Prompt templates specifically for code patch and autofix generation. |

---

### `guardian/ai/` — RAG Pipeline & Vector Store (Legacy / Extended AI)

**Feature: RAG Knowledge System & Semantic Code Search**

| File | Purpose |
| :--- | :--- |
| `rag_pipeline.py` | Full Retrieval-Augmented Generation pipeline: embed query → retrieve chunks → augment prompt → generate answer. |
| `vector_store.py` | Vector database client managing embedding storage and similarity search (Qdrant or in-memory). |
| `embeddings.py` | Embedding model wrapper (sentence-transformers or OpenAI). |
| `local_embedder.py` | Local CPU-based embedding using `all-MiniLM-L6-v2` for offline environments. |
| `codebert.py` | CodeBERT integration for code-specific semantic embeddings. |
| `document_loader.py` | Loads and chunks documents from txt, md, pdf, docx, xlsx, csv, yaml, json for RAG ingestion. |
| `code_indexer.py` | Indexes repository source files into the vector store for semantic code search. |
| `retriever.py` | Semantic retriever — given a query, returns the top-K most relevant code chunks or knowledge fragments. |
| `chatbot.py` | Conversational AI security assistant managing multi-turn dialogue over the scan context. |
| `conversation_memory.py` | Stores and retrieves conversation history for multi-turn chat sessions. |
| `prompt_builder.py` | Constructs prompts for the RAG pipeline with code context injection. |
| `scan_context.py` | Packages scan report findings into a compressed context block for the chatbot. |
| `validator.py` | Validates RAG-generated responses for safety and relevance. |
| `models.py` | Dataclasses for RAG chunks, retrieved results, and chat messages. |
| `config.py` | AI subsystem configuration (vector DB URL, embedding model, chunk size). |

---

### `guardian/knowledge/` — Structured Knowledge Graph & Retrieval

**Feature: Architecture Knowledge Graph + Mind Map Data**

| Directory / File | Purpose |
| :--- | :--- |
| `graph/builder.py` | Builds an in-memory code graph: files → modules → classes → functions → dependencies. Data powering the **Mind Map** feature. |
| `graph/manager.py` | Manages graph lifecycle (build, query, serialize). |
| `embeddings/` | Stores pre-computed knowledge embeddings for fast lookup. |
| `qdrant/` | Qdrant vector database client configuration and collection management. |
| `retrieval/engine.py` | Basic vector retrieval engine. |
| `retrieval/hybrid_engine.py` | Hybrid BM25 + vector retrieval combining keyword and semantic search. |
| `retrieval/budget_manager.py` | Manages the token budget across multiple RAG retrievals to avoid prompt overflow. |
| `services/knowledge_service.py` | High-level service for indexing and retrieving OWASP/NIST security knowledge. |
| `services/requirement_service.py` | Parses and indexes business requirement documents for the alignment engine. |
| `config.py` | Knowledge module configuration (index paths, chunk sizes, top-K). |

---

### `guardian/orchestrator/` — Multi-agent LangGraph Orchestration

**Feature: Multi-Agent Workflow Engine**

Coordinates specialized AI agents using a LangGraph state-machine.

| File | Purpose |
| :--- | :--- |
| `langgraph_flow.py` | Defines the LangGraph DAG of agents: security → patch → validation → risk → report. |
| `workflow.py` | High-level workflow entry point — triggers the LangGraph flow. |
| `planner.py` | Task planner — breaks a scan into subtasks and assigns them to agents. |
| `state.py` | `OrchestratorState` dataclass shared across all agents in a run. |
| `events.py` | Event bus — agents emit and subscribe to scan events. |
| `checkpointer.py` | Saves intermediate state for resume-on-failure. |
| `registry.py` | Registers available agent types with the orchestrator. |
| `tools.py` | Orchestrator-level tools (start scan, get findings, generate report). |

---

### `guardian/agents/` — Specialized AI Agents

**Feature: Multi-agent Security Assessment**

Each sub-directory is a specialised agent invoked by the orchestrator.

| Agent | Directory | What it does |
| :--- | :--- | :--- |
| **Security Agent** | `agents/security/` | Analyses UST evidence and produces security findings with CWE mappings. |
| **Patch Agent** | `agents/patch/` | Generates code patches and unified diffs for fixing detected vulnerabilities. |
| **Validation Agent** | `agents/validation/` | Validates that suggested patches don't break syntax or introduce new issues. |
| **Risk Agent** | `agents/risk/` | Aggregates all findings into a unified risk score and merge decision. |
| **Business Agent** | `agents/business/` | Assesses business requirement alignment and flags violations. |
| **Dependency Agent** | `agents/dependency/` | Audits third-party dependency vulnerabilities and licensing issues. |
| **Policy Agent** | `agents/policy/` | Enforces custom organisational security policies. |
| **Architecture Agent** | `agents/architecture/` | Analyses code structure, design patterns, and architectural anti-patterns. |
| **Threat Simulation Agent** | `agents/threat_simulation/` | Simulates attacker-perspective threat scenarios based on the code structure. |
| **Chat Agent** | `agents/chat/` | Powers the interactive Security Copilot chat session. |
| **Repository Agent** | `agents/repository/` | Manages repository cloning, loading, and workspace preparation. |
| **Base** | `agents/base/` | Abstract base class and shared utilities all agents inherit from. |
| **Shared** | `agents/shared/` | Shared agent utilities, memory, and context managers. |

---

### `guardian/copilot/` — Security Copilot Chat Assistant

**Feature: PR Review / AI Security Assistant**

| File | Purpose |
| :--- | :--- |
| `assistant.py` | `SecurityCopilot` class — conversational interface for the developer. Answers questions about findings, explains CWEs, suggests fixes, and reviews code diffs interactively. |

---

### `guardian/threat_intel/` — External Threat Intelligence

**Feature: Live Threat Intelligence Feed**

| File | Purpose |
| :--- | :--- |
| `collector.py` | Fetches threat intelligence from external feeds (CVE/NVD, CISA KEV, EPSS scores). |
| `normalizer.py` | Normalises raw threat intel into a common schema for correlation. |
| `retriever.py` | Retrieves relevant threat intel for a given finding/package. |
| `cache.py` | Caches threat intel locally to avoid repeated API calls. |
| `models.py` | `ThreatIntelItem`, `CVERecord` dataclasses. |

---

### `guardian/policy/` — Policy Extraction & Enforcement

**Feature: Custom Security Policy Engine**

| File | Purpose |
| :--- | :--- |
| `extractor.py` | Extracts structured policy rules from natural-language policy documents (PDF/DOCX/MD). |
| `models.py` | `PolicyRule`, `PolicyViolation` dataclasses. |

---

### `guardian/policies/` — Policy Management

| File | Purpose |
| :--- | :--- |
| `loader.py` | Loads policy files from disk (YAML/JSON). |
| `manager.py` | Policy manager — applies loaded rules against scan findings. |
| `schema.py` | YAML/JSON schema for defining custom policy rules. |

---

### `guardian/intent/` — Business Domain Classifier

**Feature: Business Domain Detection**

| File | Purpose |
| :--- | :--- |
| `classifier.py` | Classifies the repository into a business domain (Cybersecurity, FinTech, Healthcare, E-commerce, etc.) based on code patterns and keywords. |
| `domains.py` | Domain taxonomy definitions and keyword maps. |

---

### `guardian/reporting/` — Report Generation

**Feature: Reports (PDF, HTML, SARIF, JSON, CSV)**

| File | Purpose |
| :--- | :--- |
| `json_reporter.py` | Writes the full scan report as structured JSON (`guardian_report.json`). |
| `html_reporter.py` | Generates a rich self-contained HTML report with charts and finding tables. |
| `sarif.py` | Produces SARIF 2.1.0 output for GitHub Advanced Security, VS Code, and Azure DevOps integration. |
| `pdf_reporter.py` | Generates a formatted executive PDF security assessment report. |
| `csv_reporter.py` | Exports findings as a CSV spreadsheet for tracking in Excel or Jira. |

---

### `guardian/dashboard/` — Dashboard Data Layer

**Feature: Dashboard / Overview tab**

| File / Dir | Purpose |
| :--- | :--- |
| `app.py` | Dashboard application entry point — aggregates scan metrics into the JSON payload consumed by the web dashboard. |
| `charts/` | Chart data generators (severity distribution, score trends, finding heatmaps). |
| `components/` | Reusable dashboard data components. |
| `views/` | View renderers for different dashboard sections (security overview, quantum, business). |
| `models/` | Dashboard-specific data models. |
| `utils/` | Shared formatting and calculation helpers. |

---

### `guardian/sandbox/` — Isolated Execution Sandbox

**Feature: Sandbox Isolation (Docker & Process Fallback)**

| File | Purpose |
| :--- | :--- |
| `config.py` | `SandboxConfig` — resource limits (CPU=2.0, RAM=4 GB), network isolation, environment variable redaction patterns. |
| `docker_runner.py` | `DockerSandboxRunner` — runs commands inside a Docker container (`--network=none`, read-only volume mount). Falls back to `_run_in_process_sandbox()` (copies repo to `%TEMP%\acg_sandbox_<id>`) when Docker is unavailable. `prepare_isolated_workspace()` creates `%TEMP%\acg_workspace_<id>` for the scan. |

---

### `guardian/workspace/` — Workspace & Repository Manager

**Feature: IDE Workspace / Repository Input**

| File | Purpose |
| :--- | :--- |
| `manager.py` | `RepositoryManager` — registers local folders, extracts ZIP uploads, and clones GitHub repos into `.acg_workspaces/`. Maintains a `history.json` tracking all repositories ever registered. |

---

### `guardian/db/` — Database Layer

**Feature: Persistent Scan Storage (PostgreSQL)**

| File | Purpose |
| :--- | :--- |
| `session.py` | Async SQLAlchemy session factory and `init_db()` startup function. Falls back to in-memory store when PostgreSQL is unavailable. |
| `models.py` | ORM models: `Scan`, `Finding`, `Report`, `Repository` tables. |

---

### `guardian/cache/` — Caching Layer

**Feature: Performance Caching (Redis)**

| File | Purpose |
| :--- | :--- |
| `redis_manager.py` | Redis cache client for caching UST parse results, embedding vectors, and scan summaries. Auto-disables with a warning when Redis is not running. |

---

## REST API Backend — `backend/`

FastAPI application exposing all guardian engine features as async HTTP endpoints.

```
backend/
├── requirements.txt               ← Backend-specific Python dependencies
└── app/
    ├── main.py                    ← FastAPI app init, CORS middleware, lifespan hooks, router registration
    ├── core/
    │   └── config.py              ← Settings (API version, project name, CORS origins from .env)
    └── api/
        └── v1/
            ├── scans.py           ← POST /api/v1/scans  — Trigger a new background scan
            ├── findings.py        ← GET  /api/v1/findings — Query/filter vulnerability findings
            ├── files.py           ← GET  /api/v1/files — Serve file tree and raw source content (IDE Workspace)
            ├── chat.py            ← POST /api/v1/chat — AI Security Copilot streaming chat (PR Review)
            └── reports.py         ← GET  /api/v1/reports — Download scan reports (PDF/SARIF/HTML/JSON)
```

| API Route | Feature | Description |
| :--- | :--- | :--- |
| `POST /api/v1/scans` | All features | Starts a new repository scan job (local path, GitHub URL, or ZIP). Returns `scan_id`. |
| `GET /api/v1/scans/{scan_id}` | Overview / Dashboard | Retrieves full scan report JSON. |
| `GET /api/v1/findings` | Security | Lists findings with filters (severity, CWE, file). |
| `GET /api/v1/findings/{finding_id}` | Security / PR Review | Gets full detail for a single finding with remediation advice. |
| `GET /api/v1/files/tree` | IDE Workspace | Returns the file tree of the scanned repository. |
| `GET /api/v1/files/content` | IDE Workspace | Returns raw source content of a specific file. |
| `POST /api/v1/chat` | PR Review / Copilot | Streams AI chat responses from the Security Copilot. |
| `GET /api/v1/reports/download` | Reports | Downloads the report in the requested format (json/sarif/html/pdf/csv). |

---

## Web Frontend — `frontend/`

Next.js 14 single-page application providing the full Security Operations Centre (SOC) dashboard.

```
frontend/
├── package.json                   ← npm dependencies (Next.js, Monaco Editor, React Flow, Tailwind, Lucide)
└── src/
    ├── app/
    │   ├── layout.tsx             ← Root HTML layout (font imports, metadata)
    │   ├── globals.css            ← Global CSS design tokens (dark theme, glassmorphism, animations)
    │   └── page.tsx               ← Main SPA page: tab router, scan trigger, report loading, state management
    └── components/
        ├── cyberlock/             ← Feature: Dashboard tab
        ├── workspace/             ← Feature: IDE Workspace tab
        ├── mindmap/               ← Feature: Mind Map tab
        ├── scan/                  ← Feature: Security tab
        ├── chat/                  ← Feature: PR Review / AI Copilot
        └── editor/                ← Feature: Code diff & vulnerability viewer
```

### Tab Navigation (`page.tsx`)

| Tab ID | Label | Feature |
| :--- | :--- | :--- |
| `cyber_dashboard` | Dashboard | Cyber risk gauge, top CWEs, severity distribution, live risk summary |
| `workspace` | IDE Workspace | In-browser code editor with vulnerability annotations |
| `mindmap` | Mind Map | Interactive architecture and vulnerability relationship graph |
| `overview` | Overview | Triage funnel — all findings with severity filters and search |
| `security_compliance` | Security | Detailed security & compliance findings with CWE mapping |
| `pr_review` | PR Review | AI Security Copilot chat and automated code diff review |
| `reports` | Reports | Download centre for JSON, SARIF, HTML, PDF, CSV reports |

---

### Feature: Dashboard (`components/cyberlock/`)

| File | Purpose |
| :--- | :--- |
| `CyberDashboard.tsx` | Main dashboard component. Displays: animated risk gauge, critical/high/medium finding counts, NVIDIA Nemotron AI reasoning summary, security score trend chart, active CWE badges, quantum readiness indicator, and quick-action buttons. |

---

### Feature: IDE Workspace (`components/workspace/`)

| File | Purpose |
| :--- | :--- |
| `IDEWorkspace.tsx` | Full IDE layout container. Manages repository input, file tree sidebar, code editor panel, and vulnerability insight panel. |
| `RepoInput.tsx` | Repo selection widget — accepts local path, GitHub URL, or ZIP file upload. |
| `FileTreeSidebar.tsx` | Collapsible file tree explorer. Color-codes files by vulnerability status (red=critical, orange=high, green=clean). |
| `AuraCodeEditor.tsx` | Monaco-based code editor with inline vulnerability gutter annotations and hover tooltips. |
| `VSCodeEditor.tsx` | Simplified VS Code-style editor view for read-only file browsing. |
| `CodeViewer.tsx` | Lightweight syntax-highlighted code viewer for small snippets. |
| `VulnerabilityPanel.tsx` | Right-side panel listing all findings for the currently open file, with CWE links and severity badges. |
| `AuraVulnerabilityInsight.tsx` | AI-powered insight card for the selected finding — shows explanation, evidence IDs, and remediation steps fetched from the AI. |
| `AuraHeader.tsx` | IDE top toolbar — displays repo name, branch, scan status, and action buttons. |

---

### Feature: Mind Map (`components/mindmap/`)

| File | Purpose |
| :--- | :--- |
| `CodeMindMap.tsx` | React Flow canvas rendering the interactive architecture and vulnerability graph. Supports pan/zoom, node selection, and animated edges. |
| `MindMapDetailPanel.tsx` | Right-side drawer showing details for the selected node (file info, findings, function list). |
| `utils.ts` | `buildMindMapFromScan()` — transforms the raw scan report JSON into React Flow nodes and edges. |
| `layout.ts` | Dagre graph layout algorithm — auto-positions nodes for clean hierarchical or force-directed layouts. |
| `defaultData.ts` | Fallback demo graph data shown before a scan report is loaded. |
| `types.ts` | TypeScript types for `MindMapNode`, `MindMapEdge`. |
| `nodes/FileNode.tsx` | Custom React Flow node for source files (shows language icon, finding count badge). |
| `nodes/FolderNode.tsx` | Custom node for directories. |
| `nodes/FindingNode.tsx` | Custom node for vulnerability findings (colored by severity). |
| `nodes/ClassNode.tsx` | Custom node for class definitions. |
| `nodes/FunctionNode.tsx` | Custom node for function definitions. |
| `nodes/ModuleNode.tsx` | Custom node for module-level entities. |

---

### Feature: Security & Overview (`components/scan/`)

| File | Purpose |
| :--- | :--- |
| `TriageFunnel.tsx` | Findings table with severity filter pills (All / Critical / High / Medium / Low), keyword search, and sortable columns. Clicking a row opens `FindingDrawer`. |
| `FindingDrawer.tsx` | Slide-over detail panel for a selected finding: CWE description, affected file and line, evidence snippet, confidence level, remediation recommendation, and AI analysis button. |

---

### Feature: PR Review / AI Copilot (`components/chat/`)

| File | Purpose |
| :--- | :--- |
| `ChatDrawer.tsx` | Full-screen slide-over chat interface. Streams responses from `POST /api/v1/chat`. Supports asking questions about any finding, requesting autofix patches, and getting PR review summaries. |

---

### Feature: Code Diff Viewer (`components/editor/`)

| File | Purpose |
| :--- | :--- |
| `VulnerabilityViewer.tsx` | Side-by-side before/after code diff viewer for displaying automated patch suggestions from the autofix engine. |

---

## Configuration & Static Data

### `config/default.yaml`
Master YAML configuration file. Key settings:

```yaml
enable_sandbox: false        # set true to scan in isolated Docker container
enable_ai: false             # set true to enable NVIDIA Nemotron AI reasoning (needs NVIDIA_API_KEY)
enable_knowledge: false      # set true to build code knowledge graph and vector index
alignment_score: 75          # minimum required business alignment score (0–100)
fail_on_severity: null       # block merge if any finding at this severity or above (High / Critical)
```

### `data/knowledge/security_knowledge.json`
Curated OWASP Top 10, NIST guidelines, and PQC migration notes bundled as a static knowledge base for offline RAG operation.

### `data/rules/Security_Rules.json`
Static detection rule definitions (pattern, CWE ID, severity, description) loaded by the rule registry.

---

## Tests

The `tests/` directory contains **26 Pytest test files** covering every major subsystem.

| Test File | What it tests |
| :--- | :--- |
| `test_sandbox.py` | Docker container isolation, process fallback, env redaction, workspace creation |
| `test_pipeline_integration.py` | Full end-to-end scan pipeline with report validation |
| `test_engines.py` | Security engine CWE detection rule accuracy |
| `test_new_engines.py` | Extended engine tests (new rules and edge cases) |
| `test_ust.py` | Tree-sitter UST parsing for all supported languages |
| `test_reasoning.py` | AI reasoning gateway, validation, and anti-hallucination guardrails |
| `test_llm_layer.py` | LLM abstraction layer, prompt builder, and output parser |
| `test_agents.py` | Multi-agent orchestration and individual agent behaviour |
| `test_orchestrator.py` | LangGraph workflow and state machine transitions |
| `test_business_intent.py` | Business requirement alignment engine |
| `test_knowledge.py` | Knowledge graph builder and vector retrieval |
| `test_evidence_store.py` | Evidence store append, deduplication, and ID stability |
| `test_ai_grounding.py` | AI output grounding and evidence citation validation |
| `test_hybrid_rag_upgrade.py` | Hybrid BM25 + vector RAG retrieval accuracy |
| `test_interactive_rag.py` | Multi-turn RAG chat pipeline |
| `test_conversational_memory.py` | Chat conversation history storage and retrieval |
| `test_scaffold.py` | Project scaffolding and package structure integrity |
| `test_security_rule_engine.py` | Rule engine pattern matching correctness |
| `test_redis_cache.py` | Redis cache connection and fallback behaviour |
| `test_github_service.py` | GitHub API metadata fetching |
| `test_repo_detector_v3.py` | Repository language/framework detection |
| `test_phase5.py` — `test_phase8.py` | Integration tests for Phases 5–8 feature additions |

---

## Runtime Storage & Workspaces

### `.acg_workspaces/`  (Persistent — in project root)
Created automatically by `RepositoryManager`. Stores repositories that were uploaded or cloned via the web dashboard.

```
.acg_workspaces/
├── history.json               ← Registry of all known repositories (scan history)
├── repo-git-<hash>/           ← Cloned GitHub repository (git clone --depth 1)
└── repo-zip-<hash>/           ← Extracted ZIP archive upload
```

### `%TEMP%\acg_scan_workspace_<id>\`  (Ephemeral — OS temp dir)
Created at scan start when `--sandbox` is used. The repository is copied here for isolation. **Automatically deleted** after the scan completes.

### `%TEMP%\acg_sandbox_<id>\`  (Ephemeral — OS temp dir)
Created by the process-fallback sandbox when Docker is unavailable. **Automatically deleted** after each command.

### `reports/`  (Persistent — in project root)
Default output directory for scan reports when using the `--out-dir` flag.

---

## Quick Command Reference

```bash
# ─── CLI Scan ────────────────────────────────────────────────────────────────
# Scan current directory (basic)
python main.py scan .

# Scan any folder and output JSON + HTML reports
python main.py scan /path/to/repo --format json html --out-dir reports/

# Scan inside isolated Docker sandbox
python main.py scan . --sandbox

# Scan with NVIDIA Nemotron AI reasoning enabled
python main.py scan . --ai

# Scan with architecture knowledge graph
python main.py scan . --knowledge

# Scan with business requirement documents
python main.py scan . --requirements docs/requirements.md

# Quick repository profile only (no full scan)
python main.py detect .

# Show Tree-sitter grammar coverage
python main.py parsers


# ─── Backend API Server (Port 8000) ─────────────────────────────────────────
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
# Docs: http://127.0.0.1:8000/api/v1/docs


# ─── Next.js Web Dashboard (Port 3000) ──────────────────────────────────────
cd frontend
cmd /c npm run dev
# UI: http://localhost:3000


# ─── Static HTML Dashboard Preview ──────────────────────────────────────────
python dashboard_preview.py
# Then open dashboard_preview.html in a browser


# ─── Run All Tests ───────────────────────────────────────────────────────────
pytest tests/ -v
```
