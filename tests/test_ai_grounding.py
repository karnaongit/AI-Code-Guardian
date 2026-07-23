"""Anti-hallucination layer tests. No live NVIDIA endpoint required: the point of
this suite is that hallucination control is MECHANICAL, not model-dependent."""
import json
from pathlib import Path

import pytest

from guardian.ai.scan_context import exact_match_context, findings_to_documents
from guardian.ai.validator import ResponseValidator


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    f = tmp_path / "src" / "pay.py"
    f.parent.mkdir()
    f.write_text("\n".join(f"line{i}" for i in range(1, 51)))  # 50 lines
    return tmp_path


@pytest.fixture()
def report() -> dict:
    return {"scan": {"target": "x", "files_scanned": 1, "total_findings": 1,
                     "by_severity": {"High": 1},
                     "findings": [{
                         "finding_id": "abc123def4567890", "rule_id": "RS-SQLI-001",
                         "category": "SQL Injection", "severity": "High",
                         "file": "src/pay.py", "line": 12,
                         "snippet": "format!(\"SELECT ...\")",
                         "recommendation": "Use bind parameters.",
                         "cwe": "CWE-89", "owasp": "A03", "confidence": 0.6}]},
            "risk": {"security_score": 60.0, "overall_risk_score": 70.0,
                     "merge_decision": "Warn"}}


# ---- validator -------------------------------------------------------
def test_validator_catches_fabricated_file(repo, report):
    v = ResponseValidator(repo_root=repo, scan_report=report)
    r = v.validate("The bug is in `src/imaginary_module.py:44` and violates RS-SQLI-001.")
    assert not r.ok
    assert any("imaginary_module" in x for x in r.violations)


def test_validator_catches_impossible_line(repo, report):
    v = ResponseValidator(repo_root=repo, scan_report=report)
    r = v.validate("See src/pay.py:400 for the vulnerable query.")
    assert not r.ok and any("out of range" in x for x in r.violations)


def test_validator_catches_invented_rule(repo, report):
    v = ResponseValidator(repo_root=repo, scan_report=report)
    r = v.validate("This was flagged by rule ACG-MAGIC-999.")
    assert not r.ok and any("ACG-MAGIC-999" in x for x in r.violations)


def test_validator_accepts_true_claims(repo, report):
    v = ResponseValidator(repo_root=repo, scan_report=report)
    r = v.validate("Finding RS-SQLI-001 is at src/pay.py:12; fix with bind parameters.")
    assert r.ok, r.violations
    assert r.checked_refs >= 2


# ---- exact-match grounding ------------------------------------------
def test_exact_match_by_rule_id(report):
    ctx = exact_match_context("Why did RS-SQLI-001 fire?", report)
    assert "RS-SQLI-001" in ctx and "src/pay.py:12" in ctx


def test_exact_match_by_filename(report):
    ctx = exact_match_context("what's wrong in pay.py?", report)
    assert "SQL Injection" in ctx


def test_exact_match_returns_empty_not_guess(report):
    assert exact_match_context("tell me about kubernetes", report) == ""


def test_findings_become_documents(report):
    docs = findings_to_documents(report)
    assert len(docs) == 2  # 1 finding + 1 summary
    assert any("RS-SQLI-001" in d.content for d in docs)
    assert any("merge_decision" in d.content for d in docs)


# ---- deterministic refusal (fake pipeline, no hosted LLM) ------------
def test_pipeline_refuses_without_evidence(repo, report, monkeypatch):
    from guardian.ai.config import AssistantConfig
    from guardian.ai.rag_pipeline import RAGPipeline
    from guardian.ai.models import RAGResult, RAGQuery

    class FakeRetriever:
        def retrieve(self, q):
            return RAGResult(query=q, chunks=[], merged_context="", citations=[])

    class ExplodingNemotron:  # LLM must NOT be called on empty evidence
        def chat(self, *a, **k):
            raise AssertionError("LLM called despite zero evidence")

    class FakeMemory:
        class _Ctx: repo_summary = ""
        context = _Ctx()
        def get_history(self): return []
        def add_user_message(self, m): pass
        def add_assistant_message(self, m): pass

    pipe = RAGPipeline(AssistantConfig(), ExplodingNemotron(), FakeRetriever(),
                       prompt_builder=None, memory=FakeMemory())
    resp = pipe.ask("what is the meaning of life?")
    assert resp.grounded is False
    assert "could not find evidence" in resp.answer
