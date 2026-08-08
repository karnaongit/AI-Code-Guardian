"""
AI Assistant — Scan Context Grounding
=====================================
Fixes hallucination cause #3: scan findings never reached the model, so
questions about findings — the platform's core use case — were answered
from imagination.

Two mechanisms:

1. `findings_to_documents(report)` — converts every Finding in a scan
   report into an indexable Document (doc_type SCAN_REPORT) so semantic
   retrieval can surface findings for fuzzy questions
   ("what's wrong with the payment code?").

2. `exact_match_context(question, report)` — deterministic lookup: if
   the question literally names a rule ID, finding ID, or file path
   that exists in the report, the exact finding records are injected
   verbatim into the prompt. Exact questions get exact context —
   retrieval similarity never gets the chance to miss.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Optional

from ai.models import Document, DocumentType

_TOKEN = re.compile(r"[\w./\-]{3,}")


def finding_text(f: dict) -> str:
    return (f"FINDING {f.get('finding_id', '?')} | rule {f.get('rule_id')} | "
            f"{f.get('severity')} {f.get('category')} | "
            f"{f.get('file')}:{f.get('line')}\n"
            f"code: {f.get('snippet', '')}\n"
            f"recommendation: {f.get('recommendation', '')}\n"
            f"cwe: {f.get('cwe') or 'n/a'} | owasp: {f.get('owasp') or 'n/a'} | "
            f"confidence: {f.get('confidence')}")


def findings_to_documents(report: dict) -> list[Document]:
    docs: list[Document] = []
    for f in report.get("security_findings", []):
        text = finding_text(f)
        docs.append(Document(
            doc_id=hashlib.sha1(text.encode()).hexdigest()[:16],
            content=text,
            source_path=str(f.get("file", "scan_report")),
            doc_type=DocumentType.SCAN_REPORT,
            start_line=int(f.get("line") or 0),
            end_line=int(f.get("line") or 0),
            metadata={"finding_id": f.get("finding_id"),
                      "rule_id": f.get("rule"),
                      "severity": f.get("severity")},
        ))
    # one summary document so "how did the scan go overall" is answerable
    summary = report.get("summary", {})
    summary_content = ("SCAN SUMMARY | target " + str(summary.get("repository"))
                 + f" | files_scanned {summary.get('files_scanned')}"
                 + f" | total_findings {summary.get('security_findings_count')}"
                 + f" | security_score {summary.get('repository_risk_score')}")
    docs.append(Document(
        doc_id=hashlib.sha1(summary_content.encode()).hexdigest()[:16],
        content=summary_content,
        source_path="scan:summary",
        doc_type=DocumentType.RISK_REPORT,
    ))
    return docs

def get_scan_summary_context(report: Optional[dict]) -> str:
    """Returns a general summary of the scan report to always include in context."""
    if not report:
        return ""
    summary_data = report.get("summary", {})
    
    # Extract unique categories from findings
    findings = report.get("security_findings", [])
    categories = list(set(f.get("category", "Unknown") for f in findings))
    
    summary = ("SCAN SUMMARY:\n"
             + f"- Target: {summary_data.get('repository', 'unknown')}\n"
             + f"- Files scanned: {summary_data.get('files_scanned', 0)}\n"
             + f"- Total findings: {summary_data.get('security_findings_count', 0)}\n"
             + f"- Vulnerability categories found: {', '.join(categories) if categories else 'None'}\n"
             + f"- Repository risk score: {summary_data.get('repository_risk_score', 0)}\n")
    return summary

def exact_match_context(question: str, report: Optional[dict],
                        max_findings: int = 6) -> str:
    """Deterministic context: findings whose rule_id, finding_id, or file
    path literally appears in the question. Returns '' when nothing
    matches — never guesses."""
    if not report:
        return ""
    findings = report.get("security_findings", [])
    if not findings:
        return ""
    q_tokens = {t.lower() for t in _TOKEN.findall(question)}
    q_lower = question.lower()

    hits: list[dict] = []
    for f in findings:
        rid = str(f.get("rule") or "").lower()
        fid = str(f.get("finding_id") or "").lower()
        fpath = str(f.get("file") or "").lower().replace("\\", "/")
        fname = fpath.rsplit("/", 1)[-1]
        if (rid and rid in q_tokens) or (fid and fid in q_tokens) \
                or (fpath and fpath in q_lower) or (fname and fname in q_tokens):
            hits.append(f)
        if len(hits) >= max_findings:
            break
    if not hits:
        return ""
    body = "\n\n".join(finding_text(f) for f in hits)
    return ("EXACT SCAN-REPORT MATCHES for this question "
            "(authoritative — prefer these over any other context):\n" + body)
