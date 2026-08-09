"""Query-aware, evidence-grounded Copilot response synthesis."""
from __future__ import annotations

import re
from collections import Counter
from typing import Any, Dict, Iterable, List, Optional, Tuple


SMALL_TALK = {
    "hi", "hii", "hiii", "hello", "hey", "heyy", "ok", "okay", "cool",
    "thanks", "thank you", "yo", "good morning", "good afternoon", "good evening",
}

STOPWORDS = {
    "a", "an", "and", "are", "as", "be", "been", "by", "do", "does", "done",
    "for", "from", "how", "i", "in", "is", "it", "me", "of", "on", "or", "so",
    "tell", "that", "the", "then", "there", "this", "to", "was", "what", "when",
    "where", "why", "with", "should", "can", "could", "would", "please", "about",
}

REMEDIATION_TERMS = {
    "fix", "fixed", "remediate", "remediation", "solve", "solution", "solutions",
    "done", "patch", "prevent", "mitigate", "change", "secure",
}

SUMMARY_TERMS = {"summary", "overview", "posture", "risk", "risks", "findings", "vulnerabilities"}

RULE_HINTS = {
    "SEC-001": ("SQL Injection", "Use parameterized queries and avoid string-built SQL."),
    "SEC-002": ("Cross-Site Scripting", "Use context-aware output encoding and avoid unsafe HTML sinks."),
    "SEC-004": ("Hardcoded Secret", "Move secrets and sensitive paths into environment-backed configuration or a secret manager."),
    "SEC-006": ("Broken Authentication", "Keep TLS/certificate verification enabled and avoid auth bypass patterns."),
    "SEC-010": ("Sensitive Logging", "Remove or mask sensitive values before logging."),
}


def synthesize_security_answer(
    user_query: str,
    findings: Iterable[Any],
    *,
    evidence: Optional[Iterable[Dict[str, Any]]] = None,
    profile: Optional[Dict[str, Any]] = None,
    risk_scores: Optional[Dict[str, Any]] = None,
    persona: str = "Developer",
    conversation: Optional[Iterable[Any]] = None,
    knowledge: Optional[Iterable[Dict[str, Any]]] = None,
) -> Tuple[str, List[Dict[str, Any]]]:
    """Return a grounded answer and compact citations for a user question."""
    query = (user_query or "").strip()
    query_lower = query.lower()
    normalized_findings = [_normalize_finding(f) for f in findings]

    if _is_small_talk(query_lower):
        repo = (profile or {}).get("repo_path") or (profile or {}).get("root") or "the active repository"
        return (
            f"Hi. I am your AI Security Copilot for {repo}.\n\n"
            "Ask me about a finding, a file, a rule such as `SEC-004`, or say "
            "`what should be fixed first` and I will ground the answer in the current scan.",
            [],
        )

    if not normalized_findings:
        return (
            "I do not see any active scan findings loaded for this conversation yet. "
            "Run a repository scan first, then ask about a rule, file, category, or remediation.",
            [],
        )

    query_scope = _conversation_scope(query, conversation)
    matched = _rank_findings(query_scope, normalized_findings)

    wants_summary = any(term in query_lower for term in SUMMARY_TERMS)
    wants_fix = any(term in query_lower for term in REMEDIATION_TERMS) or _is_vague_followup(query_lower)

    if wants_summary and not wants_fix and not _specific_terms(query):
        return _summary_answer(normalized_findings, profile or {}, risk_scores or {})

    if not matched and _is_vague_followup(query_lower):
        matched = _top_priority_findings(normalized_findings)

    if not matched:
        rules = ", ".join(f"`{r}`" for r in sorted({f["rule_id"] for f in normalized_findings if f["rule_id"]})[:8])
        return (
            f"I do not see evidence for that specific issue in the current scan.\n\n"
            f"Current scan rules I can discuss include: {rules or 'no rule IDs available'}. "
            "Try asking about a rule ID, file path, category, or `what should be fixed first`.",
            [],
        )

    finding = matched[0]
    citations = [_citation(f) for f in matched[:4]]
    answer = _finding_answer(finding, matched, wants_fix=wants_fix, persona=persona, knowledge=list(knowledge or []))
    return answer, citations


def _is_small_talk(query_lower: str) -> bool:
    return query_lower in SMALL_TALK or bool(re.fullmatch(r"(hi+|hello+|hey+|ok+|thanks?)[.! ]*", query_lower))


def _normalize_finding(finding: Any) -> Dict[str, Any]:
    if hasattr(finding, "to_dict"):
        raw = finding.to_dict()
    elif isinstance(finding, dict):
        raw = dict(finding)
    else:
        raw = {}

    evidence_ids = raw.get("evidence_ids") or []
    if isinstance(evidence_ids, str):
        evidence_ids = [evidence_ids]
    evidence_id = raw.get("evidence_id") or (evidence_ids[0] if evidence_ids else "")

    return {
        "finding_id": raw.get("finding_id") or raw.get("id") or "",
        "rule_id": raw.get("rule_id") or raw.get("rule") or "",
        "category": raw.get("category") or raw.get("title") or "Security Finding",
        "severity": str(raw.get("severity") or "Medium"),
        "file_path": raw.get("file_path") or raw.get("file") or "unknown",
        "line_number": raw.get("line_number") or raw.get("line") or 0,
        "description": raw.get("description") or raw.get("reason") or raw.get("recommendation") or "",
        "snippet": raw.get("snippet") or raw.get("code_snippet") or "",
        "recommendation": raw.get("recommendation") or "",
        "evidence_id": evidence_id,
        "confidence": raw.get("confidence", 0.0),
        "is_exploitable": bool(raw.get("is_exploitable", False)),
    }


def _conversation_scope(query: str, conversation: Optional[Iterable[Any]]) -> str:
    parts = []
    for msg in list(conversation or [])[-6:]:
        if isinstance(msg, dict):
            parts.append(str(msg.get("content", "")))
        else:
            parts.append(str(getattr(msg, "content", "")))
    parts.append(query)
    return "\n".join(p for p in parts if p).strip()


def _tokens(text: str) -> List[str]:
    return [t for t in re.findall(r"[a-zA-Z0-9_.:/-]+", text.lower()) if len(t) > 2 and t not in STOPWORDS]


def _specific_terms(query: str) -> List[str]:
    return [t for t in _tokens(query) if t not in REMEDIATION_TERMS and t not in SUMMARY_TERMS]


def _rank_findings(query: str, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    tokens = _tokens(query)
    if not tokens:
        return []

    scored: List[Tuple[int, Dict[str, Any]]] = []
    for f in findings:
        haystack = " ".join(
            str(f.get(k, ""))
            for k in ("finding_id", "rule_id", "category", "file_path", "description", "snippet", "recommendation")
        ).lower()
        score = 0
        for token in tokens:
            if token and token in haystack:
                score += 3 if token.startswith("sec-") or token in str(f.get("rule_id", "")).lower() else 1
        if score:
            score += _severity_weight(f.get("severity", ""))
            if f.get("is_exploitable"):
                score += 2
            scored.append((score, f))

    scored.sort(key=lambda pair: pair[0], reverse=True)
    return [f for _, f in scored]


def _top_priority_findings(findings: List[Dict[str, Any]], limit: int = 4) -> List[Dict[str, Any]]:
    return sorted(
        findings,
        key=lambda f: (_severity_weight(f.get("severity", "")), bool(f.get("is_exploitable")), f.get("confidence", 0.0)),
        reverse=True,
    )[:limit]


def _severity_weight(severity: str) -> int:
    return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(str(severity).lower(), 0)


def _is_vague_followup(query_lower: str) -> bool:
    return any(phrase in query_lower for phrase in [
        "what should be done", "what to do", "what now", "how to fix", "fix this",
        "solution", "solutions", "remediate", "remediation", "what should i do",
    ])


def _summary_answer(findings: List[Dict[str, Any]], profile: Dict[str, Any], risk_scores: Dict[str, Any]) -> Tuple[str, List[Dict[str, Any]]]:
    severity_counts = Counter(f["severity"] for f in findings)
    category_counts = Counter(f["category"] for f in findings)
    top = _top_priority_findings(findings, limit=5)
    lines = [
        "**Context:** The current scan has "
        f"{len(findings)} security finding(s) for `{profile.get('repo_path') or profile.get('root') or 'the active repository'}`.",
        "",
        "**The Risk:** The highest-volume categories are "
        + ", ".join(f"{cat} ({count})" for cat, count in category_counts.most_common(4))
        + f". Severity distribution: {dict(severity_counts)}.",
        "",
        "**Remediation:** Start with these highest-priority items:",
    ]
    for idx, f in enumerate(top, 1):
        lines.append(f"{idx}. `{f['rule_id'] or f['category']}` in `{f['file_path']}:{f['line_number']}` - {_remediation_for(f)}")
    if risk_scores:
        lines.append(f"\nCurrent composite risk: `{risk_scores.get('composite_risk_score', 0.0)}`.")
    return "\n".join(lines), [_citation(f) for f in top]


def _finding_answer(
    finding: Dict[str, Any],
    matched: List[Dict[str, Any]],
    *,
    wants_fix: bool,
    persona: str,
    knowledge: List[Dict[str, Any]],
) -> str:
    rule = finding["rule_id"] or finding["category"]
    location = f"`{finding['file_path']}:{finding['line_number']}`"
    category = finding["category"]
    snippet = finding["snippet"].strip()

    lines = [
        f"**Context:** `{rule}` was found in {location}. It is categorized as **{category}**"
        f" with **{finding['severity']}** severity.",
    ]
    if finding["description"]:
        lines.append(f"The scanner reason is: {finding['description']}")

    lines.extend([
        "",
        f"**The Risk:** {_risk_for(finding)}",
        "",
        f"**Remediation:** {_remediation_for(finding)}",
    ])

    code = _code_fix_for(finding)
    if code:
        lines.append("\nSuggested pattern:")
        lines.append(f"```python\n{code}\n```")

    if snippet and not wants_fix:
        lines.append("\nRelevant snippet:")
        lines.append(f"```text\n{snippet[:400]}\n```")

    if len(matched) > 1:
        lines.append(f"\nI found {len(matched)} related finding(s). The next closest matches are:")
        for f in matched[1:4]:
            lines.append(f"- `{f['rule_id'] or f['category']}` in `{f['file_path']}:{f['line_number']}`")

    if knowledge:
        top = knowledge[0]
        title = top.get("title") or top.get("standard") or "security guidance"
        lines.append(f"\nRelated guidance: {title}.")

    return "\n".join(lines)


def _risk_for(finding: Dict[str, Any]) -> str:
    rule = finding["rule_id"].upper()
    category = finding["category"].lower()
    if "sql" in category or "SEC-001" in rule:
        return "SQL injection can let attacker-controlled input change database queries, leading to data exposure or unauthorized changes."
    if "secret" in category or "SEC-004" in rule:
        return "Hardcoded secrets or sensitive token paths can expose credentials, make rotation difficult, and leak environment assumptions into source control."
    if "xss" in category or "SEC-002" in rule:
        return "Cross-site scripting can allow attacker-controlled content to execute in a user's browser."
    if "auth" in category or "SEC-006" in rule:
        return "Authentication or TLS verification weaknesses can allow bypass, impersonation, or man-in-the-middle exposure."
    if "logging" in category or "SEC-010" in rule:
        return "Sensitive logging can place credentials or private data into logs where retention and access controls are weaker."
    return "This finding can weaken the application's security posture if the affected code is reachable or handles sensitive data."


def _remediation_for(finding: Dict[str, Any]) -> str:
    rec = finding.get("recommendation", "").strip()
    rule = finding["rule_id"].upper()
    category = finding["category"].lower()
    if rec and "parameterized coding standards" not in rec.lower():
        return rec
    if "sql" in category or "SEC-001" in rule:
        return "Replace string-built SQL with parameterized queries, validate inputs, and keep query structure static."
    if "secret" in category or "SEC-004" in rule:
        return "Move the value into environment-backed configuration or a secret manager, restrict runtime file permissions, rotate any exposed token, and keep token files out of source control."
    if "xss" in category or "SEC-002" in rule:
        return "Use context-aware escaping, avoid unsafe HTML sinks, and sanitize user-controlled content before rendering."
    if "auth" in category or "SEC-006" in rule:
        return "Remove bypass patterns, keep certificate verification enabled, and add regression tests for the auth/TLS path."
    if "logging" in category or "SEC-010" in rule:
        return "Remove sensitive fields from logs or mask them before logging."
    return rec or "Apply the scanner recommendation, add a regression test, and rerun the scan to confirm the finding is gone."


def _code_fix_for(finding: Dict[str, Any]) -> str:
    rule = finding["rule_id"].upper()
    category = finding["category"].lower()
    snippet = finding["snippet"]
    if "secret" in category or "SEC-004" in rule:
        var_match = re.search(r"\b([A-Z][A-Z0-9_]{2,})\s*=", snippet)
        var_name = var_match.group(1) if var_match else "SECRET_VALUE"
        return f"import os\n\n{var_name} = os.environ.get(\"{var_name}\", \"\")"
    if "sql" in category or "SEC-001" in rule:
        return "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))"
    if "xss" in category or "SEC-002" in rule:
        return "import html\n\nsafe_output = html.escape(user_input)"
    return ""


def _citation(finding: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "evidence_id": finding.get("evidence_id", ""),
        "finding_id": finding.get("finding_id", ""),
        "file_path": finding.get("file_path", "unknown"),
        "line_number": finding.get("line_number", 0),
        "rule_id": finding.get("rule_id", ""),
        "confidence": finding.get("confidence", 0.0),
    }
