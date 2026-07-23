"""
LLM Layer — Response Parser (spec §6, §11)
==========================================
Converts free-form Nemotron output into the structured `SecurityAnalysis`
contract the dashboard and reporting layers consume.

LLMs emit JSON imperfectly: fenced in ```json blocks, wrapped in prose,
with trailing commas, or with smart quotes. Rather than failing the
whole analysis on a formatting slip, the parser escalates through four
strategies and only then falls back to a degraded-but-valid object with
`parse_failed=True` so callers can decide what to do. A malformed
response never crashes a scan (spec §11).

Extraction order:
    1. whole string as JSON
    2. ```json ... ``` fenced block
    3. first balanced {...} object (brace matching, string-aware)
    4. common-defect repair (trailing commas, smart quotes) then retry
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

log = logging.getLogger(__name__)

_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.S | re.I)
_SMART = {"\u201c": '"', "\u201d": '"', "\u2018": "'", "\u2019": "'"}

_VALID_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}


@dataclass
class SecurityAnalysis:
    """Structured Nemotron analysis (spec §6 schema)."""
    summary: str = ""
    findings: list[dict] = field(default_factory=list)
    severity: str = ""
    confidence: float = 0.0
    business_impact: str = ""
    technical_explanation: str = ""
    recommendation: str = ""
    secure_code: str = ""
    owasp: str = ""
    nist: str = ""
    rmf: str = ""
    cwe: str = ""

    # parser metadata (not part of the model's schema)
    parse_failed: bool = False
    parse_error: str = ""
    raw_response: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def is_usable(self) -> bool:
        return not self.parse_failed and bool(self.summary or self.findings)


class ResponseParser:
    """Parses and normalises Nemotron responses."""

    def parse(self, text: str) -> SecurityAnalysis:
        if not text or not text.strip():
            return SecurityAnalysis(parse_failed=True,
                                    parse_error="empty response", raw_response=text or "")
        data = self._extract_json(text)
        if data is None:
            # Not JSON at all — preserve the prose rather than discarding it,
            # so a chat-style answer still reaches the user.
            log.warning("Nemotron response was not valid JSON; returning prose fallback")
            return SecurityAnalysis(summary=text.strip()[:2000], parse_failed=True,
                                    parse_error="no JSON object found", raw_response=text)
        return self._normalise(data, raw=text)

    # ------------------------------------------------------------------
    def _extract_json(self, text: str) -> Optional[dict]:
        for candidate in self._candidates(text):
            for attempt in (candidate, self._repair(candidate)):
                try:
                    parsed = json.loads(attempt)
                except (ValueError, TypeError):
                    continue
                if isinstance(parsed, dict):
                    return parsed
                if isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
                    return {"findings": parsed}
        return None

    def _candidates(self, text: str) -> list[str]:
        out = [text.strip()]
        out.extend(m.group(1).strip() for m in _FENCE.finditer(text))
        balanced = self._balanced_object(text)
        if balanced:
            out.append(balanced)
        return out

    @staticmethod
    def _balanced_object(text: str) -> Optional[str]:
        """First brace-balanced {...}, ignoring braces inside strings."""
        start = text.find("{")
        if start == -1:
            return None
        depth, in_str, esc = 0, False, False
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return text[start:i + 1]
        return None

    @staticmethod
    def _repair(text: str) -> str:
        for bad, good in _SMART.items():
            text = text.replace(bad, good)
        text = re.sub(r",\s*([}\]])", r"\1", text)   # trailing commas
        text = re.sub(r"^\s*//.*$", "", text, flags=re.M)  # // comments
        return text

    # ------------------------------------------------------------------
    def _normalise(self, data: dict, raw: str) -> SecurityAnalysis:
        """Coerce provider output into the strict schema. Models return
        strings where numbers are expected, lists where strings are, and
        vice versa — normalise rather than reject."""
        def s(key: str, default: str = "") -> str:
            v = data.get(key, default)
            if isinstance(v, (list, tuple)):
                return ", ".join(str(x) for x in v)
            if isinstance(v, dict):
                return json.dumps(v)
            return str(v) if v is not None else default

        findings = data.get("findings") or []
        if isinstance(findings, dict):
            findings = [findings]
        if not isinstance(findings, list):
            findings = []
        findings = [f if isinstance(f, dict) else {"description": str(f)} for f in findings]

        severity = s("severity").strip().title()
        if severity and severity not in _VALID_SEVERITIES:
            severity = {"CRIT": "Critical", "WARNING": "Medium",
                        "ERROR": "High", "INFORMATIONAL": "Info"}.get(
                            severity.upper(), severity)

        return SecurityAnalysis(
            summary=s("summary"),
            findings=findings,
            severity=severity,
            confidence=self._confidence(data.get("confidence")),
            business_impact=s("business_impact"),
            technical_explanation=s("technical_explanation"),
            recommendation=s("recommendation"),
            secure_code=s("secure_code"),
            owasp=s("owasp"),
            nist=s("nist"),
            rmf=s("rmf"),
            cwe=s("cwe"),
            raw_response=raw,
        )

    @staticmethod
    def _confidence(value: Any) -> float:
        """Accept 0.85, '85%', 'high', 85 — return 0.0-1.0."""
        if value is None:
            return 0.0
        if isinstance(value, (int, float)):
            v = float(value)
            return round(v / 100.0, 3) if v > 1.0 else round(v, 3)
        text = str(value).strip().lower()
        word_map = {"very high": 0.95, "high": 0.85, "medium": 0.6,
                    "moderate": 0.6, "low": 0.3, "very low": 0.15}
        if text in word_map:
            return word_map[text]
        m = re.search(r"(\d+(?:\.\d+)?)", text)
        if not m:
            return 0.0
        v = float(m.group(1))
        return round(v / 100.0, 3) if v > 1.0 else round(v, 3)
