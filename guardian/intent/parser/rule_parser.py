"""
Strong Requirement -> Rule Parser Module
=======================================
Decomposes requirements into 3 explicit components:
  1. Action     (verbs e.g. refund, transfer, encrypt, execute)
  2. Condition  (thresholds/conditions e.g. amount > 50000, user input)
  3. Control    (demanded controls e.g. manager approval, sha-256, parameterization)

Fallback: rule.type = "UNSTRUCTURED" if parsing cannot split cleanly.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

from guardian.intent.ingestion.document_loader import Requirement

log = logging.getLogger(__name__)

# Verb / Action extraction patterns
ACTION_VERB_PATTERNS = re.compile(
    r"(?i)\b(refund|refunds|process_refund|transfer|transfers|encrypt|hashing|hash|query|queries|database|delete|purge|mutate|audit|log|authenticate|approval|approve)\b"
)

# Threshold / Condition extraction patterns
NUMERIC_CONDITION_PATTERNS = re.compile(
    r"(?i)(\b(greater\s+than|exceeding|above|>|<|=|>=|<=)\s*\$?\s*[\d,]+|\b[\d,]+\s*(usd|dollars)?|\buser\s+input\b|\bexternal\b)"
)

# Demanded Control extraction patterns
CONTROL_PATTERNS = re.compile(
    r"(?i)\b(manager\s+approval|authorization|signoff|dual-control|sha-256|argon2id|parameterized|prepared\s+statement|audit\s+trail|audit\s+log|rate\s+limit|rbac|permission)\b"
)


@dataclass
class ParsedRule:
    rule_id: str
    requirement_text: str
    source_file: str
    line_number: int
    action: str
    condition: str
    control: str
    rule_type: str  # "STRUCTURED" or "UNSTRUCTURED"
    priority: str = "Medium"

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "requirement_text": self.requirement_text,
            "source_file": self.source_file,
            "line_number": self.line_number,
            "action": self.action,
            "condition": self.condition,
            "control": self.control,
            "rule_type": self.rule_type,
            "priority": self.priority,
        }


class RuleParser:
    """Parses Requirement objects into structured ParsedRule items."""

    def parse_requirement(self, req: Requirement) -> ParsedRule:
        text = req.text
        lower_text = text.lower()

        # 1. Action extraction
        action_match = ACTION_VERB_PATTERNS.search(text)
        action = action_match.group(0).lower() if action_match else "generic_action"

        # 2. Condition extraction
        condition_match = NUMERIC_CONDITION_PATTERNS.search(text)
        condition = condition_match.group(0).strip() if condition_match else "none"

        # 3. Control extraction
        control_match = CONTROL_PATTERNS.search(text)
        control = control_match.group(0).lower() if control_match else "generic_control"

        # Rule type classification
        is_structured = bool(action_match or control_match or condition_match != "none")
        rule_type = "STRUCTURED" if is_structured else "UNSTRUCTURED"

        # Priority calculation based on threshold or keywords
        priority = "High" if ("50000" in lower_text or "critical" in lower_text or "must" in lower_text) else "Medium"

        return ParsedRule(
            rule_id=req.id,
            requirement_text=req.text,
            source_file=req.source,
            line_number=req.line_number,
            action=action,
            condition=condition,
            control=control,
            rule_type=rule_type,
            priority=priority,
        )

    def parse_all(self, requirements: list[Requirement]) -> list[ParsedRule]:
        """Parse a list of requirements into ParsedRule objects."""
        return [self.parse_requirement(r) for r in requirements]
