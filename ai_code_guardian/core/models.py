"""
AI Code Guardian - Core Data Models
Universal AST node shapes + Finding/ScanResult contracts shared by every
detector and consumed downstream by the Risk Scorer and Dashboard.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class TaintLabel(str, Enum):
    SOURCE = "source"          # user-controlled input (HTTP param, env var, file read)
    SANITIZED = "sanitized"    # passed through a recognised sanitiser
    SINK = "sink"               # dangerous operation (SQL exec, OS exec, eval, etc.)


@dataclass
class SourceLocation:
    file_path: str
    line: int
    column: int = 0


@dataclass
class Finding:
    """
    A single security finding. `to_dict()` output is intentionally flat
    and stable so it can feed directly into the Day-7 Risk Scorer and the
    Streamlit dashboard without transformation.
    """
    category: str
    severity: str
    rule_id: Optional[str]
    file: str
    line: int
    snippet: str
    recommendation: str
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    confidence: float = 0.9          # detector self-reported confidence (0-1)
    tainted: bool = False            # True if confirmed via data-flow tracing
    finding_id: str = field(default="", init=False)

    def __post_init__(self):
        # Stable SHA-1 id for dedup across incremental scans (Day 4 design).
        basis = f"{self.file}:{self.line}:{self.category}:{self.rule_id}"
        self.finding_id = hashlib.sha1(basis.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        return asdict(self) | {"finding_id": self.finding_id}


@dataclass
class ScanResult:
    target: str
    files_scanned: int
    findings: list[Finding] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None

    def finish(self):
        self.finished_at = time.time()

    @property
    def duration_seconds(self) -> float:
        end = self.finished_at or time.time()
        return round(end - self.started_at, 3)

    @property
    def counts_by_severity(self) -> dict:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    @property
    def counts_by_category(self) -> dict:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.category] = out.get(f.category, 0) + 1
        return out

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "files_scanned": self.files_scanned,
            "duration_seconds": self.duration_seconds,
            "total_findings": len(self.findings),
            "by_severity": self.counts_by_severity,
            "by_category": self.counts_by_category,
            "findings": [f.to_dict() for f in self.findings],
        }
