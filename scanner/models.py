from dataclasses import dataclass, field
import hashlib

from typing import List


@dataclass
class SecurityFinding:
    finding_id: str = field(init=False)

    rule_id: str = ""
    category: str = ""
    severity: str = ""
    confidence: float = 1.0

    language: str = "Python"
    file: str = ""
    line: int = 0
    snippet: str = ""
    cwe: str = ""
    owasp: str = ""
    description: str = ""
    recommendation: str = ""
    references: List[str] = field(default_factory=list)

    why: str = ""
    how_to_fix: str = ""
    example_attack: str = ""

    def __post_init__(self):
        basis = f"{self.file}:{self.line}:{self.category}"
        self.finding_id = hashlib.sha1(
            basis.encode()
        ).hexdigest()[:16]


@dataclass
class ScanResult:
    target: str
    files_scanned: int
    findings: list

    @property
    def total_findings(self):
        return len(self.findings)

    @property
    def counts_by_severity(self):

        output = {}

        for finding in self.findings:
            output[finding.severity] = output.get(
                finding.severity,
                0
            ) + 1

        return output