from dataclasses import dataclass, field
import hashlib


@dataclass
class SecurityFinding:
    category: str
    severity: str
    file: str
    line: int
    snippet: str
    recommendation: str
    confidence: float = 0.9
    finding_id: str = field(default="", init=False)

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