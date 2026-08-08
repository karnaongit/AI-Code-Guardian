from dataclasses import dataclass, field
import hashlib

from typing import List


@dataclass
class SecurityFinding:
    finding_id: str = field(init=False)

    # Core details
    title: str = ""
    rule_id: str = ""
    matched_rule: str = ""
    category: str = ""
    severity: str = ""
    confidence: float = 1.0
    evidence: str = ""

    # Traceability
    repository: str = ""
    language: str = "Python"
    relative_path: str = ""
    file: str = ""
    file_id: str = ""
    class_name: str = ""
    function_name: str = ""
    
    # Location
    symbol_id: str = ""
    line: int = 0
    end_line: int = 0
    column: int = 0
    node_type: str = ""
    snippet: str = ""
    
    # Graph relationships
    capability: str = ""
    related_findings: List[str] = field(default_factory=list)

    # Context & Remediation
    cwe: str = ""
    owasp: str = ""
    description: str = ""
    recommendation: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)

    why: str = ""
    how_to_fix: str = ""
    example_attack: str = ""

    def __post_init__(self):
        basis = f"{self.file}:{self.line}:{self.category}:{self.rule_id}:{self.symbol_id}"
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
    
# ============================================================
# Parser Models
# ============================================================

from typing import Any


@dataclass
class Capture:
    capture_name: str
    node_type: str
    text: str
    start_line: int
    end_line: int
    start_byte: int = 0
    end_byte: int = 0

@dataclass
class Symbol:
    symbol_id: str = ""
    name: str = ""
    line: int = 0
    snippet: str = ""
    end_line: int = 0
    start_byte: int = 0
    end_byte: int = 0
    context: dict = field(default_factory=dict)
    parent_id: str = ""


@dataclass
class FunctionSymbol(Symbol):
    pass


@dataclass
class ClassSymbol(Symbol):
    pass


@dataclass
class ImportSymbol(Symbol):
    pass


@dataclass
class VariableSymbol(Symbol):
    pass


@dataclass
class CallSymbol(Symbol):
    pass


@dataclass
class ConstantSymbol(Symbol):
    pass


@dataclass
class ParsedFile:
    file_id: str = field(init=False)
    file_path: str = ""
    language: str = ""

    functions: List[FunctionSymbol] = field(default_factory=list)
    classes: List[ClassSymbol] = field(default_factory=list)
    imports: List[ImportSymbol] = field(default_factory=list)
    variables: List[VariableSymbol] = field(default_factory=list)
    calls: List[CallSymbol] = field(default_factory=list)
    constants: List[ConstantSymbol] = field(default_factory=list)

    captures: List[Capture] = field(default_factory=list)
    metrics: dict = field(default_factory=dict)

    def __post_init__(self):
        self.file_id = hashlib.sha1(self.file_path.encode()).hexdigest()[:16] if self.file_path else ""