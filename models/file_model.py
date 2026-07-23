from dataclasses import dataclass, field
from models.status import ScanStatus

@dataclass
class ProjectFile:
    path: str
    content: str = ""

    status: ScanStatus = ScanStatus.PENDING

    imports: list = field(default_factory=list)
    functions: list = field(default_factory=list)
    classes: list = field(default_factory=list)

    lines_of_code: int = 0

    vulnerabilities: list = field(default_factory=list)

    business_module: str | None = None
    business_score: int = 0

    risk_score: int = 0