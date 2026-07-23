from enum import Enum

class ScanStatus(Enum):
    PENDING = "Pending"
    SAFE = "Safe"
    WARNING = "Warning"
    CRITICAL = "Critical"