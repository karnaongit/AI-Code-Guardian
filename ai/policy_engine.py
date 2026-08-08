import json
from dataclasses import dataclass
from typing import Optional

@dataclass
class PolicyDecision:
    decision: str
    severity: str
    reachable: bool
    reason_code: str
    
    def to_dict(self):
        return {
            "decision": self.decision,
            "severity": self.severity,
            "reachable": self.reachable,
            "reason_code": self.reason_code
        }

def evaluate(severity: str, reachable: bool) -> PolicyDecision:
    if not isinstance(reachable, bool):
        raise ValueError("Reachability must be an explicit boolean")
        
    if not severity:
        raise ValueError("Severity is missing")
        
    severity = str(severity).upper()
    valid_severities = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    
    if severity not in valid_severities:
        raise ValueError(f"Unsupported severity: {severity}")
        
    if severity in ("LOW", "MEDIUM"):
        if not reachable:
            return PolicyDecision(
                decision="ALLOW",
                severity=severity,
                reachable=reachable,
                reason_code=f"{severity}_UNREACHABLE_ALLOWED"
            )
        else:
            return PolicyDecision(
                decision="WARN",
                severity=severity,
                reachable=reachable,
                reason_code=f"{severity}_REACHABLE_WARNING"
            )
            
    if severity in ("HIGH", "CRITICAL"):
        if not reachable:
            return PolicyDecision(
                decision="WARN",
                severity=severity,
                reachable=reachable,
                reason_code=f"{severity}_UNREACHABLE_WARNING"
            )
        else:
            return PolicyDecision(
                decision="BLOCK",
                severity=severity,
                reachable=reachable,
                reason_code=f"{severity}_REACHABLE_BLOCKED"
            )
