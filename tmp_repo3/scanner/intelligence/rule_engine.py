import yaml
from dataclasses import dataclass
from typing import Dict, List
from pathlib import Path

from scanner.models import ParsedFile, Symbol

@dataclass
class RuleMatch:
    rule_id: str
    symbol: Symbol
    category: str
    severity: str
    description: str
    recommendation: str
    confidence: float = 1.0

@dataclass
class Rule:
    id: str
    capability: str
    severity: str
    category: str
    description: str
    recommendation: str

class GenericRuleEngine:
    """
    Evaluates YAML rules against capabilities and generic context.
    """
    
    def __init__(self, config_path: str = None):
        if config_path is None:
            config_path = Path(__file__).parent.parent / "config" / "rules.yaml"
            
        self.rules: List[Rule] = []
        self._load_config(config_path)

    def _load_config(self, path: Path):
        if not path.exists():
            return
            
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or []
            
        for rule_data in data:
            self.rules.append(Rule(
                id=rule_data.get("id", "UNKNOWN"),
                capability=rule_data.get("capability", ""),
                severity=rule_data.get("severity", "Low"),
                category=rule_data.get("category", "Unknown"),
                description=rule_data.get("description", ""),
                recommendation=rule_data.get("recommendation", "")
            ))

    def evaluate(self, parsed_file: ParsedFile) -> List[RuleMatch]:
        """
        Evaluate all symbols in the parsed file against rules.
        """
        matches = []
        
        # We group rules by capability for faster lookup
        rules_by_cap = {}
        for rule in self.rules:
            rules_by_cap.setdefault(rule.capability, []).append(rule)
            
        # Iterate over all symbols (calls for now, but could be extended)
        for symbol in parsed_file.calls:
            cap = symbol.context.get("capability")
            if not cap:
                continue
                
            applicable_rules = rules_by_cap.get(cap, [])
            for rule in applicable_rules:
                # Basic match logic: if it has the capability, it matches.
                # Advanced conditions could be added here (e.g. checking arguments)
                matches.append(RuleMatch(
                    rule_id=rule.id,
                    symbol=symbol,
                    category=rule.category,
                    severity=rule.severity,
                    description=rule.description,
                    recommendation=rule.recommendation,
                ))
                
        return matches
