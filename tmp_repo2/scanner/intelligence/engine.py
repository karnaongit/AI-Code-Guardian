from scanner.models import ParsedFile, ScanResult
from scanner.intelligence.capability_engine import CapabilityEngine
from scanner.intelligence.rule_engine import GenericRuleEngine
from scanner.intelligence.fp_reducer import FalsePositiveReducer
from scanner.intelligence.finding_builder import FindingBuilder

class IntelligenceEngine:
    """
    The new intelligence layer that replaces the legacy SecurityEngine.
    """
    
    def __init__(self):
        self.capability_engine = CapabilityEngine()
        self.rule_engine = GenericRuleEngine()
        self.fp_reducer = FalsePositiveReducer()
        self.finding_builder = FindingBuilder()

    def scan(self, parsed: ParsedFile, file_name: str) -> ScanResult:
        
        # 1. Map symbols to capabilities
        self.capability_engine.assign_capabilities(parsed)
        
        # 2. Evaluate rules against capabilities
        raw_matches = self.rule_engine.evaluate(parsed)
        
        # 3. Reduce false positives
        confirmed_matches = self.fp_reducer.filter(raw_matches)
        
        # 4. Build standardized findings
        findings = self.finding_builder.build(confirmed_matches, parsed, file_name)
        
        return ScanResult(
            target=file_name,
            files_scanned=1,
            findings=findings,
        )
