from typing import List
from scanner.intelligence.rule_engine import RuleMatch

class FalsePositiveReducer:
    """
    Deterministic false-positive filtering using spatial and semantic context.
    Reduces confidence or drops matches completely.
    """
    
    def filter(self, matches: List[RuleMatch]) -> List[RuleMatch]:
        filtered = []
        
        for match in matches:
            # 1. Literal argument checks (e.g. command execution with all literal args is less severe)
            # This requires 'arguments' to be collected by SymbolBuilder/ContextEnricher,
            # which could be parsed in the future.
            
            # 2. Scope awareness (e.g., test files might lower confidence)
            scope = match.symbol.context.get("scope", "")
            if "test" in scope.lower():
                match.confidence -= 0.3
                
            # Drop if confidence is too low
            if match.confidence > 0.0:
                filtered.append(match)
                
        return filtered
