from typing import List
from scanner.models import SecurityFinding, ParsedFile
from scanner.intelligence.rule_engine import RuleMatch

class FindingBuilder:
    """
    Translates a confirmed rule match into a standardized SecurityFinding object.
    """
    
    def _resolve_context(self, parsed_file: ParsedFile, symbol) -> tuple[str, str]:
        function_name = ""
        class_name = ""

        func_by_id = {f.symbol_id: f for f in parsed_file.functions}
        cls_by_id  = {c.symbol_id: c for c in parsed_file.classes}

        if symbol.__class__.__name__ == "FunctionSymbol":
            function_name = symbol.context.get("name", [symbol.name])[0] if symbol.context and "name" in symbol.context else symbol.name
            parent_cls = cls_by_id.get(symbol.parent_id)
            if parent_cls:
                class_name = parent_cls.context.get("name", [parent_cls.name])[0] if parent_cls.context and "name" in parent_cls.context else parent_cls.name
        elif symbol.__class__.__name__ == "ClassSymbol":
            class_name = symbol.context.get("name", [symbol.name])[0] if symbol.context and "name" in symbol.context else symbol.name
        else:
            parent_func = func_by_id.get(symbol.parent_id)
            if parent_func:
                fname = parent_func.context.get("name", [parent_func.name])[0] if parent_func.context and "name" in parent_func.context else parent_func.name
                function_name = fname
                parent_cls = cls_by_id.get(parent_func.parent_id)
                if parent_cls:
                    cname = parent_cls.context.get("name", [parent_cls.name])[0] if parent_cls.context and "name" in parent_cls.context else parent_cls.name
                    class_name = cname
            else:
                parent_cls = cls_by_id.get(symbol.parent_id)
                if parent_cls:
                    cname = parent_cls.context.get("name", [parent_cls.name])[0] if parent_cls.context and "name" in parent_cls.context else parent_cls.name
                    class_name = cname

        return function_name, class_name

    def build(self, matches: List[RuleMatch], parsed_file: ParsedFile, file_name: str) -> List[SecurityFinding]:
        findings = []
        
        for match in matches:
            function_name, class_name = self._resolve_context(parsed_file, match.symbol)
            
            finding = SecurityFinding(
                rule_id=match.rule_id,
                category=match.category,
                severity=match.severity,
                confidence=match.confidence,
                language=parsed_file.language,
                file=file_name,
                file_id=parsed_file.file_id,
                symbol_id=match.symbol.symbol_id,
                line=match.symbol.line,
                snippet=match.symbol.snippet,
                recommendation=match.recommendation,
                description=match.description,
                function_name=function_name,
                class_name=class_name,
            )
            findings.append(finding)
            
        return findings
