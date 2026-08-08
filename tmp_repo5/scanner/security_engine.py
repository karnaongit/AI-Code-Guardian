from typing import Optional
from scanner.models import (
    ParsedFile,
    ScanResult,
    SecurityFinding,
)

from scanner.security_rules import RULES
from scanner.intelligence.capability_mapper import CapabilityMapper

class SecurityEngine:
    SUSPICIOUS_VARIABLE_NAMES = {
        "password": "HARDCODED_PASSWORD",
        "passwd": "HARDCODED_PASSWORD",
        "pwd": "HARDCODED_PASSWORD",
        "secret": "HARDCODED_SECRET",
        "api_key": "HARDCODED_SECRET",
        "apikey": "HARDCODED_SECRET",
        "token": "HARDCODED_TOKEN",
        "access_key": "HARDCODED_SECRET",
        "private_key": "HARDCODED_SECRET",
        "client_secret": "HARDCODED_SECRET",
    }

    CAPABILITY_MAPPINGS = {
        "execute_sql_query": "CAP_SQL_INJECTION",
        "execute_os_command": "CAP_COMMAND_INJECTION",
        "unsafe_evaluation": "CAP_UNSAFE_EVAL",
        "read_file": "CAP_PATH_TRAVERSAL",
        "write_file": "CAP_PATH_TRAVERSAL",
        "make_http_request": "CAP_SSRF",
        "parse_xml": "CAP_XXE",
    }

    def __init__(self, capability_mapper: Optional[CapabilityMapper] = None):
        self.findings = []
        self.capability_mapper = capability_mapper or CapabilityMapper()

    # ------------------------------------------------------------------
    # Symbol Context Resolution
    # ------------------------------------------------------------------

    def _resolve_context(self, parsed, symbol):
        """
        Given a matched symbol (Call, Import, Variable, Constant), return
        (function_name, class_name) by walking the parent_id chain through
        the already-resolved symbols in the ParsedFile.

        SymbolBuilder.build() sets symbol_id and parent_id on every symbol.
        A Call whose parent_id == a Function's symbol_id is inside that function.
        A Function whose parent_id == a Class's symbol_id is a method of that class.
        """
        function_name = ""
        class_name = ""

        # Build fast lookup maps from symbol_id
        func_by_id = {f.symbol_id: f for f in parsed.functions}
        cls_by_id  = {c.symbol_id: c for c in parsed.classes}

        # Step 1: is the symbol directly inside a function?
        parent_func = func_by_id.get(symbol.parent_id)
        if parent_func:
            fname = parent_func.context.get("name", [parent_func.name])[0] if parent_func.context and "name" in parent_func.context else parent_func.name
            function_name = fname
            # Step 2: is that function inside a class?
            parent_cls = cls_by_id.get(parent_func.parent_id)
            if parent_cls:
                cname = parent_cls.context.get("name", [parent_cls.name])[0] if parent_cls.context and "name" in parent_cls.context else parent_cls.name
                class_name = cname
        else:
            # Symbol may be directly inside a class (e.g. a class-level call)
            parent_cls = cls_by_id.get(symbol.parent_id)
            if parent_cls:
                cname = parent_cls.context.get("name", [parent_cls.name])[0] if parent_cls.context and "name" in parent_cls.context else parent_cls.name
                class_name = cname

        return function_name, class_name

    def scan(
        self,
        parsed: ParsedFile,
        file_name: str,
    ) -> ScanResult:

        self.findings = []

        # Phase 2: Capability Mapping
        # We classify nodes before we scan them
        try:
            self.capability_mapper.map_capabilities(parsed)
        except Exception as e:
            print(f"Warning: Capability mapping failed - {e}")

        self._scan_calls(
            parsed,
            file_name,
        )

        self._scan_imports(
            parsed,
            file_name,
        )
        self._scan_constants(
            parsed,
            file_name,
        )
        self._scan_variables(
            parsed,
            file_name,
        )
        
        # New capability scan
        try:
            self._scan_capabilities(parsed, file_name)
        except Exception as e:
            print(f"Warning: Capability scan failed - {e}")

        return ScanResult(
            target=file_name,
            files_scanned=1,
            findings=self.findings,
        )
        
        # -------------------------------------------------------
    # Calls
    # -------------------------------------------------------

    def _scan_calls(
        self,
        parsed: ParsedFile,
        file_name: str,
    ) -> None:

        for call in parsed.calls:

            rule = RULES.get(call.name)

            if rule is None:
                continue

            function_name, class_name = self._resolve_context(parsed, call)

            finding = SecurityFinding(
                title=rule.get("title", rule["category"]),
                rule_id=rule.get("rule_id", "CUSTOM"),
                category=rule["category"],
                severity=rule["severity"],
                confidence=rule.get("confidence", 1.0),
                language=parsed.language,
                file=file_name,
                file_id=parsed.file_id,
                line=call.line,
                snippet=call.snippet,
                recommendation=rule["recommendation"],
                cwe=rule.get("cwe", ""),
                owasp=rule.get("owasp", ""),
                description=rule.get("description", ""),
                # Traceability: link finding to its containing symbol
                symbol_id=call.symbol_id,
                function_name=function_name,
                class_name=class_name,
            )

            self.findings.append(finding)
    # -------------------------------------------------------
    # Imports
    # -------------------------------------------------------

    def _scan_imports(
    self,
    parsed: ParsedFile,
    file_name: str,
) -> None:

        for imported in parsed.imports:

            rule = RULES.get(imported.name)

            if rule is None:
                continue

            function_name, class_name = self._resolve_context(parsed, imported)

            finding = SecurityFinding(
                title=rule.get("title", rule["category"]),
                rule_id=rule.get("rule_id", "CUSTOM"),
                category=rule["category"],
                severity=rule["severity"],
                confidence=rule.get("confidence", 1.0),
                language=parsed.language,
                file=file_name,
                file_id=parsed.file_id,
                line=imported.line,
                snippet=imported.snippet,
                recommendation=rule["recommendation"],
                cwe=rule.get("cwe", ""),
                owasp=rule.get("owasp", ""),
                description=rule.get("description", ""),
                symbol_id=imported.symbol_id,
                function_name=function_name,
                class_name=class_name,
            )

            self.findings.append(finding)

    # -------------------------------------------------------
    # Variables
    # -------------------------------------------------------

    def _scan_variables(
    self,
    parsed: ParsedFile,
    file_name: str,
) -> None:
        for variable in parsed.variables:
            name = variable.name.lower()
            for keyword, rule_name in self.SUSPICIOUS_VARIABLE_NAMES.items():

                if keyword not in name:
                    continue

                rule = RULES[rule_name]
                function_name, class_name = self._resolve_context(parsed, variable)

                self.findings.append(
                    SecurityFinding(
                        title=rule.get("title", rule["category"]),
                        rule_id="CUSTOM",
                        category=rule["category"],
                        severity=rule["severity"],
                        confidence=1.0,
                        language=parsed.language,
                        file=file_name,
                        file_id=parsed.file_id,
                        line=variable.line,
                        snippet=variable.snippet,
                        recommendation=rule["recommendation"],
                        cwe=rule.get("cwe", ""),
                        owasp=rule.get("owasp", ""),
                        description=rule.get("description", ""),
                        symbol_id=variable.symbol_id,
                        function_name=function_name,
                        class_name=class_name,
                    )
                )

                break

    # -------------------------------------------------------
    # Constants
    # -------------------------------------------------------

    def _scan_constants(
    self,
    parsed: ParsedFile,
    file_name: str,
) -> None:
        for constant in parsed.constants:
            name = constant.name.lower()
            rule = None
            if any(keyword in name for keyword in ("secret", "apikey", "api_key", "access_key", "private_key", "client_secret")):
                rule = RULES["HARDCODED_SECRET"]

            elif any(keyword in name for keyword in ("password", "passwd", "pwd")):
                rule = RULES["HARDCODED_PASSWORD"]

            elif "token" in name:
                rule = RULES["HARDCODED_TOKEN"]

            if rule is None:
                continue

            function_name, class_name = self._resolve_context(parsed, constant)

            self.findings.append(
                SecurityFinding(
                    title=rule.get("title", rule["category"]),
                    rule_id="CUSTOM",
                    category=rule["category"],
                    severity=rule["severity"],
                    confidence=1.0,
                    language=parsed.language,
                    file=file_name,
                    file_id=parsed.file_id,
                    line=constant.line,
                    snippet=constant.snippet,
                    recommendation=rule["recommendation"],
                    cwe=rule.get("cwe", ""),
                    owasp=rule.get("owasp", ""),
                    description=rule.get("description", ""),
                    symbol_id=constant.symbol_id,
                    function_name=function_name,
                    class_name=class_name,
                )
            )

    # -------------------------------------------------------
    # Phase 2: Capabilities
    # -------------------------------------------------------

    def _scan_capabilities(
        self,
        parsed: ParsedFile,
        file_name: str,
    ) -> None:
        """
        Scans for high-level abstract behaviors rather than exact string matches.
        """
        # Check all calls
        for call in getattr(parsed, 'calls', []):
            if hasattr(call, 'capability') and call.capability in self.CAPABILITY_MAPPINGS:
                rule_name = self.CAPABILITY_MAPPINGS[call.capability]
                rule = RULES[rule_name]
                function_name, class_name = self._resolve_context(parsed, call)

                self.findings.append(
                    SecurityFinding(
                        title=rule.get("title", rule["category"]),
                        rule_id=rule.get("rule_id", "CAP-CUSTOM"),
                        category=rule["category"],
                        severity=rule["severity"],
                        confidence=rule.get("confidence", 0.8),
                        language=parsed.language,
                        file=file_name,
                        file_id=parsed.file_id,
                        line=call.line,
                        snippet=call.snippet,
                        recommendation=rule["recommendation"],
                        capability=call.capability,
                        matched_rule=rule_name,
                        cwe=rule.get("cwe", ""),
                        owasp=rule.get("owasp", ""),
                        description=rule.get("description", ""),
                        symbol_id=call.symbol_id,
                        function_name=function_name,
                        class_name=class_name,
                    )
                )

        # Check all variables
        for variable in getattr(parsed, 'variables', []):
            if hasattr(variable, 'capability') and variable.capability in self.CAPABILITY_MAPPINGS:
                rule_name = self.CAPABILITY_MAPPINGS[variable.capability]
                rule = RULES[rule_name]
                function_name, class_name = self._resolve_context(parsed, variable)

                self.findings.append(
                    SecurityFinding(
                        title=rule.get("title", rule["category"]),
                        rule_id=rule.get("rule_id", "CAP-CUSTOM"),
                        category=rule["category"],
                        severity=rule["severity"],
                        confidence=rule.get("confidence", 0.8),
                        language=parsed.language,
                        file=file_name,
                        file_id=parsed.file_id,
                        line=variable.line,
                        snippet=variable.snippet,
                        recommendation=rule["recommendation"],
                        capability=variable.capability,
                        matched_rule=rule_name,
                        cwe=rule.get("cwe", ""),
                        owasp=rule.get("owasp", ""),
                        description=rule.get("description", ""),
                        symbol_id=variable.symbol_id,
                        function_name=function_name,
                        class_name=class_name,
                    )
                )