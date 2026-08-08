import ast
from pathlib import Path
from tree_sitter import Parser
from tree_sitter_language_pack import get_language
from scanner.security_rules import RULES
from scanner.models import SecurityFinding, ScanResult


class SecurityEngine(ast.NodeVisitor):

    def __init__(self):
        self.findings = []
        
    def scan_source(self, source_code, file_name="Current File"):

        extension = Path(file_name).suffix.lower()

        if extension == ".py":
            return self._scan_python(source_code, file_name)

        return self._scan_tree_sitter(source_code, file_name, extension)

    
    
    def _scan_python(self, source_code, file_name="Current File"):

        self.findings = []
        self.file_name = file_name

        try:
            tree = ast.parse(source_code)
            self.visit(tree)

        except Exception as e:
            import traceback
            traceback.print_exc()

        return ScanResult(
            target=file_name,
            files_scanned=1,
            findings=self.findings
        )
        
    def _scan_tree_sitter(self, source_code, file_name, extension):

        self.findings = []
        self.file_name = file_name

        language_map = {
            ".java": "java",
            ".js": "javascript",
            ".ts": "typescript",
            ".cpp": "cpp",
            ".c": "c",
            ".cs": "c_sharp",
            ".go": "go",
            ".rs": "rust",
            ".php": "php",
            ".kt": "kotlin",
        }

        language_name = language_map.get(extension)

        if language_name is None:
            return ScanResult(
                target=file_name,
                files_scanned=1,
                findings=[]
            )

        language = get_language(language_name)

        parser = Parser(language)

        tree = parser.parse(source_code.encode("utf8"))

        print(f"Scanning {file_name}")
        print(tree.root_node.type)

        return ScanResult(
            target=file_name,
            files_scanned=1,
            findings=self.findings
        )

    # ----------------------------------------------------
    # Function Call Scanner
    # ----------------------------------------------------

    def visit_Call(self, node):

        function_name = ""

        if isinstance(node.func, ast.Name):
            function_name = node.func.id

        elif isinstance(node.func, ast.Attribute):
            function_name = node.func.attr

        if function_name in RULES:

            rule = RULES[function_name]

            category = rule["category"]
            severity = rule["severity"]
            recommendation = rule["recommendation"]

            self.findings.append(
    SecurityFinding(
        rule_id=rule.get("rule_id", "CUSTOM"),

        category=rule["category"],
        severity=rule["severity"],
        confidence=rule.get("confidence", 1.0),
        file=self.file_name,
        line=node.lineno,
        snippet=function_name,
        recommendation=rule["recommendation"],
                )
            )

        self.generic_visit(node)

    # ----------------------------------------------------
    # Variable Scanner
    # ----------------------------------------------------

    def visit_Assign(self, node):

        # Ignore things like os.getenv(...)
        if isinstance(node.value, ast.Call):
            self.generic_visit(node)
            return

        # -------------------------
        # Hardcoded Secrets
        # -------------------------

        if (
            isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):

            patterns = [
                "password",
                "passwd",
                "pwd",
                "secret",
                "secret_key",
                "api_key",
                "apikey",
                "access_key",
                "private_key",
                "client_secret",
                "token",
                "bearer",
                "jwt",
                "aws_secret",
                "aws_access_key",
                "aws_access_key_id",
                "aws_secret_access_key"
            ]

            value = node.value.value

            for target in node.targets:

                if isinstance(target, ast.Name):

                    name = target.id.lower()

                    if any(keyword in name for keyword in patterns):

                        self.findings.append(
                            SecurityFinding(
                                category="Hardcoded Secret",
                                severity="High",
                                file=self.file_name,
                                line=node.lineno,
                                snippet=value,
                                recommendation="Move secrets to environment variables."
                            )
                        )

        # -------------------------
        # Debug=True
        # -------------------------

        if (
            isinstance(node.value, ast.Constant)
            and node.value.value is True
        ):

            for target in node.targets:

                if (
                    isinstance(target, ast.Name)
                    and target.id.lower() == "debug"
                ):

                    self.findings.append(
                        SecurityFinding(
                            category="Insecure Configuration",
                            severity="Medium",
                            file=self.file_name,
                            line=node.lineno,
                            snippet="debug=True",
                            recommendation="Disable debug mode in production."
                        )
                    )

        self.generic_visit(node)