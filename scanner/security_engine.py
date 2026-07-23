import ast
from scanner.security_rules import RULES
from scanner.models import SecurityFinding, ScanResult


class SecurityEngine(ast.NodeVisitor):

    def __init__(self):
        self.findings = []

    def scan_source(self, source_code, file_name="Current File"):

        self.findings = []
        self.file_name = file_name

        try:
            tree = ast.parse(source_code)
            self.visit(tree)

        except Exception:
            pass

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

            category, severity, recommendation = RULES[function_name]

            self.findings.append(
                SecurityFinding(
                    category=category,
                    severity=severity,
                    file=self.file_name,
                    line=node.lineno,
                    snippet=function_name,
                    recommendation=recommendation
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