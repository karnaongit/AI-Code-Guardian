import ast


DANGEROUS_FUNCTIONS = {
    "eval",
    "exec",
    "system",
    "popen",
    "run",
    "call",
    "check_output",
    "loads"
}


class PythonParser(ast.NodeVisitor):

    def __init__(self):

        self.functions = []
        self.classes = []
        self.imports = []
        self.variables = []
        self.calls = []
        self.constants = []
        self.dangerous_calls = []

    def parse(self, source_code):

        try:
            tree = ast.parse(source_code)

        except SyntaxError:
            return None

        self.visit(tree)

        metrics = {
            "lines": len(source_code.splitlines()),
            "functions": len(self.functions),
            "classes": len(self.classes),
            "imports": len(self.imports),
            "variables": len(self.variables)
        }

        return {
            "functions": self.functions,
            "classes": self.classes,
            "imports": self.imports,
            "variables": self.variables,
            "calls": self.calls,
            "constants": self.constants,
            "dangerous_calls": self.dangerous_calls,
            "metrics": metrics
        }

    def visit_FunctionDef(self, node):

        self.functions.append(node.name)

        self.generic_visit(node)

    def visit_ClassDef(self, node):

        self.classes.append(node.name)

        self.generic_visit(node)

    def visit_Import(self, node):

        for alias in node.names:
            self.imports.append(alias.name)

    def visit_ImportFrom(self, node):

        if node.module:
            self.imports.append(node.module)

    def visit_Assign(self, node):

        for target in node.targets:

            if isinstance(target, ast.Name):

                self.variables.append(target.id)

        if isinstance(node.value, ast.Constant):

            self.constants.append(node.value.value)

        self.generic_visit(node)

    def visit_Call(self, node):

        function_name = ""

        if isinstance(node.func, ast.Name):

            function_name = node.func.id

        elif isinstance(node.func, ast.Attribute):

            function_name = node.func.attr

        if function_name:

            self.calls.append(function_name)

            if function_name in DANGEROUS_FUNCTIONS:

                self.dangerous_calls.append(
                    {
                        "function": function_name,
                        "line": node.lineno
                    }
                )

        self.generic_visit(node)