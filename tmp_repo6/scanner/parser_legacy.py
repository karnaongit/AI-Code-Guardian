import ast
from pathlib import Path
from platform import node
from dotenv import parser
from dotenv import parser
from tree_sitter import Parser
from tree_sitter_language_pack import get_language

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
class UniversalParser(ast.NodeVisitor):

    def __init__(self):
        self.functions = []
        self.classes = []
        self.imports = []
        self.variables = []
        self.calls = []
        self.constants = []
        self.dangerous_calls = []

    def parse(self, source_code, filename):
        
        extension = Path(filename).suffix.lower()

        if extension == ".py":
            return self._parse_python(source_code)

        return self._parse_tree_sitter(
            source_code,
            extension
        )

    def _parse_python(self, source_code):
        # ----------------------------------
        # Reset parser state for each file
        # ----------------------------------
        self.functions = []
        self.classes = []
        self.imports = []
        self.variables = []
        self.calls = []
        self.constants = []
        self.dangerous_calls = []
        
        

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
        
    def _parse_tree_sitter(self, source_code, extension):
        self.language = extension
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
            return None

        language = get_language(language_name)
        parser = Parser(language)
        
        tree = parser.parse(bytes(source_code, "utf8"))
        
        
        root = tree.root_node
        print(tree.root_node.type)
        print(root.type)
        
        print(f"Extension: {extension}")
        print(f"Language: {language_name}")

        self.functions = []
        self.classes = []
        self.imports = []
        self.variables = []
        self.calls = []
        self.constants = []
        self.dangerous_calls = []

        self._walk_tree(root)

        return {
            "functions": self.functions,
            "classes": self.classes,
            "imports": self.imports,
            "variables": self.variables,
            "calls": self.calls,
            "constants": self.constants,
            "dangerous_calls": self.dangerous_calls,
            "metrics": {
                "lines": len(source_code.splitlines()),
                "functions": len(self.functions),
                "classes": len(self.classes),
                "imports": len(self.imports),
                "variables": len(self.variables),
            },
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

            value = node.value.value

            if isinstance(value, bytes):
                value = repr(value)

            self.constants.append(value)

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
        
  