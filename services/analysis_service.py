from services.github_service import GitHubService
from scanner.parser import PythonParser
from scanner.security_engine import SecurityEngine
from scanner.serializer import ResponseSerializer

class AnalysisService:

    def __init__(self):
        self.github = GitHubService()
        self.parser = PythonParser()
        self.security = SecurityEngine()

    def analyze_repository(self, repo_name: str):

        # -----------------------------------------
        # Repository Information
        # -----------------------------------------
        repository = self.github.get_repository(repo_name)

        # -----------------------------------------
        # Fetch Python Files
        # -----------------------------------------
        python_files = self.github.get_python_files(repo_name)

        analysis_results = []

        total_findings = 0
        total_functions = 0
        total_classes = 0
        total_imports = 0
        total_lines = 0

        # -----------------------------------------
        # Analyze Every Python File
        # -----------------------------------------
        for file in python_files:

            try:

                source_code = self.github.get_file_content(
                    file["download_url"]
                )

                if not source_code:
                    continue

                # -------------------------
                # AST Analysis
                # -------------------------
                analysis = self.parser.parse(source_code)

                # -------------------------
                # Security Scan
                # -------------------------
                security = self.security.scan_source(
                    source_code,
                    file["path"]
                )

                if analysis:

                    metrics = analysis["metrics"]

                    total_functions += metrics["functions"]
                    total_classes += metrics["classes"]
                    total_imports += metrics["imports"]
                    total_lines += metrics["lines"]

                total_findings += security.total_findings

                # -------------------------
                # Convert Security Findings
                # -------------------------
                serialized_security = ResponseSerializer.serialize(security)

                analysis_results.append(
    {
        "file": file["path"],
        "analysis": ResponseSerializer.serialize(analysis),
        "security": serialized_security,
    }
)

            except Exception as e:

                analysis_results.append(
                    {
                        "file": file["path"],
                        "error": str(e),
                    }
                )
        return {
    "summary": {
        "files_scanned": len(python_files),
        "functions": total_functions,
        "classes": total_classes,
        "imports": total_imports,
        "lines": total_lines,
        "security_findings": total_findings,
    }
}
        