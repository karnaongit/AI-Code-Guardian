import traceback
import logging
from dataclasses import asdict

logger = logging.getLogger(__name__)
from typing import Optional
import contextlib

from services.github_service import GitHubService
from scanner.parser import UniversalParser
from scanner.intelligence.execution_builder import ExecutionTreeBuilder
from scanner.security_engine import SecurityEngine
from scanner.intelligence import IntelligenceEngine
from scanner.serializer import ResponseSerializer
from rag.faiss_manager import VectorStore
from rag.pipeline import RAGPipeline
from scanner.language_manager import LanguageManager
from scanner.language_learning.manager import LanguageLearningManager

class AnalysisService:

    def __init__(
        self,
        github_service: Optional[GitHubService] = None,
        parser: Optional[UniversalParser] = None,
        security_engine: Optional[IntelligenceEngine] = None,
        rag_pipeline: Optional[RAGPipeline] = None,
        vector_store: Optional[VectorStore] = None,
    ):
        self.github = github_service or GitHubService()
        self.parser = parser or UniversalParser()
        self.security = security_engine or IntelligenceEngine()
        self.rag = rag_pipeline or RAGPipeline()
        self.vector_store = vector_store or VectorStore()
        # self.language_manager = LanguageManager()
    def analyze_repository(self, repo_name: str, extracted_dir: Optional[str] = None):
        import tempfile

        # -----------------------------------------
        # Repository Information
        # -----------------------------------------
        if extracted_dir:
            repository = {"owner": "local", "name": repo_name}
            logger.info(f"Local Repository Details: {repository}")
            temp_dir_context = contextlib.nullcontext(extracted_dir)
        else:
            repository = self.github.get_repository(repo_name)
            logger.info(f"Repository Details: {repository}")
            logger.info(f"Repository Type: {type(repository)}")
            temp_dir_context = tempfile.TemporaryDirectory()

        # We wrap the entire process in a temporary directory
        with temp_dir_context as temp_dir:
            
            if not extracted_dir:
                # Download and extract the repository lightweightly
                self.github.download_and_extract(repo_name, temp_dir)

            # -----------------------------------------
            # Fetch source Files
            # -----------------------------------------
            source_files = self.github.get_source_files(temp_dir)

            analysis_results = []

            total_findings = 0
            total_functions = 0
            total_classes = 0
            total_imports = 0
            total_lines = 0

            # -----------------------------------------
            # Analyze Every source File
            # -----------------------------------------
            for file in source_files:

                try:

                    source_code = self.github.get_file_content(
                        file["local_path"]
                    )
                    file["content"] = source_code

                    if not source_code:
                        continue

                    language_name, language = LanguageManager.detect_language(
                        file["path"]
                    )

                    # -------------------------
                    # AST Analysis
                    # -------------------------
                    logger.info(f"Parsing : {file['path']}")
                    analysis = self.parser.parse(
                        source_code,
                        file["path"]
                    )
                    logger.info("Parser completed successfully")

                    # -------------------------
                    # Security Scan
                    # -------------------------
                    security = self.security.scan(
                            analysis,
                            file["path"],
                        )
                    
                    logger.info(file["path"])
                    logger.info(f"Findings: {len(security.findings)}")
                    logger.info(security.findings)

                    # -------------------------
                    # RAG Enhancement is now handled by InvestigationService
                    # -------------------------
                    
                    # -------------------------
                    # Metrics
                    # -------------------------
                    if analysis:

                        total_functions += len(analysis.functions)
                        total_classes += len(analysis.classes)
                        total_imports += len(analysis.imports)

                        total_lines += (
                            len(source_code.splitlines())
                            if source_code
                            else 0
                        )

                    total_findings += len(security.findings)

                    # -------------------------
                    # Serialize
                    # -------------------------
                    serialized_security = ResponseSerializer.serialize(security)

                    analysis_results.append(
                        {
                            "file": file["path"],
                            "analysis": ResponseSerializer.serialize(analysis),
                            "security": serialized_security,
                            "parsed_file": analysis,
                            "findings": security.findings,
                        }
                    )

                except Exception as e:

                    logger.error("=" * 80)
                    logger.error(f"FAILED FILE : {file['path']}")
                    logger.error(f"EXCEPTION   : {type(e).__name__}")
                    logger.error(f"MESSAGE     : {e}")
                    logger.error("=" * 80)

                    traceback.print_exc()

                    analysis_results.append(
                        {
                            "file": file["path"],
                            "error": str(e),
                            "exception": type(e).__name__,
                        }
                    )
            # Build the Knowledge Graph
            from scanner.intelligence.knowledge_graph import KnowledgeGraphBuilder
            from scanner.intelligence.semantic_resolver import SemanticResolver
            from scanner.intelligence.risk_engine import RiskPropagationEngine
            from scanner.intelligence.tree_service import TreeService
            
            logger.info("Building Knowledge Graph...")
            
            # Extract ParsedFiles and Findings from analysis_results
            all_parsed_files = [res["parsed_file"] for res in analysis_results if "parsed_file" in res]
            all_findings = [f for res in analysis_results if "findings" in res for f in res["findings"]]
            
            graph_builder = KnowledgeGraphBuilder(repo_name)
            raw_graph = graph_builder.build(all_parsed_files, all_findings)
            
            logger.info("Running Semantic Resolution...")
            semantic_resolver = SemanticResolver()
            graph = semantic_resolver.resolve(raw_graph)
            
            logger.info(f"Semantic Graph built with {len(graph.nodes)} nodes and {len(graph.edges)} edges.")
            
            # Risk Propagation
            logger.info("Running Risk Propagation Engine...")
            risk_engine = RiskPropagationEngine()
            graph = risk_engine.propagate(graph)
            
            # Tree Service
            logger.info("Generating Intelligence Trees...")
            tree_service = TreeService()
            structure_view = tree_service.get_structure_view(graph)
            directory_view = tree_service.get_directory_view(graph)
            security_view = tree_service.get_security_view(graph)

            # Neo4j Projection
            logger.info("Projecting Graph into Neo4j...")
            try:
                from scanner.intelligence.neo4j_adapter import Neo4jAdapter
                adapter = Neo4jAdapter()
                adapter.project_graph(graph, repo_name)
                adapter.close()
            except Exception as e:
                logger.error(f"Failed to project graph to Neo4j: {e}")

            # Build and save the repository index for RAG queries
            if not self.vector_store.exists(index_name=repo_name):
                logger.info("Building RAG Index (this may take some time on CPU)...")
                documents, metadata = self.vector_store.build_repository_documents(
                    repo_name,
                    source_files
                )
                logger.info(f"Repository documents: {len(documents)}")
                
                if documents:
                    self.vector_store.build_index(documents, metadata)
                    self.vector_store.save(index_name=repo_name)
            else:
                logger.info(f"RAG Index for {repo_name} already exists. Skipping embedding generation.")

            # Build flat list of findings for the frontend to easily reference
            flat_findings = []
            execution_views = {}
            for finding in all_findings:
                flat_findings.append({
                    "finding_id": finding.finding_id,
                    "symbol_id": finding.symbol_id,
                    "file_id": finding.file_id,
                    "rule": finding.rule_id,
                    "category": finding.category,
                    "severity": finding.severity,
                    "line": finding.line,
                    "message": finding.description,
                    "function": finding.function_name,
                    "file": finding.file
                })
                # Add execution path for each finding
                execution_views[finding.finding_id] = tree_service.get_execution_view(graph, finding.finding_id)

            repo_node = next((n for n in graph.nodes.values() if n.type == "Repository"), None)
            repo_risk = repo_node.properties.get("risk_weight", 0) if repo_node else 0

            entry_points = tree_service.get_entry_points(graph)
            global_execution_views = {}
            for ep in entry_points:
                global_execution_views[ep["id"]] = tree_service.get_global_execution_view(graph, ep["id"])

            summary_counts = {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0
            }
            for finding in all_findings:
                sev = finding.severity.upper()
                if sev in summary_counts:
                    summary_counts[sev] += 1

            return {
                "summary": {
                    "repository": f"{repository['owner']}/{repository['name']}",
                    "files_scanned": len(source_files),
                    "functions": total_functions,
                    "classes": total_classes,
                    "imports": total_imports,
                    "lines": total_lines,
                    "security_findings_count": total_findings,
                    "repository_risk_score": repo_risk,
                    "critical_findings": summary_counts["CRITICAL"],
                    "high_findings": summary_counts["HIGH"],
                    "medium_findings": summary_counts["MEDIUM"],
                    "low_findings": summary_counts["LOW"]
                },
                "security_findings": flat_findings,
                "structure_view": structure_view,
                "directory_view": directory_view,
                "security_view": security_view,
                "execution_views": execution_views,
                "entry_points": entry_points,
                "global_execution_views": global_execution_views,
                "graph": graph
            }