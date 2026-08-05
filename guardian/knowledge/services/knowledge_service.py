"""
AI Code Guardian v3 — Unified Knowledge Service
=================================================
The single facade and abstraction layer for all repository knowledge graph queries
and Qdrant semantic vector retrievals.

All future LangGraph agents communicate exclusively with KnowledgeService.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from guardian.discovery.repo_detector import RepositoryProfile
from guardian.knowledge.config import KnowledgeConfig
from guardian.knowledge.embeddings.service import EmbeddingService
from guardian.knowledge.graph.builder import RepositoryGraphBuilder
from guardian.knowledge.graph.manager import Neo4jManager
from guardian.knowledge.qdrant.manager import QdrantManager
from guardian.knowledge.retrieval.engine import RetrievalEngine
from guardian.ust.models import USTFile


class KnowledgeService:
    """Unified repository graph and semantic intelligence facade for AI agents."""

    def __init__(self, config: Optional[KnowledgeConfig] = None):
        self.config = config or KnowledgeConfig()

        self.embedder = EmbeddingService(self.config.embedding)
        self.qdrant = QdrantManager(self.config.qdrant, embedder=self.embedder)
        self.neo4j = Neo4jManager(self.config.neo4j)
        self.graph_builder = RepositoryGraphBuilder(self.neo4j)
        self.retrieval = RetrievalEngine(self.qdrant, self.neo4j)

    def build_repository_graph(
        self,
        repo_path: Path,
        profile: RepositoryProfile,
        ust_files: Optional[List[USTFile]] = None
    ) -> Dict[str, int]:
        """Populates Neo4j knowledge graph from repository files, profile, and UST AST nodes."""
        return self.graph_builder.build_graph(repo_path, profile, ust_files)

    def index_documents(
        self,
        documents: List[Dict[str, Any]],
        category: str = "documentation",
        repo_id: str = "default"
    ) -> List[str]:
        """Indexes semantic text documents (README, specs, policies, OWASP/NIST) into Qdrant."""
        return self.qdrant.insert_documents(
            documents=documents,
            category=category,
            repo_id=repo_id
        )

    def semantic_search(
        self,
        query: str,
        limit: int = 5,
        category: Optional[str] = None,
        repo_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Performs semantic vector retrieval against indexed documents."""
        return self.qdrant.search(
            query=query,
            limit=limit,
            category_filter=category,
            repo_id_filter=repo_id
        )

    def get_symbol_graph(self, symbol_or_func: str) -> Dict[str, Any]:
        """Retrieves graph topology (calls, imports, enclosing class) for a given symbol."""
        return self.retrieval.find_connected_symbols(symbol_or_func)

    def get_endpoints(self) -> List[Dict[str, Any]]:
        """Retrieves all API endpoints registered in the repository knowledge graph."""
        return self.retrieval.get_endpoints()

    def get_architecture_context(self, repo_name: str) -> Dict[str, Any]:
        """Retrieves architecture shape, file counts, and graph topology summary."""
        return self.retrieval.get_repository_topology(repo_name)

    def get_related_files(self, file_path: str) -> List[str]:
        """Retrieves files imported by or connected to a target file in the knowledge graph."""
        file_node_id = f"file:{file_path}"
        imports = self.neo4j.get_outgoing_relationships(file_node_id, Neo4jManager.REL_IMPORTS)
        return [imp.target_id.replace("module:", "") for imp in imports]

    def close(self):
        """Cleanly releases database resources."""
        self.neo4j.close()
