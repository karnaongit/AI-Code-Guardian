"""
AI Code Guardian v3 — Knowledge Layer Configuration
===================================================
Defines configuration schemas for Embedding Models, Qdrant Vector DB,
and Neo4j Knowledge Graph.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class EmbeddingConfig:
    """Configures vector embedding models."""
    model_name: str = "all-MiniLM-L6-v2"
    codebert_model_name: str = "microsoft/codebert-base"
    device: str = "cpu"
    batch_size: int = 32
    normalize_embeddings: bool = True
    cache_embeddings: bool = True
    load_local_model: bool = False       # opt in to sentence-transformers; fallback is offline


@dataclass
class QdrantConfig:
    """Configures Qdrant Vector Store connection and indexing."""
    host: str = "localhost"
    port: int = 6333
    grpc_port: int = 6334
    api_key: Optional[str] = None
    location: str = field(default_factory=lambda: os.getenv("QDRANT_LOCATION", ":memory:"))  # Use ":memory:" for in-memory or host URL for server
    default_collection: str = "acg_semantic_docs"
    vector_size: int = 384                 # Dimension for all-MiniLM-L6-v2
    distance_metric: str = "Cosine"
    repository_isolation: bool = True


@dataclass
class Neo4jConfig:
    """Configures Neo4j Knowledge Graph connection."""
    uri: str = field(default_factory=lambda: os.getenv("NEO4J_URI", "bolt://localhost:7687"))
    user: str = field(default_factory=lambda: os.getenv("NEO4J_USER", "neo4j"))
    password: str = field(default_factory=lambda: os.getenv("NEO4J_PASSWORD", "password"))
    database: str = field(default_factory=lambda: os.getenv("NEO4J_DATABASE", "neo4j"))
    fallback_to_inmemory: bool = True     # Gracefully fall back to NetworkX/In-Memory graph if server offline


@dataclass
class KnowledgeConfig:
    """Master configuration for the Knowledge Layer."""
    embedding: EmbeddingConfig = field(default_factory=EmbeddingConfig)
    qdrant: QdrantConfig = field(default_factory=QdrantConfig)
    neo4j: Neo4jConfig = field(default_factory=Neo4jConfig)
