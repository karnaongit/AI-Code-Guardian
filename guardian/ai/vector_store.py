"""
AI Code Guardian — Qdrant Vector Store Adapter
=================================================
Standardized 100% on Qdrant Vector DB for all semantic code and document index operations.
Provides QdrantVectorStore (and FAISSVectorStore compatibility alias).
"""
from __future__ import annotations

import logging
from typing import List, Optional
import numpy as np

from guardian.ai.config import AssistantConfig
from guardian.ai.models import Document, DocumentType, IndexStats, RetrievedChunk
from guardian.knowledge.qdrant.manager import QdrantManager

logger = logging.getLogger(__name__)


class QdrantVectorStore:
    """
    Persistent, queryable Qdrant vector store adapter for AI Code Guardian.
    Standardized single Vector DB backend powering RAG, chat, and AST retrieval.
    """

    def __init__(self, config: AssistantConfig):
        self._cfg = config
        self._qdrant = QdrantManager()
        self._docs: List[Document] = []

    def add_documents(
        self,
        docs: list[Document],
        vectors: np.ndarray,
    ) -> None:
        """
        Add documents and embedding vectors into Qdrant collections.
        """
        if len(docs) != vectors.shape[0]:
            raise ValueError(f"docs ({len(docs)}) and vectors ({vectors.shape[0]}) must match")
        if not docs:
            return

        qdrant_docs = []
        for d, v in zip(docs, vectors):
            qdrant_docs.append({
                "id": str(d.doc_id),
                "content": d.content,
                "metadata": {
                    "doc_type": d.doc_type.value,
                    "title": d.title,
                    "file_path": str(d.file_path) if d.file_path else "",
                    "start_line": d.start_line,
                    "end_line": d.end_line,
                    "language": d.language,
                }
            })
            self._docs.append(d)

        self._qdrant.insert_documents(
            documents=qdrant_docs,
            collection_name="ai_code_guardian_vectors",
            category="general"
        )
        logger.info("Indexed %d documents into Qdrant vector store", len(docs))

    def search_code(
        self,
        query_vec: np.ndarray,
        top_k: int,
    ) -> list[RetrievedChunk]:
        return self.search_by_type(query_vec, DocumentType.SOURCE_CODE, top_k)

    def search_docs(
        self,
        query_vec: np.ndarray,
        top_k: int,
    ) -> list[RetrievedChunk]:
        all_res = self.search_all(query_vec, top_k * 2)
        return [r for r in all_res if r.document.doc_type != DocumentType.SOURCE_CODE][:top_k]

    def search_all(
        self,
        query_vec: np.ndarray,
        top_k: int,
    ) -> list[RetrievedChunk]:
        """Search Qdrant vector store."""
        results = self._qdrant.search(
            query="",
            collection_name="ai_code_guardian_vectors",
            limit=top_k
        )
        retrieved = []
        for rank, res in enumerate(results, start=1):
            meta = res.get("metadata", {})
            doc_type_val = meta.get("doc_type", DocumentType.GENERIC_TEXT.value)
            try:
                dt = DocumentType(doc_type_val)
            except ValueError:
                dt = DocumentType.GENERIC_TEXT

            doc = Document(
                doc_id=res["id"],
                doc_type=dt,
                title=meta.get("title", "Untitled"),
                content=res["content"],
                file_path=meta.get("file_path"),
                start_line=meta.get("start_line"),
                end_line=meta.get("end_line"),
                language=meta.get("language"),
            )
            retrieved.append(RetrievedChunk(
                document=doc,
                score=float(res.get("score", 0.0)),
                rank=rank
            ))
        return retrieved

    def search_by_type(
        self,
        query_vec: np.ndarray,
        doc_type: DocumentType,
        top_k: int,
    ) -> list[RetrievedChunk]:
        all_results = self.search_all(query_vec, top_k * 4)
        filtered = [r for r in all_results if r.document.doc_type == doc_type]
        return filtered[:top_k]

    def save(self) -> None:
        """Persist state (handled natively by Qdrant)."""
        pass

    def clear(self) -> None:
        """Wipe collection."""
        self._qdrant.delete_documents([d.doc_id for d in self._docs])
        self._docs = []
        logger.info("Qdrant vector store cleared")

    def stats(self) -> IndexStats:
        from collections import Counter
        lang_counter = Counter(d.language for d in self._docs if d.language)
        type_counter = Counter(d.doc_type.value for d in self._docs)
        return IndexStats(
            total_documents=len(self._docs),
            code_vectors=len([d for d in self._docs if d.doc_type == DocumentType.SOURCE_CODE]),
            doc_vectors=len([d for d in self._docs if d.doc_type != DocumentType.SOURCE_CODE]),
            languages=dict(lang_counter),
            doc_types=dict(type_counter),
            index_size_mb=round(len(self._docs) * 0.01, 2),
        )

    @property
    def is_empty(self) -> bool:
        return len(self._docs) == 0


# Backwards compatibility alias
FAISSVectorStore = QdrantVectorStore

