import faiss
import pickle
import logging
from typing import List, Dict, Tuple

import numpy as np
from sentence_transformers import SentenceTransformer

from rag.config import (
    EMBEDDING_MODEL,
    INDEX_PATH,
    METADATA_PATH,
    VALID_SOURCES,
)

logging.basicConfig(level=logging.INFO)


class VectorStore:
    """
    Responsible for:

    1. Creating semantic documents
    2. Creating embeddings
    3. Building FAISS index
    4. Saving index
    5. Loading index
    """

    def __init__(self):

        logging.info("Loading embedding model...")

        self.model = SentenceTransformer(
            EMBEDDING_MODEL
        )

        self.index = None
        self.metadata = []

    # --------------------------------------------------

    def build_documents(
        self,
        dataframe
    ) -> Tuple[List[str], List[Dict]]:
        logging.info(f"Documents before filtering: {len(dataframe)}")

        dataframe = dataframe[
            dataframe["source"].isin(VALID_SOURCES)
        ].reset_index(drop=True)

        logging.info(f"Documents after filtering: {len(dataframe)}")

        documents = []
        metadata = []

        for idx, row in dataframe.iterrows():

            document = f"""
# Python Application Security Knowledge

Source:
{row["source"]}

Knowledge Type:
Security Vulnerability Reference

Vulnerability:
{row["vulnerability"]}

Description:
{row["description"]}

Recommendation:
{row["recommendation"]}

Reference:
{row["url"]}

This document provides guidance for identifying, understanding,
and mitigating Python application security vulnerabilities.
"""

            documents.append(document)

            metadata.append(
{
    "id": idx,
    "source": row["source"],
    "vulnerability": row["vulnerability"],
    "description": row["description"],
    "recommendation": row["recommendation"],
    "url": row["url"],

    # Future filtering support
    "language": "python",
    "document_type": "security_reference",
}
)

        logging.info(
            f"{len(documents)} knowledge documents created."
        )

        return documents, metadata

    # --------------------------------------------------

    def build_index(
        self,
        documents: List[str],
        metadata: List[Dict],
    ):

        logging.info(
            "Generating embeddings..."
        )

        embeddings = self.model.encode(
            documents,
            convert_to_numpy=True,
            normalize_embeddings=True,
            show_progress_bar=True,
        )

        dimension = embeddings.shape[1]

        self.index = faiss.IndexFlatIP(
            dimension
        )

        self.index.add(
            embeddings.astype(np.float32)
        )

        self.metadata = metadata

        logging.info(
            f"FAISS index created with {self.index.ntotal} vectors."
        )

    def _get_paths(self, index_name: str):
        safe_name = index_name.replace("/", "_")
        from rag.config import VECTOR_STORE_DIR
        idx_path = VECTOR_STORE_DIR / f"{safe_name}.index"
        meta_path = VECTOR_STORE_DIR / f"{safe_name}_metadata.pkl"
        return idx_path, meta_path

    def save(self, index_name="security"):

        if self.index is None:
            raise ValueError(
                "No FAISS index to save."
            )
            
        idx_path, meta_path = self._get_paths(index_name)

        faiss.write_index(
            self.index,
            str(idx_path),
        )

        with open(
            meta_path,
            "wb",
        ) as file:

            pickle.dump(
                self.metadata,
                file,
            )

        logging.info(
            f"Vector store '{index_name}' saved successfully."
        )

    # --------------------------------------------------

    def load(self, index_name="security"):

        idx_path, meta_path = self._get_paths(index_name)
        self.index = faiss.read_index(
            str(idx_path)
        )

        with open(
            meta_path,
            "rb",
        ) as file:

            self.metadata = pickle.load(file)

        logging.info(
            f"{self.index.ntotal} vectors loaded for '{index_name}'."
        )

    # --------------------------------------------------

    def exists(self, index_name="security"):
        idx_path, meta_path = self._get_paths(index_name)
        return (
            idx_path.exists()
            and
            meta_path.exists()
        )
        
        
    
    def build_repository_documents(self, repo_name, source_files):

        documents = []
        metadata = []

        for file in source_files:

            document = f"""
    Repository:
    {repo_name}

    File:
    {file['path']}

    Language:
    {file['extension']}

    Source Code:
    {file['content']}
    """

            documents.append(document)

            metadata.append(
                {
                    "repo": repo_name,
                    "file": file["path"],
                    "language": file["extension"],
                    "document_type": "repository",
                    "content": file["content"],
                }
            )

        return documents, metadata
#         # {
#   "repo_name": "pallets/flask"
# }

    