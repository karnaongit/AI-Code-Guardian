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

    # --------------------------------------------------

    def save(self):

        if self.index is None:
            raise ValueError(
                "No FAISS index to save."
            )

        faiss.write_index(
            self.index,
            str(INDEX_PATH),
        )

        with open(
            METADATA_PATH,
            "wb",
        ) as file:

            pickle.dump(
                self.metadata,
                file,
            )

        logging.info(
            "Vector store saved successfully."
        )

    # --------------------------------------------------

    def load(self):

        self.index = faiss.read_index(
            str(INDEX_PATH)
        )

        with open(
            METADATA_PATH,
            "rb",
        ) as file:

            self.metadata = pickle.load(file)

        logging.info(
            f"{self.index.ntotal} vectors loaded."
        )

    # --------------------------------------------------

    def exists(self):

        return (
            INDEX_PATH.exists()
            and
            METADATA_PATH.exists()
        )
        
        
        
#         # {
#   "repo_name": "pallets/flask"
# }