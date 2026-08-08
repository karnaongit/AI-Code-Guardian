import logging
from typing import Dict, List

import numpy as np

from rag.faiss_manager import VectorStore
from rag.config import TOP_K

logging.basicConfig(level=logging.INFO)


class Retriever:
    """
    Responsible for:

    1. Loading the FAISS index.
    2. Converting search query into embedding.
    3. Searching similar documents.
    4. Returning metadata.
    """

    def __init__(self, default_index="security"):

        self.vector_store = VectorStore()

        if not self.vector_store.exists(default_index):
            logging.warning(f"Vector store '{default_index}' not found. Run test_vector_store.py first if needed.")
        else:
            self.vector_store.load(default_index)

    def load_index(self, index_name: str):
        if self.vector_store.exists(index_name):
            self.vector_store.load(index_name)
        else:
            logging.warning(f"Vector store '{index_name}' not found.")

    # ---------------------------------------------------------

    def _embed_query(self, query: str):

        embedding = self.vector_store.model.encode(
            query,
            convert_to_numpy=True,
            normalize_embeddings=True,
        )

        return np.array(
            [embedding],
            dtype=np.float32
        )

    # ---------------------------------------------------------

    def search(
        self,
        query: str,
        top_k: int = TOP_K,
    ) -> List[Dict]:

        logging.info(
            f"Searching knowledge base for: {query}"
        )

        query_embedding = self._embed_query(query)

        scores, indices = self.vector_store.index.search(
            query_embedding,
            top_k,
        )

        results = []

        for score, idx in zip(scores[0], indices[0]):

            if idx == -1:
                continue

            metadata = self.vector_store.metadata[idx].copy()

            metadata["score"] = round(float(score), 4)

            # Skip very weak matches
            if metadata["score"] < 0.30:
                continue

            results.append(metadata)

        logging.info(
            f"{len(results)} documents retrieved."
        )

        return results