from pathlib import Path

# ------------------------
# Embedding Model
# ------------------------

EMBEDDING_MODEL = "all-MiniLM-L6-v2"

# ------------------------
# Retrievalfrom pathlib import Path



# ------------------------
# Retrieval
# ------------------------

TOP_K = 3

# ------------------------
# Knowledge Sources
# ------------------------

VALID_SOURCES = {
    "OWASP Cheat Sheets",
    "MITRE CWE",
    "MITRE ATT&CK",
}

# ------------------------
# Paths
# ------------------------

BASE_DIR = Path(__file__).resolve().parent

KNOWLEDGE_PATH = BASE_DIR / "knowledge" / "master_rag_dataset.csv"

VECTOR_STORE_DIR = BASE_DIR / "vector_store"
VECTOR_STORE_DIR.mkdir(parents=True, exist_ok=True)

INDEX_PATH = VECTOR_STORE_DIR / "security.index"

METADATA_PATH = VECTOR_STORE_DIR / "security_metadata.pkl"
# ------------------------

TOP_K = 3

# ------------------------
# Paths
# ------------------------

BASE_DIR = Path(__file__).resolve().parent

KNOWLEDGE_PATH = BASE_DIR / "knowledge" / "master_rag_dataset.csv"

VECTOR_STORE_DIR = BASE_DIR / "vector_store"

INDEX_PATH = VECTOR_STORE_DIR / "security.index"

METADATA_PATH = VECTOR_STORE_DIR / "security_metadata.pkl"