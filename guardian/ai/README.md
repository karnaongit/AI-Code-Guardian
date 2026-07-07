# AI Code Guardian — AI Security Copilot

> **100% local.** No cloud APIs. Source code never leaves your machine.

## Architecture

```
User Question
    │
    ▼
EmbeddingRouter ──── CodeBERT (code) ─── FAISS Code Index
    │           └─── Ollama embed (text) ── FAISS Doc Index
    │
    ▼
Retriever
  ├── Intent classification (auth? vulnerability? quantum? business?)
  ├── Hybrid FAISS search (code index + doc index)
  ├── Deduplication
  └── Context assembly (max_context_chars budget)
    │
    ▼
PromptBuilder
  ├── System prompt (role + GROUNDING RULE + guardrails)
  ├── Repository summary
  ├── Retrieved context (<<CONTEXT_START>> ... <<CONTEXT_END>>)
  ├── Citations
  ├── Conversation history (last N turns)
  └── User question
    │
    ▼
OllamaClient.chat_stream()
    │
    ▼
Streamlit streaming render + citations panel
```

## Module Map

| File | Responsibility |
|---|---|
| `config.py` | All tunable parameters — no hardcoded values anywhere else |
| `models.py` | Data types: Document, RetrievedChunk, RAGResult, AssistantResponse |
| `ollama_client.py` | All Ollama API calls (chat, embed, health, stream) |
| `codebert.py` | CodeBERT semantic embeddings for source code (embedding only, never generation) |
| `document_loader.py` | Reads every file type → chunked Document objects |
| `embeddings.py` | Routes code → CodeBERT, text → Ollama; normalises vectors |
| `vector_store.py` | FAISS index management: build, persist, load, query |
| `code_indexer.py` | Orchestrates load → embed → store pipeline |
| `retriever.py` | Intent classification, hybrid search, context merge |
| `prompt_builder.py` | Structured prompt assembly with grounding guardrail |
| `conversation_memory.py` | Per-session chat history + context state |
| `rag_pipeline.py` | End-to-end RAG (non-streaming + streaming) |
| `chatbot.py` | `AISecurityCopilot` facade + factory (`create()`) |
| `dashboard/chat_page.py` | Streamlit UI: file upload, streaming chat, index panel |

## Setup

### 1. Install Ollama
```bash
# macOS/Linux
curl -fsSL https://ollama.com/install.sh | sh
# Windows: https://ollama.com/download
```

### 2. Pull models
```bash
ollama serve                        # start the server
ollama pull llama3.1               # chat model
ollama pull nomic-embed-text       # document embeddings
```

### 3. Install Python dependencies
```bash
pip install faiss-cpu ollama
# Optional but recommended for CodeBERT:
pip install torch transformers
# Optional for rich file formats:
pip install pdfminer.six python-docx
```

### 4. Run the dashboard
```bash
streamlit run dashboard/app.py
```

## Configuration

All settings are in `ai_assistant/config.py` or environment variables:

| Env var | Default | Description |
|---|---|---|
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama server URL |
| `ACG_CHAT_MODEL` | `llama3.1` | LLM for generation |
| `ACG_EMBED_MODEL` | `nomic-embed-text` | Embedding model |
| `ACG_EMBED_DIM` | `768` | Embedding dimension |
| `ACG_CODEBERT_DEVICE` | `cpu` | `cpu` or `cuda` |
| `ACG_LOG_LEVEL` | `INFO` | Logging verbosity |

Override in Python:
```python
from guardian.ai.config import AssistantConfig
cfg = AssistantConfig(
    chat_model="qwen2.5:14b",
    embed_model="nomic-embed-text",
    retrieval_top_k=10,
)
```

## Usage (Python)

```python
from pathlib import Path
from guardian.ai.chatbot import AISecurityCopilot

copilot = AISecurityCopilot.create()

# Index your repository
copilot.index_directory(Path("./my_project"))

# Index scan reports from the engines
copilot.index_scan_report(scan_result.to_dict())
copilot.index_business_intent(bi_report.to_dict())
copilot.index_quantum_report(q_report.to_dict())

# Ask questions (non-streaming)
response = copilot.ask("Show all SQL injection risks")
print(response.answer)
print("Sources:", response.citations)

# Ask with streaming (use in Streamlit)
for token in copilot.ask_stream("Explain the authentication flow"):
    print(token, end="", flush=True)
```

## Grounding Guarantee

The system prompt contains:

> "If the answer cannot be found in the provided context, respond with exactly:
> **'I could not find evidence in the indexed repository.'**"

The LLM never invents file names, line numbers, or vulnerability details.

## Indexable Knowledge Sources

| Type | File extensions |
|---|---|
| Source code | `.java .py .js .ts .go .rs .kt .cpp .c .cs .php .rb .scala` |
| Documents | `.md .txt .rst .json .yaml .yml .xml .csv .sql .sh .tf` |
| Rich docs | `.pdf .docx` |
| Config | `Dockerfile Jenkinsfile .github/**` |
| Reports | Any JSON produced by the scan engines |

## Evaluation Metrics

Enable evaluation logging: `AssistantConfig(eval_enabled=True)`

Metrics logged to `.acg_index/eval_log.jsonl`:
- `retrieval_count` — number of chunks retrieved
- `grounded` — whether evidence was found
- `latency_ms` — end-to-end response time
- `top_sources` — which files contributed to the answer
- `answer_length` — response character count
