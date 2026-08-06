# Local Environment Setup

This project uses native local processes instead of Docker/Kubernetes. 
The system gracefully degrades if these are missing, but for full functionality, follow these installation steps.

## Prerequisites

### 1. PostgreSQL (with pgvector)
PostgreSQL is used for relational data and structured persistence.

- **macOS**: `brew install postgresql` (Install pgvector: `brew install pgvector`)
- **Linux (Ubuntu/Debian)**: `sudo apt install postgresql postgresql-contrib`
- **Windows**: Use the official EnterpriseDB installer.

**Database Setup**:
```sql
CREATE DATABASE guardian_db;
CREATE USER guardian WITH PASSWORD 'guardian_pass';
GRANT ALL PRIVILEGES ON DATABASE guardian_db TO guardian;
-- Inside guardian_db:
CREATE EXTENSION IF NOT EXISTS vector;
```

### 2. Redis
Redis is used for caching embeddings, tree-sitter AST queries, and state management.

- **macOS**: `brew install redis && brew services start redis`
- **Linux**: `sudo apt install redis-server && sudo systemctl start redis`
- **Windows**: Use WSL2 or install a native Windows port (e.g. Memurai)

### 3. Neo4j
Neo4j is used for the Knowledge Graph (relationships between files, classes, and vulnerabilities).

- **macOS**: `brew install neo4j && neo4j start`
- **Linux**: Follow official Neo4j Debian repository instructions.
- **Windows**: Download Neo4j Desktop or the Neo4j Community Server zip.

*Note: Default credentials are `neo4j` / `password`. If you change these, update `.env`.*

### 4. Qdrant
Qdrant is our Vector Database for semantic search.
**No separate installation is required.** The application uses `qdrant-client` in **embedded mode** (file-backed) by default. Data is saved to the `./qdrant_data` folder in the project root.

---

## Environment Variables

Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
Ensure the connection strings match your local setup.

## Running the Application

We provide helper scripts to start the environment natively:

**macOS / Linux:**
```bash
./scripts/start_local.sh
```

**Windows:**
```cmd
.\scripts\start_local.bat
```

These scripts will check if the required ports (5432, 6379, 7687) are open, run database migrations (via `scripts/seed_db.py`), and start both the FastAPI backend and Vite frontend simultaneously.
