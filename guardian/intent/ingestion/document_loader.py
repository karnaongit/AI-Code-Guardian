"""
Smart Document Ingestion Module for Business Intent Engine
===========================================================
- Cleans noise (headers/footers, page numbers, dividers).
- Filters actionable requirement lines (must, should, require, only if, cannot, allowed).
- Chunks into structured Requirement objects.
- Caches document parsing results by file mtime & hash for high performance.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Trigger keywords for actionable business requirements
ACTIONABLE_PATTERNS = re.compile(
    r"(?i)\b(must|should|require|requires|required|only\s+if|cannot|allowed|forbidden|prohibited|shall|mandatory|needs)\b"
)

# Noise line patterns (headers, footers, page numbers, markdown dividers)
NOISE_PATTERNS = [
    re.compile(r"(?i)^page\s+\d+(\s+of\s+\d+)?$"),
    re.compile(r"^\s*[\-_*]{3,}\s*$"),
    re.compile(r"^\s*#*\s*$"),
    re.compile(r"(?i)^(confidential|draft|internal\s+use\s+only)$"),
]


@dataclass
class Requirement:
    id: str
    text: str
    source: str
    line_number: int
    raw_text: str


def get_business_docs_dir(custom_path: str | Path | None = None) -> Path:
    """Resolve the business documents directory path."""
    if custom_path:
        p = Path(custom_path)
        p.mkdir(parents=True, exist_ok=True)
        return p

    workspace_root = Path.cwd()
    possible_paths = [
        workspace_root / "data" / "business_docs",
        workspace_root / "AI-Code-Guardian-ai_features" / "data" / "business_docs",
        Path("/data/business_docs"),
        Path("C:/data/business_docs"),
    ]

    for path in possible_paths:
        if path.exists():
            return path

    default_dir = workspace_root / "data" / "business_docs"
    default_dir.mkdir(parents=True, exist_ok=True)
    return default_dir


class DocumentLoader:
    """Smart document loader with cleaning, actionable sentence extraction, and caching."""

    SUPPORTED_EXTENSIONS = {".md", ".txt", ".json", ".csv", ".yaml", ".yml", ".docx", ".pdf"}

    def __init__(self, docs_dir: str | Path | None = None):
        self.docs_dir = get_business_docs_dir(docs_dir)
        self._cache: dict[str, dict[str, Any]] = {}

    def list_documents(self) -> list[dict[str, Any]]:
        """List all business documents in the directory."""
        if not self.docs_dir.exists():
            return []

        docs = []
        for file_path in sorted(self.docs_dir.glob("*")):
            if file_path.is_file() and file_path.suffix.lower() in self.SUPPORTED_EXTENSIONS:
                stat = file_path.stat()
                docs.append({
                    "filename": file_path.name,
                    "path": str(file_path),
                    "size_bytes": stat.st_size,
                    "mtime": stat.st_mtime,
                    "extension": file_path.suffix.lower(),
                })
        return docs

    def _clean_line(self, line: str) -> str:
        """Strip headers, footers, page numbers, and excess whitespace."""
        line_str = line.strip()
        for pattern in NOISE_PATTERNS:
            if pattern.match(line_str):
                return ""
        # Remove header prefixes like ### or 1.2
        cleaned = re.sub(r"^(#+|\d+[\.\)]|\-\s*)\s*", "", line_str)
        # Normalize internal whitespace
        cleaned = re.sub(r"\s+", " ", cleaned)
        return cleaned.strip()

    def extract_actionable_requirements(self) -> list[Requirement]:
        """Extract actionable requirements from documents with caching."""
        docs = self.list_documents()
        requirements: list[Requirement] = []
        req_counter = 1

        for doc in docs:
            file_path = Path(doc["path"])
            cache_key = f"{doc['path']}_{doc['mtime']}"

            if cache_key in self._cache:
                requirements.extend(self._cache[cache_key]["requirements"])
                continue

            try:
                raw_content = file_path.read_text(encoding="utf-8", errors="ignore")
                lines = raw_content.splitlines()
                doc_requirements: list[Requirement] = []

                for idx, raw_line in enumerate(lines, start=1):
                    cleaned = self._clean_line(raw_line)
                    if not cleaned or len(cleaned) < 12:
                        continue

                    # Check if line contains modal/action requirement keywords
                    if ACTIONABLE_PATTERNS.search(cleaned) or cleaned.lower().startswith("rule"):
                        req_obj = Requirement(
                            id=f"REQ-{req_counter:03d}",
                            text=cleaned,
                            source=doc["filename"],
                            line_number=idx,
                            raw_text=raw_line.strip()
                        )
                        doc_requirements.append(req_obj)
                        req_counter += 1

                # Cache extracted requirements for this file
                self._cache[cache_key] = {"requirements": doc_requirements}
                requirements.extend(doc_requirements)

            except Exception as err:
                log.warning(f"Failed to read/extract requirements from {doc['filename']}: {err}")

        return requirements
