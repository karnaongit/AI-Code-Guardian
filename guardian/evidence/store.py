"""
Shared Evidence Store
=====================
The repository-level source of truth. Every deterministic engine
publishes here; every reasoning layer reads from here.

Why this exists
---------------
Before this, each module built its own prompt and shipped whatever
source it liked to the LLM. That made cost unbounded, grounding
impossible to verify, and hallucinations undetectable. With a store:

  * evidence IDs are stable and quotable, so an AI claim can be checked
    mechanically ("does E102 exist, and does it say what you claim?");
  * selection is explicit — a reasoning task asks for the few evidence
    items it needs rather than dumping a repository;
  * deduplication is centralised, so two engines observing the same line
    do not double-count into the risk score.
"""
from __future__ import annotations

import logging
import threading
from collections import defaultdict
from typing import Iterable, Iterator, Optional

from guardian.evidence.models import Evidence, EvidenceType

log = logging.getLogger(__name__)


class EvidenceStore:
    """Append-only, thread-safe collection of Evidence keyed by stable ID."""

    def __init__(self, id_prefix: str = "E") -> None:
        self._prefix = id_prefix
        self._items: dict[str, Evidence] = {}
        self._by_fingerprint: dict[str, str] = {}
        self._by_type: dict[EvidenceType, list[str]] = defaultdict(list)
        self._by_file: dict[str, list[str]] = defaultdict(list)
        self._by_source: dict[str, list[str]] = defaultdict(list)
        self._counter = 0
        self._lock = threading.Lock()

    # -- publication ----------------------------------------------------
    def add(self, evidence: Evidence) -> Evidence:
        """Publish one observation. Duplicates (same fingerprint) return
        the previously stored item so IDs stay stable and counts honest."""
        with self._lock:
            existing_id = self._by_fingerprint.get(evidence.fingerprint)
            if existing_id is not None:
                return self._items[existing_id]

            self._counter += 1
            evidence.id = f"{self._prefix}{self._counter}"
            self._items[evidence.id] = evidence
            self._by_fingerprint[evidence.fingerprint] = evidence.id
            self._by_type[evidence.type].append(evidence.id)
            if evidence.file:
                self._by_file[evidence.file].append(evidence.id)
            self._by_source[evidence.source].append(evidence.id)
            return evidence

    def add_many(self, items: Iterable[Evidence]) -> list[Evidence]:
        return [self.add(e) for e in items]

    # -- lookup ---------------------------------------------------------
    def get(self, evidence_id: str) -> Optional[Evidence]:
        return self._items.get(evidence_id)

    def exists(self, evidence_id: str) -> bool:
        return evidence_id in self._items

    def resolve(self, evidence_ids: Iterable[str]) -> tuple[list[Evidence], list[str]]:
        """Split requested IDs into (found evidence, unknown IDs).

        This is the primitive the AI validator uses to reject fabricated
        citations, so it must never silently drop an unknown ID.
        """
        found: list[Evidence] = []
        missing: list[str] = []
        for eid in evidence_ids:
            item = self._items.get(str(eid).strip())
            if item is None:
                missing.append(str(eid).strip())
            else:
                found.append(item)
        return found, missing

    def by_type(self, *types: EvidenceType) -> list[Evidence]:
        out: list[Evidence] = []
        for t in types:
            out.extend(self._items[i] for i in self._by_type.get(t, ()))
        return out

    def by_file(self, file: str) -> list[Evidence]:
        return [self._items[i] for i in self._by_file.get(file, ())]

    def by_source(self, source: str) -> list[Evidence]:
        return [self._items[i] for i in self._by_source.get(source, ())]

    def by_tag(self, tag: str) -> list[Evidence]:
        return [e for e in self._items.values() if tag in e.tags]

    def search(self, *, types: Optional[Iterable[EvidenceType]] = None,
               files: Optional[Iterable[str]] = None,
               sources: Optional[Iterable[str]] = None,
               tags: Optional[Iterable[str]] = None,
               min_confidence: float = 0.0,
               limit: Optional[int] = None) -> list[Evidence]:
        """Filtered selection — the only sanctioned way to build LLM context."""
        type_set = set(types) if types else None
        file_set = set(files) if files else None
        source_set = set(sources) if sources else None
        tag_set = set(tags) if tags else None

        out: list[Evidence] = []
        for e in self._items.values():
            if type_set and e.type not in type_set:
                continue
            if file_set and e.file not in file_set:
                continue
            if source_set and e.source not in source_set:
                continue
            if tag_set and not (tag_set & set(e.tags)):
                continue
            if e.confidence < min_confidence:
                continue
            out.append(e)
        out.sort(key=lambda e: (-e.confidence, e.file, e.line))
        return out[:limit] if limit else out

    # -- introspection ---------------------------------------------------
    def __len__(self) -> int:
        return len(self._items)

    def __iter__(self) -> Iterator[Evidence]:
        return iter(self._items.values())

    @property
    def all(self) -> list[Evidence]:
        return list(self._items.values())

    def counts_by_type(self) -> dict[str, int]:
        return {t.value: len(ids) for t, ids in self._by_type.items() if ids}

    def counts_by_source(self) -> dict[str, int]:
        return {s: len(ids) for s, ids in self._by_source.items() if ids}

    def summary(self) -> dict:
        return {
            "total": len(self._items),
            "by_type": self.counts_by_type(),
            "by_source": self.counts_by_source(),
            "files_with_evidence": len(self._by_file),
        }

    def to_dict(self) -> dict:
        return {
            "summary": self.summary(),
            "evidence": [e.to_dict() for e in self._items.values()],
        }
