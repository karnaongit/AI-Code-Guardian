from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


# ============================================================
# Grammar Models
# ============================================================

@dataclass(slots=True, frozen=True)
class GrammarMetadata:
    """
    Information about a Tree-sitter grammar.
    """

    language: str
    grammar_dir: Path
    node_types_file: Path


@dataclass(slots=True, frozen=True)
class GrammarAnalysis:
    """
    Result of analyzing a Tree-sitter grammar.
    """

    grammar: GrammarMetadata

    # All node types
    node_types: tuple[str, ...]

    # Only named node types
    named_node_types: tuple[str, ...]

    # Root grammar node
    root_node: str | None

    # Grammar statistics
    statistics: dict[str, int]

    # NEW -------------------------------

    # node_type -> {field_name: (allowed_node_types)}
    field_map: dict[str, dict[str, tuple[str, ...]]]

    # node_type -> (allowed_children)
    children_map: dict[str, tuple[str, ...]]

    # node_type -> (subtypes)
    subtype_map: dict[str, tuple[str, ...]]


# ============================================================
# Query Models
# ============================================================

@dataclass(slots=True, frozen=True)
class GeneratedQuery:
    """
    Query produced by the LLM.
    """

    name: str

    source: str


# ============================================================
# Validation Models
# ============================================================

@dataclass(slots=True, frozen=True)
class ValidationResult:
    """
    Result of validating a generated Tree-sitter query.
    """

    valid: bool

    coverage: float

    captures: int

    confidence: float

    execution_time: float

    warnings: tuple[str, ...] = ()

    errors: tuple[str, ...] = ()
    
    recovered_query: str | None = None


# ============================================================
# Cache Models
# ============================================================

@dataclass(slots=True, frozen=True)
class LanguageProfile:
    """
    Metadata stored alongside a learned language.
    """

    language: str

    coverage: float

    captures: int

    confidence: float

    query_file: Path