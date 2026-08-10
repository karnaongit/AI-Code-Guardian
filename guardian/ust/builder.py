"""
UST Builder
===========
The single entry point that turns source into a Unified Syntax Tree.

    source -> Tree-sitter parse -> language normalizer -> tagging
           -> data-flow -> USTFile

Degradation ladder (never raises to the caller):

    1. Tree-sitter grammar for the language              (parser="tree-sitter")
    2. Python only: stdlib `ast`                         (parser="python-ast")
    3. Any language: line-oriented regex scanner         (parser="regex")
    4. Unsupported/binary/unreadable file                (parser="none")

Every USTFile records which rung it landed on, so downstream engines can
weight confidence honestly instead of pretending a regex scan is a parse.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterable, Optional

from guardian.ust import parsers
from guardian.ust.dataflow import analyze_file
from guardian.ust.fallback import python_ast_ust, regex_ust
from guardian.ust.languages.base import LanguageNormalizer
from guardian.ust.languages.java_lang import JavaNormalizer
from guardian.ust.languages.javascript_lang import JavaScriptNormalizer, TypeScriptNormalizer
from guardian.ust.languages.python_lang import PythonNormalizer
from guardian.ust.languages.rust_lang import RustNormalizer
from guardian.ust.models import UST, USTFile
from guardian.ust.tagging import tag_file

log = logging.getLogger(__name__)

#: language key -> normalizer factory. Adding a language = one row here
#: plus one row in `parsers._GRAMMARS`.
NORMALIZERS: dict[str, type[LanguageNormalizer] | object] = {
    "python": PythonNormalizer,
    "java": JavaNormalizer,
    "javascript": JavaScriptNormalizer,
    "typescript": TypeScriptNormalizer,
    "tsx": TypeScriptNormalizer,
    "rust": RustNormalizer,
}

MAX_SOURCE_BYTES = 2_000_000


def _normalizer_for(language: str) -> Optional[LanguageNormalizer]:
    factory = NORMALIZERS.get(language)
    if factory is None:
        return None
    if language in ("javascript",):
        return JavaScriptNormalizer("javascript")
    if language == "typescript":
        return TypeScriptNormalizer("typescript")
    if language == "tsx":
        return TypeScriptNormalizer("typescript")
    return factory()  # type: ignore[operator]


class USTBuilder:
    """Builds USTFiles and repository-level USTs."""

    def __init__(self, *, enable_dataflow: bool = True,
                 enable_tagging: bool = True,
                 promote_semantic_types: bool = False) -> None:
        self.enable_dataflow = enable_dataflow
        self.enable_tagging = enable_tagging
        self.promote_semantic_types = promote_semantic_types

    # ------------------------------------------------------------------
    def build_source(self, source: str, file_label: str,
                     language: str = "") -> USTFile:
        """Build a UST for one file's text. Never raises."""
        language = language or parsers.language_for_path(file_label)
        if not language:
            return USTFile(path=file_label, language="unknown", parser="none",
                           parse_error="unsupported language",
                           line_count=len(source.splitlines()))
        if len(source.encode("utf-8", errors="ignore")) > MAX_SOURCE_BYTES:
            return USTFile(path=file_label, language=language, parser="none",
                           parse_error="file exceeds UST size limit",
                           line_count=len(source.splitlines()))

        ust_file = self._parse(source, file_label, language)

        if self.enable_tagging and ust_file.nodes:
            try:
                tag_file(ust_file, promote=self.promote_semantic_types)
            except Exception as exc:  # noqa: BLE001 — tagging must never kill a scan
                log.debug("tagging failed for %s: %s", file_label, exc)
        if self.enable_dataflow and ust_file.nodes:
            try:
                analyze_file(ust_file)
            except Exception as exc:  # noqa: BLE001
                log.debug("data-flow pass failed for %s: %s", file_label, exc)
        return ust_file

    def build_file(self, path: Path, file_label: str = "",
                   language: str = "") -> USTFile:
        label = file_label or str(path)
        try:
            source = Path(path).read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            return USTFile(path=label, language=language or parsers.language_for_path(path),
                           parser="none", parse_error=f"unreadable: {exc}")
        return self.build_source(source, label, language)

    def build_repository(self, root: Path | str, files: Iterable[Path],
                         relative: bool = True) -> UST:
        """Build the repository-level UST. Per-file failures are recorded
        on the USTFile, never propagated — a partial UST is still useful."""
        root_path = Path(root)
        
        from guardian.cache.redis_manager import RedisManager
        redis_mgr = RedisManager()
        repo_hash = redis_mgr.generate_repo_hash(root_path)
        cache_key = f"ust:cache:{repo_hash}"
        cached_data = redis_mgr.get_json(cache_key)
        
        if cached_data:
            log.info("UST Cache hit for %s", repo_hash)
            try:
                return UST.from_cache_dict(cached_data)
            except Exception as e:
                log.warning("Failed to deserialize cached UST: %s", e)

        ust = UST(root=str(root_path))
        for fp in files:
            language = parsers.language_for_path(fp)
            if not language:
                continue
            label = str(fp)
            if relative:
                try:
                    label = str(Path(fp).resolve().relative_to(root_path.resolve()))
                except (ValueError, OSError):
                    label = str(fp)
            try:
                ust.add(self.build_file(fp, file_label=label, language=language))
            except Exception as exc:  # noqa: BLE001 — belt and braces
                log.warning("UST build failed for %s: %s", label, exc)
                ust.add(USTFile(path=label, language=language, parser="none",
                                parse_error=str(exc)))
                                
        if redis_mgr.enabled:
            redis_mgr.set_json(cache_key, ust.to_cache_dict(), ttl=86400)
            
        return ust

    # ------------------------------------------------------------------
    def _parse(self, source: str, file_label: str, language: str) -> USTFile:
        tree = parsers.parse(source, language)
        if tree is not None:
            normalizer = _normalizer_for(language)
            if normalizer is not None:
                try:
                    nodes, imports = normalizer.normalize(tree, source, file_label)
                    ust_file = USTFile(
                        path=file_label,
                        language=parsers.normalizer_language(language),
                        nodes=nodes, imports=imports, parser="tree-sitter",
                        line_count=len(source.splitlines()))
                    root = getattr(tree, "root_node", None)
                    if root is not None and getattr(root, "has_error", False):
                        # Tree-sitter recovered from syntax errors: keep the
                        # partial tree but record that it is partial.
                        ust_file.parse_error = ""
                        ust_file.line_count = len(source.splitlines())
                        for node in ust_file.nodes:
                            node.metadata.setdefault("partial_parse", True)
                    return ust_file
                except Exception as exc:  # noqa: BLE001
                    log.debug("normalizer failed for %s (%s); falling back", file_label, exc)

        # -- fallbacks --------------------------------------------------
        if language == "python":
            fallback = python_ast_ust(source, file_label)
            if fallback is not None and (fallback.nodes or fallback.parse_error):
                if fallback.nodes:
                    return fallback
        return regex_ust(source, file_label,
                         parsers.normalizer_language(language))


#: Shared default builder — cheap to construct, but callers that need
#: custom toggles should make their own.
default_builder = USTBuilder()


def build_ust(source: str, file_label: str, language: str = "") -> USTFile:
    """Module-level convenience wrapper around the default builder."""
    return default_builder.build_source(source, file_label, language)
