from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from scanner.language_learning.models import GrammarMetadata


class GrammarLoader:

    GRAMMAR_REPOS = {
        "python": "https://github.com/tree-sitter/tree-sitter-python.git",
        "java": "https://github.com/tree-sitter/tree-sitter-java.git",
        "javascript": "https://github.com/tree-sitter/tree-sitter-javascript.git",
        "typescript": "https://github.com/tree-sitter/tree-sitter-typescript.git",
        "go": "https://github.com/tree-sitter/tree-sitter-go.git",
        "rust": "https://github.com/tree-sitter/tree-sitter-rust.git",
        "cpp": "https://github.com/tree-sitter/tree-sitter-cpp.git",
        "c": "https://github.com/tree-sitter/tree-sitter-c.git",
        "c_sharp": "https://github.com/tree-sitter/tree-sitter-c-sharp.git",
        "php": "https://github.com/tree-sitter/tree-sitter-php.git",
        "kotlin": "https://github.com/fwcd/tree-sitter-kotlin.git",
    }

    def __init__(self, cache_root: str | Path = ".cache/grammars"):
        self.cache_root = Path(cache_root)
        self.cache_root.mkdir(parents=True, exist_ok=True)

    def load(self, language: str) -> GrammarMetadata:

        grammar_dir = self.cache_root / language

        if not grammar_dir.exists():
            self._download(language, grammar_dir)

        # Try the standard Tree-sitter layout first
        node_types = grammar_dir / "src" / "node-types.json"

        if not node_types.exists():

            # Search recursively for node-types.json
            matches = list(grammar_dir.rglob("node-types.json"))

            if not matches:
                raise FileNotFoundError(
                    f"No node-types.json found in {grammar_dir}"
                )

            # Prefer the TypeScript grammar over TSX if both exist
            preferred = None

            for match in matches:
                path = match.as_posix().lower()

                if "/typescript/" in path:
                    preferred = match
                    break

            node_types = preferred or matches[0]
            
            print(f"Using grammar: {node_types}")

        return GrammarMetadata(
            language=language,
            grammar_dir=grammar_dir,
            node_types_file=node_types,
        )

    def _download(self, language: str, destination: Path):

        repo = self.GRAMMAR_REPOS.get(language)

        if repo is None:
            raise ValueError(
                f"No grammar repository configured for '{language}'."
            )

        temp = destination.parent / f"{language}_tmp"

        if temp.exists():
            shutil.rmtree(temp)

        subprocess.run(
            [
                "git",
                "clone",
                "--depth",
                "1",
                repo,
                str(temp),
            ],
            check=True,
        )

        if destination.exists():
            shutil.rmtree(destination)

        temp.rename(destination)