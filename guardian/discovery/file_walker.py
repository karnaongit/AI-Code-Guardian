"""
AI Code Guardian 2.0 — Recursive File Discovery
===============================================
Repository-agnostic file walker. Responsibilities:
    - honour the configured ignore list (.git, node_modules, target, ...)
    - handle symbolic links safely (cycle detection via resolved inodes)
    - cap file count and per-file size for 100k+ file repositories
    - classify each file for downstream routing (source / manifest /
      infrastructure / docs / other)

Uses os.scandir via os.walk for performance; yields lazily so callers
can stream on very large repositories.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from guardian.config import GuardianConfig

INFRA_NAMES = {
    "dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "jenkinsfile", ".gitlab-ci.yml", "azure-pipelines.yml", "chart.yaml",
}
INFRA_EXTS = {".tf", ".tfvars"}
DOC_EXTS = {".md", ".rst", ".txt"}
MANIFEST_NAMES = {
    "pom.xml", "build.gradle", "build.gradle.kts", "requirements.txt",
    "pyproject.toml", "setup.py", "pipfile", "package.json",
    "package-lock.json", "yarn.lock", "cargo.toml", "cargo.lock",
    "go.mod", "go.sum", "gemfile", "gemfile.lock", "composer.json",
    "composer.lock",
}


@dataclass
class DiscoveredFiles:
    root: Path
    source: list[Path] = field(default_factory=list)
    manifests: list[Path] = field(default_factory=list)
    infrastructure: list[Path] = field(default_factory=list)
    docs: list[Path] = field(default_factory=list)
    other: list[Path] = field(default_factory=list)
    skipped_large: int = 0
    truncated: bool = False  # True if max_files cap was hit

    @property
    def all_files(self) -> list[Path]:
        return self.source + self.manifests + self.infrastructure + self.docs + self.other


class FileWalker:
    def __init__(self, config: GuardianConfig | None = None):
        self.config = config or GuardianConfig()

    def walk(self, root: str | Path) -> Iterator[Path]:
        """Yield files under root, honouring ignore list, symlink cycles,
        size limits, and the max_files cap."""
        root = Path(root)
        cfg = self.config
        seen_real: set[str] = set()
        count = 0

        for dirpath, dirnames, filenames in os.walk(root, followlinks=cfg.follow_symlinks):
            # prune ignored directories in-place
            dirnames[:] = [d for d in dirnames if d not in cfg.ignore_dirs and not d.startswith(".git")]

            if cfg.follow_symlinks:
                # cycle guard: never re-enter a directory we've resolved before
                real = os.path.realpath(dirpath)
                if real in seen_real:
                    dirnames[:] = []
                    continue
                seen_real.add(real)

            for fn in filenames:
                fp = Path(dirpath) / fn
                if fp.is_symlink() and not cfg.follow_symlinks:
                    continue
                try:
                    if fp.stat().st_size > cfg.max_file_bytes:
                        continue
                except OSError:
                    continue
                yield fp
                count += 1
                if count >= cfg.max_files:
                    return

    def discover(self, root: str | Path, source_extensions: set[str]) -> DiscoveredFiles:
        """Walk and classify. `source_extensions` comes from the plugin
        registry, so 'what counts as source' is plugin-driven."""
        root = Path(root)
        out = DiscoveredFiles(root=root)
        n = 0
        for fp in self.walk(root):
            n += 1
            name = fp.name.lower()
            ext = fp.suffix.lower()
            if name in INFRA_NAMES or ext in INFRA_EXTS or "/.github/workflows/" in str(fp).replace("\\", "/"):
                out.infrastructure.append(fp)
            elif name in MANIFEST_NAMES:
                out.manifests.append(fp)
            elif ext in source_extensions:
                out.source.append(fp)
            elif ext in DOC_EXTS:
                out.docs.append(fp)
            else:
                out.other.append(fp)
        out.truncated = n >= self.config.max_files
        return out
