"""
AI Code Guardian 2.0 — Configuration
====================================
Single source of configuration truth. Everything the platform does is
driven by this object; no module may hardcode repository-specific
behavior. Precedence: explicit kwargs > YAML file > built-in defaults.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

DEFAULT_IGNORE_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "dist", "build", "target",
    "venv", ".venv", "env", ".idea", ".vscode", "coverage", "__pycache__",
    ".mypy_cache", ".pytest_cache", ".tox", "vendor", "bower_components",
}

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "default.yaml"


@dataclass
class GuardianConfig:
    # discovery
    ignore_dirs: set[str] = field(default_factory=lambda: set(DEFAULT_IGNORE_DIRS))
    follow_symlinks: bool = False
    max_files: int = 200_000
    max_file_bytes: int = 2_000_000  # skip files larger than 2 MB

    # analysis toggles
    enable_dependencies: bool = True
    enable_infrastructure: bool = True
    enable_quantum: bool = True
    enable_quantum_gate: bool = False  # opt-in: hard-block merges on Shor-class crypto inventory
    enable_intent: bool = True
    enable_threat_intel: bool = False   # requires network; off by default
    enable_ai: bool = False             # requires NVIDIA_API_KEY; off by default

    # risk
    alignment_score_default: float = 75.0
    fail_on_severity: Optional[str] = None  # e.g. "High" for CI gating

    # ai / rag
    llm_provider: str = "nemotron"      # see guardian/llm/factory.py
    llm_model: str = ""                 # blank = provider default (NVIDIA_MODEL)
    rag_persist: bool = False

    # reporting
    report_formats: list[str] = field(default_factory=lambda: ["json"])

    extras: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Optional[str | Path] = None, **overrides) -> "GuardianConfig":
        data: dict[str, Any] = {}
        cfg_path = Path(path) if path else DEFAULT_CONFIG_PATH
        if yaml is not None and cfg_path.exists():
            loaded = yaml.safe_load(cfg_path.read_text()) or {}
            data.update(loaded)
        data.update({k: v for k, v in overrides.items() if v is not None})

        known = {f for f in cls.__dataclass_fields__}
        kwargs = {k: v for k, v in data.items() if k in known}
        extras = {k: v for k, v in data.items() if k not in known}
        if "ignore_dirs" in kwargs:
            kwargs["ignore_dirs"] = set(kwargs["ignore_dirs"]) | DEFAULT_IGNORE_DIRS
        cfg = cls(**kwargs)
        cfg.extras.update(extras)
        return cfg
