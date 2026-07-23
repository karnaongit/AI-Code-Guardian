"""
AI Code Guardian 2.0 — Repository Detection Engine
==================================================
Answers, for ANY repository with zero prior knowledge:
    - What languages is it written in (with % distribution)?
    - Which frameworks does it use?
    - Which build systems?
    - What architecture shape (monorepo / microservices / frontend /
      backend / full-stack / cloud-native)?

Detection is entirely manifest- and extension-driven. Nothing here may
reference any specific project.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

EXTENSION_LANGUAGES = {
    ".java": "Java", ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".go": "Go", ".rs": "Rust",
    ".cs": "C#", ".cpp": "C++", ".cc": "C++", ".c": "C", ".h": "C/C++ Header",
    ".kt": "Kotlin", ".scala": "Scala", ".php": "PHP", ".rb": "Ruby",
    ".sql": "SQL", ".tf": "Terraform", ".yaml": "YAML", ".yml": "YAML",
    ".xml": "XML", ".json": "JSON", ".md": "Markdown", ".sh": "Shell",
}

# manifest file -> (build_tool, primary_language_hint)
BUILD_MANIFESTS = {
    "pom.xml": ("Maven", "Java"),
    "build.gradle": ("Gradle", "Java"),
    "build.gradle.kts": ("Gradle (Kotlin DSL)", "Kotlin"),
    "requirements.txt": ("pip", "Python"),
    "pyproject.toml": ("Python (PEP 517)", "Python"),
    "setup.py": ("setuptools", "Python"),
    "Pipfile": ("pipenv", "Python"),
    "package.json": ("npm/yarn", "JavaScript"),
    "Cargo.toml": ("Cargo", "Rust"),
    "go.mod": ("Go modules", "Go"),
    "Gemfile": ("Bundler", "Ruby"),
    "composer.json": ("Composer", "PHP"),
    "*.csproj": ("MSBuild", "C#"),
    "CMakeLists.txt": ("CMake", "C++"),
    "Makefile": ("Make", None),
}

# filename or content signature -> framework
FRAMEWORK_SIGNATURES = [
    ("pom.xml", re.compile(r"spring-boot|springframework", re.I), "Spring Boot"),
    ("build.gradle", re.compile(r"spring-boot|springframework", re.I), "Spring Boot"),
    ("requirements.txt", re.compile(r"^django", re.I | re.M), "Django"),
    ("requirements.txt", re.compile(r"^flask", re.I | re.M), "Flask"),
    ("requirements.txt", re.compile(r"^fastapi", re.I | re.M), "FastAPI"),
    ("requirements.txt", re.compile(r"^streamlit", re.I | re.M), "Streamlit"),
    ("package.json", re.compile(r'"react"'), "React"),
    ("package.json", re.compile(r'"vue"'), "Vue"),
    ("package.json", re.compile(r'"@angular/core"'), "Angular"),
    ("package.json", re.compile(r'"express"'), "Express"),
    ("package.json", re.compile(r'"next"'), "Next.js"),
    ("go.mod", re.compile(r"gin-gonic|labstack/echo"), "Go web framework"),
]

CLOUD_NATIVE_MARKERS = {
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "Chart.yaml",            # Helm
    ".gitlab-ci.yml", "Jenkinsfile", "azure-pipelines.yml",
}
KUBE_HINT = re.compile(r"^\s*(apiVersion|kind):", re.M)
API_SPEC_NAMES = {"openapi.yaml", "openapi.yml", "openapi.json", "swagger.yaml", "swagger.json"}


@dataclass
class RepositoryProfile:
    root: str
    languages: dict[str, float] = field(default_factory=dict)   # language -> % of source files
    primary_language: str = "Unknown"
    frameworks: list[str] = field(default_factory=list)
    build_tools: list[str] = field(default_factory=list)
    architecture: list[str] = field(default_factory=list)       # e.g. ["backend", "cloud-native"]
    is_monorepo: bool = False
    has_api_spec: bool = False
    manifest_files: list[str] = field(default_factory=list)
    total_files: int = 0

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "primary_language": self.primary_language,
            "languages": self.languages,
            "frameworks": self.frameworks,
            "build_tools": self.build_tools,
            "architecture": self.architecture,
            "is_monorepo": self.is_monorepo,
            "has_api_spec": self.has_api_spec,
            "manifest_files": self.manifest_files,
            "total_files": self.total_files,
        }


class RepositoryDetector:
    """Builds a RepositoryProfile from the discovered file list."""

    def detect(self, repo_root: Path, files: Iterable[Path]) -> RepositoryProfile:
        files = list(files)
        profile = RepositoryProfile(root=str(repo_root), total_files=len(files))

        lang_counts: Counter[str] = Counter()
        manifest_dirs: set[Path] = set()
        frameworks: set[str] = set()
        build_tools: set[str] = set()
        cloud_native = False

        for fp in files:
            name = fp.name
            ext = fp.suffix.lower()

            lang = EXTENSION_LANGUAGES.get(ext)
            if lang and lang not in ("YAML", "JSON", "Markdown", "XML"):
                lang_counts[lang] += 1

            if name in BUILD_MANIFESTS:
                tool, _ = BUILD_MANIFESTS[name]
                build_tools.add(tool)
                profile.manifest_files.append(str(fp))
                manifest_dirs.add(fp.parent)
            elif ext == ".csproj":
                build_tools.add("MSBuild")
                manifest_dirs.add(fp.parent)

            if name in CLOUD_NATIVE_MARKERS or "/.github/workflows/" in str(fp).replace("\\", "/"):
                cloud_native = True
            if name.lower() in API_SPEC_NAMES:
                profile.has_api_spec = True

            for sig_file, pattern, fw in FRAMEWORK_SIGNATURES:
                if name == sig_file:
                    try:
                        text = fp.read_text(encoding="utf-8", errors="ignore")[:200_000]
                        if pattern.search(text):
                            frameworks.add(fw)
                    except OSError:
                        pass

        total_src = sum(lang_counts.values()) or 1
        profile.languages = {
            lang: round(100.0 * n / total_src, 1)
            for lang, n in lang_counts.most_common()
        }
        if lang_counts:
            profile.primary_language = lang_counts.most_common(1)[0][0]
        profile.frameworks = sorted(frameworks)
        profile.build_tools = sorted(build_tools)

        # multiple build manifests in distinct directories -> monorepo signal
        profile.is_monorepo = len({d for d in manifest_dirs}) > 1

        arch: list[str] = []
        fe = {"React", "Vue", "Angular", "Next.js"}
        be = {"Spring Boot", "Django", "Flask", "FastAPI", "Express", "Go web framework"}
        if frameworks & fe and frameworks & be:
            arch.append("full-stack")
        elif frameworks & fe:
            arch.append("frontend")
        elif frameworks & be or profile.primary_language in {"Java", "Go", "C#", "Python"}:
            arch.append("backend")
        if cloud_native:
            arch.append("cloud-native")
        if profile.is_monorepo:
            arch.append("monorepo")
        profile.architecture = arch or ["unclassified"]
        return profile
