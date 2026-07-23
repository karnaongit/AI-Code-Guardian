"""
Dependency manifest parsers — repository-agnostic extraction of
(name, version, ecosystem) from common lockfiles/manifests.

Supported now: requirements.txt, package.json, package-lock.json,
pom.xml, go.mod.
TODO(deps-roadmap): Cargo.lock, Gemfile.lock, composer.lock, go.sum.
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class Dependency:
    name: str
    version: Optional[str]
    ecosystem: str        # PyPI | npm | Maven | Go
    manifest: str         # file it came from


def parse_requirements_txt(path: Path) -> list[Dependency]:
    deps = []
    for line in path.read_text(errors="ignore").splitlines():
        line = line.split("#")[0].strip()
        if not line or line.startswith("-"):
            continue
        m = re.match(r'^([A-Za-z0-9_.\-]+)\s*(?:[=<>!~]{1,2}=?\s*([\w.\-*]+))?', line)
        if m:
            deps.append(Dependency(m.group(1).lower(), m.group(2), "PyPI", str(path)))
    return deps


def parse_package_json(path: Path) -> list[Dependency]:
    try:
        data = json.loads(path.read_text(errors="ignore"))
    except json.JSONDecodeError:
        return []
    deps = []
    for section in ("dependencies", "devDependencies"):
        for name, ver in (data.get(section) or {}).items():
            deps.append(Dependency(name, str(ver).lstrip("^~"), "npm", str(path)))
    return deps


def parse_package_lock(path: Path) -> list[Dependency]:
    try:
        data = json.loads(path.read_text(errors="ignore"))
    except json.JSONDecodeError:
        return []
    deps = []
    for name, meta in (data.get("packages") or {}).items():
        if not name:
            continue
        short = name.split("node_modules/")[-1]
        deps.append(Dependency(short, meta.get("version"), "npm", str(path)))
    return deps


def parse_pom_xml(path: Path) -> list[Dependency]:
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return []
    ns = {"m": root.tag.split("}")[0].strip("{")} if root.tag.startswith("{") else {}
    q = (lambda t: f"m:{t}") if ns else (lambda t: t)
    deps = []
    for dep in root.iterfind(f".//{q('dependencies')}/{q('dependency')}", ns):
        gid = dep.findtext(q("groupId"), default="", namespaces=ns)
        aid = dep.findtext(q("artifactId"), default="", namespaces=ns)
        ver = dep.findtext(q("version"), default=None, namespaces=ns)
        if aid:
            deps.append(Dependency(f"{gid}:{aid}".strip(":"), ver, "Maven", str(path)))
    return deps


def parse_go_mod(path: Path) -> list[Dependency]:
    deps = []
    in_block = False
    for line in path.read_text(errors="ignore").splitlines():
        s = line.strip()
        if s.startswith("require ("):
            in_block = True
            continue
        if in_block and s == ")":
            in_block = False
            continue
        m = re.match(r'^(?:require\s+)?([\w./\-]+)\s+v([\w.\-+]+)', s) if (in_block or s.startswith("require")) else None
        if m:
            deps.append(Dependency(m.group(1), m.group(2), "Go", str(path)))
    return deps


PARSERS = {
    "requirements.txt": parse_requirements_txt,
    "package.json": parse_package_json,
    "package-lock.json": parse_package_lock,
    "pom.xml": parse_pom_xml,
    "go.mod": parse_go_mod,
}


def parse_manifest(path: Path) -> list[Dependency]:
    parser = PARSERS.get(path.name)
    return parser(path) if parser else []
