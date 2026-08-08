"""
POST-FIX COVERAGE VERIFIER
============================
Uses the PRODUCTION ExecutionTreeBuilder (not the instrumented subclass)
to verify that the IMPORTS-fix achieves full repository file coverage.

Run:  python scratch/verify_coverage.py
"""

import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from scanner.parser import UniversalParser
from scanner.security_engine import SecurityEngine
from scanner.intelligence.knowledge_graph import KnowledgeGraphBuilder
from scanner.intelligence.semantic_resolver import SemanticResolver
from scanner.intelligence.execution_builder import ExecutionTreeBuilder, ExecutionNode

REPO_DIR  = os.path.dirname(os.path.dirname(__file__))
SKIP_DIRS = {"__pycache__", ".git", "venv", ".venv", "node_modules",
             "tmp_repo", "tmp_repo2", "tmp_repo3", "tmp_repo4",
             "tmp_repo5", "tmp_repo6", "tmp_repo7", "tmp_repo8", ".cache"}

# ── parse ──────────────────────────────────────────────────────────────────────
print("Parsing…")
parser   = UniversalParser()
engine   = SecurityEngine()
pf_list  = []
findings = []

for root, dirs, files in os.walk(REPO_DIR):
    dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
    for fname in files:
        if not fname.endswith(".py"):
            continue
        full = os.path.join(root, fname)
        rel  = os.path.relpath(full, REPO_DIR).replace("\\", "/")
        try:
            with open(full, "r", encoding="utf-8", errors="ignore") as f:
                src = f.read()
            pf = parser.parse(src, rel)
            if pf:
                pf_list.append(pf)
                sec = engine.scan(pf, rel)
                findings.extend(sec.findings)
        except Exception as exc:
            pass   # suppress parse noise

print(f"  {len(pf_list)} files parsed, {len(findings)} findings")

# ── build graph ────────────────────────────────────────────────────────────────
print("Building graph…")
kg      = KnowledgeGraphBuilder("local")
raw     = kg.build(pf_list, findings)
graph   = SemanticResolver().resolve(raw)

file_nodes = [n for n in graph.nodes.values() if n.type == "File"]
print(f"  {len(graph.nodes)} nodes, {len(graph.edges)} edges, {len(file_nodes)} file nodes")

# ── entry point ────────────────────────────────────────────────────────────────
entry_names = ["main.py", "app.py", "server.py", "manage.py"]
ep = next(
    (n for n in graph.nodes.values()
     if n.type == "File" and any(n.properties.get("path","").endswith(e) for e in entry_names)),
    None
)
if not ep:
    print("No entry point found"); sys.exit(1)
print(f"  Entry: {ep.properties.get('path')}")

# ── build tree ────────────────────────────────────────────────────────────────
print("Building execution tree…")
builder = ExecutionTreeBuilder()
tree    = builder.build_global_tree(graph, ep.id)

# ── coverage ──────────────────────────────────────────────────────────────────
all_ids     = {n.id for n in file_nodes}
visited_ids: set = set()

def collect(node: ExecutionNode):
    if node.type == "File":
        visited_ids.add(node.id)
    for c in node.children:
        collect(c)

if tree:
    collect(tree)

missed = all_ids - visited_ids
print()
print(f"Total repository files : {len(all_ids)}")
print(f"Files reached by tree  : {len(visited_ids)}")
print(f"Files NOT reached      : {len(missed)}")

if missed:
    print("\nMISSED (first 20):")
    for fid in sorted(missed)[:20]:
        fn = graph.get_node(fid)
        print(f"  {fn.properties.get('path','') if fn else fid}")
    # Explain why each is still missed
    print("\nEdge analysis for missed files:")
    for fid in sorted(missed)[:20]:
        fn = graph.get_node(fid)
        fpath = fn.properties.get("path","") if fn else fid
        in_edges = graph.get_in_edges(fid)
        if not in_edges:
            print(f"  {fpath}: DISCONNECTED – no incoming edges at all")
        else:
            types = list({e.type for e in in_edges})
            print(f"  {fpath}: incoming edge types = {types}")
else:
    print("\n[OK] All repository files reached.")

# ── tree skeleton ─────────────────────────────────────────────────────────────
def skeleton(node: ExecutionNode, depth=0, max_depth=3):
    pad = "  " * depth
    label = f"[{node.type}] {node.name}"
    if depth <= max_depth:
        print(f"{pad}{label}  ({len(node.children)} children)")
        for c in node.children:
            skeleton(c, depth+1, max_depth)
    else:
        print(f"{pad}{label}  …")

print("\n── Tree skeleton (depth≤3) ──────────────────────")
if tree:
    skeleton(tree)
