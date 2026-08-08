"""
Categorize the 58 missed files into:
1. Alternative entry points
2. Test files
3. Scratch files
4. Dead code (not reachable from main.py via any import chain)
5. Utility modules imported dynamically (inline / importlib)
6. Reachable but still missed (has RESOLVES_TO from a reached file -- traversal bug)
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from scanner.parser import UniversalParser
from scanner.security_engine import SecurityEngine
from scanner.intelligence.knowledge_graph import KnowledgeGraphBuilder
from scanner.intelligence.semantic_resolver import SemanticResolver
from scanner.intelligence.execution_builder import ExecutionTreeBuilder, ExecutionNode

SKIP_DIRS = {"__pycache__", ".git", "venv", ".venv", "node_modules",
             "tmp_repo","tmp_repo2","tmp_repo3","tmp_repo4",
             "tmp_repo5","tmp_repo6","tmp_repo7","tmp_repo8",".cache"}
ROOT = os.path.dirname(os.path.dirname(__file__))

# ── 1. Build graph and run tree ───────────────────────────────────────────────
parser  = UniversalParser()
engine_s = SecurityEngine()
pf_list  = []
findings = []

for root, dirs, files in os.walk(ROOT):
    dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
    for fname in files:
        if not fname.endswith(".py"): continue
        full = os.path.join(root, fname)
        rel  = os.path.relpath(full, ROOT).replace("\\", "/")
        try:
            with open(full, "r", encoding="utf-8", errors="ignore") as f: src = f.read()
            pf = parser.parse(src, rel)
            if pf:
                pf_list.append(pf)
                sec = engine_s.scan(pf, rel)
                findings.extend(sec.findings)
        except Exception: pass

kg  = KnowledgeGraphBuilder("local")
raw = kg.build(pf_list, findings)
g   = SemanticResolver().resolve(raw)

ep = next((n for n in g.nodes.values()
           if n.type == "File" and n.properties.get("path","").endswith("main.py")), None)

builder = ExecutionTreeBuilder()
tree    = builder.build_global_tree(g, ep.id)

reached: set = set()
def collect(node: ExecutionNode):
    if node.type == "File": reached.add(node.id)
    for c in node.children: collect(c)
if tree: collect(tree)

file_nodes  = {n.id: n for n in g.nodes.values() if n.type == "File"}
path_to_id  = {n.properties.get("path",""): nid for nid, n in file_nodes.items()}
missed_ids  = set(file_nodes.keys()) - reached

# ── 2. Helper: check whether fid has any RESOLVES_TO from a REACHED file ─────
def resolves_to_from_reached(fid):
    for ie in g.get_in_edges(fid):
        if ie.type != "RESOLVES_TO": continue
        src = g.get_node(ie.source_id)
        if not src: continue
        for ie2 in g.get_in_edges(src.id):
            if ie2.type != "IMPORTS": continue
            parent = g.get_node(ie2.source_id)
            if parent and parent.type == "File" and parent.id in reached:
                return True, src.properties.get("name","?"), parent.properties.get("path","?")
    return False, None, None

# ── 3. Helper: check for dynamic/inline imports in reached files ──────────────
def reached_source_texts():
    """Return list of (path, source) for every reached file."""
    results = []
    for fid in reached:
        fn = file_nodes.get(fid)
        if not fn: continue
        rel = fn.properties.get("path","")
        full = os.path.join(ROOT, rel.replace("/", os.sep))
        try:
            with open(full,"r",encoding="utf-8",errors="ignore") as f:
                results.append((rel, f.read()))
        except Exception: pass
    return results

_reached_sources = reached_source_texts()

def is_dynamically_imported(filepath):
    """
    True if any reached file contains an INLINE import of this module
    (i.e., 'import X' or 'importlib.import_module' inside a function body,
    not a top-level IMPORTS edge that SemanticResolver would have caught).
    """
    module_tail = filepath.replace(".py","").split("/")[-1]
    module_dot  = filepath.replace(".py","").replace("/",".")

    for (rel, src) in _reached_sources:
        lines = src.splitlines()
        inside_func = False
        indent_level = 0
        for line in lines:
            stripped = line.strip()
            # Track when we're inside a function/class body (rough heuristic)
            if stripped.startswith("def ") or stripped.startswith("async def "):
                inside_func = True
                indent_level = len(line) - len(line.lstrip())
            # importlib usage anywhere
            if "importlib" in stripped and (module_tail in stripped or module_dot in stripped):
                return True
            if "__import__" in stripped and (module_tail in stripped or module_dot in stripped):
                return True
            # Inline import inside function body
            if inside_func and (stripped.startswith("import ") or stripped.startswith("from ")):
                if module_tail in stripped or module_dot in stripped:
                    return True
    return False

# ── 4. Explain why a file is dead ─────────────────────────────────────────────
def explain_dead(fid):
    in_edges = g.get_in_edges(fid)
    if not in_edges:
        return "completely disconnected -- 0 incoming edges"
    types = sorted({e.type for e in in_edges})
    if types == ["CONTAINS"]:
        return "only via directory CONTAINS; never imported by any reachable file"
    # Has RESOLVES_TO but from missed files
    for ie in g.get_in_edges(fid):
        if ie.type == "RESOLVES_TO":
            src = g.get_node(ie.source_id)
            for ie2 in g.get_in_edges(src.id) if src else []:
                if ie2.type == "IMPORTS":
                    parent = g.get_node(ie2.source_id)
                    pp = parent.properties.get("path","?") if parent else "?"
                    return f"imported by '{pp}' which is itself unreachable"
    return f"incoming types={types}, none from reached file"

# ── 5. Categorise ─────────────────────────────────────────────────────────────
ALT_ENTRY = {"app.py", "server.py", "manage.py", "wsgi.py", "asgi.py", "run.py"}

cats = {1: [], 2: [], 3: [], 4: [], 5: [], 6: []}

for fid in sorted(missed_ids, key=lambda x: file_nodes[x].properties.get("path","")):
    fn   = file_nodes[fid]
    path = fn.properties.get("path","")
    name = path.split("/")[-1]

    # Cat 6: Has RESOLVES_TO from a reached file (should have been walked -- bug)
    ok, imp_stmt, imp_file = resolves_to_from_reached(fid)
    if ok:
        cats[6].append((path, f"imported as '{imp_stmt}' in reached '{imp_file}'"))
        continue

    # Cat 1: Alternative entry points
    if name in ALT_ENTRY:
        cats[1].append((path, "named application entry-point, not imported by main.py"))
        continue

    # Cat 2: Test files
    if (name.startswith("test_") or "/test_" in path or "test_repo/" in path
            or name.endswith("_test.py")):
        cats[2].append((path, "test file"))
        continue

    # Cat 3: Scratch / diagnostic files
    if "scratch" in path or name.startswith("scratch_"):
        cats[3].append((path, "scratch / diagnostic file"))
        continue

    # Cat 5: Dynamically imported
    if is_dynamically_imported(path):
        cats[5].append((path, "inline/importlib import in a reached file"))
        continue

    # Cat 4: Dead code
    cats[4].append((path, explain_dead(fid)))

# ── 6. Print ──────────────────────────────────────────────────────────────────
LABELS = {
    1: "Alternative entry points",
    2: "Test files",
    3: "Scratch / diagnostic files",
    4: "Dead code (unreachable from main.py)",
    5: "Utility modules imported dynamically",
    6: "Reachable but still missed  [traversal gap]",
}

grand_total = 0
print("=" * 72)
print("CATEGORISATION OF MISSED FILES")
print("=" * 72)
for cat, label in LABELS.items():
    items = cats[cat]
    grand_total += len(items)
    print(f"\n[{cat}] {label}  ({len(items)} files)")
    for path, reason in sorted(items):
        print(f"    {path}")
        print(f"      -> {reason}")

print()
print("=" * 72)
print(f"GRAND TOTAL: {grand_total} missed files")
print(f"  Reached : {len(reached)} / {len(file_nodes)}")
print("=" * 72)
