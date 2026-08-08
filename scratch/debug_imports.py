"""
Debug: show IMPORTS -> RESOLVES_TO chain for main.py
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from scanner.parser import UniversalParser
from scanner.security_engine import SecurityEngine
from scanner.intelligence.knowledge_graph import KnowledgeGraphBuilder
from scanner.intelligence.semantic_resolver import SemanticResolver
from scanner.intelligence.execution_builder import ExecutionTreeBuilder

SKIP_DIRS = {"__pycache__",".git","venv",".venv","node_modules",
             "tmp_repo","tmp_repo2","tmp_repo3","tmp_repo4",
             "tmp_repo5","tmp_repo6","tmp_repo7","tmp_repo8",".cache"}

ROOT = os.path.dirname(os.path.dirname(__file__))
parser = UniversalParser()
engine = SecurityEngine()
pf_list = []
findings = []

for root, dirs, files in os.walk(ROOT):
    dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
    for fname in files:
        if not fname.endswith(".py"):
            continue
        full = os.path.join(root, fname)
        rel  = os.path.relpath(full, ROOT).replace("\\", "/")
        try:
            with open(full, "r", encoding="utf-8", errors="ignore") as f:
                src = f.read()
            pf = parser.parse(src, rel)
            if pf:
                pf_list.append(pf)
                sec = engine.scan(pf, rel)
                findings.extend(sec.findings)
        except Exception:
            pass

print(f"Parsed {len(pf_list)} files, {len(findings)} findings")
kg  = KnowledgeGraphBuilder("local")
raw = kg.build(pf_list, findings)
g   = SemanticResolver().resolve(raw)

print(f"Graph: {len(g.nodes)} nodes, {len(g.edges)} edges")

# Find main.py
ep = next((n for n in g.nodes.values()
           if n.type == "File" and n.properties.get("path","").endswith("main.py")), None)
print("Entry:", ep.properties.get("path") if ep else "NOT FOUND")

# Show what IMPORTS edges main.py has and what they resolve to
out = g.get_out_edges(ep.id)
import_edges = [e for e in out if e.type == "IMPORTS"]
print(f"main.py IMPORTS edges: {len(import_edges)}")

for ie in import_edges:
    imp_node = g.get_node(ie.target_id)
    if not imp_node:
        print("  [WARN] Import node missing:", ie.target_id)
        continue
    imp_name = imp_node.properties.get("name", "?")
    res_edges = [e for e in g.get_out_edges(imp_node.id) if e.type == "RESOLVES_TO"]
    if res_edges:
        for re in res_edges:
            tgt = g.get_node(re.target_id)
            tpath = tgt.properties.get("path", tgt.properties.get("name","?")) if tgt else "?"
            ttype = tgt.type if tgt else "?"
            print(f"  IMPORT '{imp_name}' -> RESOLVES_TO -> {ttype} '{tpath}'")
    else:
        print(f"  IMPORT '{imp_name}' -> NO RESOLVES_TO edges")

# Now try building the tree and check coverage
print()
print("Building tree from main.py...")
builder = ExecutionTreeBuilder()
tree = builder.build_global_tree(g, ep.id)

from scanner.intelligence.execution_builder import ExecutionNode
visited: set = set()
def collect(node: ExecutionNode):
    if node.type == "File":
        visited.add(node.id)
    for c in node.children:
        collect(c)

if tree:
    collect(tree)

file_nodes = [n for n in g.nodes.values() if n.type == "File"]
missed = {n.id for n in file_nodes} - visited

print(f"Total files: {len(file_nodes)}")
print(f"Reached:     {len(visited)}")
print(f"Missed:      {len(missed)}")

# Print reached files
print("\nReached files:")
for fid in visited:
    fn = g.get_node(fid)
    print(f"  {fn.properties.get('path','') if fn else fid}")

# Print first 20 missed with edge explanation
print("\nFirst 20 missed files:")
for fid in sorted(missed)[:20]:
    fn = g.get_node(fid)
    fpath = fn.properties.get("path","") if fn else fid
    in_e = g.get_in_edges(fid)
    types = list({e.type for e in in_e})
    print(f"  {fpath}: in_edge_types={types}")
