"""
Deep import chain analysis:
- For each reached file, show what its IMPORTS resolve to
- Identify which resolved files are still missed
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from scanner.parser import UniversalParser
from scanner.security_engine import SecurityEngine
from scanner.intelligence.knowledge_graph import KnowledgeGraphBuilder
from scanner.intelligence.semantic_resolver import SemanticResolver
from scanner.intelligence.execution_builder import ExecutionTreeBuilder, ExecutionNode

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
        if not fname.endswith(".py"): continue
        full = os.path.join(root, fname)
        rel  = os.path.relpath(full, ROOT).replace("\\", "/")
        try:
            with open(full, "r", encoding="utf-8", errors="ignore") as f: src = f.read()
            pf = parser.parse(src, rel)
            if pf:
                pf_list.append(pf)
                sec = engine.scan(pf, rel)
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

file_nodes = {n.id: n for n in g.nodes.values() if n.type == "File"}
missed = set(file_nodes.keys()) - reached

print(f"Reached: {len(reached)}, Missed: {len(missed)}")
print()
print("=== IMPORT CHAIN for REACHED files ===")
for fid in sorted(reached):
    fn = g.get_node(fid)
    fpath = fn.properties.get("path","") if fn else fid
    out = g.get_out_edges(fid)
    import_edges = [e for e in out if e.type == "IMPORTS"]
    resolved_files = []
    for ie in import_edges:
        imp = g.get_node(ie.target_id)
        if not imp: continue
        for re in g.get_out_edges(imp.id):
            if re.type != "RESOLVES_TO": continue
            tgt = g.get_node(re.target_id)
            if tgt and tgt.type == "File":
                resolved_files.append((imp.properties.get("name","?"), tgt.id, tgt.properties.get("path","?")))
    if resolved_files:
        print(f"  {fpath}:")
        for imp_name, tgt_id, tgt_path in resolved_files:
            status = "REACHED" if tgt_id in reached else "*** MISSED ***"
            print(f"    imports '{imp_name}' -> {tgt_path} [{status}]")
    else:
        print(f"  {fpath}: no resolved local imports")
