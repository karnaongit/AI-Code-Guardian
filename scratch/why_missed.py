"""
Find out WHY rule_engine.py, engine.py, finding_builder.py still missed.
Inspect which Import node resolves to them and whether that importer file is reached.
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

parser  = UniversalParser()
engine  = SecurityEngine()
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

# Files with RESOLVES_TO that are still missed
check_paths = [
    "scanner/intelligence/rule_engine.py",
    "scanner/intelligence/engine.py",
    "scanner/intelligence/finding_builder.py",
    "rag/loader.py",
    "rag/embedder.py",
    "scanner/security_engine_ast.py",
    "scanner/language_registry.py",
    "services/report_service.py",
    "api/__init__.py",
    "app.py",
]

print("=== RESOLVES_TO analysis for missed app files ===\n")
for check_path in check_paths:
    target_node = next((n for n in g.nodes.values()
                        if n.type == "File" and n.properties.get("path","") == check_path), None)
    if not target_node:
        print(f"  {check_path}: NOT FOUND IN GRAPH")
        continue
    status = "REACHED" if target_node.id in reached else "MISSED"
    print(f"  {check_path} [{status}]")
    in_edges = g.get_in_edges(target_node.id)
    for ie in in_edges:
        src = g.get_node(ie.source_id)
        if not src:
            print(f"    <-- {ie.type} from UNKNOWN {ie.source_id}")
            continue
        if ie.type == "RESOLVES_TO":
            # src is an Import node — find which file owns it
            import_file = None
            for ie2 in g.get_in_edges(src.id):
                if ie2.type == "IMPORTS":
                    imp_file = g.get_node(ie2.source_id)
                    if imp_file and imp_file.type == "File":
                        import_file = imp_file
                        break
            file_status = "REACHED" if import_file and import_file.id in reached else "MISSED"
            file_path   = import_file.properties.get("path","?") if import_file else "UNKNOWN"
            imp_name    = src.properties.get("name","?")
            print(f"    <-- RESOLVES_TO from Import '{imp_name}' in file '{file_path}' [{file_status}]")
        elif ie.type == "CONTAINS":
            src_path = src.properties.get("path", src.properties.get("name","?"))
            print(f"    <-- CONTAINS from '{src_path}' (folder/repo node)")
    print()
