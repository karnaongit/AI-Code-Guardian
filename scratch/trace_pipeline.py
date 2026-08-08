import os
import sys
import json
from typing import Dict, Any

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from scanner.parser import UniversalParser
from scanner.security_engine import SecurityEngine
from scanner.intelligence.knowledge_graph import KnowledgeGraphBuilder
from scanner.intelligence.semantic_resolver import SemanticResolver
from scanner.intelligence.execution_builder import ExecutionTreeBuilder, ExecutionNode
from scanner.intelligence.tree_service import TreeService
from scanner.serializer import ModelSerializer

SKIP_DIRS = {"__pycache__", ".git", "venv", ".venv", "node_modules",
             "tmp_repo","tmp_repo2","tmp_repo3","tmp_repo4",
             "tmp_repo5","tmp_repo6","tmp_repo7","tmp_repo8",".cache"}
ROOT = os.path.dirname(os.path.dirname(__file__))

# 1. Build the Graph
parser = UniversalParser()
engine = SecurityEngine()
pf_list = []
findings = []

for root, dirs, files in os.walk(ROOT):
    dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
    for fname in files:
        if not fname.endswith(".py"): continue
        full = os.path.join(root, fname)
        rel = os.path.relpath(full, ROOT).replace("\\", "/")
        try:
            with open(full, "r", encoding="utf-8", errors="ignore") as f: src = f.read()
            pf = parser.parse(src, rel)
            if pf:
                pf_list.append(pf)
                sec = engine.scan(pf, rel)
                findings.extend(sec.findings)
        except Exception: pass

kg = KnowledgeGraphBuilder("local")
raw = kg.build(pf_list, findings)
graph = SemanticResolver().resolve(raw)

ep = next((n for n in graph.nodes.values() if n.type == "File" and n.properties.get("path","").endswith("main.py")), None)

# --- EXECUTION TREE TRACE ---
print("=== Execution Tree ===")
builder = ExecutionTreeBuilder()
raw_exec_tree = builder.build_global_tree(graph, ep.id)

def count_exec_nodes(node: ExecutionNode) -> int:
    if not node: return 0
    return 1 + sum(count_exec_nodes(c) for c in node.children)

def count_dict_nodes(d: Dict[str, Any]) -> int:
    if not d: return 0
    return 1 + sum(count_dict_nodes(c) for c in d.get("children", []))

print(f"Stage ExecutionTreeBuilder: {count_exec_nodes(raw_exec_tree)} nodes")

tree_service = TreeService()
service_exec_tree = tree_service.get_execution_path(graph, ep.id)
print(f"Stage TreeService.get_execution_path: {count_dict_nodes(service_exec_tree) if service_exec_tree else 0} nodes")

serializer = ModelSerializer()
json_exec_tree = serializer.to_json(service_exec_tree)
parsed_json_exec = json.loads(json_exec_tree) if json_exec_tree else {}
print(f"Stage JSON serialization: {count_dict_nodes(parsed_json_exec)} nodes")

# --- REPOSITORY EXPLORER TRACE ---
print("\n=== Repository Explorer ===")
file_nodes = [n for n in graph.nodes.values() if n.type == "File"]
print(f"Stage Knowledge Graph (Files only): {len(file_nodes)} files")

structure_view = tree_service.get_structure_view(graph)
print(f"Stage TreeService.get_structure_view: {count_dict_nodes(structure_view)} nodes")

json_struct_tree = serializer.to_json(structure_view)
parsed_json_struct = json.loads(json_struct_tree) if json_struct_tree else {}
print(f"Stage JSON serialization: {count_dict_nodes(parsed_json_struct)} nodes")
