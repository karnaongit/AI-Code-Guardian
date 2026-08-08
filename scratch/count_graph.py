import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

from scanner.parser import UniversalParser
from scanner.security_engine import SecurityEngine
from scanner.intelligence.knowledge_graph import KnowledgeGraphBuilder
from scanner.intelligence.semantic_resolver import SemanticResolver
from scanner.intelligence.execution_builder import ExecutionTreeBuilder, ExecutionNode
from scanner.intelligence.tree_service import TreeService

SKIP_DIRS = {'__pycache__', '.git', 'venv', '.venv', 'node_modules', 'tmp_repo','tmp_repo2','tmp_repo3','tmp_repo4','tmp_repo5','tmp_repo6','tmp_repo7','tmp_repo8','.cache'}

parser = UniversalParser()
engine = SecurityEngine()
pf_list = []
findings = []

for root, dirs, files in os.walk(ROOT):
    dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith('.')]
    for fname in files:
        if not fname.endswith('.py'): continue
        full = os.path.join(root, fname)
        rel = os.path.relpath(full, ROOT).replace(chr(92), '/')
        try:
            with open(full, 'r', encoding='utf-8', errors='ignore') as f: src = f.read()
            pf = parser.parse(src, rel)
            if pf:
                pf_list.append(pf)
                sec = engine.scan(pf, rel)
                findings.extend(sec.findings)
        except Exception: pass

kg = KnowledgeGraphBuilder('local')
raw = kg.build(pf_list, findings)
graph = SemanticResolver().resolve(raw)

# Count graph nodes by type
types = ["Repository", "Folder", "File", "Class", "Function", "Finding"]
graph_count = sum(1 for n in graph.nodes.values() if n.type in types)

print('=== Repository Explorer ===')
print('Stage')
print('->')
print(f'{graph_count} nodes (Knowledge Graph)')
print('->')

tree_service = TreeService()
structure_view = tree_service.get_structure_view(graph)

def count_dict_nodes(d) -> int:
    if not d: return 0
    if isinstance(d, list): return sum(count_dict_nodes(c) for c in d)
    return 1 + sum(count_dict_nodes(c) for c in d.get('children', []))

print('Stage')
print('->')
print(f'{count_dict_nodes(structure_view)} nodes (TreeService.get_structure_view)')

