import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

from scanner.parser import UniversalParser
from scanner.security_engine import SecurityEngine
from scanner.intelligence.knowledge_graph import KnowledgeGraphBuilder
from scanner.intelligence.semantic_resolver import SemanticResolver

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

dir_types = {"Repository", "Folder", "File"}
graph_count = sum(1 for n in graph.nodes.values() if n.type in dir_types)
print(f'Knowledge Graph (Repository, Folder, File) nodes: {graph_count}')

from scanner.intelligence.tree_service import TreeService
ts = TreeService()
dv = ts.get_directory_view(graph)

def count_dict_nodes(d) -> int:
    if not d: return 0
    if isinstance(d, list): return sum(count_dict_nodes(c) for c in d)
    return 1 + sum(count_dict_nodes(c) for c in d.get('children', []))

print(f'directory_view nodes: {count_dict_nodes(dv)}')
