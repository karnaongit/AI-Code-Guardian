import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

from scanner.parser import UniversalParser
from scanner.security_engine import SecurityEngine
from scanner.intelligence.knowledge_graph import KnowledgeGraphBuilder
from scanner.intelligence.semantic_resolver import SemanticResolver
from scanner.intelligence.execution_builder import ExecutionTreeBuilder
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

ts = TreeService()
dir_view = ts.get_directory_view(graph)
struct_view = ts.get_structure_view(graph)

# Emulate React component logic for RepositoryExplorer
def get_file_semantic_map(node):
    map = {}
    if not node: return map
    def traverse(n):
        if not n: return
        node_type = n.get('type') or n.get('node_type')
        if node_type == 'File':
            metadata = n.get('metadata', {})
            path = metadata.get('path') or n.get('label') or n.get('name') or ''
            map[n.get('id')] = n.get('children', [])
            if path:
                map[path] = n.get('children', [])
        for c in n.get('children', []):
            traverse(c)
    
    root = node
    if isinstance(root, list): root = root[0]
    traverse(root)
    return map

semantic_map = get_file_semantic_map(struct_view)

# Traverse directory_view and count how many nodes it resolves through semantic_map
rendered_nodes = 0
def traverse_repo_tree(n):
    global rendered_nodes
    if not n: return
    rendered_nodes += 1
    node_type = n.get('type') or n.get('node_type')
    if node_type == 'File':
        children = semantic_map.get(n.get('id'), [])
        for c in children:
            # Emulate semantic children rendering
            rendered_nodes += count_children(c)
    else:
        for c in n.get('children', []):
            traverse_repo_tree(c)

def count_children(n):
    if not n: return 0
    return 1 + sum(count_children(c) for c in n.get('children', []))

traverse_repo_tree(dir_view)

print('=== Repository Explorer React Trace ===')
print('Stage')
print('->')
print(f'{count_children(dir_view)} nodes (directory_view input)')
print('->')
print(f'{rendered_nodes} nodes (Rendered in React)')

# Now execution tree
ep = next((n for n in graph.nodes.values() if n.type == 'File' and n.properties.get('path','').endswith('main.py')), None)
exec_view = ts.get_global_execution_view(graph, ep.id)

print('\n=== Execution Tree React Trace ===')
print('Stage')
print('->')
print(f'{count_children(exec_view)} nodes (API Response JSON)')
print('->')
print(f'{count_children(exec_view)} nodes (Rendered in React)')
