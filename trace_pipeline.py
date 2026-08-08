import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.dirname(os.path.abspath(__file__))

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

ep = next((n for n in graph.nodes.values() if n.type == 'File' and n.properties.get('path','').endswith('main.py')), None)

print('=== Execution Tree ===')
builder = ExecutionTreeBuilder()
raw_exec_tree = builder.build_global_tree(graph, ep.id)

def count_exec_nodes(node) -> int:
    if not node: return 0
    return 1 + sum(count_exec_nodes(c) for c in node.children)

def count_dict_nodes(d) -> int:
    if not d: return 0
    if isinstance(d, list):
        return sum(count_dict_nodes(c) for c in d)
    return 1 + sum(count_dict_nodes(c) for c in d.get('children', []))

print('Stage')
print('->')
print(f'{count_exec_nodes(raw_exec_tree)} nodes (ExecutionTreeBuilder.build_global_tree)')
print('->')

tree_service = TreeService()
service_exec_tree = tree_service.get_global_execution_view(graph, ep.id)
print('Stage')
print('->')
print(f'{count_dict_nodes(service_exec_tree) if service_exec_tree else 0} nodes (TreeService.get_execution_path)')
print('->')

# Check JSON
try:
    from scanner.serializer import CustomJSONEncoder
    json_exec_tree = json.dumps(service_exec_tree, cls=CustomJSONEncoder)
except:
    json_exec_tree = json.dumps(service_exec_tree)
parsed_json_exec = json.loads(json_exec_tree) if json_exec_tree else {}
print('Stage')
print('->')
print(f'{count_dict_nodes(parsed_json_exec)} nodes (API Response JSON)')

print('\n=== Repository Explorer ===')
file_nodes = [n for n in graph.nodes.values() if n.type == 'File']
print('Stage')
print('->')
print(f'{len(file_nodes)} nodes (Knowledge Graph Files)')
print('->')

structure_view = tree_service.get_structure_view(graph)
print('Stage')
print('->')
print(f'{count_dict_nodes(structure_view)} nodes (TreeService.get_structure_view)')
print('->')

directory_view = tree_service.get_directory_view(graph)
print('Stage')
print('->')
print(f'{count_dict_nodes(directory_view)} nodes (TreeService.get_directory_view)')
print('->')

try:
    from scanner.serializer import CustomJSONEncoder
    json_struct_tree = json.dumps(structure_view, cls=CustomJSONEncoder)
    json_dir_tree = json.dumps(directory_view, cls=CustomJSONEncoder)
except:
    json_struct_tree = json.dumps(structure_view)
    json_dir_tree = json.dumps(directory_view)
parsed_json_struct = json.loads(json_struct_tree) if json_struct_tree else {}
parsed_json_dir = json.loads(json_dir_tree) if json_dir_tree else {}
print('Stage')
print('->')
print(f'{count_dict_nodes(parsed_json_struct)} nodes (API Response JSON structure_view)')
print('->')
print(f'{count_dict_nodes(parsed_json_dir)} nodes (API Response JSON directory_view)')
