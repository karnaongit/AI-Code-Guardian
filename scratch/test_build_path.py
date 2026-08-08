import sys
import os
import json

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from scanner.models import SecurityFinding, FunctionSymbol, ClassSymbol, CallSymbol, ParsedFile
from scanner.intelligence.knowledge_graph import KnowledgeGraphBuilder
from scanner.intelligence.tree_service import TreeService
from scanner.intelligence.execution_builder import ExecutionTreeBuilder

# Build a chain of calls across files
f1 = ParsedFile(file_path='main.py', language='Python')
f1.functions.append(FunctionSymbol(name='main', line=1, snippet='def main():', symbol_id='f1_main'))
f1.calls.append(CallSymbol(name='start', line=2, snippet='start()', symbol_id='f1_call', parent_id='f1_main'))

f2 = ParsedFile(file_path='app.py', language='Python')
f2.functions.append(FunctionSymbol(name='start', line=1, snippet='def start():', symbol_id='f2_start'))
f2.calls.append(CallSymbol(name='run', line=2, snippet='run()', symbol_id='f2_call', parent_id='f2_start'))

f3 = ParsedFile(file_path='db.py', language='Python')
f3.functions.append(FunctionSymbol(name='run', line=1, snippet='def run():', symbol_id='f3_run'))
f3.calls.append(CallSymbol(name='query', line=2, snippet='query()', symbol_id='f3_call', parent_id='f3_run'))

finding = SecurityFinding(
    rule_id='sql_injection', title='SQL Injection', category='Injection', severity='Critical',
    confidence=0.95, file='db.py', line=2, class_name='', function_name='run',
    snippet='query()', evidence='none', cwe='CWE-89', owasp='A1', recommendation='fix it',
    symbol_id='f3_run'
)

kg = KnowledgeGraphBuilder("repo")
graph = kg.build([f1, f2, f3], [finding])

# Link them!
graph.add_edge('f1_call', 'f2_start', 'CALLS')
graph.add_edge('f2_call', 'f3_run', 'CALLS')

builder = ExecutionTreeBuilder()
tree_service = TreeService()
root = builder.build_path(graph, finding.finding_id)

def print_tree(node, indent=0):
    print(" " * indent + f"- {node.type}: {node.name}")
    for child in node.children:
        print_tree(child, indent + 2)

if root:
    print("\n\n=== RESULTING TREE ===")
    print_tree(root)
else:
    print("NO TREE RETURNED")
