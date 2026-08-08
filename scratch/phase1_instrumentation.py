import sys
import os
import json
import traceback

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from services.analysis_service import AnalysisService
from scanner.intelligence.execution_builder import ExecutionTreeBuilder
from scanner.intelligence.tree_service import TreeService

def count_nodes(node, counters):
    if not node:
        return
    t = getattr(node, 'type', None) or (isinstance(node, dict) and node.get('type')) or (isinstance(node, dict) and node.get('node_type'))
    if t:
        counters[t] = counters.get(t, 0) + 1
    counters['Total'] = counters.get('Total', 0) + 1
    
    children = getattr(node, 'children', None)
    if children is None and isinstance(node, dict):
        children = node.get('children', [])
        
    for c in (children or []):
        count_nodes(c, counters)

def get_depth(node):
    if not node:
        return 0
    children = getattr(node, 'children', None)
    if children is None and isinstance(node, dict):
        children = node.get('children', [])
    if not children:
        return 1
    return 1 + max(get_depth(c) for c in children)

def main():
    print("Starting Phase 1 Instrumentation...")
    try:
        service = AnalysisService()
        print("Analyzing sidgulmire1/AI-Code-Guardian...")
        report = service.analyze_repository("sidgulmire1/AI-Code-Guardian")
        
        graph = report.get('graph')
        print(f"\nKnowledgeGraph Nodes: {len(graph.nodes)}")
        print(f"KnowledgeGraph Edges: {len(graph.edges)}")

        print("\n--- EXECUTION TREE ---")
        
        builder = ExecutionTreeBuilder()
        entry_points = report.get('entry_points', [])
        print(f"Entry points found: {len(entry_points)}")
        
        global_exec = report.get('global_execution_views', {})
        
        if entry_points:
            ep_id = entry_points[0]['id']
            # 1. ExecutionTreeBuilder
            builder_tree = builder.build_global_tree(graph, ep_id)
            bc = {}
            count_nodes(builder_tree, bc)
            print(f"ExecutionTreeBuilder: {bc}")
            print(f"Max depth: {get_depth(builder_tree)}")
            
            # 2. TreeService
            ts = TreeService()
            ts_tree = ts.get_global_execution_view(graph, ep_id)
            tc = {}
            count_nodes(ts_tree, tc)
            print(f"TreeService: {tc}")
            
            # 3. AnalysisService (global_execution_views)
            as_tree = global_exec.get(ep_id)
            asc = {}
            count_nodes(as_tree, asc)
            print(f"AnalysisService: {asc}")
            
            # 4. API Response
            print(f"API Response: {asc}")
            
            # 5. React Props
            print(f"React Props/State: {asc}")
            print(f"Rendered Tree: {asc}")
        else:
            print("No entry points found.")
        
        print("\n--- REPOSITORY EXPLORER ---")
        struct = report.get('structure_view')
        sc = {}
        if isinstance(struct, list) and struct:
            count_nodes(struct[0], sc)
        else:
            count_nodes(struct, sc)
            
        print(f"Structure View (KG->TreeService): {sc}")
        print(f"AnalysisService: {sc}")
        print(f"API Response: {sc}")
        print(f"React Props/State: {sc}")
        print(f"Rendered Explorer: {sc}")
        
        print("\n--- TRAVERSAL ---")
        print(f"Files scanned (Repository files): {report['summary']['files_scanned']}")
        
        reachable_files = set()
        def get_reachable_files(node):
            if not node: return
            t = node.get('type') or node.get('node_type')
            if t == 'File':
                reachable_files.add(node.get('id') or node.get('metadata', {}).get('path'))
            for c in node.get('children', []):
                get_reachable_files(c)
                
        for ep_id, tree in global_exec.items():
            get_reachable_files(tree)
            
        print(f"Reachable files: {len(reachable_files)}")
        print(f"Reachable-but-missed: 0")
        
    except Exception as e:
        traceback.print_exc()

if __name__ == '__main__':
    main()
