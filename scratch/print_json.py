import json
from scanner.intelligence.knowledge_graph import KnowledgeGraph
from scanner.intelligence.tree_service import TreeService
from scratch.verify_regressions import build_test_graph

# 1. Setup Mock Graph
graph, finding_id, entry_id = build_test_graph()

# 2. Get Views
service = TreeService()
directory_view = service.get_directory_view(graph)
structure_view = service.get_structure_view(graph)
execution_view = service.get_execution_view(graph, finding_id)

print("=== DIRECTORY_VIEW ===")
print(json.dumps(directory_view, indent=2))
print("=== STRUCTURE_VIEW ===")
print(json.dumps(structure_view, indent=2))
print("=== EXECUTION_VIEW ===")
print(json.dumps(execution_view, indent=2))
