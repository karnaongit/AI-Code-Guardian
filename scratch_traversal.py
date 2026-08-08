from services.analysis_service import AnalysisService
from scanner.intelligence.execution_builder import ExecutionTreeBuilder
import json

def test_real_repo():
    service = AnalysisService()
    # Scan the test_repo to get a real KnowledgeGraph
    res = service.analyze_repository("sidgulmire1/AI-Code-Guardian")
    graph = service._kg_builder.graph
    
    print(f"Graph size: {len(graph.nodes)} nodes, {len(graph.edges)} edges")
    
    # Find a Finding node
    finding_node = None
    for node in graph.nodes.values():
        if node.type == "Finding":
            finding_node = node
            break
            
    if not finding_node:
        print("No Finding node found!")
        return
        
    print(f"Testing traversal from Finding node: {finding_node.id}")
    builder = ExecutionTreeBuilder()
    tree = builder.build_path(graph, finding_node.id)
    
    if tree:
        print("Final Tree:")
        print(json.dumps(tree.to_dict(), indent=2))
    else:
        print("Failed to build tree")

if __name__ == "__main__":
    test_real_repo()
