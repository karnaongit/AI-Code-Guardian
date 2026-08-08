from services.analysis_service import AnalysisService
from scanner.intelligence.tree_service import TreeService

def main():
    service = AnalysisService()
    report = service.analyze_repository("Siddharth Gulmire/Feb 2026 AI/AI trends/AI-Code_Guardian")
    
    graph = report.get("graph")
    
    kg_counts = {"Repository": 0, "Folder": 0, "File": 0, "Class": 0, "Function": 0, "Finding": 0, "Call": 0}
    for n in graph.nodes.values():
        if n.type in kg_counts:
            kg_counts[n.type] += 1
            
    print("KNOWLEDGE GRAPH:")
    for k, v in kg_counts.items():
        print(f"  {k}: {v}")
        
    ts = TreeService()
    structure = ts.get_structure_view(graph)
    
    struct_counts = {"Repository": 0, "Folder": 0, "File": 0, "Class": 0, "Function": 0, "Finding": 0, "Call": 0}
    
    def count_tree(node):
        if not node: return
        ntype = node.get("type", node.get("node_type"))
        if ntype in struct_counts:
            struct_counts[ntype] += 1
        for child in node.get("children", []):
            count_tree(child)
            
    count_tree(structure)
    
    print("\nSTRUCTURE VIEW:")
    for k, v in struct_counts.items():
        print(f"  {k}: {v}")

if __name__ == "__main__":
    main()
