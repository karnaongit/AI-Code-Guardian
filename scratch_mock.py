import json
from scanner.intelligence.knowledge_graph import KnowledgeGraphBuilder, GraphNode
from scanner.intelligence.tree_service import TreeService
from scanner.models import ParsedFile, ClassSymbol, FunctionSymbol, CallSymbol, SecurityFinding

def main():
    repo_name = "test_repo"
    builder = KnowledgeGraphBuilder(repo_name)
    
    # Mock data
    f1 = ParsedFile(file_path="src/main.py", language="python", classes=[], functions=[], calls=[], imports=[])
    f2 = ParsedFile(file_path="utils.py", language="python", classes=[], functions=[], calls=[], imports=[])
    
    s1 = ClassSymbol(symbol_id="c1", name="MyClass", line=10, snippet="class MyClass", parent_id=f1.file_id)
    s2 = FunctionSymbol(symbol_id="fun1", name="my_func", line=12, snippet="def my_func", parent_id="c1")
    s3 = CallSymbol(symbol_id="call1", name="requests.get", line=14, snippet="requests.get(url)", parent_id="fun1")
    
    f1.classes.append(s1)
    f1.functions.append(s2)
    f1.calls.append(s3)
    
    finding1 = SecurityFinding(rule_id="SEC_001", severity="High", file="src/main.py", line=14, description="SSRF", file_id=f1.file_id, symbol_id="call1", class_name="MyClass", function_name="my_func", snippet="requests.get(url)")
    
    graph = builder.build([f1, f2], [finding1])
    
    kg_counts = {}
    for n in graph.nodes.values():
        kg_counts[n.type] = kg_counts.get(n.type, 0) + 1
            
    print("KNOWLEDGE GRAPH:")
    for k, v in kg_counts.items():
        print(f"  {k}: {v}")
        
    ts = TreeService()
    structure = ts.get_structure_view(graph)
    dir_view = ts.get_directory_view(graph)
    
    print("\nDIRECTORY VIEW MAX SEVERITIES:")
    def print_dir_sevs(node):
        if not node: return
        ntype = node.get("type", node.get("node_type"))
        if ntype == "File":
            print(f"  {node.get('label')}: maxSeverity={node.get('metadata', {}).get('maxSeverity')}, finding_count={node.get('metadata', {}).get('finding_count')}")
        for child in node.get("children", []):
            print_dir_sevs(child)
            
    print_dir_sevs(dir_view)
    
    struct_counts = {}
    
    def count_tree(node):
        if not node: return
        ntype = node.get("type", node.get("node_type"))
        struct_counts[ntype] = struct_counts.get(ntype, 0) + 1
        for child in node.get("children", []):
            count_tree(child)
            
    count_tree(structure)
    
    print("\nSTRUCTURE VIEW:")
    for k, v in struct_counts.items():
        print(f"  {k}: {v}")

    print("\nFIRST DISCREPANCY:")
    print(json.dumps(structure, indent=2))
        
if __name__ == "__main__":
    main()
