from services.analysis_service import AnalysisService
from scanner.intelligence.knowledge_graph import KnowledgeGraphBuilder
from scanner.intelligence.semantic_resolver import SemanticResolver

def debug_semantic():
    service = AnalysisService()
    # Mocking the repository fetch to avoid GitHub API 404
    # We can just run the graph builder on the local directory
    import os
    
    # Actually, we can just run the parse manually
    from scanner.parser import UniversalParser
    from scanner.language_manager import LanguageManager
    import json
    
    parser = UniversalParser()
    parsed_files = []
    
    for root, _, files in os.walk("."):
        if "venv" in root or "node_modules" in root or "__pycache__" in root or ".git" in root:
            continue
        for file in files:
            if file.endswith(".py"):
                path = os.path.join(root, file)
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                try:
                    parsed = parser.parse(content, path)
                    parsed_files.append(parsed)
                except Exception as e:
                    print(f"Failed to parse {path}: {e}")
                    
    print(f"Parsed {len(parsed_files)} files")
    
    graph_builder = KnowledgeGraphBuilder("local")
    raw_graph = graph_builder.build(parsed_files, [])
    
    resolver = SemanticResolver()
    graph = resolver.resolve(raw_graph)
    
    print(f"Edges: {len(graph.edges)}")
    calls_edges = [e for e in graph.edges if e.type == "CALLS"]
    resolves_to = [e for e in graph.edges if e.type == "RESOLVES_TO"]
    print(f"RESOLVES_TO edges: {len(resolves_to)}")
    
    for e in resolves_to:
        target = graph.get_node(e.target_id)
        if target and target.type == "File":
            print(f"File {target.properties.get('path')} has RESOLVES_TO from {graph.get_node(e.source_id).properties.get('name')}")

if __name__ == "__main__":
    debug_semantic()
