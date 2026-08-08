from services.analysis_service import AnalysisService
from scanner.parser import UniversalParser
from scanner.intelligence.knowledge_graph import KnowledgeGraphBuilder
from scanner.intelligence.semantic_resolver import SemanticResolver

import json

svc = AnalysisService()
svc.repository_path = 'sidgulmire1/AI-Code-Guardian'
import os
pf_list = []
for root, _, files in os.walk("."):
    for file in files:
        if file.endswith('.py'):
            path = os.path.join(root, file)
            with open(path, 'r', encoding='utf-8') as f:
                pf = svc.parser.parse(f.read(), path)
                if pf: pf_list.append(pf)

kg_builder = KnowledgeGraphBuilder("sidgulmire1/AI-Code-Guardian")
print(f"Parsed {len(pf_list)} files")
kg_builder.build(pf_list, [])

resolver = SemanticResolver()
g = resolver.resolve(kg_builder.graph)

print(f"Graph has {len(g.nodes)} nodes")
from collections import Counter
counts = Counter(n.type for n in g.nodes.values())
print(counts)
for node in g.nodes.values():
    if node.type == 'Call':
        if 'include_router' in node.properties.get('name', ''):
            print("FOUND CALL:", node.properties.get('name'))
            for edge in g.get_out_edges(node.id):
                print("  OUT EDGE:", edge.type, "->", edge.target_id)
