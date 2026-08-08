import os
from scanner.parser import UniversalParser
from scanner.intelligence.knowledge_graph import KnowledgeGraphBuilder
from scanner.intelligence.semantic_resolver import SemanticResolver
from scanner.intelligence.execution_builder import ExecutionTreeBuilder

class MockLLM:
    pass

parser = UniversalParser(llm=MockLLM())

pf_list = []
import os
for root, _, files in os.walk("."):
    for file in files:
        if file.endswith('.py'):
            path = os.path.join(root, file)
            with open(path, "r", encoding="utf-8") as f:
                pf = parser.parse(f.read(), path)
                if pf: pf_list.append(pf)

kg = KnowledgeGraphBuilder("sidgulmire1/AI-Code-Guardian")
kg.build(pf_list, [])
resolver = SemanticResolver()
g = resolver.resolve(kg.graph)
builder = ExecutionTreeBuilder()
main_id = None
for n in g.nodes.values():
    if n.type == "File" and "main.py" in n.properties.get("path", ""):
        main_id = n.id
        break

tree = builder.build_global_tree(g, main_id)

import json
if tree:
    print(json.dumps(tree.to_dict(), indent=2))
else:
    print("Tree is None")

