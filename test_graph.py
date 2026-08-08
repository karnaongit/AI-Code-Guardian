from scanner.models import ParsedFile, ClassSymbol, FunctionSymbol, CallSymbol, SecurityFinding
from scanner.intelligence.knowledge_graph import KnowledgeGraphBuilder

def test_knowledge_graph_builder():
    builder = KnowledgeGraphBuilder("fportantier/vulpy")
    
    pf = ParsedFile()
    pf.file_path = "app/main.py"
    pf.language = "Python"
    pf.file_id = builder._hash("app/main.py")

    c = ClassSymbol(name="User", line=10, snippet="class User:")
    c.symbol_id = builder._hash("ClassSymbol:User:10")
    
    f = FunctionSymbol(name="login", line=12, snippet="def login():", parent_id=c.symbol_id)
    f.symbol_id = builder._hash("FunctionSymbol:login:12")
    
    call = CallSymbol(name="execute", line=15, snippet="db.execute(query)", parent_id=f.symbol_id)
    call.symbol_id = builder._hash("CallSymbol:execute:15")

    pf.classes.append(c)
    pf.functions.append(f)
    pf.calls.append(call)

    finding = SecurityFinding()
    finding.file = "app/main.py"
    finding.file_id = pf.file_id
    finding.symbol_id = call.symbol_id
    finding.category = "Injection"
    finding.rule_id = "sql-injection"
    finding.capability = "DatabaseExecution"
    finding.severity = "High"

    graph = builder.build([pf], [finding])

    # Assert repo node
    repo_node = graph.get_node(builder.repo_id)
    assert repo_node is not None
    assert repo_node.type == "Repository"

    # Assert File node
    file_node = graph.get_node(pf.file_id)
    assert file_node is not None

    # Assert contains edge from Repo to File
    assert any(e.target_id == pf.file_id and e.type == "CONTAINS" for e in graph.get_out_edges(builder.repo_id))

    # Assert contains edge from File to Class
    assert any(e.target_id == c.symbol_id and e.type == "CONTAINS" for e in graph.get_out_edges(pf.file_id))

    # Assert contains edge from Class to Function
    assert any(e.target_id == f.symbol_id and e.type == "CONTAINS" for e in graph.get_out_edges(c.symbol_id))

    # Assert executes edge from Function to Call
    assert any(e.target_id == call.symbol_id and e.type == "EXECUTES" for e in graph.get_out_edges(f.symbol_id))

    # Assert HAS_CAPABILITY from Call to Capability
    cap_id = builder._hash("capability:DatabaseExecution")
    assert any(e.target_id == cap_id and e.type == "HAS_CAPABILITY" for e in graph.get_out_edges(call.symbol_id))

    # Assert MATCHES_RULE from Capability to Rule
    rule_id = builder._hash("rule:sql-injection")
    assert any(e.target_id == rule_id and e.type == "MATCHES_RULE" for e in graph.get_out_edges(cap_id))

    print("Knowledge Graph built and verified successfully.")
    print(f"Total Nodes: {len(graph.nodes)}")
    print(f"Total Edges: {len(graph.edges)}")

if __name__ == "__main__":
    test_knowledge_graph_builder()
