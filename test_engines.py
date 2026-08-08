from scanner.models import ParsedFile, ClassSymbol, FunctionSymbol, CallSymbol, SecurityFinding
from scanner.intelligence.knowledge_graph import KnowledgeGraphBuilder
from scanner.intelligence.risk_engine import RiskPropagationEngine
from scanner.intelligence.tree_service import TreeService

def test_backend_engines():
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
    finding.severity = "Critical"

    graph = builder.build([pf], [finding])

    # 1. Test Risk Propagation
    risk_engine = RiskPropagationEngine()
    graph = risk_engine.propagate(graph)
    
    # Assert risk bubbled up to Repo
    repo_node = graph.get_node(builder.repo_id)
    assert repo_node.properties.get("risk_severity") == "Critical"
    
    # Assert risk bubbled up to File
    file_node = graph.get_node(pf.file_id)
    assert file_node.properties.get("risk_severity") == "Critical"

    # 2. Test Tree Service
    tree_service = TreeService()
    
    # Structure View
    struct_view = tree_service.get_structure_view(graph)
    assert struct_view["label"] == "fportantier/vulpy"
    assert len(struct_view["children"]) > 0
    assert struct_view["children"][0]["type"] == "Folder" # app
    
    # Execution View
    exec_view = tree_service.get_execution_view(graph, finding.finding_id)
    assert exec_view is not None
    assert exec_view["type"] == "Class" # Entry point (since no one calls it)
    
    # Security View
    sec_view = tree_service.get_security_view(graph)
    assert sec_view["metadata"].get("risk_severity") == "Critical"

    print("Phase 2 Backend Engines tested successfully.")

if __name__ == "__main__":
    test_backend_engines()
