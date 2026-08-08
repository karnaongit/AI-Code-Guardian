import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from scanner.intelligence.neo4j_adapter import Neo4jAdapter
import json

def test_reachability():
    repo_name = "sidgulmire1/AI-Code-Guardian"
    adapter = Neo4jAdapter()
    
    with adapter.driver.session() as session:
        # Get one finding
        result = session.run(
            "MATCH (f:Finding {repo_namespace: $repo}) RETURN f.node_id AS finding_id LIMIT 1",
            repo=repo_name
        )
        record = result.single()
        if not record:
            print("No findings")
            return
            
        finding_id = record["finding_id"]
        print(f"Finding: {finding_id}")
        
        # Trace up
        query = (
            "MATCH path = (caller)-[:EXECUTES|CALLS*1..10]->(vuln:Function {repo_namespace: $repo})-[:GENERATES_FINDING]->(f:Finding {node_id: $fid}) "
            "RETURN path LIMIT 1"
        )
        res = session.run(query, repo=repo_name, fid=finding_id)
        rec = res.single()
        if not rec:
            print("No callers found")
        else:
            path_obj = rec.get("path")
            names = [n.get("name", n.get("node_id", "Unknown")) for n in path_obj.nodes]
            print(f"Path: {' -> '.join(names)}")

    adapter.close()

if __name__ == "__main__":
    test_reachability()
