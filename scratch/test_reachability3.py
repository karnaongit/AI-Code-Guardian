import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from scanner.intelligence.neo4j_adapter import Neo4jAdapter
import json

def test_reachability():
    repo_name = "sidgulmire1/AI-Code-Guardian"
    adapter = Neo4jAdapter()
    
    with adapter.driver.session() as session:
        query = (
            "MATCH path = (caller:Function)-[:EXECUTES|CALLS*1..10]->(vuln:Function)-[:GENERATES_FINDING]->(f:Finding {repo_namespace: $repo}) "
            "RETURN f.node_id AS fid, path LIMIT 5"
        )
        res = session.run(query, repo=repo_name)
        records = list(res)
        if not records:
            print("No callers found for ANY finding!")
        else:
            for rec in records:
                path_obj = rec.get("path")
                names = [n.get("name", n.get("node_id", "Unknown")) for n in path_obj.nodes]
                print(f"Finding: {rec['fid']}")
                print(f"Path: {' -> '.join(names)}\n")

    adapter.close()

if __name__ == "__main__":
    test_reachability()
