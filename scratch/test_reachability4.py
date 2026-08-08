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
            "MATCH (f:Finding {repo_namespace: $repo})<-[:GENERATES_FINDING]-(s) "
            "RETURN f.node_id AS fid, s.node_id AS symbol_id, labels(s) AS labels, s.name AS name, s.is_api_endpoint AS is_api "
            "LIMIT 10"
        )
        res = session.run(query, repo=repo_name)
        records = list(res)
        for rec in records:
            print(f"Finding: {rec['fid']}")
            print(f"Symbol: {rec['symbol_id']} ({rec['labels']}) - {rec['name']}")
            print(f"Is API Endpoint: {rec['is_api']}\n")

    adapter.close()

if __name__ == "__main__":
    test_reachability()
