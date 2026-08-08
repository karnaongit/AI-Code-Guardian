import os
import sys

# Adjust path to import from the project
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scanner.intelligence.neo4j_adapter import Neo4jAdapter
import json

def test_reachability():
    repo_name = "sidgulmire1/AI-Code-Guardian"
    adapter = Neo4jAdapter()
    
    if not adapter.is_available():
        print("Neo4j unavailable.")
        return

    print("=== NEO4J FINDINGS ===")
    
    with adapter.driver.session() as session:
        # Get all findings for this repo
        result = session.run(
            "MATCH (f:Finding {repo_namespace: $repo}) RETURN f.node_id AS finding_id, f.title AS title",
            repo=repo_name
        )
        findings = list(result)
        
        reachable_count = 0
        unreachable_count = 0
        
        for record in findings:
            finding_id = record["finding_id"]
            title = record["title"]
            print(f"\nTesting Finding: {finding_id} ({title})")
            
            reachability = adapter.get_finding_reachability(repo_name, finding_id, max_depth=10)
            print(json.dumps(reachability, indent=2))
            
            if reachability.get("reachable"):
                reachable_count += 1
            else:
                unreachable_count += 1

            if reachable_count > 0 and unreachable_count > 0:
                break # We just need one of each to prove it works

    adapter.close()

if __name__ == "__main__":
    test_reachability()
