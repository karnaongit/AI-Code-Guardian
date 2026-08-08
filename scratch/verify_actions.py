import sys
import os
import json
import traceback

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from fastapi.testclient import TestClient
from main import app

def run_verification():
    client = TestClient(app)
    
    print("=== STEP 1: SCAN REPOSITORY ===")
    repo_name = "sidgulmire1/AI-Code-Guardian"
    res = client.post("/analysis/repository", json={"repo_name": repo_name})
    print(f"Scan Status: {res.status_code}")
    if res.status_code != 200:
        print("Scan Failed:", res.text)
        return
        
    data = res.json()
    findings = data.get("security_findings", [])
    print(f"Found {len(findings)} findings.")
    if not findings:
        print("No findings found to test.")
        return
        
    target_finding = findings[0]
    finding_id = target_finding["finding_id"]
    print(f"Testing with Finding ID: {finding_id}")

    results = {}
    
    # Test 6: Investigate
    print("\n=== TESTING: Investigate ===")
    res_inv = client.post("/analysis/investigate", json={"finding_id": finding_id, "repo_name": repo_name})
    print(f"Investigate Status: {res_inv.status_code}")
    session_id = None
    if res_inv.status_code == 200:
        inv_data = res_inv.json()
        session_id = inv_data.get("session_id")
        print(f"Session ID created: {session_id}")
        results["Investigate"] = {
            "status": res_inv.status_code,
            "success": True,
            "response": inv_data,
            "context_available": "YES"
        }
    else:
        results["Investigate"] = {
            "status": res_inv.status_code,
            "success": False,
            "response": res_inv.text,
            "context_available": "NO"
        }
        
    actions = [
        ("Explain Vulnerability", "EXPLAIN_FINDING"),
        ("Show Evidence", "SHOW_EVIDENCE"),
        ("Generate Secure Fix", "GENERATE_FIX"),
        ("Validate Fix", "VALIDATE_FIX"),
        ("Show References", "SHOW_REFERENCES"),
    ]

    for label, action_enum in actions:
        print(f"\n=== TESTING: {label} ({action_enum}) ===")
        res_act = client.post("/analysis/action", json={
            "session_id": session_id if session_id else "invalid_session",
            "action": action_enum,
            "repo_name": repo_name,
            "finding_id": finding_id
        })
        print(f"Status Code: {res_act.status_code}")
        if res_act.status_code == 200:
            act_data = res_act.json()
            print(f"Response snippet: {json.dumps(act_data)[:200]}...")
            results[label] = {
                "status": res_act.status_code,
                "success": True,
                "response": act_data,
                "context_available": "YES"
            }
        else:
            print(f"Response: {res_act.text}")
            results[label] = {
                "status": res_act.status_code,
                "success": False,
                "response": res_act.text,
                "context_available": "YES" if session_id else "NO"
            }

    print("\n\n================ VERIFICATION SUMMARY ================")
    for k, v in results.items():
        print(f"ACTION: {k}")
        print(f"HTTP STATUS: {v['status']}")
        print(f"SUCCESS/FAIL: {'SUCCESS' if v['success'] else 'FAIL'}")
        print(f"REPOSITORY CONTEXT AVAILABLE: {v['context_available']}")
        print(f"RESPONSE DATA: {json.dumps(v['response'])[:300]}")
        print("-" * 50)

if __name__ == "__main__":
    run_verification()
