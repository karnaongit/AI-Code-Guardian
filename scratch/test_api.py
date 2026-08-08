import sys
import os
import requests
import time
import subprocess
import threading
import json

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

def run_server():
    os.environ["PORT"] = "8002"
    subprocess.run(["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8002"], cwd=_PROJECT_ROOT)

def main():
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    
    print("Waiting for server to start...")
    time.sleep(5)
    
    # 1. scan repository
    print("Scanning repository...")
    r = requests.post("http://localhost:8002/analysis/repository", json={"repo_name": "sidgulmire1/AI-Code-Guardian"})
    print("Scan status:", r.status_code)
    
    if r.status_code != 200:
        print("Scan failed:", r.text)
        return
        
    findings = r.json().get('security_findings', [])
    if not findings:
        print("No findings found.")
        return
        
    finding_id = findings[0]['finding_id']
    print(f"Finding ID: {finding_id}")
    
    # 2. investigate
    print("Investigating...")
    r = requests.post("http://localhost:8002/analysis/investigate", json={"finding_id": finding_id, "repo_name": "sidgulmire1/AI-Code-Guardian"})
    print("Investigate status:", r.status_code)
    if r.status_code != 200:
        print("Investigate failed:", r.text)
        return
        
    session_id = r.json().get('session_id')
    print(f"Session ID: {session_id}")
    
    # 3. action
    actions = [
        "EXPLAIN_FINDING",
        "SHOW_EVIDENCE",
        "GENERATE_FIX",
        "VALIDATE_FIX",
        "SHOW_REFERENCES"
    ]
    
    for action in actions:
        print(f"\nTesting {action}...")
        r = requests.post("http://localhost:8002/analysis/action", json={
            "session_id": session_id,
            "action": action,
            "repo_name": "sidgulmire1/AI-Code-Guardian",
            "finding_id": finding_id
        })
        print(f"{action} status:", r.status_code)
        if r.status_code != 200:
            print(f"ERROR for {action}: {r.text}")
        else:
            print(f"SUCCESS: {len(r.text)} bytes")

if __name__ == '__main__':
    main()
