import sys
import os
import traceback
import json

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from api.analysis import analyze_repository, investigate, take_action
from api.analysis import RepositoryRequest, InvestigateRequest, ActionRequest
from ai.models import InvestigationAction

def main():
    print("Starting repo analysis...")
    # Analyze to populate memory
    repo_req = RepositoryRequest(repo_name="sidgulmire1/AI-Code-Guardian")
    try:
        report = analyze_repository(repo_req)
        
        findings = report.get('security_findings', [])
        if not findings:
            print("No findings to test actions on.")
            return
            
        finding_id = findings[0]['finding_id']
        print(f"Investigating finding {finding_id}...")
        
        inv_req = InvestigateRequest(finding_id=finding_id, repo_name="sidgulmire1/AI-Code-Guardian")
        session = investigate(inv_req)
        
        session_id = session['session_id']
        
        actions = [
            InvestigationAction.EXPLAIN_FINDING,
            InvestigationAction.SHOW_EVIDENCE,
            InvestigationAction.GENERATE_FIX,
            InvestigationAction.VALIDATE_FIX,
            InvestigationAction.SHOW_REFERENCES
        ]
        
        for action in actions:
            print(f"\n--- Testing {action} ---")
            act_req = ActionRequest(
                session_id=session_id,
                action=action,
                repo_name="sidgulmire1/AI-Code-Guardian",
                finding_id=finding_id
            )
            try:
                res = take_action(act_req)
                print(f"SUCCESS: {res}")
            except Exception as e:
                print(f"FAILED: {e}")
                traceback.print_exc()

    except Exception as e:
        print("Setup Failed:")
        traceback.print_exc()

if __name__ == '__main__':
    main()
