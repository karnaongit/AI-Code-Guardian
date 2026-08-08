import os
import sys
import json
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ai.models import InvestigationSession, InvestigationContext, InvestigationSummary, InvestigationAction
from ai.langgraph_orchestrator import LangGraphOrchestrator
class MockLLM:
    def chat(self, prompt):
        return """
```json
{
  "summary": "This is a summary",
  "root_cause": "The root cause",
  "policy_decision": {"decision": "ALLOW", "reason_code": "LLM_OVERRIDE"}
}
```
        """

def test_langgraph():
    llm = MockLLM()
    orchestrator = LangGraphOrchestrator(llm=llm, retriever=None)
    
    summary = InvestigationSummary(
        title="High Severity Vuln",
        severity="HIGH"
    )
    
    context = InvestigationContext(
        finding_id="123456",
        summary=summary,
        evidence="Some vulnerable code"
    )
    
    session = InvestigationSession(
        session_id="test",
        repository_id="test-repo",
        finding_id="123456",
        context=context
    )
    
    state = {
        "workspace_id": "test",
        "action": InvestigationAction.GENERATE_FIX,
        "session": session,
        "question": "Fix this",
        "repo_name": "sidgulmire1/AI-Code-Guardian",
        "evidence": "",
        "retrieved_context": "",
        "graph_context": "=== TOPOLOGY ===\nempty\n\n=== DETERMINISTIC REACHABILITY ===\n{\"reachable\": true, \"path\": [], \"endpoint\": null}",
        "policy_decision": None,
        "response": None,
        "error": None
    }
    
    # We will invoke just the policy node and reasoning node to see if LLM authority is overridden
    # For this, let's just test policy_node standalone
    print("Testing Policy Node standalone:")
    next_state = orchestrator.policy_node(state)
    print(f"Policy Decision: {next_state.get('policy_decision')}")
    
    state.update(next_state)
    
    print("\nTesting Reasoning Node standalone (to prove LLM cannot override):")
    # Tell the LLM to output some different policy decision
    state["retrieved_context"] = "The LLM should attempt to say ALLOW in its output but the code should override it to BLOCK."
    
    final_state = orchestrator.reasoning_node(state)
    res = final_state.get("response")
    print(f"\nFinal InvestigationResult Policy Decision:")
    print(json.dumps(res.policy_decision, indent=2))

if __name__ == "__main__":
    test_langgraph()
