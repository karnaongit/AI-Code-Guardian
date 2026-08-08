import sys
import os
import json
import traceback

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from ai.rag_pipeline import RAGPipeline
from ai.models import InvestigationResult

def test_take_action():
    json_str = 'null'
    try:
        data = json.loads(json_str)
        result = InvestigationResult(
            summary=data.get("summary", ""),
            root_cause=data.get("root_cause", ""),
            attack_scenario=data.get("attack_scenario", ""),
            evidence=data.get("evidence", ""),
            business_impact=data.get("business_impact", ""),
            secure_fix=data.get("secure_fix", ""),
            secure_code=data.get("secure_code", ""),
            validation_steps=data.get("validation_steps", ""),
            references=data.get("references", "")
        )
        print("Success!")
    except Exception as e:
        print(f"Caught exception: {e}")
        # print traceback
        traceback.print_exc()

if __name__ == '__main__':
    test_take_action()
