from services.analysis_service import AnalysisService
import json

service = AnalysisService()
result = service.analyze_repository('sidgulmire1/AI-Code-Guardian')

print(f"Risk Score: {result['summary']['repository_risk_score']}")
print(f"Findings: {result['summary']['security_findings_count']}")
print(f"Entry Points: {len(result.get('entry_points', []))}")

eps = result.get('entry_points', [])
if eps:
    gv = result.get('global_execution_views', {}).get(eps[0]['id'])
    print(f"Global View has children: {len(gv.get('children', [])) if gv else 'No view'}")

if result.get('execution_views'):
    first_finding_id = list(result['execution_views'].keys())[0]
    exec_view = result['execution_views'][first_finding_id]
    print(json.dumps(exec_view, indent=2))
