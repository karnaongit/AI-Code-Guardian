from services.analysis_service import AnalysisService
from ai.assistant import AIAssistant

service = AnalysisService()
assistant = AIAssistant()

print("Scanning repo...")
report = service.analyze_repository("fportantier/vulpy")
assistant.attach_scan(scan_report=report, repo_root="fportantier/vulpy")

# Get a finding ID
finding_id = report["security_findings"][0]["finding_id"]
print(f"Finding ID: {finding_id}")
finding_edges = [e for e in report["graph"].edges if e.target_id == finding_id]
print(f"Edges pointing to finding: {finding_edges}")

from scanner.intelligence.investigation_service import InvestigationService
inv_service = InvestigationService(report["graph"])
context = inv_service.investigate(finding_id)
print("--- INVESTIGATION CONTEXT ---")
print(context)
print("-----------------------------")

question = "What is the root cause of this finding?"
print("Asking LLM...")
response = assistant.ask(question, investigation_context=context)

print(response.answer)
