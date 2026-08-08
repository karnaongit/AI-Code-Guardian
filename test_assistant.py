from ai.assistant import AIAssistant
assistant = AIAssistant()
report = {
    "scan": {
        "target": "fportantier/vulpy",
        "files_scanned": 63,
        "total_findings": 12,
        "by_severity": {"High": 12},
        "findings": [
            {"category": "Server-Side Request Forgery", "severity": "High"},
            {"category": "SQL Injection", "severity": "High"}
        ]
    },
    "risk": {
        "security_score": 20,
        "overall_risk_score": "High",
        "merge_decision": "BLOCK"
    }
}
assistant.attach_scan(scan_report=report, repo_root="fportantier/vulpy")
response = assistant.ask("summerize it in two lines and tell me about vulnerabilities")
print(response.answer)
