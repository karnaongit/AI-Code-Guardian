import sys
import os

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.analysis_service import AnalysisService

if __name__ == "__main__":
    service = AnalysisService()
    
    # Use a known vulnerable repository for testing
    repo_name = "fportantier/vulpy"
    
    print("Starting end-to-end integration test...")
    print(f"Analyzing repository: {repo_name}")
    
    try:
        results = service.analyze_repository(repo_name)
        print("\n" + "="*50)
        print("SCAN COMPLETE")
        print("="*50)
        summary = results.get("summary", {})
        print(f"Files scanned: {summary.get('files_scanned')}")
        print(f"Total findings: {summary.get('security_findings')}")
        
        print("\nDetailed Findings:")
        for file_res in results.get("results", []):
            security = file_res.get("security", {})
            if security and security.get("findings"):
                print(f"\nFile: {file_res.get('file')}")
                for finding in security.get("findings"):
                    print(f"  - [{finding.get('severity')}] {finding.get('rule_id')} : {finding.get('category')}")
                    print(f"    Snippet: {finding.get('snippet')}")
                    
        print("\n" + "="*50)
        print("TESTING RAG CHAT QUERY")
        print("="*50)
        
        from api.analysis import assistant
        assistant.attach_scan(scan_report=results, repo_root=repo_name)
        response = assistant.ask("Summarize this repository in 5 sentences.")
        print("Answer:", response.answer)
        print("Citations:", response.citations)
        
    except Exception as e:
        print(f"Test failed: {e}")
