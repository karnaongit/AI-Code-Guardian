from services.analysis_service import AnalysisService

def test_analysis_orchestration():
    service = AnalysisService()
    # We can test against a tiny repo or even just check if it builds without crashing.
    # We will use fportantier/vulpy
    
    print("Starting analysis on fportantier/vulpy...")
    result = service.analyze_repository("fportantier/vulpy")
    
    assert "summary" in result
    assert "structure_view" in result
    assert "security_view" in result
    
    print(f"Summary: {result['summary']}")
    
    # Check structure view
    struct = result["structure_view"]
    assert struct["type"] == "Repository"
    assert struct["label"] == "fportantier/vulpy"
    
    print("Orchestration verified successfully!")

if __name__ == "__main__":
    test_analysis_orchestration()
