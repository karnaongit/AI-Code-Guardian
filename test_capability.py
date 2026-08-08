import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from scanner.parser import UniversalParser
from scanner.security_engine import SecurityEngine

def run_test():
    parser = UniversalParser()
    engine = SecurityEngine()
    
    file_path = "scratch/vulnerable.py"
    with open(file_path, "r") as f:
        code = f.read()
        
    parsed = parser.parse(code, file_path)
    print("All captures:")
    for cap in parsed.captures:
        print(f"[{cap.capture_name}] {cap.text}")

    print("\nCalls parsed:")
    for c in parsed.calls:
        print(f" - {c.name}")
        
    result = engine.scan(parsed, file_path)
    
    print("\nFindings:")
    for f in result.findings:
        print(f" [{f.severity}] {f.category} ({f.rule_id}) at line {f.line}")
        print(f" Capability: {getattr(f, 'capability', 'N/A')}")
        print(f" Snippet: {f.snippet.strip()}")
        print("-" * 40)

if __name__ == "__main__":
    run_test()
