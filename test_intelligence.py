import sys
from scanner.models import ParsedFile, CallSymbol
from scanner.intelligence.engine import IntelligenceEngine

# Create dummy ParsedFile
p = ParsedFile(language="Python")
call = CallSymbol(name="system", line=1, snippet="os.system('id')", context={"receiver": "os"})
p.calls.append(call)

engine = IntelligenceEngine()
res = engine.scan(p, "test.py")

print("Findings:", len(res.findings))
for f in res.findings:
    print(f"- {f.rule_id} [{f.category}]: {f.snippet} (Confidence: {f.confidence})")
