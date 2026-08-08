import sys
from scanner.models import ParsedFile, CallSymbol
from scanner.intelligence.engine import IntelligenceEngine
from scanner.intelligence.capability_learner import CapabilityLearningManager
from scanner.language_learning.query_generator import BaseLLM

class MockLLM(BaseLLM):
    def generate(self, prompt: str) -> str:
        # Mocking LLM generating Ruby sinks based on the prompt
        return """
COMMAND_EXECUTION:
  - system
  - exec
  - spawn
  - popen
WEAK_CRYPTOGRAPHY:
  - Digest::MD5.hexdigest
  - Digest::SHA1.hexdigest
UNSAFE_DESERIALIZATION:
  - Marshal.load
  - YAML.load
INSECURE_PROTOCOL:
  - Net::FTP.new
HARDCODED_SECRET:
  - password
  - api_key
"""

# 1. Trigger the capability learner for a new language: Ruby
learner = CapabilityLearningManager(MockLLM())
print("Learning Ruby sinks...")
learner.learn("Ruby")

# 2. Simulate scanning a Ruby file
print("\nScanning Ruby file...")
p = ParsedFile(language="Ruby")
call = CallSymbol(name="system", line=1, snippet="system('rm -rf /')", context={})
p.calls.append(call)

engine = IntelligenceEngine()
res = engine.scan(p, "test.rb")

print(f"Findings: {len(res.findings)}")
for f in res.findings:
    print(f"- {f.rule_id} [{f.category}]: {f.snippet} (Confidence: {f.confidence})")
