from scanner.parser import UniversalParser
from scanner.security_engine import SecurityEngine

code = """
import pickle
import marshal
import subprocess

def hello():
    print("Hello")
"""

parser = UniversalParser()

parsed = parser.parse(
    code,
    "test.py",
)

engine = SecurityEngine()

result = engine.scan(
    parsed,
    "test.py",
)

print(parsed.imports)
print(parsed.calls)
print(result.findings)

for capture in parsed.captures:
    print(capture.capture_name, "->", capture.text)