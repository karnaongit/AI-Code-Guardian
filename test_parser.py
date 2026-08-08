from scanner.parser import UniversalParser

parser = UniversalParser()

code = """
def hello():
    print("Hello")
"""

parsed = parser.parse(code, "test.py")

print(parsed.functions)
print(parsed.calls)