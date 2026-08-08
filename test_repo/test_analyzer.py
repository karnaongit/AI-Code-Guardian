from scanner.language_learning.grammar_loader import GrammarLoader
from scanner.language_learning.grammar_analyzer import GrammarAnalyzer
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

loader = GrammarLoader()
grammar = loader.load("python")   # use any language you already support

analysis = GrammarAnalyzer().analyze(grammar)

print("Field Maps:", len(analysis.field_map))
print("Children Maps:", len(analysis.children_map))
print("Subtype Maps:", len(analysis.subtype_map))

print("\nFunction Definition:")
print(analysis.field_map.get("function_definition"))