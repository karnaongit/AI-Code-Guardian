import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from scanner.parser import UniversalParser
from scanner.security_engine import SecurityEngine

def run_test():
    parser = UniversalParser()
    engine = SecurityEngine()
    
    code = """
from pathlib import Path

import click
import requests

@click.command()
@click.argument('username')
def cmd_api_client(username):
    r = requests.get('http://127.0.1.1:5000/api/post/{}'.format(username))
    if r.status_code != 200:
        click.echo('Some error ocurred. Status Code: {}'.format(r.status_code))
        print(r.text)
        return False
"""
    file_path = "scratch/test_api_list.py"
    
    parsed = parser.parse(code, file_path)
    print("Calls parsed:")
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
