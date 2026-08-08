"""
Regression Verification Script — AI-Code Guardian Frontend Recovery
Run from project root: python scratch/verify_regressions.py
"""
import sys
import os

# Ensure the project root is importable regardless of working directory
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import logging

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger('Verifier')

PASS = []
FAIL = []

def check(name, condition, msg=""):
    if condition:
        PASS.append(name)
        logger.info(f"  PASS  {name}")
    else:
        FAIL.append(name)
        logger.error(f"  FAIL  {name}" + (f" — {msg}" if msg else ""))

def section(title):
    logger.info(f"\n{'='*60}")
    logger.info(f"  {title}")
    logger.info(f"{'='*60}")

# ─────────────────────────────────────────────
# Build test fixtures
# ─────────────────────────────────────────────
section("Building test fixtures")

from scanner.models import (
    SecurityFinding, FunctionSymbol, ClassSymbol, CallSymbol, ParsedFile
)
from scanner.intelligence.knowledge_graph import KnowledgeGraphBuilder
from scanner.intelligence.tree_service import TreeService
from scanner.intelligence.execution_builder import ExecutionTreeBuilder
from scanner.intelligence.investigation_service import InvestigationService

dummy_file = ParsedFile(file_path='app/main.py', language='Python')

cls = ClassSymbol(
    name='AnalysisService', line=10,
    snippet='class AnalysisService:', symbol_id='class_abc'
)
func = FunctionSymbol(
    name='analyze_repo', line=12,
    snippet='def analyze_repo(self):', symbol_id='func_abc', parent_id='class_abc'
)
call = CallSymbol(
    name='scan', line=15, snippet='scan()',
    symbol_id='call_abc', parent_id='func_abc'
)
dummy_file.classes.append(cls)
dummy_file.functions.append(func)
dummy_file.calls.append(call)

finding = SecurityFinding(
    rule_id='sql_injection',
    title='SQL Injection',
    category='Injection',
    severity='Critical',
    confidence=0.95,
    evidence='Raw SQL concatenation',
    file='app/main.py',
    file_id=dummy_file.file_id,
    class_name='AnalysisService',
    function_name='analyze_repo',
    symbol_id='func_abc',
    line=15,
    snippet="db.execute('SELECT * FROM users WHERE id=' + uid)",
    cwe='CWE-89',
    owasp='A03:2021-Injection',
    description='SQL injection vulnerability detected',
    recommendation='Use parameterized queries'
)
finding_id = finding.finding_id
logger.info(f"  finding_id = {finding_id}")

graph = KnowledgeGraphBuilder('test_repo').build([dummy_file], [finding])
logger.info(f"  Graph: {len(graph.nodes)} nodes, {len(graph.edges)} edges")

# ─────────────────────────────────────────────
# STEP 1 — Finding metadata in graph
# ─────────────────────────────────────────────
section("STEP 1: Finding node metadata propagation")

fn = graph.get_node(finding_id)
check("Finding node exists in graph", fn is not None)
if fn:
    check("finding.file",       fn.properties.get('file') == 'app/main.py',     f"got: {fn.properties.get('file')}")
    check("finding.line",       fn.properties.get('line') == 15,               f"got: {fn.properties.get('line')}")
    check("finding.confidence", fn.properties.get('confidence') == 0.95,        f"got: {fn.properties.get('confidence')}")
    check("finding.class",      fn.properties.get('class') == 'AnalysisService', f"got: {fn.properties.get('class')}")
    check("finding.function",   fn.properties.get('function') == 'analyze_repo', f"got: {fn.properties.get('function')}")
    check("finding.cwe",        fn.properties.get('cwe') == 'CWE-89',           f"got: {fn.properties.get('cwe')}")
    check("finding.owasp",      fn.properties.get('owasp') == 'A03:2021-Injection', f"got: {fn.properties.get('owasp')}")
    check("finding.severity",   fn.properties.get('severity') == 'Critical',    f"got: {fn.properties.get('severity')}")
    check("finding.snippet",    bool(fn.properties.get('snippet')),              f"got: {fn.properties.get('snippet')}")
    check("finding.recommendation", bool(fn.properties.get('recommendation')),  f"got: {fn.properties.get('recommendation')}")

# ─────────────────────────────────────────────
# STEP 2 — Repository Explorer hierarchy
# ─────────────────────────────────────────────
section("STEP 2: Repository Explorer structure hierarchy")

ts = TreeService()
struct = ts.get_structure_view(graph)

check("Root is Repository", struct.get('type') == 'Repository', f"got: {struct.get('type')}")

children = struct.get('children', [])
check("Repository has children", len(children) > 0)

if children:
    folder = children[0]
    check("Level 1 is Folder", folder.get('type') == 'Folder', f"got: {folder.get('type')}")

    folder_children = folder.get('children', [])
    if folder_children:
        file_node = folder_children[0]
        check("Level 2 is File", file_node.get('type') == 'File', f"got: {file_node.get('type')}")

        file_children = file_node.get('children', [])
        if file_children:
            cls_node = file_children[0]
            check("Level 3 is Class", cls_node.get('type') == 'Class', f"got: {cls_node.get('type')}")

            cls_children = cls_node.get('children', [])
            if cls_children:
                func_node = cls_children[0]
                check("Level 4 is Function", func_node.get('type') == 'Function', f"got: {func_node.get('type')}")

                func_children = func_node.get('children', [])
                if func_children:
                    finding_node_v = func_children[0]
                    check("Level 5 is Finding", finding_node_v.get('type') == 'Finding', f"got: {finding_node_v.get('type')}")
                else:
                    check("Level 5 is Finding", False, "Function has no children")
            else:
                check("Level 4 is Function", False, "Class has no children")
        else:
            check("Level 3 is Class", False, "File has no children")
    else:
        check("Level 2 is File", False, "Folder has no children")

# Severity propagation — the root should be colored Critical
root_sev = struct.get('metadata', {}).get('maxSeverity', 'None')
check("Severity propagated to root", root_sev == 'Critical', f"got: {root_sev}")

# ─────────────────────────────────────────────
# STEP 3 — Execution Tree path (no folders)
# ─────────────────────────────────────────────
section("STEP 3: Execution Tree path (no Folder/Repository nodes)")

eb = ExecutionTreeBuilder()
path = eb.build_path(graph, finding_id)
check("Execution path is not None", path is not None)

if path:
    steps = []
    curr = path
    while curr:
        steps.append({'type': curr.type, 'name': curr.name})
        curr = curr.children[0] if curr.children else None

    logger.info(f"  Execution steps: {[(s['type'], s['name']) for s in steps]}")

    types = [s['type'] for s in steps]
    check("No Folder in execution path", 'Folder' not in types, f"types: {types}")
    check("No Repository in execution path", 'Repository' not in types, f"types: {types}")
    check("File appears in execution path", 'File' in types, f"types: {types}")
    check("Finding appears in execution path", 'Finding' in types, f"types: {types}")
    check("Finding is last step", types[-1] == 'Finding', f"last: {types[-1]}")
    first_step = steps[0]['type']
    check('Application is first step', first_step == 'Application', f"first: {first_step}")

    # Verify intermediate steps exist (Class or Function or Call)
    intermediate_types = {'Class', 'Function', 'Call'}
    has_intermediate = any(t in intermediate_types for t in types)
    check("Intermediate execution steps (Class/Function/Call) present", has_intermediate, f"types: {types}")

# ─────────────────────────────────────────────
# STEP 4 — Investigation Session & Summary
# ─────────────────────────────────────────────
section("STEP 4: Investigation Session & Summary fields")

inv = InvestigationService(graph)
session = inv.investigate(finding_id, 'test_repo')
check("Session is not None", session is not None)

if session:
    s = session.context.summary
    check("summary.title == 'SQL Injection'",   s.title == 'SQL Injection',         f"got: {s.title}")
    check("summary.severity == 'Critical'",     s.severity == 'Critical',           f"got: {s.severity}")
    check("summary.file == 'app/main.py'",      s.file == 'app/main.py',            f"got: {s.file}")
    check("summary.class_name correct",         s.class_name == 'AnalysisService',  f"got: {s.class_name}")
    check("summary.function_name correct",      s.function_name == 'analyze_repo',  f"got: {s.function_name}")
    check("summary.line == 15",                 s.line == 15,                       f"got: {s.line}")
    check("summary.cwe == 'CWE-89'",            s.cwe == 'CWE-89',                  f"got: {s.cwe}")
    check("summary.owasp correct",              s.owasp == 'A03:2021-Injection',    f"got: {s.owasp}")
    check("summary.confidence correct",         s.confidence == '0.95',             f"got: {s.confidence}")
    check("summary.evidence not empty",         bool(s.evidence),                   f"got: {s.evidence}")
    check("summary.recommendation not empty",   bool(s.recommendation),             f"got: {s.recommendation}")

# ─────────────────────────────────────────────
# RESULTS
# ─────────────────────────────────────────────
section("RESULTS")
total = len(PASS) + len(FAIL)
logger.info(f"  Passed: {len(PASS)}/{total}")
logger.info(f"  Failed: {len(FAIL)}/{total}")

if FAIL:
    logger.error(f"\n  FAILED CHECKS:")
    for f_name in FAIL:
        logger.error(f"    - {f_name}")
    sys.exit(1)
else:
    logger.info("\n  ALL REGRESSION CHECKS PASSED!")
    sys.exit(0)
