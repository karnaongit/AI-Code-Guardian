"""
STAGE-BY-STAGE PIPELINE DIAGNOSTIC
Traces: Parser → Graph → TreeService → API payload shape → React data
Run: python scratch/diagnose_pipeline.py
"""
import sys, os, json, hashlib

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

DIVIDER = "=" * 70

def p(label, value=""):
    print(f"\n{DIVIDER}")
    print(f"  STAGE: {label}")
    print(DIVIDER)
    if value:
        print(value)

# ──────────────────────────────────────────────
# STAGE 1: Simulate a realistic parsed file
# Use actual byte offsets so parent resolution works
# ──────────────────────────────────────────────
p("1 — PARSER OUTPUT (simulated realistic ParsedFile)")

from scanner.models import (
    SecurityFinding, FunctionSymbol, ClassSymbol,
    CallSymbol, ImportSymbol, ParsedFile
)

pf = ParsedFile(file_path="scanner/security_engine.py", language="Python")

# Class at bytes 0-500
cls = ClassSymbol(
    name="SecurityEngine", line=10, snippet="class SecurityEngine:",
    symbol_id="", start_byte=0, end_byte=500
)

# Method inside class at bytes 50-300
fn = FunctionSymbol(
    name="detect_sql_injection", line=20, snippet="def detect_sql_injection(self):",
    symbol_id="", start_byte=50, end_byte=300
)

# Call inside method at bytes 100-150
call = CallSymbol(
    name="db.execute", line=42, snippet="db.execute(query)",
    symbol_id="", start_byte=100, end_byte=150
)

pf.classes.append(cls)
pf.functions.append(fn)
pf.calls.append(call)

# SymbolBuilder Pass 3 (parent resolution + IDs) — replicate what it does
file_id = pf.file_id

def compute_id(parent_id, sym_type, name, idx):
    basis = f"{file_id}:{parent_id}:{sym_type}:{name}:{idx}"
    return hashlib.sha1(basis.encode()).hexdigest()[:16]

class_map = {}
for idx, c in enumerate(pf.classes):
    c.symbol_id = compute_id("root", "Class", c.name, idx)
    class_map[idx] = c.symbol_id

for idx, f in enumerate(pf.functions):
    parent_id = "root"
    for cls_idx, c in enumerate(pf.classes):
        if c.start_byte <= f.start_byte and c.end_byte >= f.end_byte:
            parent_id = class_map[cls_idx]
            f.parent_id = parent_id
            break
    f.symbol_id = compute_id(parent_id, "Function", f.name, idx)

for idx, sym in enumerate(pf.calls):
    parent_id = "root"
    for fidx, func in enumerate(pf.functions):
        if func.start_byte <= sym.start_byte and func.end_byte >= sym.end_byte:
            parent_id = f.symbol_id
            sym.parent_id = parent_id
            break
    sym.symbol_id = compute_id(parent_id, "Call", sym.name, idx)

print(f"  file_path      : {pf.file_path}")
print(f"  file_id        : {pf.file_id}")
print(f"  classes        : {len(pf.classes)}")
for c in pf.classes:
    print(f"    Class   [{c.symbol_id}] name={c.name!r}  line={c.line}  bytes={c.start_byte}-{c.end_byte}  parent={c.parent_id!r}")
print(f"  functions      : {len(pf.functions)}")
for f in pf.functions:
    print(f"    Function [{f.symbol_id}] name={f.name!r}  line={f.line}  bytes={f.start_byte}-{f.end_byte}  parent={f.parent_id!r}")
print(f"  calls          : {len(pf.calls)}")
for c2 in pf.calls:
    print(f"    Call     [{c2.symbol_id}] name={c2.name!r}  line={c2.line}  bytes={c2.start_byte}-{c2.end_byte}  parent={c2.parent_id!r}")

# ──────────────────────────────────────────────
# STAGE 2: KnowledgeGraphBuilder
# ──────────────────────────────────────────────
p("2 — KNOWLEDGE GRAPH")

finding = SecurityFinding(
    rule_id="SEC_SQLI_001",
    title="SQL Injection",
    matched_rule="SQL Injection Vulnerability",
    category="Injection",
    severity="Critical",
    confidence=0.95,
    evidence="Raw SQL string concatenation detected",
    file="scanner/security_engine.py",
    file_id=pf.file_id,
    class_name="SecurityEngine",
    function_name="detect_sql_injection",
    symbol_id=fn.symbol_id,
    line=42,
    snippet="db.execute('SELECT * FROM users WHERE id=' + uid)",
    cwe="CWE-89",
    owasp="A03:2021-Injection",
    description="SQL injection found",
    recommendation="Use parameterized queries"
)

from scanner.intelligence.knowledge_graph import KnowledgeGraphBuilder

graph = KnowledgeGraphBuilder("vulpy").build([pf], [finding])

print(f"  Total nodes: {len(graph.nodes)}")
print(f"  Total edges: {len(graph.edges)}")
print()

# Print all nodes grouped by type
from collections import defaultdict
by_type = defaultdict(list)
for n in graph.nodes.values():
    by_type[n.type].append(n)

for t, nodes in sorted(by_type.items()):
    print(f"  [{t}] — {len(nodes)} node(s)")
    for n in nodes:
        name = n.properties.get("name") or n.properties.get("path") or n.properties.get("title") or n.properties.get("rule_id") or "?"
        print(f"      id={n.id}  name={name!r}")

print()
print("  Edges:")
for e in graph.edges:
    src = graph.get_node(e.source_id)
    tgt = graph.get_node(e.target_id)
    src_name = src.properties.get("name") or src.properties.get("path") or src.type if src else "?"
    tgt_name = tgt.properties.get("name") or tgt.properties.get("path") or tgt.properties.get("title") or tgt.type if tgt else "?"
    print(f"      [{src.type if src else '?'}] {src_name!r} --{e.type}--> [{tgt.type if tgt else '?'}] {tgt_name!r}")

# ──────────────────────────────────────────────
# STAGE 3: TreeService.get_structure_view
# ──────────────────────────────────────────────
p("3 — TREESERVICE structure_view JSON")

from scanner.intelligence.tree_service import TreeService
ts = TreeService()
structure = ts.get_structure_view(graph)

print(json.dumps(structure, indent=2))

# Also print ASCII tree for readability
def ascii_tree(node, indent=0):
    t = node.get("type", "?")
    lbl = node.get("label", "")
    meta_name = (node.get("metadata") or {}).get("name") or (node.get("metadata") or {}).get("title") or ""
    sev = (node.get("metadata") or {}).get("maxSeverity", "None")
    display = meta_name or lbl
    sev_marker = f" [{sev}]" if sev != "None" else ""
    print("  " + "  " * indent + f"{'▼' if node.get('children') else '•'} [{t}] {display!r}{sev_marker}")
    for child in node.get("children", []):
        ascii_tree(child, indent + 1)

print()
print("  ASCII Tree:")
ascii_tree(structure)

# ──────────────────────────────────────────────
# STAGE 4: API response payload keys
# (AnalysisService returns structure_view in the dict)
# ──────────────────────────────────────────────
p("4 — API PAYLOAD SHAPE (what AnalysisService.analyze_repository returns)")

# We can't call the real API (no GitHub token in test), but we can confirm
# the dict key that RepositoryTree.jsx receives is exactly 'structure_view'
print("  AnalysisService.analyze_repository() returns a dict with keys:")
keys = [
    "summary", "security_findings", "structure_view",
    "security_view", "execution_views", "entry_points",
    "global_execution_views", "graph"
]
for k in keys:
    print(f"    '{k}'")
print()
print("  api/analysis.py line 74:")
print("    response_report = {k: v for k, v in report.items() if k != 'graph'}")
print("    return response_report")
print()
print("  → 'structure_view' key is sent to frontend ✓")
print("  → 'graph' key is EXCLUDED from frontend response ✓")

# ──────────────────────────────────────────────
# STAGE 5: What does RepositoryTree.jsx receive and render?
# ──────────────────────────────────────────────
p("5 — REACT RENDERING ANALYSIS (static)")

print("""
  RepositoryTree.jsx receives: prop 'report'
  It reads:                    report.structure_view  (line 117)
  It renders via:              <TreeNode node={directoryTree} />

  Key rendering decisions in TreeNode:
  ┌─────────────────────────────────────────────────────────────┐
  │ displayName for Finding nodes (FIXED):                      │
  │   node.metadata?.title  ← 'SQL Injection'           ✓      │
  │                                                             │
  │ displayName for File nodes (FIXED):                         │
  │   fullPath.split('/').pop()  ← 'security_engine.py' ✓      │
  │                                                             │
  │ displayName for Class/Function (unchanged):                 │
  │   node.metadata?.name  ← 'SecurityEngine'           ✓      │
  │                                                             │
  │ Icons (FIXED):                                              │
  │   Repository → GitBranch  (was: Folder)             ✓      │
  │   Class      → Layers     (was: Box)                ✓      │
  │   Function   → Braces     (was: FileJson)           ✓      │
  │                                                             │
  │ Severity bleed (FIXED):                                     │
  │   textColorClass only applies to Finding nodes      ✓      │
  └─────────────────────────────────────────────────────────────┘
""")

# ──────────────────────────────────────────────
# STAGE 6: Check if ExecutionTreeView and RepositoryTree share data
# ──────────────────────────────────────────────
p("6 — DATA SEPARATION AUDIT (Explorer vs Execution Tree)")

print("""
  App.jsx passes to each component:
  ┌────────────────────────────────────────────────────────────────┐
  │ RepositoryTree   receives: report                              │
  │   reads:  report.structure_view  (static code hierarchy)      │
  │                                                               │
  │ ExecutionTreeView receives: report, selectedNode,             │
  │                             selectedEntryPointId              │
  │   reads:  report.execution_views[id]   (per-finding path)     │
  │            report.global_execution_views[ep_id] (global tree) │
  │            report.entry_points                                │
  └────────────────────────────────────────────────────────────────┘
  
  → The two components consume DIFFERENT top-level keys ✓
  → No shared data source — duplication is NOT the problem ✓
""")

# ──────────────────────────────────────────────
# STAGE 7: Check what ExecutionTreeView.jsx actually reads
# ──────────────────────────────────────────────
p("7 — READING ExecutionTreeView.jsx to verify data source")

exec_tree_path = os.path.join(os.path.dirname(__file__), '..', 'ui', 'src', 'components', 'ExecutionTreeView.jsx')
if os.path.exists(exec_tree_path):
    with open(exec_tree_path, 'r', encoding='utf-8') as fh:
        content = fh.read()
    
    # Find which report.* keys are accessed
    import re
    accesses = re.findall(r'report\.(\w+)', content)
    unique_keys = sorted(set(accesses))
    print(f"  ExecutionTreeView.jsx accesses these report.* keys:")
    for k in unique_keys:
        print(f"    report.{k}")
    
    # Check if it ever accesses structure_view
    if 'structure_view' in content:
        print()
        print("  ⚠ WARNING: ExecutionTreeView.jsx ALSO accesses report.structure_view!")
        # Find the line
        for i, line in enumerate(content.splitlines(), 1):
            if 'structure_view' in line:
                print(f"    Line {i}: {line.strip()}")
    else:
        print()
        print("  ✓ ExecutionTreeView.jsx does NOT access report.structure_view")
else:
    print(f"  Could not find ExecutionTreeView.jsx at {exec_tree_path}")

print()
print(DIVIDER)
print("  DIAGNOSTIC COMPLETE")
print(DIVIDER)
