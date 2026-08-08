"""
INSTRUMENTED TRAVERSAL DIAGNOSTIC
==================================
Instruments ExecutionTreeBuilder to print:
  - Current node, type
  - All outgoing edges
  - Accepted vs. skipped edges with skip reason
  - First missed repository node

Run:  python scratch/diag_traversal.py
"""

import os, sys, json, textwrap
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from scanner.parser import UniversalParser
from scanner.security_engine import SecurityEngine
from scanner.intelligence.knowledge_graph import KnowledgeGraphBuilder
from scanner.intelligence.semantic_resolver import SemanticResolver
from scanner.intelligence.execution_builder import ExecutionTreeBuilder, ExecutionNode
from scanner.intelligence.knowledge_graph import KnowledgeGraph
from typing import Optional

# ── helpers ────────────────────────────────────────────────────────────────────

REPO_DIR = os.path.dirname(os.path.dirname(__file__))   # project root
SKIP_DIRS = {"__pycache__", ".git", "venv", ".venv", "node_modules",
             "tmp_repo", "tmp_repo2", "tmp_repo3", "tmp_repo4",
             "tmp_repo5", "tmp_repo6", "tmp_repo7", "tmp_repo8", ".cache"}

def is_local_path(path: str) -> bool:
    """True if the path belongs to the repository (not stdlib / site-packages)."""
    # path stored in graph is relative to the repo root download dir.
    # We accept any path that does NOT contain site-packages or lib markers.
    return "site-packages" not in path and "stdlib" not in path


def indent(n: int, text: str) -> str:
    return textwrap.indent(text, "  " * n)


# ── instrumented builder ────────────────────────────────────────────────────────

class InstrumentedBuilder(ExecutionTreeBuilder):
    """
    Subclass of ExecutionTreeBuilder that logs every traversal decision.
    """

    def __init__(self):
        super().__init__()
        self._log_lines: list[str] = []

    def _log(self, depth: int, msg: str):
        line = "  " * depth + msg
        self._log_lines.append(line)
        print(line)

    # ── override the two core traversal methods ──────────────────────────────

    def _traverse_file_execution(self, graph: KnowledgeGraph,
                                  current_file_id: str, visited_files: set,
                                  depth: int = 0) -> Optional[ExecutionNode]:
        """Instrumented _traverse_file_execution."""
        if current_file_id in visited_files:
            self._log(depth, f"[SKIP-visited_files] File {current_file_id}")
            return None

        file_node = graph.get_node(current_file_id)
        if not file_node or file_node.type != "File":
            self._log(depth, f"[SKIP-not_file] Node {current_file_id} type={getattr(file_node,'type','MISSING')}")
            return None

        visited_files.add(current_file_id)
        path = file_node.properties.get("path", "")
        name = path.split("/")[-1] if "/" in path else (path.split("\\")[-1] if "\\" in path else path)

        self._log(depth, f"[FILE] {name}  id={current_file_id}  path={path}")

        exec_node = ExecutionNode(
            id=file_node.id, type="File", name=name,
            snippet="", children=[], metadata={"path": path}
        )

        # top-level edges from the file
        all_out = graph.get_out_edges(current_file_id)
        accepted_types = ("EXECUTES", "CONTAINS")
        top_level_edges = [e for e in all_out if e.type in accepted_types]
        skipped_edges   = [e for e in all_out if e.type not in accepted_types]

        self._log(depth+1, f"out-edges total={len(all_out)}  accepted={len(top_level_edges)}  skipped={len(skipped_edges)}")
        for e in skipped_edges:
            target = graph.get_node(e.target_id)
            tname = target.properties.get("path", target.properties.get("name", e.target_id)) if target else "?"
            self._log(depth+1, f"  [EDGE-SKIP] type={e.type} target={e.target_id} ({tname}) – edge type not in EXECUTES|CONTAINS")

        for edge in top_level_edges:
            child_node = graph.get_node(edge.target_id)
            if not child_node:
                self._log(depth+1, f"  [EDGE-SKIP] {edge.type}->{edge.target_id} – target node missing in graph")
                continue
            self._log(depth+1, f"  [EDGE-OK] {edge.type} -> {child_node.type} {child_node.properties.get('name', child_node.properties.get('path','?'))}")
            child_exec = self._build_local_exec_tree(graph, child_node.id, visited_files, depth=depth+2)
            if child_exec:
                exec_node.children.append(child_exec)

        # findings directly on file
        finding_edges = [e for e in all_out if e.type == "GENERATES_FINDING"]
        for edge in finding_edges:
            fn = graph.get_node(edge.target_id)
            if fn:
                exec_node.children.append(ExecutionNode(
                    id=fn.id, type="Finding",
                    name=fn.properties.get("rule_id", "Finding"),
                    snippet=fn.properties.get("snippet", ""),
                    children=[], metadata=fn.properties
                ))
        return exec_node

    def _build_local_exec_tree(self, graph: KnowledgeGraph,
                                current_id: str, visited_files: set,
                                visited_nodes: set = None,
                                depth: int = 0) -> Optional[ExecutionNode]:
        """Instrumented _build_local_exec_tree."""
        if visited_nodes is None:
            visited_nodes = set()

        if current_id in visited_nodes:
            return None
        visited_nodes.add(current_id)

        node = graph.get_node(current_id)
        if not node:
            return None

        name = node.properties.get("name", node.type)
        if node.type in ("Function", "Call") and not name.endswith("()"):
            name = f"{name}()"
        elif node.type == "Finding":
            name = node.properties.get("rule_id", "Finding")

        self._log(depth, f"[{node.type}] {name}  id={current_id}")

        exec_node = ExecutionNode(
            id=node.id, type=node.type, name=name,
            snippet=node.properties.get("snippet", ""),
            children=[], metadata=node.properties
        )

        all_out = graph.get_out_edges(current_id)

        # ── 1. EXECUTES / CONTAINS (nested) ──────────────────────────────────
        nested_edges = [e for e in all_out if e.type in ("EXECUTES", "CONTAINS")]
        for edge in nested_edges:
            child_tree = self._build_local_exec_tree(
                graph, edge.target_id, visited_files, visited_nodes.copy(), depth+1)
            if child_tree:
                exec_node.children.append(child_tree)

        # ── 2. GENERATES_FINDING ───────────────────────────────────────────────
        for edge in [e for e in all_out if e.type == "GENERATES_FINDING"]:
            fn = graph.get_node(edge.target_id)
            if fn:
                exec_node.children.append(ExecutionNode(
                    id=fn.id, type="Finding",
                    name=fn.properties.get("rule_id", "Finding"),
                    snippet=fn.properties.get("snippet", ""),
                    children=[], metadata=fn.properties
                ))

        # ── 3. CALLS / ROUTES_TO (cross-file or same-file) ────────────────────
        transition_edges = [e for e in all_out if e.type in ("CALLS", "ROUTES_TO")]
        for edge in transition_edges:
            target_node = graph.get_node(edge.target_id)
            if not target_node:
                self._log(depth+1,
                    f"[EDGE-SKIP] {edge.type}->{edge.target_id} – target missing in graph")
                continue

            target_file_id  = self._get_parent_file(graph, target_node.id)
            current_file_id = self._get_parent_file(graph, current_id)

            if target_file_id and current_file_id and target_file_id != current_file_id:
                # ── cross-file ──
                if target_file_id in visited_files:
                    tnode = graph.get_node(target_file_id)
                    tpath = tnode.properties.get("path","?") if tnode else "?"
                    self._log(depth+1,
                        f"[EDGE-SKIP] {edge.type} -> {target_node.type} "
                        f"'{target_node.properties.get('name','?')}' in file '{tpath}' "
                        f"– *** target_file_id already in visited_files ***")
                else:
                    tf_node = graph.get_node(target_file_id)
                    if tf_node:
                        tpath = tf_node.properties.get("path","?")
                        tname = tpath.split("/")[-1] if "/" in tpath else (tpath.split("\\")[-1] if "\\" in tpath else tpath)
                        self._log(depth+1,
                            f"[EDGE-OK] {edge.type} -> cross-file {tname}")

                    visited_files.add(target_file_id)
                    curr_file_node = graph.get_node(target_file_id)
                    if curr_file_node:
                        file_path = curr_file_node.properties.get("path", "")
                        fn_name   = file_path.split("/")[-1] if "/" in file_path else (file_path.split("\\")[-1] if "\\" in file_path else file_path)
                        file_exec = ExecutionNode(
                            id=curr_file_node.id, type="File", name=fn_name,
                            snippet="", children=[], metadata={"path": file_path}
                        )
                        target_exec = self._build_local_exec_tree(
                            graph, target_node.id, visited_files, visited_nodes.copy(), depth+2)
                        if target_exec:
                            if target_node.type == "Function":
                                parent_id = target_node.properties.get("parent_id")
                                if parent_id:
                                    pn = graph.get_node(parent_id)
                                    if pn and pn.type == "Class":
                                        target_exec = ExecutionNode(
                                            id=pn.id, type="Class",
                                            name=pn.properties.get("name","Class"),
                                            snippet=pn.properties.get("snippet",""),
                                            children=[target_exec], metadata=pn.properties
                                        )
                            file_exec.children.append(target_exec)
                        exec_node.children.append(file_exec)
            else:
                # ── same-file ──
                if not target_file_id and not current_file_id:
                    self._log(depth+1,
                        f"[EDGE-SKIP] {edge.type}->{target_node.type} "
                        f"'{target_node.properties.get('name','?')}' "
                        f"– both file IDs are None (unresolvable node)")
                else:
                    self._log(depth+1,
                        f"[EDGE-OK] {edge.type} -> same-file {target_node.type} "
                        f"'{target_node.properties.get('name','?')}'")
                    target_exec = self._build_local_exec_tree(
                        graph, target_node.id, visited_files, visited_nodes.copy(), depth+2)
                    if target_exec:
                        if target_node.type == "Function":
                            for in_edge in graph.get_in_edges(target_node.id):
                                if in_edge.type == "CONTAINS":
                                    pn = graph.get_node(in_edge.source_id)
                                    if pn and pn.type == "Class":
                                        target_exec = ExecutionNode(
                                            id=pn.id, type="Class",
                                            name=pn.properties.get("name","Class"),
                                            snippet=pn.properties.get("snippet",""),
                                            children=[target_exec], metadata=pn.properties
                                        )
                                        break
                        exec_node.children.append(target_exec)

        return exec_node

    # ── Override build_global_tree to pass depth ─────────────────────────────

    def build_global_tree(self, graph: KnowledgeGraph,
                           entry_point_id: str) -> Optional[ExecutionNode]:
        visited_files: set = set()
        return self._traverse_file_execution(graph, entry_point_id, visited_files, depth=0)


# ── main ───────────────────────────────────────────────────────────────────────

def main():
    print("=" * 72)
    print("STEP 1 – Parsing repository source files")
    print("=" * 72)

    parser  = UniversalParser()
    engine  = SecurityEngine()
    pf_list = []
    findings_all = []

    for root, dirs, files in os.walk(REPO_DIR):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for fname in files:
            if not fname.endswith(".py"):
                continue
            full = os.path.join(root, fname)
            # Store relative path so graph paths are relative
            rel  = os.path.relpath(full, REPO_DIR).replace("\\", "/")
            try:
                with open(full, "r", encoding="utf-8", errors="ignore") as f:
                    src = f.read()
                pf = parser.parse(src, rel)
                if pf:
                    pf_list.append(pf)
                    sec = engine.scan(pf, rel)
                    findings_all.extend(sec.findings)
            except Exception as exc:
                print(f"  [WARN] Could not parse {rel}: {exc}")

    print(f"  Parsed {len(pf_list)} files, {len(findings_all)} findings\n")

    print("=" * 72)
    print("STEP 2 – Building Knowledge Graph + Semantic Resolution")
    print("=" * 72)

    kg_builder = KnowledgeGraphBuilder("local")
    raw_graph  = kg_builder.build(pf_list, findings_all)

    resolver = SemanticResolver()
    graph    = resolver.resolve(raw_graph)

    file_nodes = [n for n in graph.nodes.values() if n.type == "File"]
    print(f"  Graph: {len(graph.nodes)} nodes, {len(graph.edges)} edges")
    print(f"  File nodes: {len(file_nodes)}")

    # Print all file nodes so we know what *should* be reachable
    print("\n  All repository File nodes:")
    for fn in sorted(file_nodes, key=lambda n: n.properties.get("path","")):
        print(f"    {fn.id}  {fn.properties.get('path','')}")

    print()

    # Edge type summary
    from collections import Counter
    ec = Counter(e.type for e in graph.edges)
    print("  Edge type distribution:")
    for et, cnt in ec.most_common():
        print(f"    {et}: {cnt}")
    print()

    print("=" * 72)
    print("STEP 3 – Finding entry points")
    print("=" * 72)

    entry_file_names = ["main.py", "app.py", "server.py", "manage.py",
                        "index.js", "app.js", "server.js", "main.go"]
    entry_points = []
    for n in graph.nodes.values():
        if n.type == "File":
            p = n.properties.get("path","")
            if any(p.endswith(ep) for ep in entry_file_names):
                entry_points.append(n)

    print(f"  Found {len(entry_points)} entry point(s):")
    for ep in entry_points:
        print(f"    {ep.id}  {ep.properties.get('path','')}")
    print()

    if not entry_points:
        print("[ERROR] No entry points found – cannot build execution tree.")
        return

    print("=" * 72)
    print("STEP 4 – Instrumented execution tree traversal")
    print("=" * 72)
    print()

    builder = InstrumentedBuilder()
    # Use first entry point (main.py preferred)
    ep = next((e for e in entry_points if "main.py" in e.properties.get("path","")), entry_points[0])
    print(f"  Entry point: {ep.properties.get('path','')}\n")

    tree = builder.build_global_tree(graph, ep.id)

    print()
    print("=" * 72)
    print("STEP 5 – Coverage analysis")
    print("=" * 72)

    all_file_ids     = {n.id for n in file_nodes}
    visited_ids      = set()

    def collect_visited(node: ExecutionNode):
        if node.type == "File":
            visited_ids.add(node.id)
        for c in node.children:
            collect_visited(c)

    if tree:
        collect_visited(tree)

    missed = all_file_ids - visited_ids
    print(f"\n  Total repository files : {len(all_file_ids)}")
    print(f"  Files reached by tree  : {len(visited_ids)}")
    print(f"  Files NOT reached      : {len(missed)}")

    if missed:
        print("\n  *** MISSED FILES (not reached by traversal) ***")
        for fid in sorted(missed):
            fn = graph.get_node(fid)
            print(f"    {fid}  {fn.properties.get('path','') if fn else 'UNKNOWN'}")

        print("\n  *** FIRST MISSED FILE – incoming edges (why it wasn't found) ***")
        first_fid = sorted(missed)[0]
        fn = graph.get_node(first_fid)
        print(f"    File: {fn.properties.get('path','') if fn else first_fid}")
        in_edges = graph.get_in_edges(first_fid)
        if not in_edges:
            print("    [!] NO incoming edges – this file is completely disconnected from the graph")
        else:
            for ie in in_edges:
                src = graph.get_node(ie.source_id)
                sname = src.properties.get("path", src.properties.get("name", ie.source_id)) if src else "?"
                print(f"    <-- {ie.type} from {ie.source_id} ({sname})")

        print("\n  *** ALL MISSED FILES – incoming edge summary ***")
        for fid in sorted(missed):
            fn = graph.get_node(fid)
            fpath = fn.properties.get("path","") if fn else fid
            in_edges = graph.get_in_edges(fid)
            edge_summary = ", ".join(f"{ie.type}(from={ie.source_id[:8]})" for ie in in_edges[:3])
            if not in_edges:
                edge_summary = "DISCONNECTED – no incoming edges"
            print(f"    {fpath}: {edge_summary}")
    else:
        print("\n  [OK] All repository files were reached by the traversal.")

    print()
    print("=" * 72)
    print("STEP 6 – Final tree JSON (summary, depth-limited)")
    print("=" * 72)

    def tree_summary(node: ExecutionNode, max_depth=4, depth=0) -> dict:
        d = {"id": node.id, "type": node.type, "label": node.name}
        if depth < max_depth:
            d["children"] = [tree_summary(c, max_depth, depth+1) for c in node.children]
        else:
            d["children"] = f"({len(node.children)} children, truncated)"
        return d

    if tree:
        print(json.dumps(tree_summary(tree), indent=2))
    else:
        print("[WARN] Tree is None – entry point produced no traversal output")


if __name__ == "__main__":
    main()
