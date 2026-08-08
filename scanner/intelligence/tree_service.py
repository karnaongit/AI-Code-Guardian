from typing import Dict, Any, List
from scanner.intelligence.knowledge_graph import KnowledgeGraph, GraphNode
from scanner.intelligence.execution_builder import ExecutionTreeBuilder

class IntelligenceTreeNode:
    def __init__(self, node_id: str, label: str, node_type: str, metadata: dict = None):
        self.node_id = node_id
        self.label = label
        self.node_type = node_type
        self.metadata = metadata or {}
        self.children = []

    def to_dict(self):
        return {
            "id": self.node_id,
            "label": self.label,
            "type": self.node_type,
            "metadata": self.metadata,
            "children": [c.to_dict() for c in self.children]
        }

class TreeService:
    """
    Projects the flat Knowledge Graph into structured hierarchical views for the frontend.
    """

    def __init__(self):
        self.execution_builder = ExecutionTreeBuilder()

    def get_structure_view(self, graph: KnowledgeGraph) -> Dict[str, Any]:
        """
        Builds: Repo -> Folders -> Files -> Classes -> Functions -> Findings
        Full semantic tree — used for per-file semantic expansion in the Explorer.
        """
        repo_node = next((n for n in graph.nodes.values() if n.type == "Repository"), None)
        if not repo_node:
            return {}
            
        roots = self._build_recursive_tree(
            graph, 
            repo_node.id, 
            ["CONTAINS", "GENERATES_FINDING", "EXECUTES", "IMPORTS"],
            allowed_types={"Repository", "Folder", "File", "Class", "Function", "Call", "Import", "Variable", "Finding"}
        )
        root = roots[0] if roots else None
        if root:
            self._propagate_severity(root)
        return root.to_dict() if root else {}

    def get_directory_view(self, graph: KnowledgeGraph) -> Dict[str, Any]:
        """
        Directory Projection: Repo -> Folder -> File ONLY.
        No Class, Function, or Finding nodes appear at this level.
        Each File node carries maxSeverity and finding_count so the Explorer
        can display a severity indicator without requiring file expansion.

        This is the correct model for the Repository Explorer (filesystem browser).
        The Execution Tree consumes a completely separate model (execution_views).
        """
        repo_node = next((n for n in graph.nodes.values() if n.type == "Repository"), None)
        if not repo_node:
            return {}

        DIRECTORY_TYPES = {"Repository", "Folder", "File"}
        SEV_WEIGHTS = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "None": 0}

        def collect_file_findings(file_node_id: str) -> list:
            """Walk CONTAINS, EXECUTES, then GENERATES_FINDING from a File to gather its Findings."""
            findings = []
            visited = set()
            stack = [file_node_id]
            while stack:
                nid = stack.pop()
                if nid in visited:
                    continue
                visited.add(nid)
                for edge in graph.get_out_edges(nid):
                    child = graph.get_node(edge.target_id)
                    if not child:
                        continue
                    if edge.type == "GENERATES_FINDING" and child.type == "Finding":
                        findings.append(child)
                    elif edge.type in ("CONTAINS", "EXECUTES") and child.type not in DIRECTORY_TYPES:
                        stack.append(edge.target_id)
            return findings

        def file_max_severity(findings: list) -> str:
            best_w, best_s = 0, "None"
            for f in findings:
                sev = f.properties.get("severity", "None")
                w = SEV_WEIGHTS.get(sev, 0)
                if w > best_w:
                    best_w, best_s = w, sev
            return best_s

        def build_dir_node(node_id: str):
            node = graph.get_node(node_id)
            if not node or node.type not in DIRECTORY_TYPES:
                return None

            metadata = dict(node.properties)

            if node.type == "File":
                # Compute vulnerability metadata so the Explorer can show a
                # severity dot without the user having to expand the file.
                findings = collect_file_findings(node_id)
                metadata["maxSeverity"] = file_max_severity(findings)
                metadata["finding_count"] = len(findings)

            name = metadata.get("name", metadata.get("path", node.type))
            if node.type == "File" and "/" in name:
                name = name.split("/")[-1]
            elif node.type == "File" and "\\" in name:
                name = name.split("\\")[-1]

            tree_node = IntelligenceTreeNode(
                node_id=node.id,
                label=name,
                node_type=node.type,
                metadata=metadata
            )

            for edge in graph.get_out_edges(node_id):
                if edge.type == "CONTAINS":
                    child_tree = build_dir_node(edge.target_id)
                    if child_tree:
                        tree_node.children.append(child_tree)

            return tree_node

        root = build_dir_node(repo_node.id)
        return root.to_dict() if root else {}

    def _propagate_severity(self, node: IntelligenceTreeNode) -> str:
        """
        Rolls up the maximum severity from children to parents in the structure view.
        """
        SEV_WEIGHTS = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "None": 0}
        
        if node.node_type == "Finding":
            sev = node.metadata.get("severity", "None")
            node.metadata["maxSeverity"] = sev
            return sev
            
        max_w = 0
        max_sev = "None"
        
        for child in node.children:
            c_sev = self._propagate_severity(child)
            w = SEV_WEIGHTS.get(c_sev, 0)
            if w > max_w:
                max_w = w
                max_sev = c_sev
                
        node.metadata["maxSeverity"] = max_sev
        return max_sev

    def get_security_view(self, graph: KnowledgeGraph) -> Dict[str, Any]:
        """
        Builds: Repo -> Folders -> Files -> Functions -> Finding
        Only includes paths that lead to a finding.
        """
        repo_node = next((n for n in graph.nodes.values() if n.type == "Repository"), None)
        if not repo_node:
            return {}
            
        # For security view, we only include nodes with risk_weight > 0
        def security_filter(node: GraphNode):
            return node.properties.get("risk_weight", 0) > 0 or node.type == "Finding"

        roots = self._build_recursive_tree(
            graph, 
            repo_node.id, 
            ["CONTAINS", "GENERATES_FINDING"], 
            node_filter=security_filter
        )
        root = roots[0] if roots else None
        return root.to_dict() if root else {}

    def get_execution_view(self, graph: KnowledgeGraph, finding_id: str) -> Dict[str, Any]:
        """
        Builds the execution path leading up to a finding.
        """
        execution_path = self.execution_builder.build_path(graph, finding_id)
        if not execution_path:
            return {}
            
        return execution_path.to_dict()

    def get_entry_points(self, graph: KnowledgeGraph) -> List[Dict[str, str]]:
        """
        Finds application entry points.
        """
        return self.execution_builder.find_entry_points(graph)

    def get_global_execution_view(self, graph: KnowledgeGraph, entry_point_id: str) -> Dict[str, Any]:
        """
        Builds the global execution tree starting from an entry point.
        """
        execution_path = self.execution_builder.build_global_tree(graph, entry_point_id)
        if not execution_path:
            return {}
            
        return execution_path.to_dict()

    def _build_recursive_tree(self, graph: KnowledgeGraph, current_id: str, edge_types: List[str], node_filter=None, allowed_types: set = None) -> List[IntelligenceTreeNode]:
        node = graph.get_node(current_id)
        if not node:
            return []
            
        if node_filter and not node_filter(node):
            return []

        out_edges = [e for e in graph.get_out_edges(current_id) if e.type in edge_types]
        
        children = []
        for edge in out_edges:
            children.extend(self._build_recursive_tree(graph, edge.target_id, edge_types, node_filter, allowed_types))
            
        if allowed_types and node.type not in allowed_types:
            return children

        name = node.properties.get("name", node.properties.get("path", node.properties.get("rule_id", node.type)))
        
        tree_node = IntelligenceTreeNode(
            node_id=node.id,
            label=name,
            node_type=node.type,
            metadata=node.properties
        )
        tree_node.children = children
        return [tree_node]
