from dataclasses import dataclass, field
from typing import Dict, List, Set, Any
import hashlib

@dataclass
class GraphNode:
    id: str
    type: str
    properties: Dict[str, Any] = field(default_factory=dict)

@dataclass
class GraphEdge:
    source_id: str
    target_id: str
    type: str

class KnowledgeGraph:
    def __init__(self):
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []
        # Adjacency lists for fast traversal
        self._out_edges: Dict[str, List[GraphEdge]] = {}
        self._in_edges: Dict[str, List[GraphEdge]] = {}

    def add_node(self, node: GraphNode):
        self.nodes[node.id] = node

    def add_edge(self, source_id: str, target_id: str, edge_type: str):
        if source_id not in self.nodes or target_id not in self.nodes:
            # Nodes must exist before edges can be formed
            return
            
        edge = GraphEdge(source_id, target_id, edge_type)
        self.edges.append(edge)
        
        if source_id not in self._out_edges:
            self._out_edges[source_id] = []
        self._out_edges[source_id].append(edge)
        
        if target_id not in self._in_edges:
            self._in_edges[target_id] = []
        self._in_edges[target_id].append(edge)

    def get_node(self, node_id: str) -> GraphNode:
        return self.nodes.get(node_id)

    def get_out_edges(self, node_id: str) -> List[GraphEdge]:
        return self._out_edges.get(node_id, [])

    def get_in_edges(self, node_id: str) -> List[GraphEdge]:
        return self._in_edges.get(node_id, [])

class KnowledgeGraphBuilder:
    """
    Constructs a semantic Knowledge Graph from Canonical Domain Models (Generic Symbols).
    """

    def __init__(self, repo_name: str):
        self.repo_name = repo_name
        self.repo_id = self._hash(f"repo:{repo_name}")
        self.graph = KnowledgeGraph()

    def _hash(self, val: str) -> str:
        return hashlib.sha1(val.encode()).hexdigest()[:16]

    def build(self, parsed_files: list, findings: list) -> KnowledgeGraph:
        
        # 1. Add Repository Node
        self.graph.add_node(GraphNode(
            id=self.repo_id, 
            type="Repository", 
            properties={"name": self.repo_name}
        ))

        # 2. Add File and Symbol Nodes
        for pf in parsed_files:
            file_id = pf.file_id
            
            # File Node
            self.graph.add_node(GraphNode(
                id=file_id, 
                type="File", 
                properties={"path": pf.file_path, "language": pf.language}
            ))
            
            # Add Folder logic (Full Recursive Hierarchy)
            parts = pf.file_path.split('/')
            if len(parts) > 1:
                # File is in a folder. Build the directory chain
                parent_node_id = self.repo_id
                current_path = ""
                
                for part in parts[:-1]: # exclude the filename
                    current_path = f"{current_path}/{part}" if current_path else part
                    folder_id = self._hash(f"folder:{current_path}")
                    
                    if not self.graph.get_node(folder_id):
                        self.graph.add_node(GraphNode(id=folder_id, type="Folder", properties={"path": current_path, "name": part}))
                        self.graph.add_edge(parent_node_id, folder_id, "CONTAINS")
                        
                    parent_node_id = folder_id
                
                self.graph.add_edge(parent_node_id, file_id, "CONTAINS")
            else:
                # File is in root directory
                self.graph.add_edge(self.repo_id, file_id, "CONTAINS")
            
            # Class Nodes
            for cls in pf.classes:
                cls_name = cls.context.get("name", [cls.name])[0] if cls.context and "name" in cls.context else cls.name
                self.graph.add_node(GraphNode(
                    id=cls.symbol_id, type="Class", properties={"name": cls_name, "snippet": cls.name, "line": cls.line}
                ))
                self.graph.add_edge(file_id, cls.symbol_id, "CONTAINS")

            # Function Nodes
            for func in pf.functions:
                func_name = func.context.get("name", [func.name])[0] if func.context and "name" in func.context else func.name
                self.graph.add_node(GraphNode(
                    id=func.symbol_id, type="Function", properties={"name": func_name, "snippet": func.name, "line": func.line}
                ))
                # If function has parent_id (e.g. Class), link to class, else to file
                if func.parent_id and self.graph.get_node(func.parent_id):
                    self.graph.add_edge(func.parent_id, func.symbol_id, "CONTAINS")
                else:
                    self.graph.add_edge(file_id, func.symbol_id, "CONTAINS")
                    
            # Call Nodes
            for call in pf.calls:
                call_name = call.context.get("name", [call.name])[0] if call.context and "name" in call.context else call.name
                self.graph.add_node(GraphNode(
                    id=call.symbol_id, type="Call", properties={"name": call_name, "snippet": call.snippet}
                ))
                if call.parent_id and self.graph.get_node(call.parent_id):
                    self.graph.add_edge(call.parent_id, call.symbol_id, "EXECUTES")
                else:
                    self.graph.add_edge(file_id, call.symbol_id, "EXECUTES")
                    
            # IMPORTS
            for imp in pf.imports:
                imp_id = imp.symbol_id
                self.graph.add_node(GraphNode(
                    id=imp_id, type="Import", properties={"name": imp.name, "snippet": imp.name}
                ))
                self.graph.add_edge(file_id, imp_id, "IMPORTS")

        # 3. Add Security Findings, Capabilities, and Rules
        import logging
        logger = logging.getLogger(__name__)

        for finding in findings:
            finding_id = finding.finding_id
            
            metadata_fields = {
                "finding_id": finding_id,
                "title": getattr(finding, "title", "") or finding.rule_id,
                "severity": finding.severity,
                "file": finding.file,
                "class": finding.class_name,
                "function": finding.function_name,
                "line": finding.line,
                "snippet": finding.snippet,
                "evidence": finding.evidence or finding.description,
                "confidence": getattr(finding, "confidence", 1.0),
                "cwe": getattr(finding, "cwe", ""),
                "owasp": getattr(finding, "owasp", ""),
                "recommendation": finding.recommendation
            }
            
            properties = {}
            for field_name, value in metadata_fields.items():
                if value is None or value == "" or (isinstance(value, int) and value == 0):
                    logger.warning(f"Finding {finding_id}: metadata field '{field_name}' is missing or empty.")
                    if isinstance(value, (int, float)):
                        properties[field_name] = 0
                    else:
                        properties[field_name] = f"MISSING_{field_name.upper()}"
                else:
                    properties[field_name] = value

            # Preserve rule_id, category, and description for backwards compatibility
            properties["rule_id"] = finding.rule_id
            properties["category"] = finding.category
            properties["description"] = finding.description or finding.evidence or properties["evidence"]
            
            self.graph.add_node(GraphNode(
                id=finding_id,
                type="Finding",
                properties=properties
            ))
            
            if finding.symbol_id and self.graph.get_node(finding.symbol_id):
                self.graph.add_edge(finding.symbol_id, finding_id, "GENERATES_FINDING")
            elif finding.file_id and self.graph.get_node(finding.file_id):
                self.graph.add_edge(finding.file_id, finding_id, "GENERATES_FINDING")

            # Capability Node
            if finding.capability:
                cap_id = self._hash(f"capability:{finding.capability}")
                if not self.graph.get_node(cap_id):
                    self.graph.add_node(GraphNode(id=cap_id, type="Capability", properties={"name": finding.capability}))
                
                # The symbol HAS_CAPABILITY
                if finding.symbol_id and self.graph.get_node(finding.symbol_id):
                    self.graph.add_edge(finding.symbol_id, cap_id, "HAS_CAPABILITY")
                    
                # Rule Node
                rule_node_id = self._hash(f"rule:{finding.rule_id}")
                if not self.graph.get_node(rule_node_id):
                    self.graph.add_node(GraphNode(id=rule_node_id, type="Rule", properties={"rule_id": finding.rule_id}))
                    
                # Capability MATCHES_RULE Rule
                self.graph.add_edge(cap_id, rule_node_id, "MATCHES_RULE")

        # 4. Post-processing: Resolve cross-file calls
        # (Moved to SemanticResolver to preserve separation of concerns)

        return self.graph
