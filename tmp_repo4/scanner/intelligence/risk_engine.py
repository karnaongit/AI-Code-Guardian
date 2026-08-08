from scanner.intelligence.knowledge_graph import KnowledgeGraph

class RiskPropagationEngine:
    """
    Propagates risk upward through the Knowledge Graph.
    Finding -> Function -> Class -> File -> Folder -> Repository.
    """

    SEVERITY_WEIGHTS = {
        "Critical": 4,
        "High": 3,
        "Medium": 2,
        "Low": 1,
        "Unknown": 0
    }

    def __init__(self):
        pass

    def _get_weight(self, severity: str) -> int:
        return self.SEVERITY_WEIGHTS.get(severity, 0)

    def _get_severity_by_weight(self, weight: int) -> str:
        for sev, w in self.SEVERITY_WEIGHTS.items():
            if w == weight:
                return sev
        return "Unknown"

    def propagate(self, graph: KnowledgeGraph) -> KnowledgeGraph:
        """
        Calculates and updates risk for all ancestor nodes of findings.
        """
        # Find all finding nodes
        findings = [node for node in graph.nodes.values() if node.type == "Finding"]

        for finding in findings:
            severity = finding.properties.get("severity", "Unknown")
            weight = self._get_weight(severity)
            
            if weight == 0:
                continue
                
            # Bubble up risk from finding to its sources (Symbol/File)
            # Find incoming edges where source GENERATES_FINDING finding
            in_edges = [e for e in graph.get_in_edges(finding.id) if e.type == "GENERATES_FINDING"]
            for edge in in_edges:
                self._bubble_up(graph, edge.source_id, weight)

        return graph

    def _bubble_up(self, graph: KnowledgeGraph, node_id: str, incoming_weight: int):
        node = graph.get_node(node_id)
        if not node:
            return

        current_severity = node.properties.get("risk_severity", "Unknown")
        current_weight = self._get_weight(current_severity)

        # Update if incoming risk is higher
        if incoming_weight > current_weight:
            node.properties["risk_severity"] = self._get_severity_by_weight(incoming_weight)
            node.properties["risk_weight"] = incoming_weight

            # Propagate upwards (CONTAINS / EXECUTES edges reversed: look for in-edges of those types)
            # Find nodes that CONTAIN or EXECUTE this node
            parent_edges = [e for e in graph.get_in_edges(node_id) if e.type in ["CONTAINS", "EXECUTES"]]
            for edge in parent_edges:
                self._bubble_up(graph, edge.source_id, incoming_weight)
