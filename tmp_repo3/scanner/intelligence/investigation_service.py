from typing import Dict, Any, List
import uuid
from datetime import datetime
from ai.models import InvestigationSummary, InvestigationContext, InvestigationSession

class InvestigationService:
    def __init__(self, graph):
        self.graph = graph

    def investigate(self, finding_id: str, repo_id: str = "unknown") -> InvestigationSession:
        """
        Traverse the Knowledge Graph to build a highly targeted
        investigation context for the AI.
        """
        finding_node = self.graph.get_node(finding_id)
        if not finding_node:
            raise ValueError(f"Finding {finding_id} not found in the Knowledge Graph")

        summary = InvestigationSummary(
            title=finding_node.properties.get('title', finding_node.properties.get('rule_id', '')),
            severity=finding_node.properties.get('severity', ''),
            cwe=finding_node.properties.get('cwe', ''),
            owasp=finding_node.properties.get('owasp', ''),
            description=finding_node.properties.get('description', ''),
            recommendation=finding_node.properties.get('recommendation', ''),
            snippet=finding_node.properties.get('snippet', ''),
            confidence=str(finding_node.properties.get('confidence', '')),
            line=finding_node.properties.get('line', 0),
            evidence=finding_node.properties.get('evidence', ''),
            file=finding_node.properties.get('file', ''),
            class_name=finding_node.properties.get('class', ''),
            function_name=finding_node.properties.get('function', '')
        )

        path = []
        file_node = None
        symbol_node = None

        # Look for GENERATES_FINDING (Symbol -> Finding)
        gen_edges = [edge for edge in self.graph.edges if edge.target_id == finding_node.id and edge.type == "GENERATES_FINDING"]
        if gen_edges:
            symbol_node = self.graph.get_node(gen_edges[0].source_id)

        if symbol_node:
            current = symbol_node
            
            # If the finding is on a Call node
            if current.type == "Call":
                path.append(f"Call: {current.properties.get('name')} at line {current.properties.get('line', '?')}")
                
                func_edges = [edge for edge in self.graph.edges if edge.target_id == current.id and edge.type == "EXECUTES"]
                if func_edges:
                    current = self.graph.get_node(func_edges[0].source_id)

            if current.type == "Function":
                summary.function_name = current.properties.get('name', '')
                path.append(f"Function: {summary.function_name}")
                
                callers = [self.graph.get_node(edge.source_id) for edge in self.graph.edges if edge.target_id == current.id and edge.type == "CALLS"]
                if callers:
                    caller_names = [c.properties.get("name") for c in callers]
                    path.append(f"Called By: {', '.join(caller_names)}")
                
                contains_edges = [edge for edge in self.graph.edges if edge.target_id == current.id and edge.type == "CONTAINS"]
                if contains_edges:
                    current = self.graph.get_node(contains_edges[0].source_id)

            if current.type == "Class":
                summary.class_name = current.properties.get('name', '')
                path.append(f"Class: {summary.class_name}")
                
                contains_edges = [edge for edge in self.graph.edges if edge.target_id == current.id and edge.type == "CONTAINS"]
                if contains_edges:
                    current = self.graph.get_node(contains_edges[0].source_id)

            if current.type == "File":
                file_node = current
                summary.file = current.properties.get('path', '')

        # Build execution path string
        exec_path = ""
        if path:
            exec_path = "Execution Path Trace (Top-Down):\n"
            for i, step in enumerate(path[::-1]):
                exec_path += f"{i+1}. {step}\n"

        context = InvestigationContext(
            finding_id=finding_id,
            summary=summary,
            evidence=finding_node.properties.get('description', ''),
            future_execution_path=exec_path
        )

        session = InvestigationSession(
            session_id=str(uuid.uuid4()),
            repository_id=repo_id,
            finding_id=finding_id,
            context=context,
            created_at=datetime.utcnow().isoformat(),
            updated_at=datetime.utcnow().isoformat()
        )

        return session
