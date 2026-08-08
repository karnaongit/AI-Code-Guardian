import os
import logging
from neo4j import GraphDatabase
from scanner.intelligence.semantic_resolver import SemanticGraph

logger = logging.getLogger(__name__)

class Neo4jAdapter:
    def __init__(self):
        self.uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.user = os.getenv("NEO4J_USERNAME", "neo4j")
        self.password = os.getenv("NEO4J_PASSWORD", "ChangeThisPassword123!")
        try:
            self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
            self.driver.verify_connectivity()
            self._is_available = True
            logger.info("Neo4j driver connected successfully.")
        except Exception as e:
            logger.error(f"Neo4j driver unavailable: {e}")
            self.driver = None
            self._is_available = False

    def close(self):
        if self.driver:
            self.driver.close()

    def is_available(self) -> bool:
        return self._is_available

    def project_graph(self, graph: SemanticGraph, repo_name: str) -> None:
        """
        Projects the SemanticGraph into Neo4j.
        Nodes and relationships are scoped by the repo_name namespace.
        """
        if not self._is_available:
            return

        with self.driver.session() as session:
            # 1. First, clear out old data for this repo to allow fresh projection
            session.run(
                "MATCH (n) WHERE n.repo_namespace = $repo_name DETACH DELETE n",
                repo_name=repo_name
            )

            # 2. Project Nodes
            for node_id, node in graph.nodes.items():
                props = node.properties.copy()
                props["node_id"] = node.id
                props["repo_namespace"] = repo_name

                # Clean up properties that might be complex objects or dicts (not supported natively by Neo4j driver without serialization)
                clean_props = {}
                for k, v in props.items():
                    if v is None:
                        continue
                    if isinstance(v, (str, int, float, bool)):
                        clean_props[k] = v
                    else:
                        clean_props[k] = str(v)

                label = node.type
                # Use parameterized query to set properties
                query = (
                    f"CREATE (n:{label} $props)"
                )
                session.run(query, props=clean_props)

            # 3. Project Relationships
            for edge in graph.edges:
                edge_type = edge.type
                query = (
                    "MATCH (a {node_id: $source_id, repo_namespace: $repo_name}) "
                    "MATCH (b {node_id: $target_id, repo_namespace: $repo_name}) "
                    f"CREATE (a)-[r:{edge_type}]->(b)"
                )
                session.run(
                    query, 
                    source_id=edge.source_id, 
                    target_id=edge.target_id, 
                    repo_name=repo_name
                )
                
        logger.info(f"Successfully projected graph for {repo_name} into Neo4j.")

    def get_topology(self, finding_id: str, repo_name: str) -> str:
        """
        Retrieves graph topology context for a specific finding.
        Returns a formatted string describing the structural context.
        """
        if not self._is_available:
            return "Neo4j driver unavailable"

        try:
            with self.driver.session() as session:
                query = (
                    "MATCH path = (f:Finding {node_id: $finding_id, repo_namespace: $repo_name})<-[:GENERATES_FINDING]-(s) "
                    "OPTIONAL MATCH call_path = (s)<-[:EXECUTES|CALLS*1..3]-(caller) "
                    "RETURN path, call_path LIMIT 10"
                )
                result = session.run(query, finding_id=finding_id, repo_name=repo_name)
                
                context_lines = [f"Topology for Finding {finding_id} in {repo_name}:"]
                records = list(result)
                if not records:
                    return f"No structural topology found for finding {finding_id}."
                    
                for record in records:
                    path = record.get("path")
                    if path:
                        # Extract basic path info
                        nodes = [n.get("name", n.get("node_id", "Unknown")) for n in path.nodes]
                        context_lines.append(f"Source structure: {' -> '.join(nodes)}")
                        
                    call_path = record.get("call_path")
                    if call_path:
                        nodes = [n.get("name", n.get("node_id", "Unknown")) for n in call_path.nodes]
                        context_lines.append(f"Call trace: {' <- '.join(nodes)}")
                        
                return "\n".join(context_lines)
        except Exception as e:
            logger.error(f"Error querying topology: {e}")
            return f"Error retrieving topology: {str(e)}"

    def get_finding_reachability(self, repo_namespace: str, finding_id: str, max_depth: int = 10) -> dict:
        """
        Determines deterministically whether the vulnerable Function for a given finding
        is reachable from any API endpoint.
        """
        if not self._is_available:
            return {"reachable": False, "path": [], "endpoint": None, "error": "Neo4j unavailable"}

        try:
            with self.driver.session() as session:
                query = (
                    f"MATCH path = (endpoint:Function {{repo_namespace: $repo_name, is_api_endpoint: true}})"
                    f"-[r:EXECUTES|CALLS*1..{max_depth}]->"
                    f"(vuln {{repo_namespace: $repo_name}})-[:GENERATES_FINDING]->"
                    f"(f:Finding {{node_id: $finding_id, repo_namespace: $repo_name}}) "
                    f"RETURN path, endpoint "
                    f"LIMIT 1"
                )
                result = session.run(query, repo_name=repo_namespace, finding_id=finding_id)
                record = result.single()

                if not record:
                    return {
                        "reachable": False,
                        "path": [],
                        "endpoint": None
                    }

                endpoint_node = record.get("endpoint")
                path_obj = record.get("path")
                
                path_names = [n.get("name", n.get("node_id", "Unknown")) for n in path_obj.nodes]

                return {
                    "reachable": True,
                    "path": path_names,
                    "endpoint": {
                        "function": endpoint_node.get("name"),
                        "route": endpoint_node.get("route"),
                        "method": endpoint_node.get("http_method")
                    }
                }
        except Exception as e:
            logger.error(f"Error checking reachability: {e}")
            return {"reachable": False, "path": [], "endpoint": None, "error": str(e)}
