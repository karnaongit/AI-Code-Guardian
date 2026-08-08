import copy
from typing import List
from scanner.intelligence.knowledge_graph import KnowledgeGraph
import re

class SemanticGraph(KnowledgeGraph):
    """
    An enriched version of the Knowledge Graph that includes program semantics.
    """
    def __init__(self, raw_graph: KnowledgeGraph):
        super().__init__()
        # Deepcopy to avoid modifying the original
        self.nodes = copy.deepcopy(raw_graph.nodes)
        self.edges = copy.deepcopy(raw_graph.edges)
        
        # Rebuild adjacency lists
        for edge in self.edges:
            self._out_edges.setdefault(edge.source_id, []).append(edge)
            self._in_edges.setdefault(edge.target_id, []).append(edge)


class BaseResolver:
    """Base class for all semantic resolution passes."""
    def resolve(self, graph: SemanticGraph) -> None:
        raise NotImplementedError
    
    # --- Helpers ---
    def _is_contained_in(self, graph: SemanticGraph, child_id: str, container_id: str) -> bool:
        curr_id = child_id
        visited = set()
        while curr_id and curr_id != container_id and curr_id not in visited:
            visited.add(curr_id)
            found_parent = False
            for edge in graph.get_in_edges(curr_id):
                if edge.type == "CONTAINS":
                    curr_id = edge.source_id
                    found_parent = True
                    break
            if not found_parent:
                break
        return curr_id == container_id

    def _get_parent_file(self, graph: SemanticGraph, node_id: str) -> str:
        curr_id = node_id
        visited = set()
        while curr_id and curr_id not in visited:
            visited.add(curr_id)
            node = graph.get_node(curr_id)
            if node and node.type == "File":
                return curr_id
            found_parent = False
            for edge in graph.get_in_edges(curr_id):
                if edge.type in ("CONTAINS", "EXECUTES", "IMPORTS"):
                    curr_id = edge.source_id
                    found_parent = True
                    break
            if not found_parent:
                break
        return None


class ImportResolver(BaseResolver):
    def resolve(self, graph: SemanticGraph) -> None:
        files_by_path = {}
        classes_by_name = {}
        functions_by_name = {}
        
        for node in graph.nodes.values():
            if node.type == "File":
                path = node.properties.get("path", "")
                module_path = path.replace(".py", "").replace("/", ".").replace("\\", ".")
                files_by_path[module_path] = node.id
            elif node.type == "Class":
                classes_by_name.setdefault(node.properties.get("name"), []).append(node.id)
            elif node.type == "Function":
                functions_by_name.setdefault(node.properties.get("name"), []).append(node.id)

        for node in graph.nodes.values():
            if node.type == "Import":
                import_stmt = node.properties.get("name", "")
                module_name, symbol_name = None, None
                
                if import_stmt.startswith("from "):
                    parts = import_stmt.split(" import ")
                    if len(parts) == 2:
                        module_name = parts[0].replace("from ", "").strip()
                        symbol_name = parts[1].split(" as ")[0].strip()
                elif import_stmt.startswith("import "):
                    module_name = import_stmt.replace("import ", "").split(" as ")[0].strip()
                
                if module_name:
                    if module_name.startswith("."):
                        parent_file_id = self._get_parent_file(graph, node.id)
                        if parent_file_id:
                            parent_file_node = graph.get_node(parent_file_id)
                            p_path = parent_file_node.properties.get("path", "")
                            p_module = p_path.replace(".py", "").replace("/", ".").replace("\\", ".")
                            
                            dots = 0
                            for char in module_name:
                                if char == '.': dots += 1
                                else: break
                            
                            parts = p_module.split(".")
                            keep_parts = parts[:-dots] if dots <= len(parts) else []
                            base = ".".join(keep_parts)
                            rest = module_name[dots:]
                            
                            if base and rest: module_name = f"{base}.{rest}"
                            elif base: module_name = base
                            else: module_name = rest

                # Find the file id by matching the normalized module_path
                file_id = None
                
                # 1. Check if the symbol is actually a module (e.g. from . import engine)
                if module_name and symbol_name:
                    combined = f"{module_name}.{symbol_name}"
                    for m_path, f_id in files_by_path.items():
                        if m_path == combined or m_path.endswith("." + combined):
                            file_id = f_id
                            symbol_name = None  # it resolves to the file itself
                            break
                            
                # 2. Check if the module_name is the file
                if not file_id and module_name:
                    for m_path, f_id in files_by_path.items():
                        if m_path == module_name or m_path.endswith("." + module_name):
                            file_id = f_id
                            break

                # 3. Check if the module_name is a package (i.e. has __init__)
                if not file_id and module_name:
                    pkg = f"{module_name}.__init__"
                    for m_path, f_id in files_by_path.items():
                        if m_path == pkg or m_path.endswith("." + pkg):
                            file_id = f_id
                            break

                if not file_id and module_name:
                    print(f"ImportResolver failed to find file for module {module_name}")
                            
                resolved_id = None
                if symbol_name and file_id:
                    for candidate_id in classes_by_name.get(symbol_name, []):
                        if self._is_contained_in(graph, candidate_id, file_id):
                            resolved_id = candidate_id
                            break
                    if not resolved_id:
                        for candidate_id in functions_by_name.get(symbol_name, []):
                            if self._is_contained_in(graph, candidate_id, file_id):
                                resolved_id = candidate_id
                                break
                
                if not resolved_id and file_id:
                    resolved_id = file_id
                
                if resolved_id:
                    graph.add_edge(node.id, resolved_id, "RESOLVES_TO")


class FrameworkResolver(BaseResolver):
    def resolve(self, graph: SemanticGraph) -> None:
        for node in graph.nodes.values():
            if node.type == "Call":
                call_name = node.properties.get("name", "")
                call_snippet = node.properties.get("snippet", "")
                if "include_router" in call_name:
                    match = re.search(r"include_router\((.*?)\)", call_snippet)
                    if match:
                        router_arg = match.group(1).strip()
                        parent_file_id = self._get_parent_file(graph, node.id)
                        if not parent_file_id: continue
                        
                        module_prefix = router_arg.split(".")[0] if "." in router_arg else router_arg
                        
                        for edge in graph.get_out_edges(parent_file_id):
                            if edge.type == "IMPORTS":
                                import_node = graph.get_node(edge.target_id)
                                if import_node and module_prefix in import_node.properties.get("name", ""):
                                    for res_edge in graph.get_out_edges(import_node.id):
                                        if res_edge.type == "RESOLVES_TO":
                                            graph.add_edge(node.id, res_edge.target_id, "ROUTES_TO")
                                            break


class ScopedCallResolver(BaseResolver):
    def resolve(self, graph: SemanticGraph) -> None:
        functions_by_name = {}
        for node in graph.nodes.values():
            if node.type == "Function":
                name = node.properties.get("name")
                if name: functions_by_name.setdefault(name, []).append(node.id)

        for node in list(graph.nodes.values()):
            if node.type == "Call":
                raw_call = node.properties.get("name", "")
                clean_name = raw_call.split("(")[0].split(".")[-1].strip()
                
                if clean_name and clean_name in functions_by_name:
                    parent_file_id = self._get_parent_file(graph, node.id)
                    matched_func_id = None
                    
                    for candidate_id in functions_by_name[clean_name]:
                        candidate_file_id = self._get_parent_file(graph, candidate_id)
                        
                        if candidate_file_id == parent_file_id:
                            matched_func_id = candidate_id
                            break
                        
                        if parent_file_id and candidate_file_id:
                            for edge in graph.get_out_edges(parent_file_id):
                                if edge.type == "IMPORTS":
                                    for res_edge in graph.get_out_edges(edge.target_id):
                                        if res_edge.type == "RESOLVES_TO":
                                            if res_edge.target_id in (candidate_id, candidate_file_id):
                                                matched_func_id = candidate_id
                                                break
                                            elif self._is_contained_in(graph, candidate_id, res_edge.target_id):
                                                matched_func_id = candidate_id
                                                break
                                if matched_func_id: break
                        if matched_func_id: break
                    
                    if matched_func_id:
                        graph.add_edge(node.id, matched_func_id, "CALLS")


class SemanticResolver:
    """Orchestrates independent resolution passes on the SemanticGraph."""
    def __init__(self, resolvers: List[BaseResolver] = None):
        self.resolvers = resolvers or [
            ImportResolver(),
            FrameworkResolver(),
            ScopedCallResolver()
        ]
        
    def resolve(self, raw_graph: KnowledgeGraph) -> SemanticGraph:
        semantic_graph = SemanticGraph(raw_graph)
        for resolver in self.resolvers:
            resolver.resolve(semantic_graph)
        return semantic_graph
