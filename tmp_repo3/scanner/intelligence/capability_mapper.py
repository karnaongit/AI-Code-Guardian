from scanner.models import ParsedFile
from scanner.intelligence.capabilities import CAPABILITIES

class CapabilityMapper:
    """
    Scans through the AST (ParsedFile) and maps specific nodes (like function calls or variables)
    to abstract Capabilities (e.g., 'execute_sql_query', 'read_http_input').
    """

    def map_capabilities(self, parsed: ParsedFile) -> None:
        """
        Iterates over all calls and variables in the parsed file, and assigns
        a .capability attribute if the node matches a known pattern.
        Note: We are not mutating the base AST fields right now since we 
        will use this in parallel to the main security engine.
        """
        for call in parsed.calls:
            capability = self._identify_capability(call.name)
            if capability:
                # Dynamically attach the capability to the call object
                call.capability = capability

        for variable in parsed.variables:
            capability = self._identify_capability(variable.name)
            if capability:
                variable.capability = capability

    def _identify_capability(self, name: str) -> str:
        """
        Matches a given node name against the known capability dictionary.
        This allows for basic matching right now, but can be expanded to
        semantic matching later.
        """
        # Exact match
        if name in CAPABILITIES:
            return CAPABILITIES[name]
        
        # Substring match (e.g. 'sqlite3.execute' in 'db.execute')
        # Very simple fallback for now
        for pattern, capability in CAPABILITIES.items():
            if pattern in name:
                return capability

        return ""
