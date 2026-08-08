import yaml
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from pathlib import Path

from scanner.models import ParsedFile, CallSymbol

@dataclass
class Capability:
    name: str
    category: str
    severity: str
    sinks: List[str] = field(default_factory=list)

class CapabilityEngine:
    """
    Tags generic symbols with behavioral capabilities based on YAML configuration.
    Uses a partitioned cache to lazily load sinks only for the language being scanned.
    """
    
    def __init__(self, config_dir: str = None):
        if config_dir is None:
            self.config_dir = Path(__file__).parent.parent / "config"
        else:
            self.config_dir = Path(config_dir)
            
        self.capabilities: Dict[str, Capability] = {}
        # Stores which languages have been loaded to avoid repeated disk I/O
        self.loaded_languages = set()
        
        self._load_schema()

    def _load_schema(self):
        """Loads the base capabilities without sinks."""
        schema_path = self.config_dir / "capabilities.yaml"
        if not schema_path.exists():
            return
            
        with open(schema_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            
        for cap_name, cap_data in data.items():
            self.capabilities[cap_name] = Capability(
                name=cap_name,
                category=cap_data.get("category", "Unknown"),
                severity=cap_data.get("severity", "Low")
            )

    def _load_language_sinks(self, language: str):
        """Lazily loads the sinks for a specific language."""
        language_lower = language.lower() if language else "unknown"
        if language_lower in self.loaded_languages:
            return
            
        sinks_path = self.config_dir / "sinks" / f"{language_lower}.yaml"
        if not sinks_path.exists():
            self.loaded_languages.add(language_lower)
            return
            
        with open(sinks_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            
        for cap_name, sinks in data.items():
            if cap_name in self.capabilities:
                self.capabilities[cap_name].sinks.extend(sinks)
                
        self.loaded_languages.add(language_lower)

    def assign_capabilities(self, parsed_file: ParsedFile) -> None:
        """
        Iterates through symbols and assigns capabilities to their context.
        Lazily loads sinks for the parsed file's language.
        """
        self._load_language_sinks(parsed_file.language)
        
        # Build sink lookup for fast matching
        sink_to_capability = {}
        for cap in self.capabilities.values():
            for sink in cap.sinks:
                sink_to_capability[sink] = cap
                
        # Evaluate calls
        for call in parsed_file.calls:
            fqn = self._build_call_fqn(call)
            
            # Substring match for fqn
            matched = False
            for sink, cap in sink_to_capability.items():
                if sink == fqn or fqn.endswith(f".{sink}") or fqn.endswith(f"::{sink}") or fqn.startswith(f"{sink}."):
                    call.context["capability"] = cap.name
                    matched = True
                    break
            
            if matched:
                continue
                
            # Exact match for actual_name
            actual_name = call.context.get("name", [call.name])[0]
            for sink, cap in sink_to_capability.items():
                if sink == actual_name:
                    call.context["capability"] = cap.name
                    break

    def _build_call_fqn(self, call: CallSymbol) -> str:
        """
        Reconstructs the Fully Qualified Name (FQN) using ContextEnricher data.
        """
        receiver_list = call.context.get("receiver")
        receiver = receiver_list[0] if receiver_list else None
        resolved_import = call.context.get("resolved_import")
        
        actual_name = call.context.get("name", [call.name])[0]
        
        # If we know the exact import path, that's the best FQN
        if resolved_import:
            return f"{resolved_import}::{actual_name}" if "::" in resolved_import else f"{resolved_import}.{actual_name}"
            
        # If we have a receiver but no import resolution (e.g. built-ins or unresolvable)
        if receiver:
            # Simple heuristic for dot vs double colon
            sep = "::" if "::" in call.snippet or "::" in receiver else "."
            return f"{receiver}{sep}{actual_name}"
            
        return actual_name
