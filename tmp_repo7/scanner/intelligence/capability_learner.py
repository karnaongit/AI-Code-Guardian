from pathlib import Path
import yaml
from scanner.language_learning.query_generator import BaseLLM

class CapabilityLearningManager:
    """
    Dynamically learns security capabilities (sinks) for new languages using an LLM.
    Partitions the cache by saving sinks into language-specific YAML files.
    """
    def __init__(self, llm: BaseLLM, config_dir: str = None):
        self.llm = llm
        if config_dir is None:
            self.config_dir = Path(__file__).parent.parent / "config"
        else:
            self.config_dir = Path(config_dir)

    def learn(self, language_name: str) -> bool:
        """
        Learns the sinks for the given language and writes them to the partitioned cache.
        Returns True if newly learned, False if already cached.
        """
        sinks_path = self.config_dir / "sinks" / f"{language_name}.yaml"
        if sinks_path.exists():
            return False
            
        schema_path = self.config_dir / "capabilities.yaml"
        if not schema_path.exists():
            raise FileNotFoundError("capabilities.yaml schema not found")
            
        with open(schema_path, "r", encoding="utf-8") as f:
            schema = yaml.safe_load(f) or {}
            
        capabilities_list = list(schema.keys())
        
        prompt = f"""
You are an expert security engineer. I need you to map common security capabilities to their standard library sinks (function calls) in the programming language: {language_name}.

Capabilities to map:
{", ".join(capabilities_list)}

Requirements:
- Provide the Fully Qualified Names (FQNs) for the sinks (e.g. 'os.system' for Python, 'std::process::Command::new' for Rust, 'os/exec.Command' for Go).
- Respond ONLY with valid YAML. No markdown formatting, no explanations.
- The YAML must be a dictionary where the keys are the capability names, and the values are lists of string FQNs.

Example format:
COMMAND_EXECUTION:
  - foo.bar
  - baz.qux
"""
        response = self.llm.generate(prompt).strip()
        
        # Clean up possible markdown fences
        if response.startswith("```yaml"):
            response = response[7:]
        if response.startswith("```"):
            response = response[3:]
        if response.endswith("```"):
            response = response[:-3]
            
        response = response.strip()
        
        # Validate that it is valid YAML
        try:
            parsed = yaml.safe_load(response)
        except Exception as e:
            print(f"Failed to parse LLM capability response for {language_name}: {e}")
            return False
            
        # Ensure directory exists
        sinks_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(sinks_path, "w", encoding="utf-8") as f:
            yaml.dump(parsed, f, default_flow_style=False)
            
        print(f"[+] Dynamically discovered and cached capabilities for {language_name}.")
        return True
