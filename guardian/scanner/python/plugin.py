"""Python language plugin — stdlib-AST parsing with per-function taint
tracking (source -> sink, sanitiser-aware) plus entropy-filtered secret
detection. Ported intact from v1."""
from guardian.core.registry import register_language
from guardian.scanner.base import EngineBackedPlugin


@register_language
class PythonPlugin(EngineBackedPlugin):
    name = "python"
    extensions = (".py",)
    _engine_language = "python"
