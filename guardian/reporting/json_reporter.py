"""JSON reporter — the canonical machine-readable report."""
from __future__ import annotations

import json

from guardian.core.registry import register_reporter


@register_reporter
class JsonReporter:
    name = "json"
    file_extension = ".json"

    def render(self, report: dict) -> str:
        return json.dumps(report, indent=2, default=str)
