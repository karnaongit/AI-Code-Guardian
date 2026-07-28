"""
SARIF 2.1.0 reporter — the interchange format GitHub/GitLab code
scanning, VS Code, and most DevSecOps platforms consume. Emitting SARIF
is what makes CI integration (Phase: DevSecOps) a config change rather
than a code change.
"""
from __future__ import annotations

import json

from guardian.core.registry import register_reporter

_SEVERITY_TO_LEVEL = {
    "Critical": "error", "High": "error",
    "Medium": "warning", "Low": "note", "Info": "note",
}


@register_reporter
class SarifReporter:
    name = "sarif"
    file_extension = ".sarif"

    def render(self, report: dict) -> str:
        findings = report.get("scan", {}).get("findings", [])
        rules_index: dict[str, int] = {}
        rules: list[dict] = []
        results: list[dict] = []

        for f in findings:
            rule_id = f.get("rule_id") or f.get("category", "UNKNOWN")
            if rule_id not in rules_index:
                rules_index[rule_id] = len(rules)
                rules.append({
                    "id": rule_id,
                    "name": f.get("category", rule_id),
                    "shortDescription": {"text": f.get("category", rule_id)},
                    "help": {"text": f.get("recommendation", "")},
                    "properties": {"cwe": f.get("cwe"), "owasp": f.get("owasp")},
                })
            results.append({
                "ruleId": rule_id,
                "ruleIndex": rules_index[rule_id],
                "level": _SEVERITY_TO_LEVEL.get(f.get("severity", "Medium"), "warning"),
                "message": {"text": f"{f.get('category')}: {f.get('recommendation', '')}"},
                "partialFingerprints": {"guardianFindingId": f.get("finding_id", "")},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.get("file", "")},
                        "region": {"startLine": max(1, int(f.get("line", 1))),
                                   "snippet": {"text": f.get("snippet", "")}},
                    }
                }],
            })

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {
                    "name": "AI Code Guardian",
                    "version": report.get("tool", {}).get("version", "2.0.0"),
                    "informationUri": "https://github.com/ai-code-guardian",
                    "rules": rules,
                }},
                "results": results,
            }],
        }
        return json.dumps(sarif, indent=2)
