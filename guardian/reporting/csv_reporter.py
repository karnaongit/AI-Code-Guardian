"""
CSV Reporter — Tabular export for Security Operations Centers (SOCs) and SIEM tools.
"""
from __future__ import annotations

import csv
import io
from guardian.core.registry import register_reporter


@register_reporter
class CSVReporter:
    name = "csv"
    file_extension = ".csv"

    def render(self, report_dict: dict) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow([
            "Finding ID", "Rule ID", "Category", "Severity",
            "File", "Line", "Snippet", "Recommendation", "Confidence"
        ])
        
        scan = report_dict.get("scan", {})
        findings = scan.get("findings", [])
        
        for f in findings:
            writer.writerow([
                f.get("id", ""),
                f.get("rule_id", ""),
                f.get("category", ""),
                f.get("severity", ""),
                f.get("file", ""),
                f.get("line", 0),
                f.get("snippet", "").replace("\n", " ")[:150],
                f.get("recommendation", ""),
                f.get("confidence", 0.0),
            ])
            
        return output.getvalue()
