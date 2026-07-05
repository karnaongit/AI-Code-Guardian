#!/usr/bin/env python3
"""
AI Code Guardian - CLI
Usage:
    python main.py scan <path> [--out report.json]
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from core.security_rule_engine import SecurityRuleEngine
from core.risk_scoring import compute_risk_report


def main():
    parser = argparse.ArgumentParser(description="AI Code Guardian - secure code scanner")
    parser.add_argument("command", choices=["scan"])
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--out", default="scan_report.json", help="Output report path")
    parser.add_argument("--alignment-score", type=float, default=75.0,
                         help="Business alignment score 0-100 (stub until Business Intent module is wired in)")
    args = parser.parse_args()

    engine = SecurityRuleEngine()
    target = Path(args.path)

    print(f"Scanning {target} ...")
    if target.is_dir():
        result = engine.scan_directory(target)
    else:
        result = engine.scan_file(target)

    risk = compute_risk_report(result, alignment_score=args.alignment_score)

    print(f"\nFiles scanned: {result.files_scanned}")
    print(f"Findings: {len(result.findings)}")
    print(f"By severity: {result.counts_by_severity}")
    print(f"By category: {result.counts_by_category}")
    print(f"\nSecurity Score:        {risk.security_score:.1f}/100")
    print(f"Alignment Score:       {risk.alignment_score:.1f}/100")
    print(f"Maintainability Score: {risk.maintainability_score:.1f}/100")
    print(f"Overall Risk Score:    {risk.overall_risk_score:.1f}/100")
    print(f"Merge Decision:        {risk.merge_decision}")

    out = {"scan": result.to_dict(), "risk": risk.to_dict()}
    Path(args.out).write_text(json.dumps(out, indent=2))
    print(f"\nFull report written to {args.out}")


if __name__ == "__main__":
    main()
