"""
AI Code Guardian 2.0 — CLI
Usage:
    python -m guardian scan <path> [--format json sarif html] [--out-dir reports/]
                                   [--config config/default.yaml]
                                   [--alignment-score 75]
                                   [--fail-on-severity High]
    python -m guardian detect <path>          # repository profile only
    python -m guardian intent <path>          # business-domain verdict only
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SEVERITY_ORDER = ["Info", "Low", "Medium", "High", "Critical"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="guardian", description="AI Code Guardian 2.0")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Full pipeline scan")
    p_scan.add_argument("path")
    p_scan.add_argument("--format", nargs="+", default=["json"],
                        choices=["json", "sarif", "html", "csv", "pdf"])
    p_scan.add_argument("--out-dir", default=".")
    p_scan.add_argument("--config", default=None)
    p_scan.add_argument("--alignment-score", type=float, default=None)
    p_scan.add_argument("--fail-on-severity", default=None,
                        choices=SEVERITY_ORDER[1:])

    for name in ("detect", "intent"):
        p = sub.add_parser(name)
        p.add_argument("path")

    args = parser.parse_args(argv)

    from guardian.config import GuardianConfig
    from guardian.core.registry import load_builtin_plugins

    from guardian.discovery.github_service import is_github_url, GitHubService
    target_path = GitHubService().fetch_repository(args.path) if is_github_url(args.path) else Path(args.path)

    if args.command == "detect":
        from guardian.discovery.file_walker import FileWalker
        from guardian.discovery.repo_detector import RepositoryDetector
        cfg = GuardianConfig.load()
        files = list(FileWalker(cfg).walk(target_path))
        profile = RepositoryDetector().detect(target_path, files)
        print(json.dumps(profile.to_dict(), indent=2))
        return 0

    if args.command == "intent":
        from guardian.intent.classifier import DomainClassifier
        verdict = DomainClassifier().classify(target_path)
        print(json.dumps(verdict.to_dict(), indent=2))
        return 0

    # ---- scan --------------------------------------------------------
    cfg = GuardianConfig.load(args.config, fail_on_severity=args.fail_on_severity)
    registry = load_builtin_plugins()
    from guardian.core.pipeline import ScanPipeline

    pipeline = ScanPipeline(cfg, registry)
    print(f"Scanning {args.path} ...")
    report = pipeline.scan(args.path, alignment_score=args.alignment_score)

    scan, risk = report["scan"], report["risk"]
    repo = report["repository"]
    print(f"\nRepository:   {repo['primary_language']} "
          f"{'/'.join(repo['architecture'])} "
          f"[{', '.join(repo['frameworks']) or 'no framework detected'}]")
    if report.get("business_domain"):
        bd = report["business_domain"]
        print(f"Domain:       {bd['domain']} ({bd['confidence']:.0%} confidence)")
    print(f"Files:        {scan['files_scanned']} source scanned "
          f"({report['discovery']['infrastructure_files']} infra, "
          f"{report['discovery']['manifest_files']} manifests)")
    print(f"Findings:     {scan['total_findings']}  {scan['by_severity']}")
    print(f"Security:     {risk['security_score']:.1f}/100")
    print(f"Alignment:    {risk['alignment_score']:.1f}/100")
    print(f"Overall risk: {risk['overall_risk_score']:.1f}/100")
    print(f"Decision:     {risk['merge_decision']}")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    for fmt in args.format:
        reporter = registry.reporter(fmt)
        if reporter is None:
            print(f"  ! no reporter registered for {fmt}", file=sys.stderr)
            continue
        out = out_dir / f"guardian_report{reporter.file_extension}"
        out.write_text(reporter.render(report))
        print(f"Report:       {out}")

    # CI gate
    if cfg.fail_on_severity:
        threshold = SEVERITY_ORDER.index(cfg.fail_on_severity)
        worst = max((SEVERITY_ORDER.index(s) for s in scan["by_severity"]
                     if s in SEVERITY_ORDER), default=-1)
        if worst >= threshold:
            print(f"\nFAIL: findings at or above {cfg.fail_on_severity} severity.")
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
