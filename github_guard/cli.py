"""CLI entry point for GitHub Actions scanner."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from github_guard.checks import run_checks, SEVERITY_ORDER
from github_guard.config import load_config
from github_guard.formatter import format_json, format_sarif, format_text
from github_guard.parser import parse_directory, parse_workflow


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="github-guard",
        description="Security scanner for GitHub Actions workflows",
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Path to a repo directory (scans .github/workflows/) or a single YAML file",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["json", "sarif", "text"],
        default="json",
        dest="output_format",
        help="Output format (default: json)",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output file (default: stdout)",
    )
    parser.add_argument(
        "--config", "-c",
        default=None,
        help="Config file with trust lists and check settings",
    )
    parser.add_argument(
        "--min-severity",
        default=None,
        choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        help="Minimum severity to report (overrides config)",
    )
    parser.add_argument(
        "--fail-on",
        default=None,
        choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        help="Exit 1 only if findings at or above this severity (default: any finding)",
    )
    parser.add_argument(
        "--exit-zero",
        action="store_true",
        default=False,
        help="Always exit 0 regardless of findings (for informational runs)",
    )
    parser.add_argument(
        "--baseline",
        default=None,
        help="Baseline file to suppress known findings (.github-guard-baseline.json)",
    )
    parser.add_argument(
        "--update-baseline",
        default=None,
        help="Write current findings as a new baseline file",
    )
    parser.add_argument(
        "--explain",
        default=None,
        metavar="RULE_ID",
        help="Show detailed information about a specific check rule",
    )

    args = parser.parse_args(argv)

    if args.explain:
        from github_guard.checks._common import get_all_checks
        rule = args.explain.upper()
        for check_fn in get_all_checks():
            check_id = getattr(check_fn, "check_id", "")
            if check_id == rule:
                doc = check_fn.__doc__ or ""
                print(f"\n{check_id}: {doc.split(':', 1)[1].strip() if ':' in doc else doc}")
                print(f"\nDocs: https://ugiordan.github.io/github-guard/reference/rules/#{rule.lower()}")
                return 0
        print(f"Unknown rule: {rule}", file=sys.stderr)
        return 2

    if not args.target:
        parser.error("the following arguments are required: target")

    config = load_config(args.config)
    if args.min_severity:
        config.min_severity = args.min_severity

    target = Path(args.target)
    if target.is_file():
        wf = parse_workflow(str(target))
        workflows = [wf] if wf else []
    elif target.is_dir():
        workflows = parse_directory(str(target))
    else:
        print(f"Error: '{args.target}' is not a valid file or directory", file=sys.stderr)
        return 2

    if not workflows:
        print("No workflows found to scan", file=sys.stderr)

    findings = run_checks(workflows, config)

    if args.baseline:
        import hashlib
        from datetime import datetime, timezone

        baseline_path = Path(args.baseline)
        if baseline_path.exists():
            baseline_data = json.loads(baseline_path.read_text())
            baseline_keys: set[tuple[str, str, str]] = set()
            now = datetime.now(timezone.utc)
            expired_count = 0
            for entry in baseline_data.get("findings", []):
                if not isinstance(entry, dict):
                    continue
                rule_id = entry.get("rule_id", "")
                if not rule_id:
                    print("Baseline: rejecting entry without rule_id", file=sys.stderr)
                    continue
                if not entry.get("reason"):
                    print(
                        f"Baseline: rejecting entry without reason "
                        f"(rule: {rule_id}, file: {entry.get('file')})",
                        file=sys.stderr,
                    )
                    continue
                expires = entry.get("expires")
                if expires:
                    try:
                        exp_dt = datetime.fromisoformat(expires)
                        if exp_dt.tzinfo is None:
                            exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                        if exp_dt < now:
                            expired_count += 1
                            continue
                    except (ValueError, TypeError):
                        pass
                key = (rule_id, entry.get("file", ""), entry.get("content_hash", ""))
                baseline_keys.add(key)
            if expired_count:
                print(f"Baseline: {expired_count} expired entry(ies) ignored", file=sys.stderr)
            original_count = len(findings)
            findings = [f for f in findings if (
                f["rule_id"], f["file"],
                hashlib.sha256(
                    f"{f.get('rule_id', '')}:{f.get('message', '')}".encode()
                ).hexdigest()[:16],
            ) not in baseline_keys]
            suppressed = original_count - len(findings)
            if suppressed:
                print(f"Baseline: suppressed {suppressed} known finding(s)", file=sys.stderr)

    if args.update_baseline:
        import hashlib
        from datetime import datetime, timezone

        baseline = {
            "version": "1.0",
            "generated": datetime.now(timezone.utc).isoformat(),
            "findings": [],
        }
        for f in findings:
            hash_input = f"{f.get('rule_id', '')}:{f.get('message', '')}"
            content_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:16]
            baseline["findings"].append({
                "rule_id": f["rule_id"],
                "file": f["file"],
                "content_hash": content_hash,
                "line_hint": f.get("line_start", 0),
                "reason": "Accepted via --update-baseline",
            })
        Path(args.update_baseline).write_text(json.dumps(baseline, indent=2))
        print(
            f"Baseline written: {len(baseline['findings'])} finding(s) "
            f"to {args.update_baseline}",
            file=sys.stderr,
        )

    if args.output_format == "json":
        output = format_json(findings, str(target))
    elif args.output_format == "sarif":
        output = format_sarif(findings, str(target))
    else:
        output = format_text(findings, str(target))

    if args.output:
        Path(args.output).write_text(output)
    else:
        print(output)

    if args.exit_zero:
        return 0

    if not findings:
        return 0

    if args.fail_on:
        threshold = SEVERITY_ORDER.get(args.fail_on, 0)
        if any(SEVERITY_ORDER.get(f["severity"], 0) >= threshold for f in findings):
            return 1
        return 0

    return 1
