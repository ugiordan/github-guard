"""Check registry with explicit imports (PyInstaller-compatible)."""

from __future__ import annotations

import logging
from typing import Any

from github_guard.checks._common import (
    SEVERITY_ORDER,
    get_all_checks,
    get_all_correlation_checks,
)
from github_guard.checks import triggers  # noqa: F401
from github_guard.checks import permissions  # noqa: F401
from github_guard.checks import pinning  # noqa: F401
from github_guard.checks import secrets  # noqa: F401
from github_guard.checks import runners  # noqa: F401
from github_guard.checks import flow  # noqa: F401
from github_guard.config import ScannerConfig
from github_guard.parser import GHAWorkflow

logger = logging.getLogger(__name__)

_EXPECTED_MIN_CHECKS = 16

_loaded = get_all_checks()
_correlation_loaded = get_all_correlation_checks()
_total = len(_loaded) + len(_correlation_loaded)
if _total < _EXPECTED_MIN_CHECKS:
    logger.warning(
        "Expected at least %d checks but only %d registered. "
        "Some check modules may have failed to import.",
        _EXPECTED_MIN_CHECKS, _total,
    )


def run_checks(
    workflows: list[GHAWorkflow],
    config: ScannerConfig,
) -> list[dict[str, Any]]:
    """Run all registered checks against all workflows."""
    min_sev = SEVERITY_ORDER.get(config.min_severity.upper(), 0)
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int, str]] = set()

    all_checks = get_all_checks()
    for workflow in workflows:
        for check_fn in all_checks:
            check_id = getattr(check_fn, "check_id", "")
            if check_id and not config.should_run_check(check_id):
                continue
            for f in check_fn(workflow, config):
                if SEVERITY_ORDER.get(f["severity"], 0) < min_sev:
                    continue
                dedup_key = (
                    f["rule_id"], f["file"],
                    f.get("line_start", 0), f.get("title", ""),
                )
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                findings.append(f)

    # Correlation checks operate across all workflows
    for check_fn in get_all_correlation_checks():
        check_id = getattr(check_fn, "check_id", "")
        if check_id and not config.should_run_check(check_id):
            continue
        for f in check_fn(workflows, config):
            if SEVERITY_ORDER.get(f["severity"], 0) < min_sev:
                continue
            dedup_key = (
                f["rule_id"], f["file"],
                f.get("line_start", 0), f.get("title", ""),
            )
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            findings.append(f)

    return findings
