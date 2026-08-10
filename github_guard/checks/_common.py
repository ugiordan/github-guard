"""Shared helpers for github-guard checks."""

from __future__ import annotations

from typing import Any, Callable

from github_guard.config import ScannerConfig
from github_guard.parser import GHAWorkflow

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

CheckFn = Callable[[GHAWorkflow, ScannerConfig], list[dict]]
CorrelationCheckFn = Callable[[list[GHAWorkflow], ScannerConfig], list[dict]]

_REGISTRY: list[CheckFn] = []
_CORRELATION_REGISTRY: list[CorrelationCheckFn] = []


def register_check(func: CheckFn) -> CheckFn:
    """Decorator that registers a per-workflow check function."""
    doc = func.__doc__ or ""
    colon_pos = doc.find(":")
    func.check_id = doc[:colon_pos].strip() if colon_pos > 0 else ""  # type: ignore[attr-defined]
    _REGISTRY.append(func)
    return func


def register_correlation_check(func: CorrelationCheckFn) -> CorrelationCheckFn:
    """Decorator that registers a cross-workflow check function."""
    doc = func.__doc__ or ""
    colon_pos = doc.find(":")
    func.check_id = doc[:colon_pos].strip() if colon_pos > 0 else ""  # type: ignore[attr-defined]
    _CORRELATION_REGISTRY.append(func)
    return func


def get_all_checks() -> list[CheckFn]:
    return list(_REGISTRY)


def get_all_correlation_checks() -> list[CorrelationCheckFn]:
    return list(_CORRELATION_REGISTRY)


def _finding(
    rule_id: str,
    severity: str,
    title: str,
    workflow: GHAWorkflow,
    line: int,
    message: str,
    *,
    cwe: str = "",
    remediation: str = "",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    docs_url = f"https://ugiordan.github.io/github-guard/reference/rules/#{rule_id.lower()}"
    result = {
        "rule_id": rule_id,
        "severity": severity,
        "title": title,
        "file": workflow.file_path,
        "line_start": line,
        "line_end": line,
        "message": message,
        "cwe": cwe,
        "remediation": remediation,
        "docs_url": docs_url,
    }
    if extra:
        _RESERVED = {
            "rule_id", "severity", "title", "file", "line_start",
            "line_end", "message", "cwe", "remediation", "docs_url",
        }
        safe = {k: v for k, v in extra.items() if k not in _RESERVED}
        result.update(safe)
    return result
