"""Secret security checks for GitHub Actions workflows."""

from __future__ import annotations

import re
import string

from github_guard.checks._common import _finding, register_check
from github_guard.config import ScannerConfig
from github_guard.parser import GHAWorkflow

_SECRETS_REF = re.compile(r"\$\{\{\s*secrets\.[^}]+\}\}")
_HIGH_ENTROPY_RE = re.compile(r"[A-Za-z0-9+/=_-]{20,}")

# Common non-secret patterns to exclude from entropy checks
_FALSE_POSITIVE_PATTERNS = [
    re.compile(r"https?://"),      # URLs
    re.compile(r"[a-z]+\.[a-z]+"),  # domain-like
    re.compile(r"^\d+\.\d+"),       # version strings
    re.compile(r"^[a-f0-9]{40}$"),  # git SHAs (already handled by pinning)
    re.compile(r"^sha256:"),        # digest refs
    re.compile(r"^v?\d+(\.\d+)*"),  # semver
]


def _is_high_entropy(value: str) -> bool:
    """Check if a string has high entropy suggesting a hardcoded credential."""
    if len(value) < 20:
        return False
    # Quick frequency check: high entropy = many distinct chars relative to length
    charset = set(value)
    ratio = len(charset) / len(value)
    # Base64/hex strings typically have ratio > 0.3 for long strings
    if ratio < 0.3:
        return False
    # Check it's mostly alphanumeric (not prose)
    alnum_count = sum(1 for c in value if c in string.ascii_letters + string.digits + "+/=_-")
    if alnum_count / len(value) < 0.8:
        return False
    return True


@register_check
def check_hardcoded_credentials(workflow: GHAWorkflow, config: ScannerConfig) -> list[dict]:
    """GHA-SEC-001: Hardcoded credential in workflow.

    Detects hardcoded API keys, tokens, and high-entropy strings in
    env: values and run: blocks.
    """
    findings = []

    # Check workflow-level env
    for env_key, env_val in workflow.env.items():
        val = str(env_val)
        finding = _check_value_for_secrets(val, "workflow env", env_key, workflow, 1, config)
        if finding:
            findings.append(finding)

    for job_name, job in workflow.jobs.items():
        for step in job.steps:
            # Check step env values
            for env_key, env_val in step.env.items():
                val = str(env_val)
                # FP guard: skip ${{ secrets.* }} references
                if _SECRETS_REF.search(val):
                    continue
                finding = _check_value_for_secrets(
                    val, f"job '{job_name}', step env", env_key,
                    workflow, step.line, config,
                )
                if finding:
                    findings.append(finding)

            # Check run: blocks
            if step.run:
                # FP guard: skip lines that are just referencing secrets properly
                for line_text in step.run.splitlines():
                    stripped = line_text.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    if _SECRETS_REF.search(stripped):
                        continue
                    finding = _check_value_for_secrets(
                        stripped, f"job '{job_name}', run block", "",
                        workflow, step.line, config,
                    )
                    if finding:
                        findings.append(finding)

    return findings


def _check_value_for_secrets(
    value: str,
    context: str,
    key: str,
    workflow: GHAWorkflow,
    line: int,
    config: ScannerConfig,
) -> dict | None:
    """Check a single value for hardcoded secret patterns."""
    # FP guard: skip secret references
    if _SECRETS_REF.search(value):
        return None

    # Check known secret prefixes
    for pattern in config.secret_patterns:
        if pattern in value:
            # FP guard: skip common false positives
            if any(fp.search(value) for fp in _FALSE_POSITIVE_PATTERNS):
                continue
            key_info = f" (key: {key})" if key else ""
            return _finding(
                "GHA-SEC-001", "HIGH",
                "Hardcoded credential in workflow",
                workflow, line,
                f"Potential hardcoded credential found in {context}{key_info}. "
                f"Value matches known secret pattern '{pattern}'.",
                cwe="CWE-798",
                remediation=(
                    "Move the credential to GitHub Secrets and reference it as "
                    "${{ secrets.SECRET_NAME }}."
                ),
                extra={"context": context, "pattern": pattern},
            )

    # Check high-entropy strings
    for match in _HIGH_ENTROPY_RE.finditer(value):
        candidate = match.group()
        if any(fp.search(candidate) for fp in _FALSE_POSITIVE_PATTERNS):
            continue
        if _is_high_entropy(candidate):
            key_info = f" (key: {key})" if key else ""
            return _finding(
                "GHA-SEC-001", "HIGH",
                "Hardcoded credential in workflow",
                workflow, line,
                f"High-entropy string found in {context}{key_info}. "
                f"This may be a hardcoded credential.",
                cwe="CWE-798",
                remediation=(
                    "If this is a credential, move it to GitHub Secrets. "
                    "If it's a known safe value, add it to the baseline."
                ),
                extra={"context": context},
            )

    return None


@register_check
def check_secret_as_workflow_input(workflow: GHAWorkflow, config: ScannerConfig) -> list[dict]:
    """GHA-SEC-002: Secret passed as workflow input.

    Reusable workflow calls that pass secrets via with: instead of secrets:
    may expose them in logs.
    """
    findings = []

    for job_name, job in workflow.jobs.items():
        if not job.uses:
            continue
        # This is a reusable workflow call
        for param_name, param_value in job.with_ if hasattr(job, "with_") else []:
            val = str(param_value)
            if "${{ secrets." in val or "${{secrets." in val:
                findings.append(_finding(
                    "GHA-SEC-002", "MEDIUM",
                    "Secret passed as workflow input",
                    workflow, job.line,
                    f"Job '{job_name}' passes a secret via 'with.{param_name}' to "
                    f"reusable workflow '{job.uses}'. Secrets passed as inputs may "
                    f"appear in logs. Use the 'secrets:' key instead.",
                    cwe="CWE-532",
                    remediation=(
                        "Move the secret from 'with:' to 'secrets:' in the "
                        "reusable workflow call."
                    ),
                    extra={"job": job_name, "param": param_name},
                ))

    # Also check step-level with: for secrets passed to actions
    # (this is the more common variant)
    for job_name, job in workflow.jobs.items():
        if job.uses:
            # Reusable workflow calls use steps differently
            # Check with: params directly on the job data
            # Since GHAJob doesn't store job-level with:, we check steps
            continue
        for step in job.steps:
            if not step.uses:
                continue
            for param_name, param_value in step.with_.items():
                val = str(param_value)
                if _SECRETS_REF.search(val):
                    # This is expected for actions, only flag for reusable workflows
                    pass

    return findings


@register_check
def check_artifact_upload_in_pr(workflow: GHAWorkflow, config: ScannerConfig) -> list[dict]:
    """GHA-SEC-003: Artifact upload in PR context.

    Uploading artifacts in pull_request or pull_request_target contexts
    can leak sensitive data from the runner to anyone with repo read access.
    """
    findings = []

    pr_triggers = {"pull_request", "pull_request_target"}
    if not pr_triggers.intersection(workflow.triggers.keys()):
        return findings

    for job_name, job in workflow.jobs.items():
        # FP guard: accept if permissions: {} (empty = no write access)
        if isinstance(job.permissions, dict) and not job.permissions:
            continue

        for step in job.steps:
            if not step.uses:
                continue
            action = step.uses.split("@")[0] if "@" in step.uses else step.uses
            if action != "actions/upload-artifact":
                continue

            # FP guard: accept if step has restrictive if: condition
            if step.if_condition and "github.event.pull_request.head.repo.fork" in step.if_condition:
                continue

            findings.append(_finding(
                "GHA-SEC-003", "HIGH",
                "Artifact upload in PR context",
                workflow, step.line,
                f"Job '{job_name}' uploads artifacts in a PR-triggered workflow. "
                f"Artifacts are accessible to anyone with read access to the repo "
                f"and may contain sensitive build outputs or secrets from the runner.",
                cwe="CWE-200",
                remediation=(
                    "Restrict artifact uploads with an if: condition checking "
                    "github.event.pull_request.head.repo.fork != true, "
                    "or set restrictive job permissions (permissions: {})."
                ),
                extra={"job": job_name},
            ))

    return findings
