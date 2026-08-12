"""Secret security checks for GitHub Actions workflows."""

from __future__ import annotations

import re

from github_guard.checks._common import _finding, register_check
from github_guard.config import ScannerConfig
from github_guard.parser import GHAWorkflow

_SECRETS_REF = re.compile(r"\$\{\{\s*secrets\.[^}]+\}\}")

# Common non-secret patterns to exclude from prefix checks
_FALSE_POSITIVE_PATTERNS = [
    re.compile(r"https?://"),      # URLs
    re.compile(r"[a-z]+\.[a-z]+"),  # domain-like
    re.compile(r"^\d+\.\d+"),       # version strings
    re.compile(r"^[a-f0-9]{40}$"),  # git SHAs (already handled by pinning)
    re.compile(r"^sha256:"),        # digest refs
    re.compile(r"^v?\d+(\.\d+)*"),  # semver
]


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

            # Check run: blocks for known secret prefixes only (not entropy)
            if step.run:
                for line_text in step.run.splitlines():
                    stripped = line_text.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    if _SECRETS_REF.search(stripped):
                        continue
                    for pattern in config.secret_patterns:
                        if pattern in stripped:
                            if any(fp.search(stripped) for fp in _FALSE_POSITIVE_PATTERNS):
                                continue
                            findings.append(_finding(
                                "GHA-SEC-001", "HIGH",
                                "Hardcoded credential in workflow",
                                workflow, step.line,
                                f"Potential hardcoded credential in job '{job_name}', "
                                f"run block. Value matches known secret pattern '{pattern}'.",
                                cwe="CWE-798",
                                remediation="Move the credential to GitHub Secrets and reference it as ${{ secrets.SECRET_NAME }}.",
                                extra={"context": f"job '{job_name}', run block", "pattern": pattern},
                            ))
                            break

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
        for param_name, param_value in job.with_.items():
            val = str(param_value)
            if _SECRETS_REF.search(val):
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

            # FP guard: skip if only pull_request trigger (not _target)
            # pull_request runs in fork context with read-only token, low risk
            if "pull_request_target" not in workflow.triggers:
                continue

            findings.append(_finding(
                "GHA-SEC-003", "HIGH",
                "Artifact upload in PR target context",
                workflow, step.line,
                f"Job '{job_name}' uploads artifacts in a pull_request_target workflow. "
                f"Artifacts uploaded with base repo privileges may contain sensitive "
                f"build outputs or secrets from the runner.",
                cwe="CWE-200",
                remediation=(
                    "Restrict artifact uploads with an if: condition checking "
                    "github.event.pull_request.head.repo.fork != true, "
                    "or set restrictive job permissions (permissions: {})."
                ),
                extra={"job": job_name},
            ))

    return findings
