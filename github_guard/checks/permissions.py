"""Permission security checks for GitHub Actions workflows."""

from __future__ import annotations

from github_guard.checks._common import _finding, register_check
from github_guard.config import ScannerConfig
from github_guard.parser import GHAWorkflow


@register_check
def check_missing_permissions(workflow: GHAWorkflow, config: ScannerConfig) -> list[dict]:
    """GHA-PERM-001: Missing permissions block.

    Workflows without explicit permissions run with the default token permissions,
    which may include write access to contents, packages, and more.
    """
    findings = []

    # FP guard: skip workflow_call-only workflows (they inherit caller permissions)
    trigger_keys = set(workflow.triggers.keys())
    if trigger_keys == {"workflow_call"} or trigger_keys == {"composite_action"}:
        return findings

    has_top_level = workflow.permissions is not None
    all_jobs_have_perms = all(
        job.permissions is not None for job in workflow.jobs.values()
    )

    if not has_top_level and not all_jobs_have_perms:
        findings.append(_finding(
            "GHA-PERM-001", "HIGH",
            "Missing permissions block",
            workflow, 1,
            "Workflow has no top-level permissions and not all jobs define permissions. "
            "Without explicit permissions, the GITHUB_TOKEN gets broad default access "
            "including write to contents, packages, and pull-requests.",
            cwe="CWE-250",
            remediation=(
                "Add a top-level 'permissions: {}' to restrict to read-only by default, "
                "then grant specific permissions per job as needed."
            ),
        ))

    # Check for write-all at top level
    if workflow.permissions == "write-all":
        findings.append(_finding(
            "GHA-PERM-001", "HIGH",
            "Overly permissive write-all permissions",
            workflow, 1,
            "Workflow uses 'permissions: write-all', granting full write access "
            "to all scopes. This violates least-privilege and expands the blast "
            "radius if the workflow is compromised.",
            cwe="CWE-250",
            remediation=(
                "Replace 'permissions: write-all' with explicit per-scope permissions "
                "(e.g., contents: write) to follow least-privilege."
            ),
        ))

    # Check for write-all at job level
    for job_name, job in workflow.jobs.items():
        if job.permissions == "write-all":
            findings.append(_finding(
                "GHA-PERM-001", "HIGH",
                "Overly permissive write-all permissions",
                workflow, job.line,
                f"Job '{job_name}' uses 'permissions: write-all', granting full write "
                f"access to all scopes.",
                cwe="CWE-250",
                remediation=(
                    "Replace 'permissions: write-all' with explicit per-scope permissions."
                ),
                extra={"job": job_name},
            ))

    return findings


@register_check
def check_oidc_without_consumer(workflow: GHAWorkflow, config: ScannerConfig) -> list[dict]:
    """GHA-PERM-002: id-token:write without audience restriction.

    Granting id-token:write allows OIDC token minting, but without a known
    OIDC consumer action, the token may be misused or is unnecessary.
    """
    findings = []

    def _has_oidc_write(perms) -> bool:
        if isinstance(perms, dict):
            return perms.get("id-token") == "write"
        return False

    def _job_has_oidc_consumer(job) -> bool:
        for step in job.steps:
            if not step.uses:
                continue
            action = step.uses.split("@")[0] if "@" in step.uses else step.uses
            if action in config.known_oidc_actions:
                return True
        return False

    # Check top-level permissions
    if _has_oidc_write(workflow.permissions):
        # Check if any job has a known OIDC consumer
        any_consumer = any(
            _job_has_oidc_consumer(job) for job in workflow.jobs.values()
        )
        if not any_consumer:
            findings.append(_finding(
                "GHA-PERM-002", "MEDIUM",
                "id-token:write without OIDC consumer",
                workflow, 1,
                "Top-level permissions grant id-token:write but no job uses a known "
                "OIDC consumer action. The OIDC token may be unnecessary or could "
                "be used to impersonate the workflow.",
                cwe="CWE-250",
                remediation=(
                    "Remove id-token:write if not needed, or ensure it is consumed "
                    "by a known OIDC action (e.g., aws-actions/configure-aws-credentials)."
                ),
            ))

    # Check per-job permissions
    for job_name, job in workflow.jobs.items():
        if _has_oidc_write(job.permissions) and not _job_has_oidc_consumer(job):
            findings.append(_finding(
                "GHA-PERM-002", "MEDIUM",
                "id-token:write without OIDC consumer",
                workflow, job.line,
                f"Job '{job_name}' grants id-token:write but does not use a known "
                f"OIDC consumer action.",
                cwe="CWE-250",
                remediation=(
                    "Remove id-token:write from job permissions if not needed."
                ),
                extra={"job": job_name},
            ))

    return findings
