"""Runner security checks for GitHub Actions workflows."""

from __future__ import annotations

from github_guard.checks._common import _finding, register_check
from github_guard.config import ScannerConfig
from github_guard.parser import GHAWorkflow

# Triggers that can be activated by external users (PRs, issues, comments)
_EXTERNAL_TRIGGERS = {
    "pull_request", "pull_request_target", "pull_request_review",
    "pull_request_review_comment", "issue_comment", "issues",
    "discussion", "discussion_comment", "fork", "watch",
}

# Triggers that are trusted (only repo maintainers/scheduled)
_TRUSTED_TRIGGERS = {
    "schedule", "push", "workflow_dispatch", "workflow_call",
}


@register_check
def check_self_hosted_without_protection(
    workflow: GHAWorkflow, config: ScannerConfig,
) -> list[dict]:
    """GHA-RUN-001: Self-hosted runner without environment protection.

    Self-hosted runners triggered by external events without environment
    protection can be used by attackers to run arbitrary code on your infra.
    """
    findings = []

    # FP guard: only flag for externally-triggerable workflows
    trigger_keys = set(workflow.triggers.keys())
    if not trigger_keys.intersection(_EXTERNAL_TRIGGERS):
        return findings

    for job_name, job in workflow.jobs.items():
        if not job.runs_on:
            continue

        # Check if runner is self-hosted (not matching GitHub-hosted patterns)
        runs_on_values = [v.strip() for v in job.runs_on.split(",")]
        is_self_hosted = False
        for val in runs_on_values:
            if val == "self-hosted":
                is_self_hosted = True
                break
            if not config.is_github_hosted(val):
                is_self_hosted = True
                break

        if not is_self_hosted:
            continue

        # Check for environment protection gate
        if job.environment:
            continue

        findings.append(_finding(
            "GHA-RUN-001", "HIGH",
            "Self-hosted runner without environment protection",
            workflow, job.line,
            f"Job '{job_name}' runs on self-hosted runner ({job.runs_on}) "
            f"in an externally-triggerable workflow without environment protection. "
            f"An attacker can submit a PR to execute arbitrary code on your runner.",
            cwe="CWE-284",
            remediation=(
                "Add an 'environment:' gate that requires approval, "
                "or switch to GitHub-hosted runners for untrusted workloads."
            ),
            extra={"job": job_name, "runs_on": job.runs_on},
        ))

    return findings


@register_check
def check_job_without_timeout(workflow: GHAWorkflow, config: ScannerConfig) -> list[dict]:
    """GHA-RUN-002: Job without timeout.

    Jobs without timeout-minutes can run indefinitely, wasting resources
    or being abused for crypto mining.
    """
    findings = []

    # FP guard: skip trusted-only triggers
    trigger_keys = set(workflow.triggers.keys())
    if trigger_keys and trigger_keys.issubset(_TRUSTED_TRIGGERS):
        return findings

    for job_name, job in workflow.jobs.items():
        # Skip reusable workflow calls (no steps to run)
        if job.uses and not job.steps:
            continue

        if job.timeout_minutes is None:
            findings.append(_finding(
                "GHA-RUN-002", "LOW",
                "Job without timeout",
                workflow, job.line,
                f"Job '{job_name}' does not set timeout-minutes. "
                f"Without a timeout, the job can run up to the platform maximum "
                f"(6 hours for GitHub-hosted, 5 days for self-hosted), "
                f"wasting compute resources.",
                cwe="CWE-400",
                remediation=(
                    "Add 'timeout-minutes: 30' (or an appropriate value) to the job."
                ),
                extra={"job": job_name},
            ))

    return findings
