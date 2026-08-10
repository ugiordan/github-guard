"""Cross-workflow flow security checks for GitHub Actions workflows."""

from __future__ import annotations

from github_guard.checks._common import (
    _finding,
    register_check,
    register_correlation_check,
)
from github_guard.config import ScannerConfig
from github_guard.parser import GHAWorkflow

_FORK_TRIGGERABLE = {"pull_request", "pull_request_target"}


@register_correlation_check
def check_workflow_run_from_fork_triggerable(
    workflows: list[GHAWorkflow], config: ScannerConfig,
) -> list[dict]:
    """GHA-FLOW-001: workflow_run triggered by fork-triggerable workflow.

    A workflow_run workflow inherits some context from the triggering workflow.
    If the trigger workflow is fork-triggerable, an attacker can influence
    the workflow_run workflow via crafted PR data.
    """
    findings = []

    # Build a map of workflow name -> triggers
    name_to_triggers: dict[str, set[str]] = {}
    for wf in workflows:
        if wf.name:
            name_to_triggers[wf.name] = set(wf.triggers.keys())

    for wf in workflows:
        wf_run_config = wf.triggers.get("workflow_run", {})
        if not wf_run_config:
            continue

        referenced_names = wf_run_config.get("workflows", [])
        if isinstance(referenced_names, str):
            referenced_names = [referenced_names]

        for ref_name in referenced_names:
            ref_name = str(ref_name)
            ref_triggers = name_to_triggers.get(ref_name, set())

            # FP guard: skip if referenced workflow name doesn't match any file
            if not ref_triggers:
                continue

            if ref_triggers.intersection(_FORK_TRIGGERABLE):
                findings.append(_finding(
                    "GHA-FLOW-001", "MEDIUM",
                    "workflow_run triggered by fork-triggerable workflow",
                    wf, 1,
                    f"This workflow is triggered by workflow_run from '{ref_name}', "
                    f"which is fork-triggerable ({ref_triggers.intersection(_FORK_TRIGGERABLE)}). "
                    f"An attacker can craft PR metadata to influence this workflow's behavior.",
                    cwe="CWE-94",
                    remediation=(
                        "Validate all data from github.event.workflow_run before use. "
                        "Do not check out code from the triggering PR without sanitization."
                    ),
                    extra={"referenced_workflow": ref_name},
                ))

    return findings


@register_check
def check_composite_action_unpinned(
    workflow: GHAWorkflow, config: ScannerConfig,
) -> list[dict]:
    """GHA-FLOW-002: Composite action with unpinned refs.

    Composite actions (action.yml) that use unpinned action references
    inherit the same supply chain risks as workflows.
    """
    findings = []

    # Only check composite actions
    if "composite_action" not in workflow.triggers:
        return findings

    import re
    sha_pattern = re.compile(r"^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")

    for job_name, job in workflow.jobs.items():
        for step in job.steps:
            if not step.uses:
                continue

            uses = step.uses

            # FP guard: skip local (./) refs
            if uses.startswith("./") or uses.startswith("docker://"):
                continue

            if "@" not in uses:
                findings.append(_finding(
                    "GHA-FLOW-002", "MEDIUM",
                    "Composite action with unpinned refs",
                    workflow, step.line,
                    f"Composite action uses '{uses}' without a version ref. "
                    f"Pin to a full commit SHA.",
                    cwe="CWE-829",
                    remediation=f"Pin '{uses}' to a specific commit SHA.",
                ))
                continue

            action_ref = uses.split("@", 1)[1]
            if not sha_pattern.match(action_ref):
                findings.append(_finding(
                    "GHA-FLOW-002", "MEDIUM",
                    "Composite action with unpinned refs",
                    workflow, step.line,
                    f"Composite action uses '{uses}' with mutable ref '{action_ref}'. "
                    f"Pin to a full commit SHA for supply chain security.",
                    cwe="CWE-829",
                    remediation=(
                        f"Pin '{uses.split('@')[0]}' to a specific commit SHA "
                        f"instead of '{action_ref}'."
                    ),
                ))

    return findings


@register_check
def check_secrets_inherit(workflow: GHAWorkflow, config: ScannerConfig) -> list[dict]:
    """GHA-FLOW-003: Reusable workflow with secrets:inherit.

    Using secrets:inherit passes ALL repository secrets to the called workflow,
    violating least-privilege for external workflow refs.
    """
    findings = []

    for job_name, job in workflow.jobs.items():
        if not job.uses:
            continue

        if job.secrets != "inherit":
            continue

        # FP guard: only flag for external refs (not ./ local)
        if job.uses.startswith("./"):
            continue

        findings.append(_finding(
            "GHA-FLOW-003", "MEDIUM",
            "Reusable workflow with secrets:inherit",
            workflow, job.line,
            f"Job '{job_name}' calls reusable workflow '{job.uses}' with "
            f"secrets:inherit, passing ALL repository secrets. If the called "
            f"workflow is compromised, all secrets are exposed.",
            cwe="CWE-250",
            remediation=(
                "Explicitly pass only the secrets needed: "
                "secrets: { MY_SECRET: ${{ secrets.MY_SECRET }} } "
                "instead of secrets: inherit."
            ),
            extra={"job": job_name, "called_workflow": job.uses},
        ))

    return findings
