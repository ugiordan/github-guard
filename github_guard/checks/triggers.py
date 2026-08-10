"""Trigger security checks for GitHub Actions workflows."""

from __future__ import annotations

import re

from github_guard.checks._common import _finding, register_check
from github_guard.config import ScannerConfig
from github_guard.parser import GHAWorkflow

_FORK_REF_PATTERNS = [
    "github.event.pull_request.head",
    "github.head_ref",
    "refs/pull/",
]

_CHECKOUT_ACTION = "actions/checkout"


@register_check
def check_prt_fork_checkout(workflow: GHAWorkflow, config: ScannerConfig) -> list[dict]:
    """GHA-TRIG-001: pull_request_target with fork checkout.

    Detects workflows using pull_request_target that check out fork code,
    which can lead to arbitrary code execution with write permissions.
    """
    findings = []
    if "pull_request_target" not in workflow.triggers:
        return findings

    for job_name, job in workflow.jobs.items():
        for step in job.steps:
            if not step.uses:
                continue
            # Extract action name before @
            action_name = step.uses.split("@")[0] if "@" in step.uses else step.uses
            if action_name != _CHECKOUT_ACTION:
                continue

            ref_value = str(step.with_.get("ref", ""))
            if not ref_value:
                # No ref = defaults to base branch, safe
                continue

            for pattern in _FORK_REF_PATTERNS:
                if pattern in ref_value:
                    findings.append(_finding(
                        "GHA-TRIG-001", "CRITICAL",
                        "pull_request_target with fork checkout",
                        workflow, step.line,
                        f"Job '{job_name}' checks out fork code (ref: {ref_value}) "
                        f"in a pull_request_target workflow. This allows arbitrary code "
                        f"execution with write permissions and secrets access.",
                        cwe="CWE-94",
                        remediation=(
                            "Use pull_request trigger instead, or avoid checking out "
                            "fork code. If you must use pull_request_target, run in a "
                            "separate job with no secrets and minimal permissions."
                        ),
                        extra={"job": job_name, "ref": ref_value},
                    ))
                    break  # one finding per step

    return findings


@register_check
def check_unsafe_if_gate(workflow: GHAWorkflow, config: ScannerConfig) -> list[dict]:
    """GHA-TRIG-002: Unsafe if condition as security gate.

    Detects workflows that use github.event.pull_request.head.repo.full_name == github.repository
    as a security gate, which is bypassable via repository renaming.
    """
    findings = []
    bypass_pattern = "github.event.pull_request.head.repo.full_name"
    repo_compare = "github.repository"

    for job_name, job in workflow.jobs.items():
        # Check job-level if
        if bypass_pattern in job.if_condition and repo_compare in job.if_condition:
            # FP guard: only flag if the job uses secrets or GITHUB_TOKEN
            if _job_uses_secrets(job, workflow):
                findings.append(_finding(
                    "GHA-TRIG-002", "HIGH",
                    "Bypassable fork detection via repo name comparison",
                    workflow, job.line,
                    f"Job '{job_name}' uses head.repo.full_name == github.repository as a "
                    f"security gate. An attacker can bypass this by renaming their fork to "
                    f"match the target repository name.",
                    cwe="CWE-290",
                    remediation=(
                        "Use a more robust check such as "
                        "github.event.pull_request.head.repo.fork == true, "
                        "or move sensitive operations to a separate workflow "
                        "triggered by workflow_run."
                    ),
                    extra={"job": job_name},
                ))

        for step in job.steps:
            if bypass_pattern in step.if_condition and repo_compare in step.if_condition:
                if _job_uses_secrets(job, workflow) or _step_uses_secrets(step):
                    findings.append(_finding(
                        "GHA-TRIG-002", "HIGH",
                        "Bypassable fork detection via repo name comparison",
                        workflow, step.line,
                        f"Step '{step.name or '(unnamed)'}' in job '{job_name}' uses "
                        f"head.repo.full_name == github.repository as a security gate. "
                        f"An attacker can bypass this by renaming their fork.",
                        cwe="CWE-290",
                        remediation=(
                            "Use github.event.pull_request.head.repo.fork or "
                            "move to a workflow_run pattern."
                        ),
                        extra={"job": job_name, "step": step.name},
                    ))

    return findings


@register_check
def check_workflow_dispatch_injection(
    workflow: GHAWorkflow, config: ScannerConfig,
) -> list[dict]:
    """GHA-TRIG-003: workflow_dispatch with unvalidated string inputs.

    Detects string inputs from workflow_dispatch that are interpolated
    into run: blocks, which enables command injection.
    """
    findings = []
    dispatch_config = workflow.triggers.get("workflow_dispatch", {})
    if not dispatch_config:
        return findings

    inputs = dispatch_config.get("inputs", {})
    if not isinstance(inputs, dict):
        return findings

    # Find string inputs (type: string or no type specified)
    string_inputs: set[str] = set()
    for input_name, input_config in inputs.items():
        if not isinstance(input_config, dict):
            string_inputs.add(str(input_name))
            continue
        input_type = str(input_config.get("type", "string"))
        if input_type in ("string", ""):
            string_inputs.add(str(input_name))
        # FP guard: skip choice, boolean, environment types

    if not string_inputs:
        return findings

    # Check if any string input is interpolated in run: blocks
    for job_name, job in workflow.jobs.items():
        for step in job.steps:
            if not step.run:
                continue
            for input_name in string_inputs:
                patterns = [
                    f"${{{{ github.event.inputs.{input_name} }}}}",
                    f"${{{{ inputs.{input_name} }}}}",
                ]
                for pat in patterns:
                    if pat in step.run:
                        findings.append(_finding(
                            "GHA-TRIG-003", "MEDIUM",
                            "Unvalidated workflow_dispatch input in shell command",
                            workflow, step.line,
                            f"Input '{input_name}' (type: string) from workflow_dispatch "
                            f"is interpolated into a run: block in job '{job_name}'. "
                            f"An attacker with write access can inject arbitrary shell commands.",
                            cwe="CWE-78",
                            remediation=(
                                "Use an environment variable instead of direct interpolation: "
                                "env: INPUT_VAL: ${{ inputs." + input_name + " }} "
                                "then reference $INPUT_VAL in the script. "
                                "Or use type: choice to restrict allowed values."
                            ),
                            extra={"job": job_name, "input": input_name},
                        ))
                        break  # one finding per input per step

    return findings


def _job_uses_secrets(job, workflow: GHAWorkflow) -> bool:
    """Check if a job or its steps reference secrets or GITHUB_TOKEN."""
    for step in job.steps:
        if _step_uses_secrets(step):
            return True
    return False


def _step_uses_secrets(step) -> bool:
    """Check if a step references secrets or GITHUB_TOKEN."""
    secret_pattern = re.compile(r"\$\{\{\s*secrets\.", re.IGNORECASE)
    token_pattern = re.compile(r"\$\{\{\s*github\.token", re.IGNORECASE)

    text_to_check = [step.run]
    for v in step.env.values():
        text_to_check.append(str(v))
    for v in step.with_.values():
        text_to_check.append(str(v))

    for text in text_to_check:
        if secret_pattern.search(text) or token_pattern.search(text):
            return True
    return False
