"""Pinning security checks for GitHub Actions workflows."""

from __future__ import annotations

import re

from github_guard.checks._common import _finding, register_check
from github_guard.config import ScannerConfig
from github_guard.parser import GHAWorkflow

_SHA_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")


def _is_pinned_ref(ref: str) -> bool:
    """Check if a ref is a SHA (40 or 64 hex chars)."""
    return bool(_SHA_PATTERN.match(ref))


@register_check
def check_unpinned_action(workflow: GHAWorkflow, config: ScannerConfig) -> list[dict]:
    """GHA-PIN-001: Unpinned action reference.

    Actions referenced by mutable tags (v1, main, latest) can be silently
    replaced with malicious code via tag overwriting.
    """
    findings = []

    for job_name, job in workflow.jobs.items():
        for step in job.steps:
            if not step.uses:
                continue

            uses = step.uses

            # FP guard: skip local (./) and docker:// refs
            if uses.startswith("./") or uses.startswith("docker://"):
                continue

            if "@" not in uses:
                findings.append(_finding(
                    "GHA-PIN-001", "MEDIUM",
                    "Unpinned action reference",
                    workflow, step.line,
                    f"Action '{uses}' in job '{job_name}' has no version ref. "
                    f"Pin to a full commit SHA for supply chain security.",
                    cwe="CWE-829",
                    remediation=f"Pin '{uses}' to a specific commit SHA: {uses}@<sha>",
                    extra={"job": job_name, "action": uses},
                ))
                continue

            action_ref = uses.split("@", 1)[1]
            if not _is_pinned_ref(action_ref):
                action_name = uses.split("@", 1)[0]
                findings.append(_finding(
                    "GHA-PIN-001", "MEDIUM",
                    "Unpinned action reference",
                    workflow, step.line,
                    f"Action '{uses}' in job '{job_name}' uses mutable ref '{action_ref}'. "
                    f"Tags can be overwritten; pin to a full commit SHA.",
                    cwe="CWE-829",
                    remediation=(
                        f"Pin '{action_name}' to a specific commit SHA instead of "
                        f"'{action_ref}'."
                    ),
                    extra={"job": job_name, "action": uses, "current_ref": action_ref},
                ))

    return findings


@register_check
def check_unpinned_container(workflow: GHAWorkflow, config: ScannerConfig) -> list[dict]:
    """GHA-PIN-002: Unpinned container image.

    Container images using :latest or no tag can change without notice,
    introducing supply chain risk.
    """
    findings = []

    for job_name, job in workflow.jobs.items():
        # Check job container
        images_to_check: list[tuple[str, int]] = []

        if job.container:
            if isinstance(job.container, str):
                images_to_check.append((job.container, job.line))
            elif isinstance(job.container, dict):
                img = str(job.container.get("image", ""))
                if img:
                    images_to_check.append((img, job.line))

        # Check services
        for svc_name, svc_config in job.services.items():
            if isinstance(svc_config, dict):
                img = str(svc_config.get("image", ""))
                if img:
                    images_to_check.append((img, job.line))
            elif isinstance(svc_config, str):
                images_to_check.append((svc_config, job.line))

        for image, line in images_to_check:
            # FP guard: skip expressions (dynamic images)
            if "${{" in image:
                continue

            finding = _check_image_tag(image, job_name, workflow, line)
            if finding:
                findings.append(finding)

    return findings


def _check_image_tag(
    image: str, job_name: str, workflow: GHAWorkflow, line: int,
) -> dict | None:
    """Check if a container image tag is properly pinned."""
    # Has digest: always safe
    if "@sha256:" in image:
        return None

    # Split image:tag
    if ":" in image:
        tag = image.rsplit(":", 1)[1]
        if tag == "latest":
            return _finding(
                "GHA-PIN-002", "MEDIUM",
                "Container image uses :latest tag",
                workflow, line,
                f"Container image '{image}' in job '{job_name}' uses :latest tag. "
                f"Pin to a specific version or SHA256 digest.",
                cwe="CWE-829",
                remediation=f"Pin '{image}' to a specific version tag or @sha256: digest.",
                extra={"job": job_name, "image": image},
            )
        # Has a specific version tag, accept it
        return None

    # No tag at all: defaults to :latest
    return _finding(
        "GHA-PIN-002", "MEDIUM",
        "Container image without tag",
        workflow, line,
        f"Container image '{image}' in job '{job_name}' has no tag, "
        f"which defaults to :latest. Pin to a specific version.",
        cwe="CWE-829",
        remediation=f"Add a version tag to '{image}' or use @sha256: digest.",
        extra={"job": job_name, "image": image},
    )
