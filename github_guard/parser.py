"""YAML workflow parsing and trigger normalization for GitHub Actions."""

from __future__ import annotations

import glob
import logging
import os
from dataclasses import dataclass, field
from typing import Any

from ruamel.yaml import YAML

logger = logging.getLogger(__name__)


@dataclass
class GHAStep:
    name: str = ""
    uses: str = ""
    run: str = ""
    with_: dict[str, Any] = field(default_factory=dict)
    env: dict[str, Any] = field(default_factory=dict)
    if_condition: str = ""
    line: int = 0


@dataclass
class GHAJob:
    name: str = ""
    runs_on: str = ""
    permissions: Any = None  # None, str, or dict
    environment: str = ""
    timeout_minutes: int | None = None
    steps: list[GHAStep] = field(default_factory=list)
    uses: str = ""  # reusable workflow call
    secrets: Any = None  # None, str ("inherit"), or dict
    container: Any = None  # None, str, or dict
    services: dict[str, Any] = field(default_factory=dict)
    if_condition: str = ""
    line: int = 0


@dataclass
class GHAWorkflow:
    name: str = ""
    file_path: str = ""
    triggers: dict[str, Any] = field(default_factory=dict)
    permissions: Any = None  # None, str, or dict
    env: dict[str, Any] = field(default_factory=dict)
    jobs: dict[str, GHAJob] = field(default_factory=dict)


def _get_line(node: Any) -> int:
    """Extract line number from a ruamel.yaml node (CommentedMap/Seq)."""
    if hasattr(node, "lc") and node.lc is not None:
        return node.lc.line + 1  # ruamel uses 0-based lines
    return 0


def normalize_triggers(on_value: Any) -> dict[str, Any]:
    """Normalize the on: field to a consistent dict[str, Any] form.

    Handles: string ("push"), list (["push", "pull_request"]),
    or dict ({"push": {"branches": ["main"]}}).
    """
    if on_value is None:
        return {}
    if isinstance(on_value, str):
        return {on_value: {}}
    if isinstance(on_value, list):
        return {item: {} for item in on_value}
    if isinstance(on_value, dict):
        return {k: (v if v is not None else {}) for k, v in on_value.items()}
    return {}


def _parse_step(step_data: dict[str, Any]) -> GHAStep:
    """Parse a single step from workflow YAML."""
    return GHAStep(
        name=str(step_data.get("name", "")),
        uses=str(step_data.get("uses", "")),
        run=str(step_data.get("run", "")),
        with_=dict(step_data.get("with", {})) if step_data.get("with") else {},
        env=dict(step_data.get("env", {})) if step_data.get("env") else {},
        if_condition=str(step_data.get("if", "")),
        line=_get_line(step_data),
    )


def _parse_job(job_name: str, job_data: dict[str, Any]) -> GHAJob:
    """Parse a single job from workflow YAML."""
    runs_on_raw = job_data.get("runs-on", "")
    if isinstance(runs_on_raw, list):
        runs_on = ", ".join(str(r) for r in runs_on_raw)
    else:
        runs_on = str(runs_on_raw)

    env_val = job_data.get("environment", "")
    if isinstance(env_val, dict):
        environment = str(env_val.get("name", ""))
    else:
        environment = str(env_val) if env_val else ""

    steps = []
    for step_data in job_data.get("steps", []):
        if isinstance(step_data, dict):
            steps.append(_parse_step(step_data))

    return GHAJob(
        name=job_name,
        runs_on=runs_on,
        permissions=job_data.get("permissions"),
        environment=environment,
        timeout_minutes=job_data.get("timeout-minutes"),
        steps=steps,
        uses=str(job_data.get("uses", "")),
        secrets=job_data.get("secrets"),
        container=job_data.get("container"),
        services=dict(job_data.get("services", {})) if job_data.get("services") else {},
        if_condition=str(job_data.get("if", "")),
        line=_get_line(job_data),
    )


def parse_workflow(path: str) -> GHAWorkflow | None:
    """Parse a single GitHub Actions workflow YAML file."""
    yaml = YAML(typ="rt")
    yaml.preserve_quotes = True

    try:
        with open(path) as f:
            data = yaml.load(f)
    except Exception as e:
        logger.warning("Failed to parse %s: %s", path, e)
        return None

    if not isinstance(data, dict):
        logger.debug("Skipping %s: not a valid workflow (no top-level mapping)", path)
        return None

    # GitHub Actions workflows must have "on" (or True for YAML on: -> True key)
    on_value = data.get("on") or data.get(True)
    if on_value is None and "jobs" not in data:
        logger.debug("Skipping %s: no 'on' trigger and no 'jobs'", path)
        return None

    triggers = normalize_triggers(on_value)
    jobs: dict[str, GHAJob] = {}
    for job_name, job_data in (data.get("jobs") or {}).items():
        if isinstance(job_data, dict):
            jobs[str(job_name)] = _parse_job(str(job_name), job_data)

    return GHAWorkflow(
        name=str(data.get("name", "")),
        file_path=path,
        triggers=triggers,
        permissions=data.get("permissions"),
        env=dict(data.get("env", {})) if data.get("env") else {},
        jobs=jobs,
    )


def find_workflows(repo_path: str) -> list[str]:
    """Find all workflow files in .github/workflows/."""
    workflow_dir = os.path.join(repo_path, ".github", "workflows")
    if not os.path.isdir(workflow_dir):
        return []
    patterns = [
        os.path.join(workflow_dir, "*.yml"),
        os.path.join(workflow_dir, "*.yaml"),
    ]
    files = []
    for pattern in patterns:
        files.extend(glob.glob(pattern))
    return sorted(set(files))


def find_composite_actions(repo_path: str) -> list[str]:
    """Find action.yml/action.yaml files in repo root and subdirectories."""
    results = []
    for root, _dirs, files in os.walk(repo_path):
        # Skip .github/workflows (those are workflows, not actions)
        if ".github" in root.split(os.sep) and "workflows" in root.split(os.sep):
            continue
        # Skip hidden dirs (except .github itself for root action.yml)
        parts = root.split(os.sep)
        if any(p.startswith(".") and p != ".github" for p in parts if p != parts[0]):
            continue
        for name in ("action.yml", "action.yaml"):
            full = os.path.join(root, name)
            if full in files or os.path.isfile(full):
                results.append(full)
    return sorted(results)


def parse_composite_action(path: str) -> GHAWorkflow | None:
    """Parse a composite action file as a GHAWorkflow for uniform check processing."""
    yaml = YAML(typ="rt")
    yaml.preserve_quotes = True

    try:
        with open(path) as f:
            data = yaml.load(f)
    except Exception as e:
        logger.warning("Failed to parse composite action %s: %s", path, e)
        return None

    if not isinstance(data, dict):
        return None

    runs = data.get("runs", {})
    if not isinstance(runs, dict):
        return None

    # Only composite actions have runs.steps
    if runs.get("using") != "composite" and "steps" not in runs:
        return None

    steps = []
    for step_data in runs.get("steps", []):
        if isinstance(step_data, dict):
            steps.append(_parse_step(step_data))

    # Model as a single-job workflow for uniform processing
    job = GHAJob(
        name="composite",
        steps=steps,
        line=_get_line(runs) if isinstance(runs, dict) else 0,
    )

    return GHAWorkflow(
        name=str(data.get("name", "")),
        file_path=path,
        triggers={"composite_action": {}},
        jobs={"composite": job},
    )


def parse_directory(repo_path: str) -> list[GHAWorkflow]:
    """Parse all workflows and composite actions in a repository."""
    workflows: list[GHAWorkflow] = []

    for wf_path in find_workflows(repo_path):
        wf = parse_workflow(wf_path)
        if wf:
            workflows.append(wf)

    for action_path in find_composite_actions(repo_path):
        action = parse_composite_action(action_path)
        if action:
            workflows.append(action)

    return workflows
