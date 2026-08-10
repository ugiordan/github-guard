"""Tests for github-guard security checks."""

from __future__ import annotations

import os

from github_guard.checks import run_checks
from github_guard.checks._common import get_all_checks, get_all_correlation_checks
from github_guard.config import ScannerConfig
from github_guard.parser import (
    GHAJob,
    GHAStep,
    GHAWorkflow,
    normalize_triggers,
    parse_workflow,
)

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


# ---------------------------------------------------------------------------
# Helper to build in-memory workflows
# ---------------------------------------------------------------------------

def _workflow(
    name: str = "test",
    triggers: dict | None = None,
    permissions=None,
    jobs: dict | None = None,
    env: dict | None = None,
    file_path: str = ".github/workflows/test.yml",
) -> GHAWorkflow:
    return GHAWorkflow(
        name=name,
        file_path=file_path,
        triggers=triggers or {},
        permissions=permissions,
        env=env or {},
        jobs=jobs or {},
    )


def _job(
    name: str = "build",
    runs_on: str = "ubuntu-latest",
    steps: list[GHAStep] | None = None,
    permissions=None,
    environment: str = "",
    timeout_minutes: int | None = None,
    uses: str = "",
    secrets=None,
    container=None,
    services: dict | None = None,
    if_condition: str = "",
    line: int = 10,
) -> GHAJob:
    return GHAJob(
        name=name,
        runs_on=runs_on,
        steps=steps or [],
        permissions=permissions,
        environment=environment,
        timeout_minutes=timeout_minutes,
        uses=uses,
        secrets=secrets,
        container=container,
        services=services or {},
        if_condition=if_condition,
        line=line,
    )


def _step(
    name: str = "",
    uses: str = "",
    run: str = "",
    with_: dict | None = None,
    env: dict | None = None,
    if_condition: str = "",
    line: int = 20,
) -> GHAStep:
    return GHAStep(
        name=name,
        uses=uses,
        run=run,
        with_=with_ or {},
        env=env or {},
        if_condition=if_condition,
        line=line,
    )


# ---------------------------------------------------------------------------
# Check count verification
# ---------------------------------------------------------------------------

def test_check_count():
    """Verify we have the expected number of registered checks."""
    all_checks = get_all_checks()
    correlation = get_all_correlation_checks()
    total = len(all_checks) + len(correlation)
    assert total >= 15, f"Expected at least 15 checks, got {total}"


# ---------------------------------------------------------------------------
# GHA-TRIG-001: pull_request_target with fork checkout
# ---------------------------------------------------------------------------

def test_trig_001_positive():
    """PRT + fork checkout = CRITICAL finding."""
    wf = _workflow(
        triggers={"pull_request_target": {}},
        jobs={"build": _job(steps=[
            _step(
                uses="actions/checkout@v4",
                with_={"ref": "${{ github.event.pull_request.head.sha }}"},
            ),
        ])},
    )
    findings = run_checks([wf], ScannerConfig())
    trig_001 = [f for f in findings if f["rule_id"] == "GHA-TRIG-001"]
    assert len(trig_001) >= 1
    assert trig_001[0]["severity"] == "CRITICAL"


def test_trig_001_negative_no_ref():
    """PRT + checkout without ref = safe (default checkout)."""
    wf = _workflow(
        triggers={"pull_request_target": {}},
        jobs={"build": _job(steps=[
            _step(uses="actions/checkout@v4"),
        ])},
    )
    findings = run_checks([wf], ScannerConfig())
    trig_001 = [f for f in findings if f["rule_id"] == "GHA-TRIG-001"]
    assert len(trig_001) == 0


def test_trig_001_negative_push_trigger():
    """push trigger + checkout with head ref = no PRT finding."""
    wf = _workflow(
        triggers={"push": {}},
        jobs={"build": _job(steps=[
            _step(
                uses="actions/checkout@v4",
                with_={"ref": "${{ github.event.pull_request.head.sha }}"},
            ),
        ])},
    )
    findings = run_checks([wf], ScannerConfig())
    trig_001 = [f for f in findings if f["rule_id"] == "GHA-TRIG-001"]
    assert len(trig_001) == 0


# ---------------------------------------------------------------------------
# GHA-TRIG-002: Unsafe if condition as security gate
# ---------------------------------------------------------------------------

def test_trig_002_positive():
    """Bypassable fork check with secrets = HIGH finding."""
    wf = _workflow(
        triggers={"pull_request_target": {}},
        jobs={"build": _job(
            if_condition=(
                "github.event.pull_request.head.repo.full_name == github.repository"
            ),
            steps=[
                _step(
                    run="echo deploy",
                    env={"TOKEN": "${{ secrets.DEPLOY_TOKEN }}"},
                ),
            ],
        )},
    )
    findings = run_checks([wf], ScannerConfig())
    trig_002 = [f for f in findings if f["rule_id"] == "GHA-TRIG-002"]
    assert len(trig_002) >= 1


def test_trig_002_negative_no_secrets():
    """Bypassable fork check without secrets = no finding."""
    wf = _workflow(
        triggers={"pull_request_target": {}},
        jobs={"build": _job(
            if_condition=(
                "github.event.pull_request.head.repo.full_name == github.repository"
            ),
            steps=[
                _step(run="echo hello"),
            ],
        )},
    )
    findings = run_checks([wf], ScannerConfig())
    trig_002 = [f for f in findings if f["rule_id"] == "GHA-TRIG-002"]
    assert len(trig_002) == 0


# ---------------------------------------------------------------------------
# GHA-TRIG-003: workflow_dispatch with unvalidated string inputs
# ---------------------------------------------------------------------------

def test_trig_003_positive():
    """String input interpolated in run: = MEDIUM finding."""
    wf = _workflow(
        triggers={"workflow_dispatch": {
            "inputs": {"version": {"type": "string", "description": "Version"}},
        }},
        jobs={"build": _job(steps=[
            _step(run="echo ${{ github.event.inputs.version }}"),
        ])},
    )
    findings = run_checks([wf], ScannerConfig())
    trig_003 = [f for f in findings if f["rule_id"] == "GHA-TRIG-003"]
    assert len(trig_003) >= 1


def test_trig_003_negative_choice():
    """Choice input = no finding."""
    wf = _workflow(
        triggers={"workflow_dispatch": {
            "inputs": {"env": {"type": "choice", "options": ["prod", "staging"]}},
        }},
        jobs={"build": _job(steps=[
            _step(run="echo ${{ github.event.inputs.env }}"),
        ])},
    )
    findings = run_checks([wf], ScannerConfig())
    trig_003 = [f for f in findings if f["rule_id"] == "GHA-TRIG-003"]
    assert len(trig_003) == 0


# ---------------------------------------------------------------------------
# GHA-PERM-001: Missing permissions block
# ---------------------------------------------------------------------------

def test_perm_001_positive():
    """No permissions at all = HIGH finding."""
    wf = _workflow(
        triggers={"push": {}},
        jobs={"build": _job(steps=[_step(run="echo hi")])},
    )
    findings = run_checks([wf], ScannerConfig())
    perm_001 = [f for f in findings if f["rule_id"] == "GHA-PERM-001"]
    assert len(perm_001) >= 1


def test_perm_001_negative_top_level():
    """Top-level permissions = no finding."""
    wf = _workflow(
        triggers={"push": {}},
        permissions={"contents": "read"},
        jobs={"build": _job(steps=[_step(run="echo hi")])},
    )
    findings = run_checks([wf], ScannerConfig())
    perm_001 = [f for f in findings if f["rule_id"] == "GHA-PERM-001"]
    assert len(perm_001) == 0


def test_perm_001_negative_workflow_call():
    """workflow_call-only = no finding (inherits caller)."""
    wf = _workflow(
        triggers={"workflow_call": {}},
        jobs={"build": _job(steps=[_step(run="echo hi")])},
    )
    findings = run_checks([wf], ScannerConfig())
    perm_001 = [f for f in findings if f["rule_id"] == "GHA-PERM-001"]
    assert len(perm_001) == 0


# ---------------------------------------------------------------------------
# GHA-PERM-002: id-token:write without OIDC consumer
# ---------------------------------------------------------------------------

def test_perm_002_positive():
    """id-token:write without consumer = MEDIUM finding."""
    wf = _workflow(
        triggers={"push": {}},
        permissions={"id-token": "write"},
        jobs={"build": _job(steps=[_step(run="echo hi")])},
    )
    findings = run_checks([wf], ScannerConfig())
    perm_002 = [f for f in findings if f["rule_id"] == "GHA-PERM-002"]
    assert len(perm_002) >= 1


def test_perm_002_negative_with_consumer():
    """id-token:write with OIDC consumer = no finding."""
    wf = _workflow(
        triggers={"push": {}},
        permissions={"id-token": "write"},
        jobs={"build": _job(steps=[
            _step(uses="aws-actions/configure-aws-credentials@v4"),
        ])},
    )
    findings = run_checks([wf], ScannerConfig())
    perm_002 = [f for f in findings if f["rule_id"] == "GHA-PERM-002"]
    assert len(perm_002) == 0


# ---------------------------------------------------------------------------
# GHA-PIN-001: Unpinned action reference
# ---------------------------------------------------------------------------

def test_pin_001_positive_tag():
    """Action with tag ref = MEDIUM finding."""
    wf = _workflow(
        triggers={"push": {}},
        permissions={},
        jobs={"build": _job(steps=[
            _step(uses="actions/checkout@v4"),
        ])},
    )
    findings = run_checks([wf], ScannerConfig())
    pin_001 = [f for f in findings if f["rule_id"] == "GHA-PIN-001"]
    assert len(pin_001) >= 1


def test_pin_001_negative_sha():
    """Action with SHA = no finding."""
    wf = _workflow(
        triggers={"push": {}},
        permissions={},
        jobs={"build": _job(steps=[
            _step(uses="actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29"),
        ])},
    )
    findings = run_checks([wf], ScannerConfig())
    pin_001 = [f for f in findings if f["rule_id"] == "GHA-PIN-001"]
    assert len(pin_001) == 0


def test_pin_001_negative_local():
    """Local action (./) = no finding."""
    wf = _workflow(
        triggers={"push": {}},
        permissions={},
        jobs={"build": _job(steps=[
            _step(uses="./my-action"),
        ])},
    )
    findings = run_checks([wf], ScannerConfig())
    pin_001 = [f for f in findings if f["rule_id"] == "GHA-PIN-001"]
    assert len(pin_001) == 0


# ---------------------------------------------------------------------------
# GHA-PIN-002: Unpinned container image
# ---------------------------------------------------------------------------

def test_pin_002_positive_latest():
    """Container with :latest = MEDIUM finding."""
    wf = _workflow(
        triggers={"pull_request": {}},
        permissions={},
        jobs={"build": _job(container="node:latest", steps=[_step(run="echo")])},
    )
    findings = run_checks([wf], ScannerConfig())
    pin_002 = [f for f in findings if f["rule_id"] == "GHA-PIN-002"]
    assert len(pin_002) >= 1


def test_pin_002_negative_versioned():
    """Container with version tag = no finding."""
    wf = _workflow(
        triggers={"push": {}},
        permissions={},
        jobs={"build": _job(
            container="node:18.17.0",
            steps=[_step(run="echo")],
        )},
    )
    findings = run_checks([wf], ScannerConfig())
    pin_002 = [f for f in findings if f["rule_id"] == "GHA-PIN-002"]
    assert len(pin_002) == 0


# ---------------------------------------------------------------------------
# GHA-SEC-001: Hardcoded credential in workflow
# ---------------------------------------------------------------------------

def test_sec_001_positive():
    """Hardcoded token pattern = HIGH finding."""
    wf = _workflow(
        triggers={"push": {}},
        permissions={},
        jobs={"build": _job(steps=[
            _step(
                run="echo deploy",
                env={"AWS_KEY": "AKIAIOSFODNN7EXAMPLE0"},
            ),
        ])},
    )
    findings = run_checks([wf], ScannerConfig())
    sec_001 = [f for f in findings if f["rule_id"] == "GHA-SEC-001"]
    assert len(sec_001) >= 1


def test_sec_001_negative_secrets_ref():
    """${{ secrets.* }} reference = no finding."""
    wf = _workflow(
        triggers={"push": {}},
        permissions={},
        jobs={"build": _job(steps=[
            _step(
                run="echo deploy",
                env={"TOKEN": "${{ secrets.DEPLOY_TOKEN }}"},
            ),
        ])},
    )
    findings = run_checks([wf], ScannerConfig())
    sec_001 = [f for f in findings if f["rule_id"] == "GHA-SEC-001"]
    assert len(sec_001) == 0


# ---------------------------------------------------------------------------
# GHA-SEC-002: Secret passed as workflow input (currently limited check)
# ---------------------------------------------------------------------------

def test_sec_002_no_false_positive_normal_action():
    """Normal action with secrets in with: is expected, no finding."""
    wf = _workflow(
        triggers={"push": {}},
        permissions={},
        jobs={"build": _job(steps=[
            _step(
                uses="some-action@v1",
                with_={"token": "${{ secrets.TOKEN }}"},
            ),
        ])},
    )
    findings = run_checks([wf], ScannerConfig())
    sec_002 = [f for f in findings if f["rule_id"] == "GHA-SEC-002"]
    assert len(sec_002) == 0


# ---------------------------------------------------------------------------
# GHA-SEC-003: Artifact upload in PR context
# ---------------------------------------------------------------------------

def test_sec_003_positive():
    """Artifact upload in pull_request_target context = HIGH finding."""
    wf = _workflow(
        triggers={"pull_request_target": {}},
        permissions={},
        jobs={"build": _job(steps=[
            _step(uses="actions/upload-artifact@v4"),
        ])},
    )
    findings = run_checks([wf], ScannerConfig())
    sec_003 = [f for f in findings if f["rule_id"] == "GHA-SEC-003"]
    assert len(sec_003) >= 1


def test_sec_003_negative_push_trigger():
    """Artifact upload in push context = no finding."""
    wf = _workflow(
        triggers={"push": {}},
        permissions={},
        jobs={"build": _job(steps=[
            _step(uses="actions/upload-artifact@v4"),
        ])},
    )
    findings = run_checks([wf], ScannerConfig())
    sec_003 = [f for f in findings if f["rule_id"] == "GHA-SEC-003"]
    assert len(sec_003) == 0


def test_sec_003_negative_empty_permissions():
    """Artifact upload with empty permissions = no finding."""
    wf = _workflow(
        triggers={"pull_request": {}},
        permissions={},
        jobs={"build": _job(
            permissions={},
            steps=[_step(uses="actions/upload-artifact@v4")],
        )},
    )
    findings = run_checks([wf], ScannerConfig())
    sec_003 = [f for f in findings if f["rule_id"] == "GHA-SEC-003"]
    assert len(sec_003) == 0


# ---------------------------------------------------------------------------
# GHA-RUN-001: Self-hosted runner without environment protection
# ---------------------------------------------------------------------------

def test_run_001_positive():
    """Self-hosted + PR trigger + no environment = HIGH finding."""
    wf = _workflow(
        triggers={"pull_request": {}},
        permissions={},
        jobs={"build": _job(
            runs_on="self-hosted",
            steps=[_step(run="echo hi")],
        )},
    )
    findings = run_checks([wf], ScannerConfig())
    run_001 = [f for f in findings if f["rule_id"] == "GHA-RUN-001"]
    assert len(run_001) >= 1


def test_run_001_negative_with_environment():
    """Self-hosted + environment = no finding."""
    wf = _workflow(
        triggers={"pull_request": {}},
        permissions={},
        jobs={"build": _job(
            runs_on="self-hosted",
            environment="production",
            steps=[_step(run="echo hi")],
        )},
    )
    findings = run_checks([wf], ScannerConfig())
    run_001 = [f for f in findings if f["rule_id"] == "GHA-RUN-001"]
    assert len(run_001) == 0


def test_run_001_negative_push_only():
    """Self-hosted + push only = no finding (trusted trigger)."""
    wf = _workflow(
        triggers={"push": {}},
        permissions={},
        jobs={"build": _job(
            runs_on="self-hosted",
            steps=[_step(run="echo hi")],
        )},
    )
    findings = run_checks([wf], ScannerConfig())
    run_001 = [f for f in findings if f["rule_id"] == "GHA-RUN-001"]
    assert len(run_001) == 0


# ---------------------------------------------------------------------------
# GHA-RUN-002: Job without timeout
# ---------------------------------------------------------------------------

def test_run_002_positive():
    """No timeout + pull_request_target trigger = LOW finding."""
    wf = _workflow(
        triggers={"pull_request_target": {}},
        permissions={},
        jobs={"build": _job(steps=[_step(run="echo hi")])},
    )
    findings = run_checks([wf], ScannerConfig())
    run_002 = [f for f in findings if f["rule_id"] == "GHA-RUN-002"]
    assert len(run_002) >= 1


def test_run_002_negative_has_timeout():
    """With timeout-minutes = no finding."""
    wf = _workflow(
        triggers={"pull_request": {}},
        permissions={},
        jobs={"build": _job(
            timeout_minutes=30,
            steps=[_step(run="echo hi")],
        )},
    )
    findings = run_checks([wf], ScannerConfig())
    run_002 = [f for f in findings if f["rule_id"] == "GHA-RUN-002"]
    assert len(run_002) == 0


def test_run_002_negative_trusted_trigger():
    """Push-only workflow = no finding (FP guard)."""
    wf = _workflow(
        triggers={"push": {}},
        permissions={},
        jobs={"build": _job(steps=[_step(run="echo hi")])},
    )
    findings = run_checks([wf], ScannerConfig())
    run_002 = [f for f in findings if f["rule_id"] == "GHA-RUN-002"]
    assert len(run_002) == 0


# ---------------------------------------------------------------------------
# GHA-FLOW-001: workflow_run from fork-triggerable
# ---------------------------------------------------------------------------

def test_flow_001_positive():
    """workflow_run referencing fork-triggerable = MEDIUM finding."""
    wf1 = _workflow(
        name="CI",
        triggers={"pull_request": {}},
        permissions={},
        jobs={"test": _job(steps=[_step(run="echo")])},
    )
    wf2 = _workflow(
        name="Post CI",
        triggers={"workflow_run": {"workflows": ["CI"]}},
        permissions={},
        jobs={"deploy": _job(steps=[_step(run="echo")])},
    )
    findings = run_checks([wf1, wf2], ScannerConfig())
    flow_001 = [f for f in findings if f["rule_id"] == "GHA-FLOW-001"]
    assert len(flow_001) >= 1


def test_flow_001_negative_push_only():
    """workflow_run referencing push-only workflow = no finding."""
    wf1 = _workflow(
        name="Build",
        triggers={"push": {}},
        permissions={},
        jobs={"test": _job(steps=[_step(run="echo")])},
    )
    wf2 = _workflow(
        name="Deploy",
        triggers={"workflow_run": {"workflows": ["Build"]}},
        permissions={},
        jobs={"deploy": _job(steps=[_step(run="echo")])},
    )
    findings = run_checks([wf1, wf2], ScannerConfig())
    flow_001 = [f for f in findings if f["rule_id"] == "GHA-FLOW-001"]
    assert len(flow_001) == 0


# ---------------------------------------------------------------------------
# GHA-FLOW-002: Composite action with unpinned refs
# ---------------------------------------------------------------------------

def test_flow_002_positive():
    """Composite action with tag ref = MEDIUM finding."""
    wf = _workflow(
        triggers={"composite_action": {}},
        jobs={"composite": _job(steps=[
            _step(uses="actions/setup-node@v4"),
        ])},
    )
    findings = run_checks([wf], ScannerConfig())
    flow_002 = [f for f in findings if f["rule_id"] == "GHA-FLOW-002"]
    assert len(flow_002) >= 1


def test_flow_002_negative_local():
    """Composite action with local ref = no finding."""
    wf = _workflow(
        triggers={"composite_action": {}},
        jobs={"composite": _job(steps=[
            _step(uses="./local-action"),
        ])},
    )
    findings = run_checks([wf], ScannerConfig())
    flow_002 = [f for f in findings if f["rule_id"] == "GHA-FLOW-002"]
    assert len(flow_002) == 0


# ---------------------------------------------------------------------------
# GHA-FLOW-003: Reusable workflow with secrets:inherit
# ---------------------------------------------------------------------------

def test_flow_003_positive():
    """External reusable workflow with secrets:inherit = MEDIUM finding."""
    wf = _workflow(
        triggers={"push": {}},
        permissions={},
        jobs={"call": _job(
            uses="other-org/workflows/.github/workflows/build.yml@main",
            secrets="inherit",
        )},
    )
    findings = run_checks([wf], ScannerConfig())
    flow_003 = [f for f in findings if f["rule_id"] == "GHA-FLOW-003"]
    assert len(flow_003) >= 1


def test_flow_003_negative_local():
    """Local reusable workflow with secrets:inherit = no finding."""
    wf = _workflow(
        triggers={"push": {}},
        permissions={},
        jobs={"call": _job(
            uses="./.github/workflows/build.yml",
            secrets="inherit",
        )},
    )
    findings = run_checks([wf], ScannerConfig())
    flow_003 = [f for f in findings if f["rule_id"] == "GHA-FLOW-003"]
    assert len(flow_003) == 0


# ---------------------------------------------------------------------------
# Parser tests
# ---------------------------------------------------------------------------

def test_normalize_triggers_string():
    assert normalize_triggers("push") == {"push": {}}


def test_normalize_triggers_list():
    result = normalize_triggers(["push", "pull_request"])
    assert "push" in result
    assert "pull_request" in result


def test_normalize_triggers_dict():
    result = normalize_triggers({"push": {"branches": ["main"]}})
    assert result == {"push": {"branches": ["main"]}}


# ---------------------------------------------------------------------------
# Integration: parse real fixture
# ---------------------------------------------------------------------------

def test_parse_prt_fixture():
    """Parse a real workflow fixture and verify findings."""
    fixture = os.path.join(FIXTURES_DIR, "prt_fork_checkout.yml")
    wf = parse_workflow(fixture)
    assert wf is not None
    assert "pull_request_target" in wf.triggers
    findings = run_checks([wf], ScannerConfig())
    rule_ids = {f["rule_id"] for f in findings}
    assert "GHA-TRIG-001" in rule_ids


def test_parse_safe_workflow():
    """Safe workflow should produce minimal findings."""
    fixture = os.path.join(FIXTURES_DIR, "safe_workflow.yml")
    wf = parse_workflow(fixture)
    assert wf is not None
    findings = run_checks([wf], ScannerConfig())
    # Should have no HIGH or CRITICAL findings
    high_crit = [f for f in findings if f["severity"] in ("HIGH", "CRITICAL")]
    assert len(high_crit) == 0


def test_parse_multi_issue():
    """Multi-issue workflow should produce multiple findings."""
    fixture = os.path.join(FIXTURES_DIR, "multi_issue.yml")
    wf = parse_workflow(fixture)
    assert wf is not None
    findings = run_checks([wf], ScannerConfig())
    assert len(findings) >= 3  # at minimum: TRIG-001, unpinned, missing perms


# ---------------------------------------------------------------------------
# Config tests
# ---------------------------------------------------------------------------

def test_skip_checks():
    """Skipped checks should produce no findings."""
    wf = _workflow(
        triggers={"push": {}},
        jobs={"build": _job(steps=[
            _step(uses="actions/checkout@v4"),
        ])},
    )
    config = ScannerConfig(skip_checks=["GHA-PIN-001", "GHA-PERM-001"])
    findings = run_checks([wf], config)
    rule_ids = {f["rule_id"] for f in findings}
    assert "GHA-PIN-001" not in rule_ids
    assert "GHA-PERM-001" not in rule_ids


def test_min_severity():
    """min_severity should filter out lower severity findings."""
    wf = _workflow(
        triggers={"pull_request": {}},
        permissions={},
        jobs={"build": _job(steps=[
            _step(uses="actions/checkout@v4"),
            _step(run="echo hi"),
        ])},
    )
    config = ScannerConfig(min_severity="HIGH")
    findings = run_checks([wf], config)
    for f in findings:
        assert f["severity"] in ("HIGH", "CRITICAL"), (
            f"Found {f['severity']} finding with min_severity=HIGH"
        )
