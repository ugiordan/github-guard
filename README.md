<p align="center">
  <img src="site/docs/images/logo.svg" alt="github-guard logo" width="120">
</p>

# github-guard

Static security scanner for GitHub Actions workflows.

github-guard parses GitHub Actions workflow YAML files and composite actions, running 16 security checks across 6 categories covering trigger abuse, permission escalation, supply chain pinning, secret hygiene, runner security, and workflow flow integrity. It catches what generic linters miss: `pull_request_target` + fork checkout chains, bypassable fork detection gates, workflow_dispatch injection, OIDC token misuse, and cross-workflow data flow risks.

**[Documentation](https://ugiordan.github.io/github-guard/)** | **[Detection Rules Reference](https://ugiordan.github.io/github-guard/reference/rules/)**

## Install

```bash
pip install git+https://github.com/ugiordan/github-guard.git
```

Requires Python 3.10+ and `ruamel.yaml`.

### Pre-commit
```yaml
repos:
  - repo: https://github.com/ugiordan/github-guard
    rev: v1.0.0
    hooks:
      - id: github-guard
```

## Quick Start

```bash
github-guard /path/to/repo --format text
```

Example output:
```
GitHub Actions Security Scan: my-project
Found 4 issue(s)

[CRITICAL] GHA-TRIG-001: pull_request_target with fork checkout
  File: .github/workflows/ci.yml:15
  Job 'build' checks out fork code (ref: ${{ github.event.pull_request.head.sha }})
  in a pull_request_target workflow. This allows arbitrary code execution with
  write permissions and secrets access.
  Fix: Use pull_request trigger instead, or avoid checking out fork code.

[HIGH] GHA-PERM-001: Missing permissions block
  File: .github/workflows/ci.yml:1
  Workflow has no top-level permissions and not all jobs define permissions.
  Fix: Add a top-level 'permissions: {}' to restrict to read-only by default.

Summary: 1 CRITICAL, 1 HIGH, 2 MEDIUM
```

## What It Detects

16 checks across 6 categories:

| Category | Checks | What It Catches |
|----------|--------|-----------------|
| **Triggers** | GHA-TRIG-001..004 | `pull_request_target` + fork checkout, bypassable fork detection, `workflow_dispatch` injection, expression injection via attacker-controlled context |
| **Permissions** | GHA-PERM-001..002 | Missing permissions block, `id-token:write` without OIDC consumer |
| **Pinning** | GHA-PIN-001..002 | Unpinned action references (mutable tags), unpinned container images |
| **Secrets** | GHA-SEC-001..003 | Hardcoded credentials, secrets passed as workflow inputs, artifact upload in PR context |
| **Runners** | GHA-RUN-001..002 | Self-hosted runners without environment protection, jobs without timeout |
| **Flow** | GHA-FLOW-001..003 | `workflow_run` from fork-triggerable source, composite action unpinned refs, `secrets:inherit` |

## Key Features

- **Composite action scanning**: parses `action.yml` files alongside workflows
- **Cross-workflow correlation**: detects `workflow_run` chains from fork-triggerable workflows
- **False positive suppression**: skips `workflow_call`-only workflows, trusted triggers, `${{ secrets.* }}` references
- **Baseline management**: `--baseline` / `--update-baseline` with content fingerprinting and expiration
- **CI gate**: `--fail-on` severity threshold, `--exit-zero` for informational runs
- **SARIF output**: integrates with GitHub Code Scanning

## Output Formats

- **Text**: human-readable with severity summary
- **JSON**: machine-parseable findings with `docs_url` per finding
- **SARIF**: integrates with GitHub Code Scanning

```bash
github-guard /path/to/repo --format sarif --output results.sarif
```

## Configuration

Create a `.github-guard.yaml` to customize behavior:

```yaml
skip_checks:
  - GHA-PIN-001

min_severity: MEDIUM

trusted_action_owners:
  - actions
  - github
  - my-org

github_hosted_patterns:
  - ubuntu-*
  - windows-*
  - macos-*
  - my-custom-runner-*
```

```bash
github-guard /path/to/repo --config .github-guard.yaml
```

## License

Apache 2.0
