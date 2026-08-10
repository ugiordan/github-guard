# Quick Start

## Scan a Repository

Point github-guard at a repository root. It automatically finds `.github/workflows/*.yml` and `action.yml` files:

```bash
github-guard /path/to/repo
```

## Scan a Single File

```bash
github-guard .github/workflows/ci.yml
```

## Output Formats

### Text (human-readable)

```bash
github-guard . --format text
```

```
GitHub Actions Security Scan: my-project
Found 3 issue(s)

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

[MEDIUM] GHA-PIN-001: Unpinned action reference
  File: .github/workflows/ci.yml:10
  Action 'actions/checkout@v4' in job 'build' uses mutable ref 'v4'.
  Fix: Pin 'actions/checkout' to a specific commit SHA instead of 'v4'.

Summary: 1 CRITICAL, 1 HIGH, 1 MEDIUM
```

### JSON (default)

```bash
github-guard . --format json --output results.json
```

### SARIF (GitHub Code Scanning)

```bash
github-guard . --format sarif --output results.sarif
```

## Filter by Severity

Only report HIGH and CRITICAL findings:

```bash
github-guard . --min-severity HIGH --format text
```

## CI Gate

Exit 1 only for HIGH+ findings (ignore MEDIUM and below):

```bash
github-guard . --fail-on HIGH
```

Always exit 0 (informational run):

```bash
github-guard . --exit-zero
```

## Explain a Rule

```bash
github-guard --explain GHA-TRIG-001
```

## Baseline Management

Save current findings as accepted:

```bash
github-guard . --update-baseline .github-guard-baseline.json
```

Suppress known findings in future runs:

```bash
github-guard . --baseline .github-guard-baseline.json
```
