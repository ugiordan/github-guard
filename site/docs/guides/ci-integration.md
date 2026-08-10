# CI Integration

## GitHub Actions

### Basic scan

```yaml
name: Security Scan
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  github-guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install git+https://github.com/ugiordan/github-guard.git
      - run: github-guard . --format text --fail-on HIGH
```

### With SARIF upload

Upload results to GitHub Code Scanning for inline PR annotations:

```yaml
name: Security Scan
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  github-guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install git+https://github.com/ugiordan/github-guard.git
      - run: github-guard . --format sarif --output results.sarif --exit-zero
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### With baseline suppression

Suppress known/accepted findings using a baseline file:

```yaml
- run: github-guard . --baseline .github-guard-baseline.json --format text --fail-on HIGH
```

### Severity-gated CI

Only fail on CRITICAL findings:

```yaml
- run: github-guard . --fail-on CRITICAL --format text
```

## Pre-commit

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/ugiordan/github-guard
    rev: v1.0.0
    hooks:
      - id: github-guard
```

Runs automatically on changes to `.github/workflows/` YAML files.

## GitLab CI

```yaml
github-guard:
  image: python:3.12-slim
  stage: test
  script:
    - pip install git+https://github.com/ugiordan/github-guard.git
    - github-guard . --format text --fail-on HIGH
  only:
    changes:
      - .github/workflows/**
```

## JSON output for downstream processing

```yaml
- run: github-guard . --format json --output results.json --exit-zero
- name: Process results
  run: |
    total=$(jq '.summary.total' results.json)
    echo "Found $total findings"
    if [ "$total" -gt 0 ]; then
      jq '.findings[] | "\(.severity) \(.rule_id): \(.title)"' results.json
    fi
```
