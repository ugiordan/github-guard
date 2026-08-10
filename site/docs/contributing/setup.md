# Development Setup

## Prerequisites

- Python 3.10+
- git

## Clone and Install

```bash
git clone https://github.com/ugiordan/github-guard.git
cd github-guard
pip install -e .
```

## Running Tests

```bash
PYTHONPATH=. python -m pytest tests/ -v
```

## Linting

```bash
pip install ruff
ruff check github_guard/
```

## Project Structure

```
github-guard/
  github_guard/
    __init__.py          # Version
    __main__.py          # Entry point
    cli.py               # CLI argument parsing and orchestration
    parser.py            # YAML parsing, trigger normalization
    config.py            # ScannerConfig dataclass and loader
    formatter.py         # JSON, SARIF, text output
    checks/
      __init__.py        # Check registry and runner
      _common.py         # Shared helpers, decorators, _finding()
      triggers.py        # GHA-TRIG-001..003
      permissions.py     # GHA-PERM-001..002
      pinning.py         # GHA-PIN-001..002
      secrets.py         # GHA-SEC-001..003
      runners.py         # GHA-RUN-001..002
      flow.py            # GHA-FLOW-001..003
  tests/
    test_checks.py       # All check tests
    fixtures/            # YAML fixtures for integration tests
  site/
    mkdocs.yml           # Documentation config
    docs/                # Documentation source
```

## Adding a New Check

See [CONTRIBUTING.md](https://github.com/ugiordan/github-guard/blob/main/CONTRIBUTING.md) for the full guide.

Quick summary:

1. Add your check function in the appropriate module under `github_guard/checks/`
2. Use the `@register_check` decorator (or `@register_correlation_check` for cross-workflow checks)
3. Add positive and negative tests
4. Update `_EXPECTED_MIN_CHECKS` in `github_guard/checks/__init__.py`
5. Document the rule in `site/docs/reference/rules.md`

## Building Docs Locally

```bash
pip install mkdocs-material mkdocs-glightbox
cd site
mkdocs serve
```

Open `http://localhost:8000` to preview.
