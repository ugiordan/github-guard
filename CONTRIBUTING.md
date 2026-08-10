# Contributing to github-guard

Thanks for your interest in contributing! Here's how to get started.

## Development Setup

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
ruff check github_guard/
```

## Adding a New Check

1. Choose the category module under `github_guard/checks/` (triggers, permissions, pinning, secrets, runners, flow)
2. Add your check function with the `@register_check` decorator
3. Add a test fixture in `tests/fixtures/`
4. Add positive and negative tests in `tests/test_checks.py`
5. Update `_EXPECTED_MIN_CHECKS` in `github_guard/checks/__init__.py`
6. Update the docs at `site/docs/reference/rules.md`
7. Run tests and linter before submitting

### Check function pattern

```python
@register_check
def check_my_new_check(workflow: GHAWorkflow, config: ScannerConfig) -> list[dict]:
    """GHA-CAT-NNN: Short description."""
    findings = []
    for job_name, job in workflow.jobs.items():
        for step in job.steps:
            # detection logic
            findings.append(_finding(
                "GHA-CAT-NNN", "HIGH", "Short title",
                workflow, step.line,
                "Detailed message explaining the risk.",
                cwe="CWE-XXX",
                remediation="How to fix it.",
            ))
    return findings
```

## Pull Requests

- One feature per PR
- Include tests for any new checks
- Run `ruff check` and `pytest` before submitting
- Update documentation if adding user-facing features

## Reporting Issues

Open an issue on GitHub with:
- What you expected
- What happened
- Steps to reproduce
- github-guard version (`pip show github-guard`)

## Code of Conduct

Be respectful and constructive. We're all here to make CI/CD security better.

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
