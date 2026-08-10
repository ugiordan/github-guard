# Configuration

github-guard can be configured via a YAML file passed with `--config`.

## Config File Format

Create a `.github-guard.yaml` in your repository root:

```yaml
# Skip specific checks
skip_checks:
  - GHA-PIN-001    # We accept mutable action tags in this repo
  - GHA-RUN-002    # Timeout not required for our workflows

# Minimum severity to report (default: LOW)
min_severity: MEDIUM

# Action owners considered safe (extends default list)
trusted_action_owners:
  - actions
  - github
  - azure
  - aws-actions
  - google-github-actions
  - docker
  - pypa
  - my-org          # Your organization

# Actions that legitimately consume OIDC tokens
known_oidc_actions:
  - aws-actions/configure-aws-credentials
  - google-github-actions/auth
  - Azure/login
  - pypa/gh-action-pypi-publish

# Runner label patterns for GitHub-hosted runners
# (used to distinguish self-hosted runners)
github_hosted_patterns:
  - ubuntu-*
  - windows-*
  - macos-*
  - my-custom-hosted-*   # Custom GitHub-hosted runner labels

# String prefixes that indicate hardcoded credentials
secret_patterns:
  - ghp_
  - gho_
  - ghu_
  - ghs_
  - ghr_
  - AKIA
  - sk-
  - sk_live_
  - sk_test_
  - xoxb-
  - xoxp-
  - xapp-
  - SG.
  - key-
```

## Usage

```bash
github-guard . --config .github-guard.yaml
```

## Default Values

When no config file is provided, github-guard uses sensible defaults:

| Setting | Default |
|---------|---------|
| `skip_checks` | `[]` (all checks enabled) |
| `min_severity` | `LOW` |
| `trusted_action_owners` | `actions`, `github`, `azure`, `aws-actions`, `google-github-actions`, `docker`, `pypa` |
| `known_oidc_actions` | `aws-actions/configure-aws-credentials`, `google-github-actions/auth`, `Azure/login`, `pypa/gh-action-pypi-publish` |
| `github_hosted_patterns` | `ubuntu-*`, `windows-*`, `macos-*` |
| `secret_patterns` | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `AKIA`, `sk-`, `sk_live_`, `sk_test_`, `xoxb-`, `xoxp-`, `xapp-`, `SG.`, `key-` |

## Overriding via CLI

The `--min-severity` CLI flag overrides the config file value:

```bash
# Config says min_severity: LOW, but this run only shows HIGH+
github-guard . --config .github-guard.yaml --min-severity HIGH
```
