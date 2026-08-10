# Installation

## From Git (recommended)

```bash
pip install git+https://github.com/ugiordan/github-guard.git
```

Requires Python 3.10+ and installs `ruamel.yaml` automatically.

## From Source

```bash
git clone https://github.com/ugiordan/github-guard.git
cd github-guard
pip install -e .
```

## Binary Download

Pre-built binaries are available on the [Releases](https://github.com/ugiordan/github-guard/releases) page for:

- **Linux** (amd64)
- **macOS** (arm64)
- **Windows** (amd64)

Download and make executable:

```bash
curl -L https://github.com/ugiordan/github-guard/releases/latest/download/github-guard-linux-amd64 -o github-guard
chmod +x github-guard
./github-guard --help
```

## Pre-commit Hook

Add to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/ugiordan/github-guard
    rev: v1.0.0
    hooks:
      - id: github-guard
```

This runs automatically on any changes to `.github/workflows/` YAML files.

## Verify Installation

```bash
github-guard --help
```
