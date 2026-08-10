# CLI Reference

## Usage

```bash
github-guard [OPTIONS] TARGET
```

`TARGET` is a path to a repository directory (scans `.github/workflows/` and `action.yml` files) or a single YAML file.

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `TARGET` | Path to a repo directory or a single YAML file | (required) |
| `--format`, `-f` | Output format: `json`, `sarif`, `text` | `json` |
| `--output`, `-o` | Write output to file instead of stdout | stdout |
| `--config`, `-c` | Path to config file (`.github-guard.yaml`) | None |
| `--min-severity` | Minimum severity to report: `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` | `LOW` (from config) |
| `--fail-on` | Exit 1 only if findings at or above this severity | any finding |
| `--exit-zero` | Always exit 0 regardless of findings | `false` |
| `--baseline` | Baseline file to suppress known findings | None |
| `--update-baseline` | Write current findings as a new baseline file | None |
| `--explain RULE_ID` | Show detailed information about a specific check rule | None |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No findings (or `--exit-zero` / `--fail-on` threshold not met) |
| `1` | Findings detected (at or above `--fail-on` threshold) |
| `2` | Error (invalid target, unknown rule for `--explain`) |

## Examples

### Scan a repository

```bash
github-guard /path/to/repo --format text
```

### Scan a single workflow

```bash
github-guard .github/workflows/ci.yml --format text
```

### CI gate with severity threshold

```bash
github-guard . --fail-on HIGH --format sarif --output results.sarif
```

### Informational run (never fail)

```bash
github-guard . --exit-zero --format text
```

### Filter to HIGH+ findings only

```bash
github-guard . --min-severity HIGH --format text
```

### Use a config file

```bash
github-guard . --config .github-guard.yaml
```

### Explain a specific rule

```bash
github-guard --explain GHA-TRIG-001
```

### Baseline management

```bash
# Save current findings as accepted baseline
github-guard . --update-baseline .github-guard-baseline.json

# Run with baseline suppression
github-guard . --baseline .github-guard-baseline.json --format text
```
