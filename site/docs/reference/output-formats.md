# Output Formats

github-guard supports three output formats: JSON (default), SARIF, and text.

## JSON

The default output format. Machine-parseable with a summary section.

```bash
github-guard . --format json
```

```json
{
  "version": "1.0.0",
  "scanner": "github-guard",
  "scan_date": "2026-01-15T10:30:00Z",
  "target": ".",
  "findings": [
    {
      "rule_id": "GHA-TRIG-001",
      "severity": "CRITICAL",
      "title": "pull_request_target with fork checkout",
      "file": ".github/workflows/ci.yml",
      "line_start": 15,
      "line_end": 15,
      "message": "Job 'build' checks out fork code...",
      "cwe": "CWE-94",
      "remediation": "Use pull_request trigger instead...",
      "docs_url": "https://ugiordan.github.io/github-guard/reference/rules/#gha-trig-001",
      "job": "build",
      "ref": "${{ github.event.pull_request.head.sha }}"
    }
  ],
  "summary": {
    "total": 1,
    "by_severity": {"CRITICAL": 1},
    "by_category": {"triggers": 1}
  }
}
```

### Finding fields

| Field | Type | Description |
|-------|------|-------------|
| `rule_id` | string | Unique check identifier (e.g., `GHA-TRIG-001`) |
| `severity` | string | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO` |
| `title` | string | Short human-readable title |
| `file` | string | Path to the workflow file |
| `line_start` | int | Line number where the issue was found |
| `line_end` | int | End line number |
| `message` | string | Detailed explanation of the issue |
| `cwe` | string | CWE identifier (e.g., `CWE-94`) |
| `remediation` | string | How to fix the issue |
| `docs_url` | string | Link to the rule documentation |

Additional context fields (e.g., `job`, `ref`, `action`, `input`) are included when relevant.

## SARIF

[SARIF 2.1.0](https://sarifweb.azurewebsites.net/) format for integration with GitHub Code Scanning, GitLab SAST, and other tools.

```bash
github-guard . --format sarif --output results.sarif
```

Upload to GitHub Code Scanning:

```yaml
- name: Run github-guard
  run: github-guard . --format sarif --output results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Text

Human-readable format with color-coded severity and summary.

```bash
github-guard . --format text
```

```
GitHub Actions Security Scan: my-project
Found 3 issue(s)

[CRITICAL] GHA-TRIG-001: pull_request_target with fork checkout
  File: .github/workflows/ci.yml:15
  Job 'build' checks out fork code (ref: ${{ github.event.pull_request.head.sha }})
  in a pull_request_target workflow.
  Fix: Use pull_request trigger instead, or avoid checking out fork code.

[HIGH] GHA-PERM-001: Missing permissions block
  File: .github/workflows/ci.yml:1
  Workflow has no top-level permissions and not all jobs define permissions.
  Fix: Add a top-level 'permissions: {}' to restrict to read-only by default.

[MEDIUM] GHA-PIN-001: Unpinned action reference
  File: .github/workflows/ci.yml:10
  Action 'actions/checkout@v4' uses mutable ref 'v4'.
  Fix: Pin 'actions/checkout' to a specific commit SHA instead of 'v4'.

Summary: 1 CRITICAL, 1 HIGH, 1 MEDIUM
```
