# Detection Rules

github-guard runs 15 security checks across 6 categories. Each check has a unique ID, severity level, CWE mapping, and actionable remediation.

---

## Triggers

### GHA-TRIG-001: pull_request_target with fork checkout

| Property | Value |
|----------|-------|
| **Severity** | CRITICAL |
| **CWE** | [CWE-94](https://cwe.mitre.org/data/definitions/94.html) (Code Injection) |
| **Category** | triggers |

**Detection logic**: Flags workflows triggered by `pull_request_target` that use `actions/checkout` with a `ref:` pointing to fork code (`github.event.pull_request.head`, `github.head_ref`, or `refs/pull/`).

**Why it matters**: `pull_request_target` runs with the base repository's permissions and secrets. Checking out fork code in this context allows an attacker to execute arbitrary code with write access to the target repository.

**Remediation**: Use `pull_request` trigger instead. If `pull_request_target` is required, do not check out fork code, or run the checkout in a separate job with `permissions: {}` and no secrets.

??? example "Vulnerable"
    ```yaml
    on: pull_request_target
    jobs:
      build:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4
            with:
              ref: ${{ github.event.pull_request.head.sha }}
          - run: npm test  # Executes attacker's code with write permissions
    ```

??? example "Safe"
    ```yaml
    on: pull_request
    jobs:
      build:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4
          - run: npm test
    ```

---

### GHA-TRIG-002: Bypassable fork detection via repo name comparison

| Property | Value |
|----------|-------|
| **Severity** | HIGH |
| **CWE** | [CWE-290](https://cwe.mitre.org/data/definitions/290.html) (Authentication Bypass by Spoofing) |
| **Category** | triggers |

**Detection logic**: Flags `if:` conditions that compare `github.event.pull_request.head.repo.full_name == github.repository` as a security gate, but only when the job or step also uses secrets or `GITHUB_TOKEN`.

**Why it matters**: An attacker can rename their fork to match the target repository name, bypassing this check entirely.

**Remediation**: Use `github.event.pull_request.head.repo.fork == true` instead, or move sensitive operations to a `workflow_run` pattern.

??? example "Vulnerable"
    ```yaml
    on: pull_request_target
    jobs:
      deploy:
        if: github.event.pull_request.head.repo.full_name == github.repository
        runs-on: ubuntu-latest
        steps:
          - run: deploy.sh
            env:
              TOKEN: ${{ secrets.DEPLOY_TOKEN }}
    ```

??? example "Safe"
    ```yaml
    on: pull_request_target
    jobs:
      deploy:
        if: github.event.pull_request.head.repo.fork != true
        runs-on: ubuntu-latest
        steps:
          - run: deploy.sh
            env:
              TOKEN: ${{ secrets.DEPLOY_TOKEN }}
    ```

---

### GHA-TRIG-003: Unvalidated workflow_dispatch input in shell command

| Property | Value |
|----------|-------|
| **Severity** | MEDIUM |
| **CWE** | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) (OS Command Injection) |
| **Category** | triggers |

**Detection logic**: Finds `workflow_dispatch` inputs of type `string` (or untyped, which defaults to string) that are interpolated directly into `run:` blocks via `${{ github.event.inputs.* }}` or `${{ inputs.* }}`.

**Why it matters**: Anyone with write access can trigger the workflow with crafted input values, injecting arbitrary shell commands.

**Remediation**: Use environment variables instead of direct interpolation, or use `type: choice` to restrict allowed values.

??? example "Vulnerable"
    ```yaml
    on:
      workflow_dispatch:
        inputs:
          version:
            type: string
    jobs:
      build:
        runs-on: ubuntu-latest
        steps:
          - run: echo ${{ github.event.inputs.version }}
    ```

??? example "Safe"
    ```yaml
    on:
      workflow_dispatch:
        inputs:
          version:
            type: string
    jobs:
      build:
        runs-on: ubuntu-latest
        steps:
          - run: echo "$VERSION"
            env:
              VERSION: ${{ inputs.version }}
    ```

---

## Permissions

### GHA-PERM-001: Missing permissions block

| Property | Value |
|----------|-------|
| **Severity** | HIGH |
| **CWE** | [CWE-250](https://cwe.mitre.org/data/definitions/250.html) (Execution with Unnecessary Privileges) |
| **Category** | permissions |

**Detection logic**: Flags workflows that have no top-level `permissions:` and where not all jobs define their own `permissions:`. Skips `workflow_call`-only workflows (they inherit caller permissions).

**Why it matters**: Without explicit permissions, the `GITHUB_TOKEN` gets broad default access including write to contents, packages, and pull-requests.

**Remediation**: Add a top-level `permissions: {}` to restrict to read-only by default, then grant specific permissions per job as needed.

??? example "Vulnerable"
    ```yaml
    on: push
    jobs:
      build:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4
          # GITHUB_TOKEN has write access to everything
    ```

??? example "Safe"
    ```yaml
    on: push
    permissions: {}
    jobs:
      build:
        runs-on: ubuntu-latest
        permissions:
          contents: read
        steps:
          - uses: actions/checkout@v4
    ```

---

### GHA-PERM-002: id-token:write without OIDC consumer

| Property | Value |
|----------|-------|
| **Severity** | MEDIUM |
| **CWE** | [CWE-250](https://cwe.mitre.org/data/definitions/250.html) (Execution with Unnecessary Privileges) |
| **Category** | permissions |

**Detection logic**: Flags `id-token: write` in permissions (top-level or per-job) when no job uses a known OIDC consumer action (e.g., `aws-actions/configure-aws-credentials`, `google-github-actions/auth`).

**Why it matters**: Granting `id-token:write` allows OIDC token minting. If no action consumes the token, it is either unnecessary or could be misused to impersonate the workflow.

**Remediation**: Remove `id-token: write` if not needed, or ensure it is consumed by a known OIDC action.

---

## Pinning

### GHA-PIN-001: Unpinned action reference

| Property | Value |
|----------|-------|
| **Severity** | MEDIUM |
| **CWE** | [CWE-829](https://cwe.mitre.org/data/definitions/829.html) (Inclusion of Functionality from Untrusted Control Sphere) |
| **Category** | pinning |

**Detection logic**: Flags action `uses:` references that are not pinned to a full commit SHA (40 or 64 hex characters). Skips local (`./`) and `docker://` references.

**Why it matters**: Mutable tags like `v4` or `main` can be overwritten by the action maintainer (or an attacker who compromises their account), silently replacing the action code.

**Remediation**: Pin to a specific commit SHA: `actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29`.

??? example "Vulnerable"
    ```yaml
    - uses: actions/checkout@v4
    ```

??? example "Safe"
    ```yaml
    - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29 # v4
    ```

---

### GHA-PIN-002: Unpinned container image

| Property | Value |
|----------|-------|
| **Severity** | MEDIUM |
| **CWE** | [CWE-829](https://cwe.mitre.org/data/definitions/829.html) (Inclusion of Functionality from Untrusted Control Sphere) |
| **Category** | pinning |

**Detection logic**: Flags container images in `container:` or `services:` that use `:latest` tag, or have no tag at all (defaults to `:latest`). Images with `@sha256:` digest are always accepted. Skips `${{ }}` expressions (dynamic images).

**Why it matters**: Container images using `:latest` or no tag can change without notice, introducing supply chain risk.

**Remediation**: Pin to a specific version tag or `@sha256:` digest.

---

## Secrets

### GHA-SEC-001: Hardcoded credential in workflow

| Property | Value |
|----------|-------|
| **Severity** | HIGH |
| **CWE** | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) (Use of Hard-coded Credentials) |
| **Category** | secrets |

**Detection logic**: Scans `env:` values and `run:` blocks for known secret prefixes (`ghp_`, `AKIA`, `sk-`, `xoxb-`, etc.). Skips `${{ secrets.* }}` references, URLs, version strings, git SHAs, and other common false positive patterns.

**Why it matters**: Hardcoded credentials in workflow files are visible to anyone with read access to the repository and cannot be rotated without a code change.

**Remediation**: Move the credential to GitHub Secrets and reference it as `${{ secrets.SECRET_NAME }}`.

---

### GHA-SEC-002: Secret passed as workflow input

| Property | Value |
|----------|-------|
| **Severity** | MEDIUM |
| **CWE** | [CWE-532](https://cwe.mitre.org/data/definitions/532.html) (Insertion of Sensitive Information into Log File) |
| **Category** | secrets |

**Detection logic**: Flags reusable workflow calls that pass secrets via `with:` instead of the `secrets:` key.

**Why it matters**: Secrets passed as inputs may appear in workflow logs, since GitHub only masks values passed through the `secrets:` mechanism.

**Remediation**: Move the secret from `with:` to `secrets:` in the reusable workflow call.

---

### GHA-SEC-003: Artifact upload in PR target context

| Property | Value |
|----------|-------|
| **Severity** | HIGH |
| **CWE** | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) (Exposure of Sensitive Information) |
| **Category** | secrets |

**Detection logic**: Flags `actions/upload-artifact` in `pull_request_target` workflows. Skips jobs with empty permissions (`permissions: {}`), and steps with fork-detection `if:` conditions.

**Why it matters**: Artifacts uploaded with base repo privileges in a `pull_request_target` workflow may contain sensitive build outputs or secrets from the runner, accessible to anyone with repo read access.

**Remediation**: Restrict artifact uploads with an `if:` condition checking `github.event.pull_request.head.repo.fork != true`, or set restrictive job permissions.

---

## Runners

### GHA-RUN-001: Self-hosted runner without environment protection

| Property | Value |
|----------|-------|
| **Severity** | HIGH |
| **CWE** | [CWE-284](https://cwe.mitre.org/data/definitions/284.html) (Improper Access Control) |
| **Category** | runners |

**Detection logic**: Flags jobs running on self-hosted runners (not matching GitHub-hosted patterns) in externally-triggerable workflows (`pull_request`, `issue_comment`, etc.) without an `environment:` protection gate. Skips trusted-only triggers (`push`, `schedule`, `workflow_dispatch`).

**Why it matters**: Without environment protection, any external contributor can submit a PR that executes arbitrary code on your self-hosted infrastructure.

**Remediation**: Add an `environment:` gate that requires approval, or switch to GitHub-hosted runners for untrusted workloads.

---

### GHA-RUN-002: Job without timeout

| Property | Value |
|----------|-------|
| **Severity** | LOW |
| **CWE** | [CWE-400](https://cwe.mitre.org/data/definitions/400.html) (Uncontrolled Resource Consumption) |
| **Category** | runners |

**Detection logic**: Flags jobs without `timeout-minutes` in workflows with external triggers (excluding trusted-only and `pull_request`-only workflows). Skips reusable workflow calls with no steps.

**Why it matters**: Without a timeout, jobs can run up to the platform maximum (6 hours for GitHub-hosted, 5 days for self-hosted), wasting compute resources or enabling crypto mining abuse.

**Remediation**: Add `timeout-minutes: 30` (or an appropriate value) to the job.

---

## Flow

### GHA-FLOW-001: workflow_run triggered by fork-triggerable workflow

| Property | Value |
|----------|-------|
| **Severity** | MEDIUM |
| **CWE** | [CWE-94](https://cwe.mitre.org/data/definitions/94.html) (Code Injection) |
| **Category** | flow |

**Detection logic**: Cross-workflow correlation check. Identifies workflows triggered by `workflow_run` where the referenced trigger workflow is fork-triggerable (`pull_request` or `pull_request_target`). Only flags when the referenced workflow name matches an actual workflow in the scan.

**Why it matters**: A `workflow_run` workflow inherits some context from the triggering workflow. If the trigger is fork-triggerable, an attacker can craft PR metadata to influence the downstream workflow's behavior.

**Remediation**: Validate all data from `github.event.workflow_run` before use. Do not check out code from the triggering PR without sanitization.

---

### GHA-FLOW-002: Composite action with unpinned refs

| Property | Value |
|----------|-------|
| **Severity** | MEDIUM |
| **CWE** | [CWE-829](https://cwe.mitre.org/data/definitions/829.html) (Inclusion of Functionality from Untrusted Control Sphere) |
| **Category** | flow |

**Detection logic**: Flags action references in composite actions (`action.yml`) that are not pinned to a commit SHA. Skips local (`./`) and `docker://` references.

**Why it matters**: Composite actions inherit the same supply chain risks as workflows. Unpinned refs in composite actions can be silently replaced with malicious code.

**Remediation**: Pin all action references in composite actions to full commit SHAs.

---

### GHA-FLOW-003: Reusable workflow with secrets:inherit

| Property | Value |
|----------|-------|
| **Severity** | MEDIUM |
| **CWE** | [CWE-250](https://cwe.mitre.org/data/definitions/250.html) (Execution with Unnecessary Privileges) |
| **Category** | flow |

**Detection logic**: Flags reusable workflow calls that use `secrets: inherit` for external workflow refs (not `./` local). Local workflows are not flagged since they are under the same repository's control.

**Why it matters**: `secrets: inherit` passes ALL repository secrets to the called workflow. If the called workflow is compromised, all secrets are exposed.

**Remediation**: Explicitly pass only the secrets needed: `secrets: { MY_SECRET: ${{ secrets.MY_SECRET }} }` instead of `secrets: inherit`.

??? example "Vulnerable"
    ```yaml
    jobs:
      build:
        uses: other-org/workflows/.github/workflows/build.yml@main
        secrets: inherit  # Passes ALL secrets
    ```

??? example "Safe"
    ```yaml
    jobs:
      build:
        uses: other-org/workflows/.github/workflows/build.yml@main
        secrets:
          DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
    ```
