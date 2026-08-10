"""Configuration for GitHub Actions scanner trust lists and check settings."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML


@dataclass
class ScannerConfig:
    skip_checks: list[str] = field(default_factory=list)
    min_severity: str = "LOW"

    trusted_action_owners: list[str] = field(default_factory=lambda: [
        "actions", "github", "azure", "aws-actions",
        "google-github-actions", "docker", "pypa",
    ])

    known_oidc_actions: list[str] = field(default_factory=lambda: [
        "aws-actions/configure-aws-credentials",
        "google-github-actions/auth",
        "Azure/login",
        "pypa/gh-action-pypi-publish",
    ])

    github_hosted_patterns: list[str] = field(default_factory=lambda: [
        "ubuntu-*", "windows-*", "macos-*",
    ])

    secret_patterns: list[str] = field(default_factory=lambda: [
        "ghp_", "gho_", "ghu_", "ghs_", "ghr_",
        "AKIA", "sk-", "sk_live_", "sk_test_",
        "xoxb-", "xoxp-", "xapp-",
        "SG.", "key-",
    ])

    def is_trusted_action_owner(self, uses: str) -> bool:
        """Check if an action's owner is in the trusted list."""
        if not uses or "/" not in uses:
            return False
        owner = uses.split("/")[0]
        return owner in self.trusted_action_owners

    def is_github_hosted(self, runs_on: str) -> bool:
        """Check if a runs-on value matches GitHub-hosted runner patterns."""
        import fnmatch
        for pattern in self.github_hosted_patterns:
            if fnmatch.fnmatch(runs_on, pattern):
                return True
        return False

    def should_run_check(self, check_id: str) -> bool:
        return check_id not in self.skip_checks


def load_config(config_path: str | Path | None = None) -> ScannerConfig:
    if config_path is None:
        return ScannerConfig()

    path = Path(config_path)
    if not path.exists():
        return ScannerConfig()

    yaml = YAML(typ="safe")
    with open(path) as f:
        data = yaml.load(f) or {}

    kwargs: dict[str, Any] = {}
    for key in (
        "skip_checks", "min_severity", "trusted_action_owners",
        "known_oidc_actions", "github_hosted_patterns", "secret_patterns",
    ):
        if key in data:
            kwargs[key] = data[key]

    return ScannerConfig(**kwargs)
