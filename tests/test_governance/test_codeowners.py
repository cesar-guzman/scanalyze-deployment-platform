"""Fail-closed tests for ordered CODEOWNERS review coverage."""

from __future__ import annotations

from pathlib import Path

import pytest

from tooling.validate_github_policy import GitHubPolicyError, validate_codeowners


REPO_ROOT = Path(__file__).resolve().parents[2]
CODEOWNERS_PATH = REPO_ROOT / "CODEOWNERS"
REQUIRED_HUMANS = {"@cesar-guzman", "@guguce-google"}
SENSITIVE_PATHS = (
    "CONTRIBUTING.md",
    "SECURITY.md",
    ".github/PULL_REQUEST_TEMPLATE.md",
    ".github/ISSUE_TEMPLATE/bug_report.md",
    ".github/workflows/pr-validation.yml",
    "governance/github-policy.json",
    "scripts/governance/generate_protection_payload.py",
    "tooling/validate_github_policy.py",
    "tests/test_governance/test_codeowners.py",
    "ADR/ADR-018-stable-ci-governance.md",
    "schemas/github-policy.schema.json",
    "policies/example.json",
    "session-policies/example.json",
    "modules/example/main.tf",
    "roots/example/main.tf",
    "deployment/layers.yaml",
    "scripts/supply-chain/release-graph.py",
    "ARCHITECTURE_ACCEPTANCE_GATES.md",
    "docs/engineering/GITHUB_ENFORCEMENT_BASELINE.md",
    "docs/governance/independent-approval-standard.md",
)


def _write_codeowners(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "CODEOWNERS"
    path.write_text(content, encoding="utf-8")
    return path


def test_repository_codeowners_has_effective_independent_human_coverage() -> None:
    effective = validate_codeowners(CODEOWNERS_PATH, sensitive_paths=SENSITIVE_PATHS)

    assert set(effective) == set(SENSITIVE_PATHS)
    for path, owners in effective.items():
        assert REQUIRED_HUMANS == set(owners), path


def test_every_repository_rule_uses_only_the_current_owner_roster() -> None:
    validate_codeowners(CODEOWNERS_PATH, sensitive_paths=SENSITIVE_PATHS)
    rules = [
        line.split()
        for line in CODEOWNERS_PATH.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]

    assert rules
    for pattern, *owners in rules:
        assert {owner.casefold() for owner in owners} == REQUIRED_HUMANS, pattern


def test_pr_template_routes_review_to_the_designated_independent_human() -> None:
    template = (REPO_ROOT / ".github/PULL_REQUEST_TEMPLATE.md").read_text(
        encoding="utf-8"
    )

    assert "`guguce-google` human attestation" in template
    assert "@Ferrusca08" not in template
    assert "Review covers the final material SHA" in template
    assert "Self-approval excluded" in template
    assert "P0 second-human approval" in template


def test_single_owner_rule_is_rejected(tmp_path: Path) -> None:
    path = _write_codeowners(
        tmp_path,
        "* @cesar-guzman @guguce-google\n"
        "governance/ @cesar-guzman\n",
    )

    with pytest.raises(GitHubPolicyError, match="at least two distinct owners"):
        validate_codeowners(path, sensitive_paths=("governance/policy.json",))


def test_later_override_cannot_remove_independent_reviewer(tmp_path: Path) -> None:
    path = _write_codeowners(
        tmp_path,
        "* @cesar-guzman @guguce-google\n"
        "governance/ @cesar-guzman @guguce-google\n"
        "governance/github-policy.json @cesar-guzman @former-reviewer\n",
    )

    with pytest.raises(GitHubPolicyError, match="must include @guguce-google"):
        validate_codeowners(
            path,
            sensitive_paths=("governance/github-policy.json",),
        )


@pytest.mark.parametrize(
    "content",
    [
        "* cesar-guzman @guguce-google\n",
        "* @cesar-guzman @guguce-google trailing-text\n",
        "* @cesar-guzman @guguce-google\ninvalid-rule-only\n",
    ],
)
def test_malformed_owner_tokens_or_rules_fail(tmp_path: Path, content: str) -> None:
    path = _write_codeowners(tmp_path, content)

    with pytest.raises(GitHubPolicyError, match="malformed"):
        validate_codeowners(path, sensitive_paths=("SECURITY.md",))


def test_duplicate_owners_do_not_count_as_two_humans(tmp_path: Path) -> None:
    path = _write_codeowners(
        tmp_path,
        "* @cesar-guzman @CESAR-GUZMAN @guguce-google\n",
    )

    with pytest.raises(GitHubPolicyError, match="duplicate owner"):
        validate_codeowners(path, sensitive_paths=("SECURITY.md",))


def test_default_rule_is_required_for_unmatched_sensitive_paths(tmp_path: Path) -> None:
    path = _write_codeowners(
        tmp_path,
        "governance/ @cesar-guzman @guguce-google\n",
    )

    with pytest.raises(GitHubPolicyError, match="default '\\*' rule"):
        validate_codeowners(path, sensitive_paths=("SECURITY.md",))
