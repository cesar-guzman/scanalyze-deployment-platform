from pathlib import Path

from tooling.validate_contributor_contract import (
    ISSUE_FORM_IDS,
    issue_form_errors,
    missing_required_terms,
    relative_link_errors,
    validate,
)


def test_repository_contributor_contract_is_complete() -> None:
    assert validate() == []


def test_github_walkthrough_is_part_of_the_required_contract() -> None:
    walkthrough = Path("docs/engineering/GITHUB_CONTRIBUTOR_WALKTHROUGH.md")

    from tooling.validate_contributor_contract import REQUIRED_FILES

    assert walkthrough in REQUIRED_FILES


def test_missing_required_term_is_reported(tmp_path: Path) -> None:
    contributing = tmp_path / "CONTRIBUTING.md"
    contributing.write_text("# Contributing\n", encoding="utf-8")

    errors = missing_required_terms(tmp_path)

    assert any("one issue, one branch" in error for error in errors)
    assert any("production remains **no-go**" in error for error in errors)


def test_issue_form_requires_all_contract_fields(tmp_path: Path) -> None:
    form = tmp_path / ".github/ISSUE_TEMPLATE/engineering-change.yml"
    form.parent.mkdir(parents=True)
    form.write_text("name: incomplete\nbody: []\n", encoding="utf-8")
    config = form.parent / "config.yml"
    config.write_text("blank_issues_enabled: true\n", encoding="utf-8")

    errors = issue_form_errors(tmp_path)

    for field_id in ISSUE_FORM_IDS:
        assert any(field_id in error for error in errors)
    assert "blank GitHub issues must remain disabled" in errors


def test_relative_link_cannot_escape_repository(tmp_path: Path) -> None:
    contributing = tmp_path / "CONTRIBUTING.md"
    contributing.write_text("[outside](../outside.md)\n", encoding="utf-8")

    errors = relative_link_errors(tmp_path)

    assert errors == [
        "CONTRIBUTING.md: link escapes repository: ../outside.md"
    ]
