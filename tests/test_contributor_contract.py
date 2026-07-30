import json
from pathlib import Path

from tooling.validate_contributor_contract import (
    ISSUE_FORM_IDS,
    claude_baseline_errors,
    issue_form_errors,
    missing_required_terms,
    relative_link_errors,
    validate,
    walkthrough_command_errors,
)


def test_repository_contributor_contract_is_complete() -> None:
    assert validate() == []


def test_github_walkthrough_is_part_of_the_required_contract() -> None:
    walkthrough = Path("docs/engineering/GITHUB_CONTRIBUTOR_WALKTHROUGH.md")

    from tooling.validate_contributor_contract import REQUIRED_FILES

    assert walkthrough in REQUIRED_FILES


def test_github_walkthrough_rejects_incompatible_pr_create_flags(
    tmp_path: Path,
) -> None:
    walkthrough = (
        tmp_path / "docs/engineering/GITHUB_CONTRIBUTOR_WALKTHROUGH.md"
    )
    walkthrough.parent.mkdir(parents=True)
    walkthrough.write_text(
        "```bash\n"
        "gh pr create --draft --web\n"
        "```\n",
        encoding="utf-8",
    )

    assert walkthrough_command_errors(tmp_path) == [
        "GitHub walkthrough must not combine gh pr create --draft and --web"
    ]


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


def _write_issue_templates(tmp_path: Path, form_body: str, config: str) -> None:
    form = tmp_path / ".github/ISSUE_TEMPLATE/engineering-change.yml"
    form.parent.mkdir(parents=True)
    form.write_text(form_body, encoding="utf-8")
    (form.parent / "config.yml").write_text(config, encoding="utf-8")


def test_issue_form_masked_missing_required_is_detected(tmp_path: Path) -> None:
    # A `problem` field with no validations.required, while a checkboxes field
    # supplies per-option `required: true`. An aggregate count of "required: true"
    # would pass; per-field parsing must still flag `problem`. [GUG-262 P2]
    form_body = (
        "name: form\n"
        "body:\n"
        "  - type: textarea\n"
        "    id: problem\n"
        "    attributes:\n"
        "      label: Problem\n"
        "  - type: checkboxes\n"
        "    id: confirmations\n"
        "    attributes:\n"
        "      label: Confirmations\n"
        "      options:\n"
        "        - label: A\n"
        "          required: true\n"
        "        - label: B\n"
        "          required: true\n"
    )
    _write_issue_templates(tmp_path, form_body, "blank_issues_enabled: false\n")

    errors = issue_form_errors(tmp_path)

    assert "engineering issue form field must be required: problem" in errors
    assert "engineering issue form field must be required: confirmations" not in errors


def test_blank_issues_enabled_uses_top_level_yaml_value(tmp_path: Path) -> None:
    # A stale commented `false` must not mask an active `true`. [GUG-262 P2]
    config = (
        "# blank_issues_enabled: false\n"
        "blank_issues_enabled: true\n"
    )
    _write_issue_templates(tmp_path, "name: form\nbody: []\n", config)

    errors = issue_form_errors(tmp_path)

    assert "blank GitHub issues must remain disabled" in errors


def test_repository_claude_baseline_contract_holds() -> None:
    assert claude_baseline_errors() == []


def test_claude_baseline_detects_drift(tmp_path: Path) -> None:
    settings = tmp_path / ".claude/settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(
        json.dumps(
            {
                "model": "sonnet",
                "env": {"ANTHROPIC_MODEL": "claude-opus-4-8"},
                "permissions": {
                    "defaultMode": "acceptEdits",
                    "deny": [],
                    "allow": ["Bash(make:*)"],
                },
            }
        ),
        encoding="utf-8",
    )

    errors = claude_baseline_errors(tmp_path)

    assert any("defaultMode must be 'plan'" in e for e in errors)
    assert any("model must be 'opusplan'" in e for e in errors)
    assert any("ANTHROPIC_DEFAULT_OPUS_MODEL" in e for e in errors)
    assert any("deprecated env.ANTHROPIC_MODEL" in e for e in errors)
    assert any("Bash(aws:*)" in e for e in errors)
    assert any("global 'Bash(make:*)' allow is forbidden" in e for e in errors)
    assert any("sandbox must be enabled" in e for e in errors)
