import json
from pathlib import Path

from tooling.validate_contributor_contract import (
    CLAUDE_REQUIRED_DENIES,
    CLAUDE_REQUIRED_MODELS,
    ISSUE_FORM_IDS,
    claude_configuration_errors,
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


def test_claude_baseline_is_part_of_the_required_contract() -> None:
    from tooling.validate_contributor_contract import REQUIRED_FILES

    assert Path("CLAUDE.md") in REQUIRED_FILES
    assert Path(".claude/settings.json") in REQUIRED_FILES
    assert (
        Path("docs/engineering/AI_ASSISTED_DEVELOPMENT_STANDARD.md")
        in REQUIRED_FILES
    )
    assert Path("docs/engineering/CLAUDE_CODE_SETUP.md") in REQUIRED_FILES


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


def test_claude_configuration_rejects_model_and_permission_drift(
    tmp_path: Path,
) -> None:
    settings_path = tmp_path / ".claude/settings.json"
    settings_path.parent.mkdir(parents=True)
    settings_path.write_text(
        json.dumps(
            {
                "$schema": (
                    "https://json.schemastore.org/"
                    "claude-code-settings.json"
                ),
                "model": "sonnet",
                "availableModels": ["sonnet"],
                "fallbackModel": ["haiku"],
                "effortLevel": "low",
                "permissions": {
                    "defaultMode": "acceptEdits",
                    "disableBypassPermissionsMode": "enable",
                    "deny": [],
                },
                "sandbox": {
                    "enabled": False,
                    "autoAllowBashIfSandboxed": True,
                    "allowUnsandboxedCommands": True,
                    "credentials": {"envVars": []},
                },
                "env": {},
            }
        ),
        encoding="utf-8",
    )

    errors = claude_configuration_errors(tmp_path)

    assert "Claude settings model must be opusplan" in errors
    assert "Claude fallbackModel must be an empty list" in errors
    assert "Claude permissions.defaultMode must be plan" in errors
    assert "Claude sandbox must be enabled" in errors
    assert any("missing deny rule" in error for error in errors)
    assert any("deny credential variable" in error for error in errors)


def test_claude_configuration_contract_names_exact_models_and_denies() -> None:
    assert CLAUDE_REQUIRED_MODELS == {
        "opusplan",
        "claude-opus-4-8",
        "claude-sonnet-5",
    }
    assert {
        "Bash(git push *)",
        "Bash(gh pr create *)",
        "Bash(terraform apply *)",
        "Bash(aws *)",
    }.issubset(CLAUDE_REQUIRED_DENIES)
