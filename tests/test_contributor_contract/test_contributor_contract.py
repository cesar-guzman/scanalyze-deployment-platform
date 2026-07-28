"""Tests for the contributor workflow and Claude Code baseline contract.

These tests assert the committed state directly (docs, README link, and
``.claude/settings.json``) and that the ``check_contributor_contract.py`` gate
passes against the repository. They are offline and perform no mutation.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CONTRIB_DIR = REPO_ROOT / "docs" / "contributing"
SETTINGS = REPO_ROOT / ".claude" / "settings.json"
README = REPO_ROOT / "README.md"
CHECKER = REPO_ROOT / "tooling" / "check_contributor_contract.py"

REQUIRED_DOCS = [
    "contributor-guide.md",
    "ai-assisted-development.md",
    "claude-code-setup.md",
    "onboarding-rehearsal-checklist.md",
]

REQUIRED_DENY = [
    "Read(./**/*.tfstate)",
    "Read(./**/*.tfvars)",
    "Bash(git push:*)",
    "Bash(git reset --hard:*)",
    "Bash(gh pr create:*)",
    "Bash(terraform apply:*)",
    "Bash(terraform destroy:*)",
    "Bash(aws:*)",
]


@pytest.fixture(scope="module")
def settings() -> dict:
    return json.loads(SETTINGS.read_text(encoding="utf-8"))


@pytest.mark.parametrize("name", REQUIRED_DOCS)
def test_required_doc_exists_and_is_current(name: str) -> None:
    doc = CONTRIB_DIR / name
    assert doc.exists(), f"missing document: {name}"
    assert "Status: CURRENT" in doc.read_text(encoding="utf-8"), (
        f"{name} is not marked 'Status: CURRENT'"
    )


def test_readme_links_contributor_guide() -> None:
    assert "docs/contributing/contributor-guide.md" in README.read_text(
        encoding="utf-8"
    )


def test_baseline_is_valid_json_and_plan_first(settings: dict) -> None:
    assert settings["permissions"]["defaultMode"] == "plan"


def test_baseline_pins_model_routing(settings: dict) -> None:
    assert settings["model"] == "opusplan"
    env = settings["env"]
    assert env["ANTHROPIC_MODEL"] == "claude-opus-4-8"
    assert env["ANTHROPIC_SMALL_FAST_MODEL"] == "claude-sonnet-5"


@pytest.mark.parametrize("rule", REQUIRED_DENY)
def test_baseline_denies_dangerous_action(settings: dict, rule: str) -> None:
    assert rule in settings["permissions"]["deny"], f"missing deny rule: {rule}"


def test_checker_passes_against_repo() -> None:
    result = subprocess.run(
        [sys.executable, str(CHECKER)],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"check_contributor_contract.py failed:\n{result.stdout}\n{result.stderr}"
    )
