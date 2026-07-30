"""RED tests for the additive GUG-102 task-definition input v2 schema."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from tooling.validate_schema import validate_fixture, validate_semantics


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCHEMA_PATH = REPO_ROOT / "schemas" / "task-definition-input.v2.schema.json"
VALID_FIXTURE = (
    REPO_ROOT / "fixtures" / "valid" / "task-definition-v2-ingest-api.json"
)
INVALID_FIXTURES = (
    REPO_ROOT
    / "fixtures"
    / "invalid"
    / "task-definition-v2-case-insensitive-canonical-alias.json",
    REPO_ROOT
    / "fixtures"
    / "invalid"
    / "task-definition-v2-missing-deployment-identity.json",
    REPO_ROOT
    / "fixtures"
    / "invalid"
    / "task-definition-v2-duplicate-reserved-environment.json",
    REPO_ROOT
    / "fixtures"
    / "invalid"
    / "task-definition-v2-customer-deployment-mixup.json",
    REPO_ROOT
    / "fixtures"
    / "invalid"
    / "task-definition-v2-reserved-identity-override.json",
)
SEMANTIC_INVALID_FIXTURE = (
    REPO_ROOT
    / "fixtures"
    / "invalid"
    / "task-definition-v2-environment-binding-mismatch.json"
)


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture
def validator() -> Draft202012Validator:
    assert SCHEMA_PATH.is_file(), "task-definition input v2 schema must be additive"
    schema = _load_json(SCHEMA_PATH)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def test_valid_task_definition_v2_passes(
    validator: Draft202012Validator,
) -> None:
    errors = list(validator.iter_errors(_load_json(VALID_FIXTURE)))
    assert errors == []


@pytest.mark.parametrize("fixture", INVALID_FIXTURES, ids=lambda path: path.stem)
def test_invalid_task_definition_v2_fails(
    validator: Draft202012Validator,
    fixture: Path,
) -> None:
    errors = list(validator.iter_errors(_load_json(fixture)))
    assert errors, f"{fixture.name} must fail closed"


def test_canonical_environment_must_match_identity_metadata(
    validator: Draft202012Validator,
) -> None:
    assert list(validator.iter_errors(_load_json(SEMANTIC_INVALID_FIXTURE))) == []
    valid, message = validate_fixture(SEMANTIC_INVALID_FIXTURE, SCHEMA_PATH)
    assert not valid
    assert "must match customer_identity.canonical_value" in message


def test_semantics_reject_case_insensitive_canonical_alias() -> None:
    fixture = (
        REPO_ROOT
        / "fixtures"
        / "invalid"
        / "task-definition-v2-case-insensitive-canonical-alias.json"
    )
    errors = validate_semantics(_load_json(fixture), SCHEMA_PATH)
    assert any("case-insensitively unique" in error for error in errors)
    assert any("exact uppercase spelling" in error for error in errors)
