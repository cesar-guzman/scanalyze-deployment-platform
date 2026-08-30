from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
import pytest

from tooling.platform_authority_plan_permission_repair import (
    PRIVATE_INTENT_FIELDS,
    PRIVATE_LEDGER_ACTIVE_FIELDS,
    PRIVATE_LEDGER_PLAN_FIELDS,
    PUBLIC_RECEIPT_FIELDS,
)
from tooling.validate_schema import find_schema_for_fixture, validate_fixture


REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = REPO_ROOT / "schemas"
VALID = REPO_ROOT / "fixtures/valid"
INVALID = REPO_ROOT / "fixtures/invalid"

SCHEMA_NAMES = (
    "platform-authority-plan-permission-repair-intent.v1.schema.json",
    "platform-authority-plan-permission-repair-ledger.v1.schema.json",
    "platform-authority-plan-permission-repair-receipt.v1.schema.json",
)
VALID_FIXTURES = (
    "platform-authority-plan-permission-repair-intent-v1-synthetic.json",
    "platform-authority-plan-permission-repair-ledger-v1-synthetic.json",
    "platform-authority-plan-permission-repair-receipt-v1-synthetic.json",
)
INVALID_FIXTURES = (
    "platform-authority-plan-permission-repair-intent-v1-production-overclaim.json",
    "platform-authority-plan-permission-repair-ledger-v1-impossible-progress.json",
    "platform-authority-plan-permission-repair-receipt-v1-production-overclaim.json",
)


@pytest.mark.parametrize("schema_name", SCHEMA_NAMES)
def test_plan_permission_repair_schema_is_draft_2020_12(
    schema_name: str,
) -> None:
    schema = json.loads((SCHEMAS / schema_name).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)


@pytest.mark.parametrize("fixture_name", VALID_FIXTURES)
def test_valid_plan_permission_repair_fixture_passes(fixture_name: str) -> None:
    fixture = VALID / fixture_name
    schema = find_schema_for_fixture(fixture.stem, SCHEMAS)
    assert schema is not None
    assert validate_fixture(fixture, schema) == (True, "PASS")


@pytest.mark.parametrize("fixture_name", INVALID_FIXTURES)
def test_invalid_plan_permission_repair_fixture_fails(fixture_name: str) -> None:
    fixture = INVALID / fixture_name
    schema = find_schema_for_fixture(fixture.stem, SCHEMAS)
    assert schema is not None
    passed, message = validate_fixture(fixture, schema)
    assert passed is False
    assert message.startswith("FAIL:")


def test_public_receipt_schema_rejects_raw_private_values() -> None:
    schema = json.loads(
        (SCHEMAS / SCHEMA_NAMES[2]).read_text(encoding="utf-8")
    )
    receipt = json.loads(
        (VALID / VALID_FIXTURES[2]).read_text(encoding="utf-8")
    )
    receipt["permission_set_arn"] = (
        "arn:aws:sso:::permissionSet/ssoins-0123456789ABCDEF/"
        "ps-0123456789ABCDEF"
    )
    errors = list(
        Draft202012Validator(
            schema, format_checker=FormatChecker()
        ).iter_errors(receipt)
    )
    assert errors


def test_uncertain_receipt_requires_durable_mutation_attribution() -> None:
    schema = json.loads(
        (SCHEMAS / SCHEMA_NAMES[2]).read_text(encoding="utf-8")
    )
    receipt = json.loads(
        (VALID / VALID_FIXTURES[2]).read_text(encoding="utf-8")
    )
    receipt.update(
        {
            "status": "UNCERTAIN_RECONCILE_ONLY",
            "effects_attempted": 1,
            "effects_completed": 0,
            "mutation_attribution": "UNPROVEN",
            "required_next_action": "INVOKE_RECONCILE_ALIAS",
        }
    )

    errors = list(
        Draft202012Validator(
            schema, format_checker=FormatChecker()
        ).iter_errors(receipt)
    )

    assert errors


def test_public_receipt_field_contract_matches_closed_schema() -> None:
    schema = json.loads(
        (SCHEMAS / SCHEMA_NAMES[2]).read_text(encoding="utf-8")
    )
    assert set(schema["required"]) == PUBLIC_RECEIPT_FIELDS
    assert schema["additionalProperties"] is False


def test_private_contract_field_sets_match_closed_schemas() -> None:
    intent_schema = json.loads(
        (SCHEMAS / SCHEMA_NAMES[0]).read_text(encoding="utf-8")
    )
    ledger_schema = json.loads(
        (SCHEMAS / SCHEMA_NAMES[1]).read_text(encoding="utf-8")
    )
    assert set(intent_schema["required"]) == PRIVATE_INTENT_FIELDS
    assert set(intent_schema["properties"]) == PRIVATE_INTENT_FIELDS
    assert intent_schema["additionalProperties"] is False
    assert set(ledger_schema["required"]) == PRIVATE_LEDGER_PLAN_FIELDS
    assert set(ledger_schema["properties"]) == PRIVATE_LEDGER_ACTIVE_FIELDS
    assert ledger_schema["additionalProperties"] is False
