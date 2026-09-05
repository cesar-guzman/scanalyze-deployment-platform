from __future__ import annotations

import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
import pytest

from tooling.platform_authority_plan_permission_repair import (
    PRIVATE_INTENT_FIELDS,
    PRIVATE_LEDGER_ACTIVE_FIELDS,
    PRIVATE_LEDGER_PLAN_FIELDS,
    PlanPermissionRepairError,
    PUBLIC_RECEIPT_FIELDS,
    digest_value,
    validate_public_receipt_v1,
    validate_public_receipt_v2,
)
from tooling.validate_schema import find_schema_for_fixture, validate_fixture


REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = REPO_ROOT / "schemas"
VALID = REPO_ROOT / "fixtures/valid"
INVALID = REPO_ROOT / "fixtures/invalid"
RECEIPT_V1_SCHEMA = (
    "platform-authority-plan-permission-repair-receipt.v1.schema.json"
)
RECEIPT_V2_SCHEMA = (
    "platform-authority-plan-permission-repair-receipt.v2.schema.json"
)
RECEIPT_V1_FIXTURE = (
    "platform-authority-plan-permission-repair-receipt-v1-synthetic.json"
)
RECEIPT_V2_FIXTURE = (
    "platform-authority-plan-permission-repair-receipt-v2-synthetic.json"
)
INTENT_V1_SCHEMA_SHA256 = (
    "668a797dba551ba905196287768ede83c0bf92b462d2d42c3fce2cd37bfda968"
)
RECEIPT_V1_SCHEMA_SHA256 = (
    "d2767d1305096ae037219be92aee34c9b4a7df44c4252264d2dceaec894cc8b5"
)
RECEIPT_V1_FIXTURE_SHA256 = (
    "257c74d0c4c5a7a41b79e8c3c817c861810a9d5e44c0a5d328ed960c833751c2"
)

SCHEMA_NAMES = (
    "platform-authority-plan-permission-repair-intent.v1.schema.json",
    "platform-authority-plan-permission-repair-intent.v2.schema.json",
    "platform-authority-plan-permission-repair-ledger.v1.schema.json",
    RECEIPT_V1_SCHEMA,
    RECEIPT_V2_SCHEMA,
)
VALID_FIXTURES = (
    "platform-authority-plan-permission-repair-intent-v1-synthetic.json",
    "platform-authority-plan-permission-repair-intent-v2-synthetic.json",
    "platform-authority-plan-permission-repair-ledger-v1-synthetic.json",
    RECEIPT_V1_FIXTURE,
    RECEIPT_V2_FIXTURE,
)
INVALID_FIXTURES = (
    "platform-authority-plan-permission-repair-intent-v1-production-overclaim.json",
    "platform-authority-plan-permission-repair-intent-v2-noncanonical-kms-key.json",
    "platform-authority-plan-permission-repair-ledger-v1-impossible-progress.json",
    "platform-authority-plan-permission-repair-receipt-v1-production-overclaim.json",
    "platform-authority-plan-permission-repair-receipt-v2-production-overclaim.json",
    "platform-authority-plan-permission-repair-receipt-v2-incomplete-reconcile-overclaim.json",
)


def _receipt(schema_version: int) -> dict[str, object]:
    name = {
        1: RECEIPT_V1_FIXTURE,
        2: RECEIPT_V2_FIXTURE,
    }[schema_version]
    return json.loads((VALID / name).read_text(encoding="utf-8"))


def _reseal(receipt: dict[str, object]) -> None:
    unsigned = dict(receipt)
    unsigned.pop("receipt_digest", None)
    receipt["receipt_digest"] = digest_value(unsigned)


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


def test_intent_v1_schema_bytes_remain_frozen() -> None:
    assert hashlib.sha256((SCHEMAS / SCHEMA_NAMES[0]).read_bytes()).hexdigest() == (
        INTENT_V1_SCHEMA_SHA256
    )


@pytest.mark.parametrize(
    ("path", "expected_sha256"),
    (
        (SCHEMAS / RECEIPT_V1_SCHEMA, RECEIPT_V1_SCHEMA_SHA256),
        (VALID / RECEIPT_V1_FIXTURE, RECEIPT_V1_FIXTURE_SHA256),
    ),
    ids=("schema", "fixture"),
)
def test_historical_receipt_v1_artifacts_remain_byte_frozen(
    path: Path,
    expected_sha256: str,
) -> None:
    assert hashlib.sha256(path.read_bytes()).hexdigest() == expected_sha256


@pytest.mark.parametrize(
    ("key_arn", "accepted"),
    (
        (
            "arn:aws:kms:us-east-1:839393571433:key/"
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            True,
        ),
        (
            "arn:aws:kms:us-east-1:839393571433:key/"
            "mrk-0123456789abcdef0123456789abcdef",
            True,
        ),
        (
            "arn:aws:kms:us-east-1:839393571433:alias/identity-center",
            False,
        ),
        (
            "arn:aws-cn:kms:us-east-1:839393571433:key/"
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            False,
        ),
        (
            "arn:aws:kms:us-west-2:839393571433:key/"
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            False,
        ),
        (
            "arn:aws:kms:us-east-1:000000000000:key/"
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            False,
        ),
        (
            "arn:aws:kms:us-east-1:839393571433:key/"
            "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
            False,
        ),
        (
            "arn:aws:kms:us-east-1:839393571433:key/"
            "mrk-0123456789abcdef0123456789abcdeF",
            False,
        ),
    ),
)
def test_intent_v2_kms_key_schema_matrix(
    key_arn: str,
    accepted: bool,
) -> None:
    schema = json.loads((SCHEMAS / SCHEMA_NAMES[1]).read_text(encoding="utf-8"))
    candidate = json.loads(
        (VALID / VALID_FIXTURES[1]).read_text(encoding="utf-8")
    )
    candidate["identity_center_kms_key_arn"] = key_arn
    errors = list(
        Draft202012Validator(
            schema, format_checker=FormatChecker()
        ).iter_errors(candidate)
    )
    assert (not errors) is accepted


def test_public_receipt_schema_rejects_raw_private_values() -> None:
    schema = json.loads(
        (SCHEMAS / RECEIPT_V2_SCHEMA).read_text(encoding="utf-8")
    )
    receipt = _receipt(2)
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
        (SCHEMAS / RECEIPT_V2_SCHEMA).read_text(encoding="utf-8")
    )
    receipt = _receipt(2)
    receipt.update(
        {
            "mode": "repair",
            "status": "UNCERTAIN_RECONCILE_ONLY",
            "function_qualifier": "repair-v1",
            "effects_attempted": 1,
            "effects_completed": 0,
            "required_next_action": "INVOKE_RECONCILE_ALIAS",
        }
    )
    validator = Draft202012Validator(
        schema, format_checker=FormatChecker()
    )
    assert list(validator.iter_errors(receipt)) == []

    receipt["mutation_attribution"] = "UNPROVEN"
    errors = list(validator.iter_errors(receipt))

    assert errors


@pytest.mark.parametrize(
    ("attempted", "completed"),
    ((0, 0), (0, 2), (1, 2), (2, 0)),
)
def test_uncertain_receipt_schema_rejects_nonledger_progress(
    attempted: int,
    completed: int,
) -> None:
    schema = json.loads(
        (SCHEMAS / RECEIPT_V2_SCHEMA).read_text(encoding="utf-8")
    )
    receipt = _receipt(2)
    receipt.update(
        {
            "mode": "repair",
            "status": "UNCERTAIN_RECONCILE_ONLY",
            "function_qualifier": "repair-v1",
            "effects_attempted": 1,
            "effects_completed": 0,
            "required_next_action": "INVOKE_RECONCILE_ALIAS",
        }
    )
    validator = Draft202012Validator(
        schema, format_checker=FormatChecker()
    )
    assert list(validator.iter_errors(receipt)) == []

    receipt.update(
        {
            "effects_attempted": attempted,
            "effects_completed": completed,
        }
    )
    assert list(validator.iter_errors(receipt))


def test_reconcile_schema_requires_two_completed_effects_and_stops_uncertainty(
) -> None:
    schema = json.loads(
        (SCHEMAS / RECEIPT_V2_SCHEMA).read_text(encoding="utf-8")
    )
    receipt = _receipt(2)
    receipt.update(
        {
            "mode": "reconcile",
            "status": "RECONCILE_VERIFIED",
            "function_qualifier": "reconcile-v1",
            "effects_attempted": 2,
            "effects_completed": 1,
            "required_next_action": "NONE",
        }
    )
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    assert list(validator.iter_errors(receipt))

    receipt.update(
        {
            "status": "UNCERTAIN_RECONCILE_ONLY",
            "required_next_action": "INVOKE_RECONCILE_ALIAS",
        }
    )
    assert list(validator.iter_errors(receipt))

    receipt["required_next_action"] = "REVIEW_BLOCKER"
    assert list(validator.iter_errors(receipt)) == []


def test_public_receipt_field_contract_matches_closed_schema() -> None:
    for schema_name in (RECEIPT_V1_SCHEMA, RECEIPT_V2_SCHEMA):
        schema = json.loads(
            (SCHEMAS / schema_name).read_text(encoding="utf-8")
        )
        assert set(schema["required"]) == PUBLIC_RECEIPT_FIELDS
        assert schema["additionalProperties"] is False


def test_historical_v1_reconcile_shape_and_digest_remain_readable() -> None:
    receipt = _receipt(1)
    receipt.update(
        {
            "mode": "reconcile",
            "status": "RECONCILE_VERIFIED",
            "function_qualifier": "reconcile-v1",
            "effects_attempted": 2,
            "effects_completed": 1,
            "required_next_action": "NONE",
        }
    )
    _reseal(receipt)
    schema = json.loads(
        (SCHEMAS / RECEIPT_V1_SCHEMA).read_text(encoding="utf-8")
    )

    assert list(
        Draft202012Validator(
            schema, format_checker=FormatChecker()
        ).iter_errors(receipt)
    ) == []
    validate_public_receipt_v1(receipt)
    with pytest.raises(PlanPermissionRepairError) as exc_info:
        validate_public_receipt_v2(receipt)
    assert exc_info.value.code == "RECEIPT_TYPE_MISMATCH"


def test_private_contract_field_sets_match_closed_schemas() -> None:
    intent_schemas = [
        json.loads((SCHEMAS / name).read_text(encoding="utf-8"))
        for name in SCHEMA_NAMES[:2]
    ]
    ledger_schema = json.loads(
        (SCHEMAS / SCHEMA_NAMES[2]).read_text(encoding="utf-8")
    )
    for intent_schema in intent_schemas:
        assert set(intent_schema["required"]) == PRIVATE_INTENT_FIELDS
        assert set(intent_schema["properties"]) == PRIVATE_INTENT_FIELDS
        assert intent_schema["additionalProperties"] is False
    assert intent_schemas[0]["properties"]["identity_center_kms_key_arn"] != (
        intent_schemas[1]["properties"]["identity_center_kms_key_arn"]
    )
    assert set(ledger_schema["required"]) == PRIVATE_LEDGER_PLAN_FIELDS
    assert set(ledger_schema["properties"]) == PRIVATE_LEDGER_ACTIVE_FIELDS
    assert ledger_schema["additionalProperties"] is False
