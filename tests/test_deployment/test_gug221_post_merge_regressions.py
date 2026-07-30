"""Regression coverage for GUG-221 post-merge contract review findings."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator

import tooling.platform_authority_lambda_audit_repair_change_set as change_set
from tooling.validate_schema import validate_semantics


REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = REPO_ROOT / "schemas"
FIXTURE_ROOT = REPO_ROOT / "fixtures" / "valid"
PEP_TEMPLATE = (
    REPO_ROOT / "bootstrap" / "cfn-platform-authority-lambda-audit-repair-pep.yaml"
)
PEP_CHANGE_SET_SCHEMA = (
    SCHEMA_ROOT
    / "platform-authority-lambda-audit-repair-pep-change-set-receipt.v1.schema.json"
)
PEP_CHANGE_SET_FIXTURE = (
    "platform-authority-lambda-audit-repair-pep-change-set-receipt-v1-synthetic.json"
)


def _fixture(name: str) -> dict:
    return json.loads((FIXTURE_ROOT / name).read_text(encoding="utf-8"))


def _canonical_digest(value: dict) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _schema_errors(instance: dict, schema: Path) -> list[str]:
    document = json.loads(schema.read_text(encoding="utf-8"))
    return [error.message for error in Draft202012Validator(document).iter_errors(instance)]


def _schema_resource_inventory(schema: dict) -> list[tuple[str, str]]:
    refs = schema["$defs"]["change_set"]["properties"]["resource_changes"][
        "prefixItems"
    ]
    inventory: list[tuple[str, str]] = []
    for item in refs:
        definition_name = item["$ref"].removeprefix("#/$defs/")
        typed = schema["$defs"][definition_name]["allOf"][1]["properties"]
        inventory.append(
            (
                typed["logical_resource_id"]["const"],
                typed["resource_type"]["const"],
            )
        )
    return inventory


def _initial_ledger_binding(ledger: dict) -> dict:
    fields = (
        "schema_version",
        "record_type",
        "repair_id",
        "intent_digest",
        "source_commit",
        "original_gug220_ledger_digest",
        "authority_account_id",
        "management_account_id",
        "region",
        "plan_function_version",
        "repair_function_version",
        "repair_not_before",
        "repair_not_after",
        "planned_state_digest",
        "provider_immutable",
        "claim_condition",
        "mutation_retry_attempted",
        "production_authorized",
        "planned_at",
    )
    binding = {field: ledger[field] for field in fields}
    binding.update(
        {
            "status": "PLAN_VERIFIED",
            "stage": "PLAN_STATE_VERIFIED",
            "effects_attempted": 0,
            "effects_completed": 0,
            "state_digest": ledger["planned_state_digest"],
        }
    )
    return binding


def _plan_ledger() -> dict:
    ledger = _fixture(
        "platform-authority-lambda-audit-repair-broker-ledger-v1-synthetic.json"
    )
    ledger.update(
        {
            "status": "PLAN_VERIFIED",
            "stage": "PLAN_STATE_VERIFIED",
            "effects_attempted": 0,
            "effects_completed": 0,
        }
    )
    ledger.pop("claimed_at")
    ledger.pop("updated_at")
    ledger["ledger_digest"] = _canonical_digest(_initial_ledger_binding(ledger))
    return ledger


def test_plan_verified_ledger_is_accepted_by_semantic_validation() -> None:
    ledger = _plan_ledger()
    schema = (
        SCHEMA_ROOT
        / "platform-authority-lambda-audit-repair-broker-ledger.v1.schema.json"
    )

    assert _schema_errors(ledger, schema) == []
    assert validate_semantics(ledger, schema) == []

    invalid_transition = dict(ledger, stage="BEFORE_FIRST_EFFECT")
    assert any(
        "status, stage, and counters" in error
        for error in validate_semantics(invalid_transition, schema)
    )

    ledger["source_commit"] = "b" * 40
    errors = validate_semantics(ledger, schema)
    assert any("ledger_digest" in error for error in errors)


def test_durable_plan_receipt_is_accepted_and_legacy_unproven_shape_is_rejected() -> None:
    receipt = _fixture(
        "platform-authority-lambda-audit-repair-broker-receipt-v1-synthetic.json"
    )
    receipt.update(
        {
            "mode": "plan",
            "status": "PLAN_VERIFIED",
            "function_version": "6",
            "function_qualifier": "plan-v1",
            "effects_attempted": 0,
            "effects_completed": 0,
            "mutation_attribution": "PROVEN_BY_DURABLE_LEDGER",
            "required_next_action": "INVOKE_REPAIR_ALIAS",
            "ledger_digest": _plan_ledger()["ledger_digest"],
        }
    )
    schema = (
        SCHEMA_ROOT
        / "platform-authority-lambda-audit-repair-broker-receipt.v1.schema.json"
    )

    assert _schema_errors(receipt, schema) == []
    assert validate_semantics(receipt, schema) == []

    receipt.update(
        {
            "ledger_digest": None,
            "mutation_attribution": "UNPROVEN",
            "required_next_action": "NONE",
        }
    )
    assert _schema_errors(receipt, schema)
    assert validate_semantics(receipt, schema)


def test_pep_change_set_inventory_matches_template_schema_and_fixture_exactly() -> None:
    schema = json.loads(PEP_CHANGE_SET_SCHEMA.read_text(encoding="utf-8"))
    fixture = _fixture(PEP_CHANGE_SET_FIXTURE)
    _, template_resources = change_set._template_contract(
        PEP_TEMPLATE.read_bytes()
    )
    expected = list(template_resources.items())
    schema_inventory = _schema_resource_inventory(schema)
    fixture_inventory = [
        (item["logical_resource_id"], item["resource_type"])
        for item in fixture["change_set"]["resource_changes"]
    ]

    assert len(expected) == 23
    assert schema["$defs"]["change_set"]["properties"]["resource_changes"][
        "minItems"
    ] == 23
    assert schema["$defs"]["change_set"]["properties"]["resource_changes"][
        "maxItems"
    ] == 23
    assert schema_inventory == expected
    assert fixture_inventory == expected
    assert _schema_errors(fixture, PEP_CHANGE_SET_SCHEMA) == []


def test_pep_change_set_inventory_rejects_missing_and_extra_resources() -> None:
    receipt = _fixture(PEP_CHANGE_SET_FIXTURE)

    missing = deepcopy(receipt)
    missing["change_set"]["resource_changes"].pop()
    assert _schema_errors(missing, PEP_CHANGE_SET_SCHEMA)

    extra = deepcopy(receipt)
    extra["change_set"]["resource_changes"].append(
        {
            "logical_resource_id": "UnexpectedResource",
            "resource_type": "AWS::IAM::Role",
            "action": "Add",
            "replacement": "False",
        }
    )
    assert _schema_errors(extra, PEP_CHANGE_SET_SCHEMA)


def test_pep_execution_contract_is_required_and_closed() -> None:
    receipt = _fixture(PEP_CHANGE_SET_FIXTURE)
    assert _schema_errors(receipt, PEP_CHANGE_SET_SCHEMA) == []

    missing = deepcopy(receipt)
    missing.pop("execution_contract")
    assert _schema_errors(missing, PEP_CHANGE_SET_SCHEMA)

    unexpected = deepcopy(receipt)
    unexpected["execution_contract"]["change_set_sha256"] = "f" * 64
    assert _schema_errors(unexpected, PEP_CHANGE_SET_SCHEMA)

    malformed = deepcopy(receipt)
    malformed["execution_contract"]["client_request_token"] = (
        "gug221-a-" + "a" * 48
    )
    assert _schema_errors(malformed, PEP_CHANGE_SET_SCHEMA)
