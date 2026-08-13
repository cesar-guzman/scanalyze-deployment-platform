"""Semantic regression tests for durable GUG-365 cross-boundary artifacts."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from tooling.validate_schema import validate_fixture, validate_semantics
from tooling import platform_authority_gug365_phase_execution_ledger as phase_ledger


ROOT = Path(__file__).resolve().parents[2]
SCHEMA = (
    ROOT
    / "schemas/platform-authority-retirement-entrypoint-service-role-plan.v1.schema.json"
)
VALID = (
    ROOT
    / "fixtures/valid/platform-authority-retirement-entrypoint-service-role-plan-v1-synthetic.json"
)
PHASE_LEDGER_SCHEMA = (
    ROOT / "schemas/platform-authority-gug365-phase-execution-ledger.v1.schema.json"
)
PHASE_LEDGER_VALID = (
    ROOT
    / "fixtures/valid/platform-authority-gug365-phase-execution-ledger-v1-synthetic.json"
)


def _digest(value: object) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


@pytest.fixture()
def plan() -> dict[str, object]:
    value = json.loads(VALID.read_text(encoding="utf-8"))
    value.pop("_test_metadata")
    assert validate_semantics(value, SCHEMA) == []
    return value


def _reseal(plan: dict[str, object], section: str, digest_field: str) -> None:
    plan[digest_field] = _digest(plan[section])
    plan["plan_digest"] = _digest(
        {key: value for key, value in plan.items() if key != "plan_digest"}
    )


def _reseal_complete_plan(plan: dict[str, object]) -> None:
    """Model a hostile but internally digest-consistent plan rewrite."""

    for boundary in plan["boundaries"]:
        boundary["document_digest"] = _digest(boundary["document"])
    for write in plan["planned_iam_writes"]:
        write["request_digest"] = _digest(write["request"])
    for phase in plan["authorization_phases"]:
        policy = phase["executor_policy"]
        policy["document_digest"] = _digest(policy["document"])
        phase["executor_policy_digest"] = _digest(policy)
        requirement = phase["executor_effective_authority_requirement"]
        requirement["required_policy_document_digest"] = policy[
            "document_digest"
        ]
        phase["executor_effective_authority_requirement_digest"] = _digest(
            requirement
        )
        for mutation in phase["mutations"]:
            mutation["request_digest"] = _digest(mutation["request"])
        for operation in phase["operations"]:
            if "request" in operation:
                operation["request_digest"] = _digest(operation["request"])
        phase["mutation_digest"] = _digest(phase["mutations"])
        phase["operation_digest"] = _digest(phase["operations"])
        phase["checkpoint_digest"] = _digest(phase["checkpoint"])
    revocation = plan["revocation"]
    policy = revocation["executor_policy"]
    policy["document_digest"] = _digest(policy["document"])
    revocation["executor_policy_digest"] = _digest(policy)
    requirement = revocation["executor_effective_authority_requirement"]
    requirement["required_policy_document_digest"] = policy["document_digest"]
    revocation["executor_effective_authority_requirement_digest"] = _digest(
        requirement
    )
    for mutation in revocation["mutations"]:
        mutation["request_digest"] = _digest(mutation["request"])
    for operation in revocation["operations"]:
        if "request" in operation:
            operation["request_digest"] = _digest(operation["request"])
    revocation["mutation_digest"] = _digest(revocation["mutations"])
    revocation["operation_digest"] = _digest(revocation["operations"])

    section_digests = {
        "boundaries": "boundary_set_digest",
        "child_role_boundary_assignments": (
            "child_role_boundary_assignment_digest"
        ),
        "service_role": "service_role_digest",
        "child_roles": "child_role_set_digest",
        "ledger_table": "ledger_table_digest",
        "broker_function": "broker_function_digest",
        "ledger_factory_function": "ledger_factory_function_digest",
        "ledger_factory_log_group": "ledger_factory_log_group_digest",
        "authorization_phases": "authorization_phase_digest",
        "revocation": "revocation_digest",
        "planned_iam_writes": "planned_iam_write_digest",
        "planned_readbacks": "planned_readback_digest",
    }
    for section, digest_field in section_digests.items():
        plan[digest_field] = _digest(plan[section])
    plan["plan_digest"] = _digest(
        {key: value for key, value in plan.items() if key != "plan_digest"}
    )


def test_valid_durable_fixture_passes_shape_and_semantics() -> None:
    assert validate_fixture(VALID, SCHEMA) == (True, "PASS")


@pytest.mark.parametrize(
    "mutation",
    [
        "alternate_iam_action",
        "swapped_boundary",
        "qualified_factory_drift",
        "ledger_tag_drift",
        "kms_manager_drift",
        "pagination_drift",
        "section_digest_drift",
    ],
)
def test_semantics_reject_every_cross_boundary_drift(
    plan: dict[str, object], mutation: str
) -> None:
    value = copy.deepcopy(plan)
    if mutation == "alternate_iam_action":
        value["planned_iam_writes"][0]["allowed_action"] = "iam:CreateUser"
        _reseal(value, "planned_iam_writes", "planned_iam_write_digest")
    elif mutation == "swapped_boundary":
        assignments = value["child_role_boundary_assignments"]
        assignments[0]["boundary_arn"], assignments[1]["boundary_arn"] = (
            assignments[1]["boundary_arn"],
            assignments[0]["boundary_arn"],
        )
        _reseal(
            value,
            "child_role_boundary_assignments",
            "child_role_boundary_assignment_digest",
        )
    elif mutation == "qualified_factory_drift":
        value["ledger_factory_causal_receipt_gate"][
            "qualified_function_arn"
        ] += ":2"
        value["plan_digest"] = _digest(
            {key: item for key, item in value.items() if key != "plan_digest"}
        )
    elif mutation == "ledger_tag_drift":
        value["ledger_table"]["tags"][0]["Value"] = "cloudformation"
        _reseal(value, "ledger_table", "ledger_table_digest")
    elif mutation == "kms_manager_drift":
        value["ledger_table"]["kms_key_contract"]["metadata_projection"][
            "KeyManager"
        ] = "CUSTOMER"
        _reseal(value, "ledger_table", "ledger_table_digest")
    elif mutation == "pagination_drift":
        readback = next(
            item
            for item in value["planned_readbacks"]
            if item["service"] == "dynamodb"
            and item["api_action"] == "ListTagsOfResource"
        )
        readback["complete_pagination_required"] = False
        _reseal(value, "planned_readbacks", "planned_readback_digest")
    else:
        assert mutation == "section_digest_drift"
        value["ledger_table"]["billing_mode"] = "PROVISIONED"
        value["plan_digest"] = _digest(
            {key: item for key, item in value.items() if key != "plan_digest"}
        )

    assert validate_semantics(value, SCHEMA), mutation


def test_resealed_iam_wildcard_policy_is_rejected_by_exact_repo_contract(
    plan: dict[str, object],
) -> None:
    """A fully resealed iam:* / Resource:* grant must still fail closed."""

    value = copy.deepcopy(plan)
    value["authorization_phases"][0]["executor_policy"]["document"] = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ResealedBroadAuthority",
                "Effect": "Allow",
                "Action": "iam:*",
                "Resource": "*",
            }
        ],
    }
    _reseal_complete_plan(value)

    errors = validate_semantics(value, SCHEMA)
    assert any("executor policy is not the exact repo contract" in e for e in errors)


@pytest.mark.parametrize(
    "mutation",
    ["boundary_document", "create_request", "phase_operation"],
)
def test_resealed_contract_layers_cannot_replace_repo_authority(
    plan: dict[str, object], mutation: str
) -> None:
    value = copy.deepcopy(plan)
    if mutation == "boundary_document":
        value["boundaries"][0]["document"] = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ResealedBroadAuthority",
                    "Effect": "Allow",
                    "Action": "iam:*",
                    "Resource": "*",
                }
            ],
        }
    elif mutation == "create_request":
        replacement = '{"Statement":[{"Action":"iam:*","Effect":"Allow","Resource":"*"}],"Version":"2012-10-17"}'
        value["planned_iam_writes"][0]["request"][
            "PolicyDocument"
        ] = replacement
        phase = value["authorization_phases"][0]
        phase["mutations"][0]["request"]["PolicyDocument"] = replacement
        operation = next(
            item
            for item in phase["operations"]
            if item.get("planned_write_sequence") == 1
        )
        operation["request"]["PolicyDocument"] = replacement
    else:
        assert mutation == "phase_operation"
        value["authorization_phases"][0]["operations"][0]["request"] = {
            "resealed": True
        }
    _reseal_complete_plan(value)

    assert validate_semantics(value, SCHEMA), mutation


def test_package_receipt_and_executor_evidence_are_digest_closed() -> None:
    cases = [
        (
            ROOT
            / "fixtures/valid/platform-authority-retirement-ledger-factory-package-v1-synthetic.json",
            ROOT
            / "schemas/platform-authority-retirement-ledger-factory-package.v1.schema.json",
            "manifest_digest",
        ),
        (
            ROOT
            / "fixtures/valid/platform-authority-retirement-ledger-factory-receipt-v1-synthetic.json",
            ROOT
            / "schemas/platform-authority-retirement-ledger-factory-receipt.v1.schema.json",
            "receipt_sha256",
        ),
        (
            ROOT
            / "fixtures/valid/platform-authority-gug365-executor-authority-evidence-v1-synthetic.json",
            ROOT
            / "schemas/platform-authority-gug365-executor-authority-evidence.v1.schema.json",
            "evidence_digest",
        ),
    ]
    for fixture, schema, digest_field in cases:
        assert validate_fixture(fixture, schema) == (True, "PASS")
        value = json.loads(fixture.read_text(encoding="utf-8"))
        value.pop("_test_metadata")
        value[digest_field] = "sha256:" + "0" * 64
        assert validate_semantics(value, schema)


def test_phase_ledger_fixture_closes_root_claim_and_terminal_receipt() -> None:
    assert validate_fixture(PHASE_LEDGER_VALID, PHASE_LEDGER_SCHEMA) == (
        True,
        "PASS",
    )
    record = json.loads(PHASE_LEDGER_VALID.read_text(encoding="utf-8"))
    record.pop("_test_metadata")
    claim = record["claim"]
    terminal = record["receipt_chain"][-1]
    assert phase_ledger.validate_consumed_causal_record(
        record,
        expected_plan_digest=record["plan_digest"],
        expected_bundle_digest=record["bundle_digest"],
        expected_phase=record["phase"],
        expected_ledger_id=record["ledger_id"],
        expected_initial_ledger_digest=record["initial_ledger_digest"],
        expected_claim_nonce_digest=claim["claim_nonce_digest"],
        expected_terminal_receipt_digest=terminal["receipt_digest"],
    ) == record["ledger_digest"]
    for field in (
        "expected_ledger_id",
        "expected_initial_ledger_digest",
        "expected_claim_nonce_digest",
        "expected_terminal_receipt_digest",
    ):
        arguments = {
            "expected_plan_digest": record["plan_digest"],
            "expected_bundle_digest": record["bundle_digest"],
            "expected_phase": record["phase"],
            "expected_ledger_id": record["ledger_id"],
            "expected_initial_ledger_digest": record["initial_ledger_digest"],
            "expected_claim_nonce_digest": claim["claim_nonce_digest"],
            "expected_terminal_receipt_digest": terminal["receipt_digest"],
        }
        arguments[field] = "sha256:" + "0" * 64
        with pytest.raises(phase_ledger.PhaseLedgerError):
            phase_ledger.validate_consumed_causal_record(record, **arguments)


def test_phase_ledger_invalid_fixtures_reject_reseal_replay_and_chain_drift() -> None:
    invalid = sorted(
        (ROOT / "fixtures/invalid").glob(
            "platform-authority-gug365-phase-execution-ledger-v1-*.json"
        )
    )
    assert len(invalid) == 4
    expected_codes = {
        "ambiguous-overclaim": "RECONCILIATION_RECEIPT_INVALID",
        "corrupt-receipt-chain": "RECEIPT_CAUSAL_SOURCE_MISMATCH",
        "resealed-replay-overclaim": "LEDGER_STATE_INVALID",
        "stale-root-binding": "INITIAL_LEDGER_DIGEST_MISMATCH",
    }
    for fixture in invalid:
        passed, message = validate_fixture(fixture, PHASE_LEDGER_SCHEMA)
        assert passed is False, fixture.name
        assert message.startswith("FAIL:"), fixture.name
        expected = next(
            code
            for fragment, code in expected_codes.items()
            if fragment in fixture.name
        )
        assert expected in message, fixture.name
