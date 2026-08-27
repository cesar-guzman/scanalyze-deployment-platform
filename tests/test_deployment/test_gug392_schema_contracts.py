from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from tooling.platform_authority_gug365_upstream_inventory import canonical_digest
from tooling.validate_schema import validate_fixture
from tooling.platform_authority_gug376_live_executor import (
    LiveExecutorError,
    validate_live_public_handoff,
    validate_live_run_record,
)


ROOT = Path(__file__).parents[2]
V1_RUN_SCHEMA = (
    ROOT / "schemas/platform-authority-gug376-live-readonly-run.v1.schema.json"
)
V1_HANDOFF_SCHEMA = (
    ROOT / "schemas/platform-authority-gug376-live-readonly-handoff.v1.schema.json"
)
V2_RUN_SCHEMA = (
    ROOT / "schemas/platform-authority-gug376-live-readonly-run.v2.schema.json"
)
V2_HANDOFF_SCHEMA = (
    ROOT / "schemas/platform-authority-gug376-live-readonly-handoff.v2.schema.json"
)
V1_HANDOFF_FIXTURE = (
    ROOT
    / "fixtures/valid/platform-authority-gug376-live-readonly-handoff-v1-synthetic.json"
)
V2_RUN_FIXTURE = (
    ROOT
    / "fixtures/valid/platform-authority-gug376-live-readonly-run-v2-contract-example.json"
)
V2_HANDOFF_FIXTURE = (
    ROOT
    / "fixtures/valid/platform-authority-gug376-live-readonly-handoff-v2-contract-example.json"
)

V2_FIELDS = {
    "request_digest",
    "checkpoint_digest",
    "approval_reference_digest",
    "authority_classification",
    "identity_center_classification",
    "evidence_manifest_digest",
    "sealed_at",
}


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _validator(path: Path) -> Draft202012Validator:
    schema = _load(path)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {key for item in value.values() for key in _keys(item)}
    if isinstance(value, list):
        return {key for item in value for key in _keys(item)}
    return set()


@pytest.mark.parametrize(
    ("v1_path", "v2_path"),
    [
        (V1_RUN_SCHEMA, V2_RUN_SCHEMA),
        (V1_HANDOFF_SCHEMA, V2_HANDOFF_SCHEMA),
    ],
)
def test_v2_is_exactly_v1_required_fields_plus_live_bindings(
    v1_path: Path, v2_path: Path
) -> None:
    v1 = _load(v1_path)
    v2 = _load(v2_path)

    assert set(v2["required"]) == set(v1["required"]) | V2_FIELDS
    assert set(v2["required"]) - set(v1["required"]) == V2_FIELDS
    assert V2_FIELDS.isdisjoint(v1["properties"])
    assert V2_FIELDS <= set(v2["properties"])
    assert v1["additionalProperties"] is v2["additionalProperties"] is False


def test_v2_run_keeps_v1_array_contracts() -> None:
    v1 = _load(V1_RUN_SCHEMA)
    v2 = _load(V2_RUN_SCHEMA)

    for field in (
        "authority_snapshot_digests",
        "identity_center_snapshot_digests",
        "authority_session_digests",
    ):
        assert v2["properties"][field] == v1["properties"][field]
    identity_sessions = v2["properties"]["identity_center_session_digests"]
    assert identity_sessions["type"] == "array"
    assert identity_sessions["uniqueItems"] is True
    assert identity_sessions["items"] == v1["properties"][
        "identity_center_session_digests"
    ]["items"]
    assert identity_sessions["oneOf"] == [
        {"minItems": 2, "maxItems": 2},
        {"minItems": 4, "maxItems": 4},
    ]
    for definition in ("digest", "gitSha", "twoDigests"):
        assert v2["$defs"][definition] == v1["$defs"][definition]


def test_v2_live_run_and_handoff_fixtures_validate_and_are_linked() -> None:
    run = _load(V2_RUN_FIXTURE)
    handoff = _load(V2_HANDOFF_FIXTURE)
    run_validator = _validator(V2_RUN_SCHEMA)
    handoff_validator = _validator(V2_HANDOFF_SCHEMA)

    assert not list(run_validator.iter_errors(run))
    assert not list(handoff_validator.iter_errors(handoff))
    assert validate_live_run_record(run) == run
    assert validate_live_public_handoff(handoff) == handoff
    assert set(run) == set(_load(V2_RUN_SCHEMA)["required"])
    assert set(handoff) == set(_load(V2_HANDOFF_SCHEMA)["required"])

    assert run["run_digest"] == canonical_digest(
        {key: value for key, value in run.items() if key != "run_digest"}
    )
    assert handoff["handoff_digest"] == canonical_digest(
        {key: value for key, value in handoff.items() if key != "handoff_digest"}
    )
    assert handoff["run_digest"] == run["run_digest"]
    assert run["provider_calls"] == run["aws_calls"] > 0
    assert handoff["provider_calls"] == handoff["aws_calls"] > 0

    shared_fields = set(handoff) - {"record_type", "handoff_digest", "run_digest"}
    assert {field: handoff[field] for field in shared_fields} == {
        field: run[field] for field in shared_fields
    }

    digest_arrays = (
        run["authority_snapshot_digests"],
        run["identity_center_snapshot_digests"],
        run["authority_session_digests"],
        run["identity_center_session_digests"],
    )
    assert [len(values) for values in digest_arrays] == [2, 2, 2, 2]
    assert all(len(values) == len(set(values)) for values in digest_arrays)
    assert set(run["authority_snapshot_digests"]).isdisjoint(
        run["identity_center_snapshot_digests"]
    )
    assert set(run["authority_session_digests"]).isdisjoint(
        run["identity_center_session_digests"]
    )


def test_schema_tool_applies_v2_runtime_call_count_semantics() -> None:
    mismatch = (
        ROOT
        / "fixtures/invalid/"
        "platform-authority-gug376-live-readonly-run-v2-call-count-mismatch.json"
    )
    passed, message = validate_fixture(mismatch, V2_RUN_SCHEMA)
    assert passed is False
    assert "RUN_RECORD_V2_INVALID" in message


@pytest.mark.parametrize(
    ("schema_path", "fixture_name"),
    [
        (
            V2_RUN_SCHEMA,
            "platform-authority-gug376-live-readonly-run-v2-invalid-timestamp.json",
        ),
        (
            V2_HANDOFF_SCHEMA,
            "platform-authority-gug376-live-readonly-handoff-v2-invalid-timestamp.json",
        ),
    ],
)
def test_schema_tool_rejects_impossible_v2_timestamp(
    schema_path: Path, fixture_name: str
) -> None:
    fixture_path = ROOT / "fixtures/invalid" / fixture_name
    passed, message = validate_fixture(fixture_path, schema_path)

    assert passed is False
    assert "date-time" in message or "INVALID" in message


@pytest.mark.parametrize(
    ("schema_path", "fixture_path", "expected_paths"),
    [
        (
            V2_RUN_SCHEMA,
            ROOT
            / "fixtures/invalid/platform-authority-gug376-live-readonly-run-v2-zero-calls.json",
            {"provider_calls", "aws_calls"},
        ),
        (
            V2_HANDOFF_SCHEMA,
            ROOT
            / "fixtures/invalid/platform-authority-gug376-live-readonly-handoff-v2-overclaim.json",
            {"deployment_authorized"},
        ),
        (
            V2_HANDOFF_SCHEMA,
            ROOT
            / (
                "fixtures/invalid/"
                "platform-authority-gug376-live-readonly-handoff-v2-sensitive-leak.json"
            ),
            set(),
        ),
    ],
)
def test_invalid_v2_fixtures_fail_closed(
    schema_path: Path, fixture_path: Path, expected_paths: set[str]
) -> None:
    errors = list(_validator(schema_path).iter_errors(_load(fixture_path)))

    assert errors
    if expected_paths:
        assert expected_paths <= {str(error.path[0]) for error in errors if error.path}
    else:
        assert any(error.validator == "additionalProperties" for error in errors)


@pytest.mark.parametrize(
    ("schema_path", "fixture_path"),
    [
        (V2_RUN_SCHEMA, V2_RUN_FIXTURE),
        (V2_HANDOFF_SCHEMA, V2_HANDOFF_FIXTURE),
    ],
)
@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        ("status", "LIVE_INVENTORY_NOT_PROVEN"),
        ("classification", "SYNTHETIC_VALIDATED"),
        ("provider_calls", 0),
        ("aws_calls", 0),
        ("evidence_complete", False),
        ("evidence_stable", False),
        ("live_provider_evidence", False),
        ("read_only", False),
        ("aws_mutations", 1),
        ("reconciliation_only", True),
        ("deployment_authorized", True),
        ("two_human_status", "PROVEN"),
        ("independent_approval_present", True),
        ("production_status", "GO"),
        ("authority_classification", "EXACT_PRESENT_NO_TOUCH"),
        ("authority_classification", "DRIFT_BLOCKED_NO_REPAIR"),
        ("authority_classification", "UNCERTAIN_RECONCILE_ONLY"),
        ("identity_center_classification", "UNCERTAIN_RECONCILE_ONLY"),
    ],
)
def test_v2_rejects_incomplete_unstable_nonlive_or_overclaimed_receipts(
    schema_path: Path, fixture_path: Path, field: str, invalid_value: object
) -> None:
    fixture = copy.deepcopy(_load(fixture_path))
    fixture[field] = invalid_value

    assert list(_validator(schema_path).iter_errors(fixture))


def test_v2_run_rejects_causally_unreachable_three_identity_sessions() -> None:
    fixture = copy.deepcopy(_load(V2_RUN_FIXTURE))
    fixture["identity_center_session_digests"].append(
        canonical_digest("third-identity-session")
    )
    fixture["run_digest"] = canonical_digest(
        {key: value for key, value in fixture.items() if key != "run_digest"}
    )

    assert list(_validator(V2_RUN_SCHEMA).iter_errors(fixture))
    with pytest.raises(LiveExecutorError, match="RUN_RECORD_V2_INVALID"):
        validate_live_run_record(fixture)


@pytest.mark.parametrize(
    ("classification", "session_count"),
    [
        ("ABSENT_READY", 4),
        ("EXACT_PRESENT_NO_TOUCH", 2),
    ],
)
def test_v2_run_rejects_impossible_identity_classification_session_pairs(
    classification: str, session_count: int
) -> None:
    fixture = copy.deepcopy(_load(V2_RUN_FIXTURE))
    fixture["identity_center_classification"] = classification
    fixture["identity_center_session_digests"] = [
        canonical_digest(f"identity-session-{index}")
        for index in range(1, session_count + 1)
    ]
    fixture["run_digest"] = canonical_digest(
        {key: value for key, value in fixture.items() if key != "run_digest"}
    )

    assert list(_validator(V2_RUN_SCHEMA).iter_errors(fixture))
    with pytest.raises(LiveExecutorError, match="RUN_RECORD_V2_INVALID"):
        validate_live_run_record(fixture)


def test_v1_remains_valid_and_cannot_be_promoted_to_v2() -> None:
    v1_fixture = _load(V1_HANDOFF_FIXTURE)
    v2_fixture = _load(V2_HANDOFF_FIXTURE)
    v1_validator = _validator(V1_HANDOFF_SCHEMA)
    v2_validator = _validator(V2_HANDOFF_SCHEMA)

    assert not list(v1_validator.iter_errors(v1_fixture))
    assert list(v2_validator.iter_errors(v1_fixture))
    assert list(v1_validator.iter_errors(v2_fixture))
    assert v1_fixture["classification"] == "SYNTHETIC_VALIDATED"
    assert v1_fixture["live_provider_evidence"] is False
    assert v1_fixture["aws_calls"] == 0


@pytest.mark.parametrize("fixture_path", [V2_RUN_FIXTURE, V2_HANDOFF_FIXTURE])
def test_public_v2_fixtures_contain_only_sanitized_digest_evidence(
    fixture_path: Path,
) -> None:
    fixture = _load(fixture_path)
    forbidden_keys = {
        "account_id",
        "principal_arn",
        "profile_name",
        "region",
        "access_key",
        "secret_access_key",
        "session_token",
        "email",
        "private_root",
        "private_path",
        "request_id",
        "next_token",
        "provider_payload",
        "raw_response",
    }
    serialized = json.dumps(fixture, sort_keys=True, separators=(",", ":"))

    assert forbidden_keys.isdisjoint(_keys(fixture))
    assert "arn:aws:" not in serialized
    assert "AWSReservedSSO" not in serialized
