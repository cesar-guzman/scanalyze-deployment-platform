"""GUG-218 report-only Lambda authority contract tests."""
from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

from tooling.validate_schema import (
    GUG218_EXPECTED_AUTHORITY_EDGES,
    find_schema_for_fixture,
    validate_fixture,
    validate_gug218_evidence_bundle,
    validate_semantics,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = REPO_ROOT / "schemas"
VALID = REPO_ROOT / "fixtures" / "valid"
INVALID = REPO_ROOT / "fixtures" / "invalid"

ALLOWLIST_SCHEMA = (
    SCHEMAS / "platform-authority-lambda-invocation-allowlist.v1.schema.json"
)
INVENTORY_SCHEMA = (
    SCHEMAS / "platform-authority-lambda-invocation-inventory.v1.schema.json"
)
RECEIPT_SCHEMA = (
    SCHEMAS / "platform-authority-lambda-invocation-guard-receipt.v1.schema.json"
)

ALLOWLIST_FIXTURE = (
    VALID / "platform-authority-lambda-invocation-allowlist-v1-synthetic.json"
)
INVENTORY_FIXTURE = (
    VALID / "platform-authority-lambda-invocation-inventory-v1-synthetic.json"
)
BLOCKED_INVENTORY_FIXTURE = (
    VALID
    / "platform-authority-lambda-invocation-inventory-v1-blocked-access-denied-synthetic.json"
)
OFFLINE_INVENTORY_FIXTURE = (
    VALID
    / "platform-authority-lambda-invocation-inventory-v1-offline-unverified-synthetic.json"
)
RECEIPT_FIXTURE = (
    VALID / "platform-authority-lambda-invocation-guard-receipt-v1-synthetic.json"
)
TRUSTED_EVALUATION_AT = datetime(2026, 7, 20, 10, 2, tzinfo=timezone.utc)
BLOCKED_RECEIPT_FIXTURE = (
    VALID
    / "platform-authority-lambda-invocation-guard-receipt-v1-blocked-access-denied-synthetic.json"
)
OFFLINE_RECEIPT_FIXTURE = (
    VALID
    / "platform-authority-lambda-invocation-guard-receipt-v1-offline-unverified-synthetic.json"
)


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _canonical_digest(value: object) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _validator(path: Path) -> Draft202012Validator:
    schema = _load(path)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _validate(path: Path, instance: dict[str, Any]) -> list[str]:
    instance = _clean(instance)
    _validator(path).validate(instance)
    if (
        path == INVENTORY_SCHEMA
        and instance.get("status") == "REVIEW_SAFE_REPORT_ONLY"
    ):
        return validate_semantics(
            instance,
            path,
            gug218_allowlist=_clean(_load(ALLOWLIST_FIXTURE)),
            evaluation_at=TRUSTED_EVALUATION_AT,
        )
    if (
        path == RECEIPT_SCHEMA
        and instance.get("status") == "PREFLIGHT_PASSED_REVIEW_REQUIRED"
    ):
        return validate_gug218_evidence_bundle(
            allowlist=_clean(_load(ALLOWLIST_FIXTURE)),
            inventory=_clean(_load(INVENTORY_FIXTURE)),
            receipt=instance,
            evaluation_at=TRUSTED_EVALUATION_AT,
        )
    return validate_semantics(instance, path)


def _reseal(instance: dict[str, Any], digest_field: str) -> None:
    instance[digest_field] = _canonical_digest(
        {key: value for key, value in instance.items() if key != digest_field}
    )


def _clean(instance: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value for key, value in instance.items() if key != "_test_metadata"
    }


@pytest.mark.parametrize(
    "schema_path",
    (ALLOWLIST_SCHEMA, INVENTORY_SCHEMA, RECEIPT_SCHEMA),
)
def test_gug218_schemas_are_valid_draft_2020_12(schema_path: Path) -> None:
    _validator(schema_path)


@pytest.mark.parametrize(
    ("schema_path", "fixture_path"),
    (
        (ALLOWLIST_SCHEMA, ALLOWLIST_FIXTURE),
        (INVENTORY_SCHEMA, INVENTORY_FIXTURE),
        (INVENTORY_SCHEMA, BLOCKED_INVENTORY_FIXTURE),
        (INVENTORY_SCHEMA, OFFLINE_INVENTORY_FIXTURE),
        (RECEIPT_SCHEMA, RECEIPT_FIXTURE),
        (RECEIPT_SCHEMA, BLOCKED_RECEIPT_FIXTURE),
        (RECEIPT_SCHEMA, OFFLINE_RECEIPT_FIXTURE),
    ),
)
def test_valid_gug218_fixtures_are_schema_and_semantically_valid(
    schema_path: Path,
    fixture_path: Path,
) -> None:
    assert _validate(schema_path, _load(fixture_path)) == []


@pytest.mark.parametrize(
    "fixture_path",
    tuple(
        sorted(
            INVALID.glob("platform-authority-lambda-invocation-*.json")
        )
    ),
)
def test_negative_gug218_fixtures_fail_closed(fixture_path: Path) -> None:
    schema_path = find_schema_for_fixture(fixture_path.stem, SCHEMAS)
    assert schema_path is not None
    instance = _load(fixture_path)
    try:
        _validator(schema_path).validate(instance)
    except ValidationError:
        return
    semantic_kwargs = {}
    if (
        schema_path.name
        == "platform-authority-lambda-invocation-allowlist-release.v1.schema.json"
    ):
        semantic_kwargs["gug219_collector_contract"] = _load(
            VALID
            / "platform-authority-lambda-invocation-collector-contract-v1-synthetic.json"
        )
    assert validate_semantics(instance, schema_path, **semantic_kwargs)


def test_repository_fixture_validator_uses_reviewed_valid_bundle_context() -> None:
    fixture_path = (
        INVALID
        / "platform-authority-lambda-invocation-inventory-v1-safe-with-access-denied.json"
    )

    passed, message = validate_fixture(fixture_path, INVENTORY_SCHEMA)

    assert passed is False
    assert message.startswith("FAIL:")


def test_allowlist_contains_exactly_twelve_invocation_and_two_trust_edges() -> None:
    allowlist = _load(ALLOWLIST_FIXTURE)
    edges = allowlist["expected_authority_edges"]
    assert len(edges) == 14
    assert sum(edge["authority_class"] == "INVOCATION" for edge in edges) == 12
    assert sum(edge["authority_class"] == "TRUST" for edge in edges) == 2
    observed = {
        (
            edge["authority_class"],
            edge["source_type"],
            edge["duty"],
            edge["target_scope"],
            edge["action"],
            edge["condition_class"],
        )
        for edge in edges
    }
    assert observed == GUG218_EXPECTED_AUTHORITY_EDGES


def test_allowlist_binds_each_trust_to_its_exact_invoker_role() -> None:
    allowlist = _load(ALLOWLIST_FIXTURE)
    edges = allowlist["expected_authority_edges"]
    invocation_role_by_duty = {
        duty: {
            edge["principal_digest"]
            for edge in edges
            if edge["authority_class"] == "INVOCATION" and edge["duty"] == duty
        }
        for duty in ("classifier", "independent_approver")
    }
    assert all(len(values) == 1 for values in invocation_role_by_duty.values())
    assert (
        invocation_role_by_duty["classifier"]
        != invocation_role_by_duty["independent_approver"]
    )
    for edge in edges:
        if edge["authority_class"] == "TRUST":
            assert edge["resource_digest"] in invocation_role_by_duty[edge["duty"]]


@pytest.mark.parametrize(
    "invalid_digest",
    (
        "",
        "sha256:" + "a" * 64,
        "A" * 43,
        "A" * 42 + "==",
    ),
)
def test_allowlist_rejects_non_lambda_code_sha256_encodings(
    invalid_digest: str,
) -> None:
    allowlist = _load(ALLOWLIST_FIXTURE)
    allowlist["broker_artifact_code_sha256"] = invalid_digest
    with pytest.raises(ValidationError):
        _validator(ALLOWLIST_SCHEMA).validate(allowlist)


def test_allowlist_requires_broker_artifact_code_sha256() -> None:
    allowlist = _load(ALLOWLIST_FIXTURE)
    del allowlist["broker_artifact_code_sha256"]
    with pytest.raises(ValidationError):
        _validator(ALLOWLIST_SCHEMA).validate(allowlist)


def test_allowlist_digest_covers_broker_artifact_code_sha256() -> None:
    allowlist = _load(ALLOWLIST_FIXTURE)
    allowlist["broker_artifact_code_sha256"] = "A" * 43 + "="
    assert _validator(ALLOWLIST_SCHEMA).is_valid(allowlist)
    assert any(
        "allowlist_digest" in error
        for error in validate_semantics(allowlist, ALLOWLIST_SCHEMA)
    )


def test_allowlist_requires_exact_collector_role_principal_digest() -> None:
    allowlist = _load(ALLOWLIST_FIXTURE)
    del allowlist["collector_role_principal_digest"]
    with pytest.raises(ValidationError):
        _validator(ALLOWLIST_SCHEMA).validate(allowlist)


def test_collector_role_must_be_distinct_from_both_invoker_duties() -> None:
    allowlist = _load(ALLOWLIST_FIXTURE)
    classifier_edge = next(
        edge
        for edge in allowlist["expected_authority_edges"]
        if edge["duty"] == "classifier"
        and edge["authority_class"] == "INVOCATION"
    )
    allowlist["collector_role_principal_digest"] = classifier_edge[
        "principal_digest"
    ]
    _reseal(allowlist, "allowlist_digest")

    assert _validator(ALLOWLIST_SCHEMA).is_valid(allowlist)
    assert "collector role must remain distinct from both invoker duties" in (
        validate_semantics(allowlist, ALLOWLIST_SCHEMA)
    )


def test_collector_role_binding_is_preserved_across_evidence_chain() -> None:
    allowlist = _load(ALLOWLIST_FIXTURE)
    expected = allowlist["collector_role_principal_digest"]
    for fixture_path in (
        INVENTORY_FIXTURE,
        BLOCKED_INVENTORY_FIXTURE,
        OFFLINE_INVENTORY_FIXTURE,
        RECEIPT_FIXTURE,
        BLOCKED_RECEIPT_FIXTURE,
        OFFLINE_RECEIPT_FIXTURE,
    ):
        assert _load(fixture_path)["collector_principal_digest"] == expected


def test_complete_inventory_proves_every_enabled_region_and_read_surface() -> None:
    inventory = _load(INVENTORY_FIXTURE)
    assert inventory["enabled_region_count"] == inventory["scanned_region_count"]
    assert inventory["enabled_region_count"] > 0
    assert {surface["status"] for surface in inventory["coverage"].values()} == {
        "COMPLETE"
    }
    assert inventory["expected_edge_count"] == 14
    assert inventory["observed_edge_count"] == 14
    assert inventory["prohibited_edge_count"] == 0
    assert inventory["unknown_edge_count"] == 0
    assert inventory["mutating_authority_count"] == 0
    assert inventory["unsupported_policy_semantics_detected"] is False
    assert inventory["structural_drift_detected"] is False


@pytest.mark.parametrize(
    "field",
    ("unsupported_policy_semantics_detected", "structural_drift_detected"),
)
def test_inventory_requires_terminal_classification_flags(field: str) -> None:
    inventory = _load(INVENTORY_FIXTURE)
    del inventory[field]
    with pytest.raises(ValidationError):
        _validator(INVENTORY_SCHEMA).validate(inventory)


@pytest.mark.parametrize("evidence_kind", ("detector_flag", "ambiguous_coverage"))
def test_unsupported_policy_status_requires_explicit_evidence(
    evidence_kind: str,
) -> None:
    inventory = _load(INVENTORY_FIXTURE)
    inventory["status"] = "POLICY_SEMANTICS_UNSUPPORTED"
    if evidence_kind == "detector_flag":
        inventory["unsupported_policy_semantics_detected"] = True
    else:
        inventory["coverage"]["iam_account_authorization"]["status"] = "AMBIGUOUS"
    _reseal(inventory, "inventory_digest")

    assert _validator(INVENTORY_SCHEMA).is_valid(inventory)
    assert validate_semantics(inventory, INVENTORY_SCHEMA) == []


def test_unsupported_policy_status_rejects_unsubstantiated_classification() -> None:
    inventory = _load(INVENTORY_FIXTURE)
    inventory["status"] = "POLICY_SEMANTICS_UNSUPPORTED"
    _reseal(inventory, "inventory_digest")

    assert _validator(INVENTORY_SCHEMA).is_valid(inventory)
    assert any(
        "unsupported policy status requires" in error
        for error in validate_semantics(inventory, INVENTORY_SCHEMA)
    )


def test_drift_inventory_requires_explicit_structural_flag() -> None:
    inventory = _load(INVENTORY_FIXTURE)
    inventory["status"] = "DRIFT_DETECTED"
    _reseal(inventory, "inventory_digest")
    with pytest.raises(ValidationError):
        _validator(INVENTORY_SCHEMA).validate(inventory)

    inventory["structural_drift_detected"] = True
    _reseal(inventory, "inventory_digest")
    assert _validator(INVENTORY_SCHEMA).is_valid(inventory)
    assert validate_semantics(inventory, INVENTORY_SCHEMA) == []


def test_drift_receipt_is_a_fresh_authenticated_terminal_block() -> None:
    receipt = _load(RECEIPT_FIXTURE)
    receipt.update(
        {
            "status": "BLOCKED_DRIFT",
            "reason_code": "AUTHORITY_DRIFT_DETECTED",
            "next_required_control": "RESOLVE_AUTHORITY_DRIFT",
            "expected_authority_exact": False,
        }
    )
    _reseal(receipt, "receipt_digest")

    assert _validator(RECEIPT_SCHEMA).is_valid(receipt)
    assert _validate(RECEIPT_SCHEMA, receipt) == []

    receipt["coverage_complete"] = False
    _reseal(receipt, "receipt_digest")
    with pytest.raises(ValidationError):
        _validator(RECEIPT_SCHEMA).validate(receipt)


@pytest.mark.parametrize(
    ("status", "reason_code", "next_control", "overrides"),
    (
        (
            "PREFLIGHT_PASSED_REVIEW_REQUIRED",
            "EXACT_AUTHORITY_REPORT_ONLY",
            "INDEPENDENT_REVIEW_AND_FRESH_DEPLOYMENT_AUTHORIZATION",
            {},
        ),
        (
            "BLOCKED_UNSAFE_AUTHORITY",
            "UNSAFE_AUTHORITY_PRESENT",
            "REMOVE_UNSAFE_AUTHORITY",
            {"expected_authority_exact": False, "prohibited_edge_count": 1},
        ),
        (
            "BLOCKED_ACCESS_DENIED",
            "READ_ACCESS_DENIED",
            "RESOLVE_ACCESS_DENIAL",
            {
                "coverage_complete": False,
                "expected_authority_exact": False,
                "denied_surface_count": 1,
            },
        ),
        (
            "BLOCKED_INCOMPLETE",
            "INVENTORY_INCOMPLETE",
            "COMPLETE_READ_ONLY_INVENTORY",
            {"coverage_complete": False, "expected_authority_exact": False},
        ),
        (
            "BLOCKED_AMBIGUOUS",
            "AMBIGUOUS_EVIDENCE",
            "RESOLVE_AMBIGUOUS_EVIDENCE",
            {"expected_authority_exact": False, "unknown_edge_count": 1},
        ),
        (
            "BLOCKED_DRIFT",
            "AUTHORITY_DRIFT_DETECTED",
            "RESOLVE_AUTHORITY_DRIFT",
            {"expected_authority_exact": False},
        ),
        (
            "BLOCKED_UNVERIFIED_SOURCE",
            "UNVERIFIED_EVIDENCE_SOURCE",
            "COLLECT_AUTHENTICATED_AWS_INVENTORY",
            {
                "evidence_source_mode": "OFFLINE_UNVERIFIED",
                "coverage_complete": False,
                "expected_authority_exact": False,
                "snapshot_fresh": False,
            },
        ),
    ),
)
def test_receipt_terminal_matrix_is_exact_and_fail_closed(
    status: str,
    reason_code: str,
    next_control: str,
    overrides: dict[str, object],
) -> None:
    receipt = _load(RECEIPT_FIXTURE)
    receipt.update(overrides)
    receipt.update(
        {
            "status": status,
            "reason_code": reason_code,
            "next_required_control": next_control,
        }
    )
    _reseal(receipt, "receipt_digest")

    assert _validator(RECEIPT_SCHEMA).is_valid(receipt)
    assert _validate(RECEIPT_SCHEMA, receipt) == []


def test_offline_evidence_is_explicitly_blocked_even_when_reads_are_complete() -> None:
    inventory = _load(OFFLINE_INVENTORY_FIXTURE)
    receipt = _load(OFFLINE_RECEIPT_FIXTURE)

    assert {surface["status"] for surface in inventory["coverage"].values()} == {
        "COMPLETE"
    }
    assert inventory["evidence_source_mode"] == "OFFLINE_UNVERIFIED"
    assert inventory["status"] == "OFFLINE_UNVERIFIED"
    assert receipt["evidence_source_mode"] == "OFFLINE_UNVERIFIED"
    assert receipt["status"] == "BLOCKED_UNVERIFIED_SOURCE"
    assert receipt["reason_code"] == "UNVERIFIED_EVIDENCE_SOURCE"
    assert receipt["next_required_control"] == "COLLECT_AUTHENTICATED_AWS_INVENTORY"
    assert receipt["coverage_complete"] is False
    assert receipt["expected_authority_exact"] is False
    assert receipt["snapshot_fresh"] is False


@pytest.mark.parametrize(
    ("fixture_path", "schema_path", "pass_status"),
    (
        (INVENTORY_FIXTURE, INVENTORY_SCHEMA, "REVIEW_SAFE_REPORT_ONLY"),
        (RECEIPT_FIXTURE, RECEIPT_SCHEMA, "PREFLIGHT_PASSED_REVIEW_REQUIRED"),
    ),
)
def test_offline_source_mode_cannot_be_spoofed_into_a_pass(
    fixture_path: Path,
    schema_path: Path,
    pass_status: str,
) -> None:
    instance = _load(fixture_path)
    instance["evidence_source_mode"] = "OFFLINE_UNVERIFIED"
    instance["status"] = pass_status
    with pytest.raises(ValidationError):
        _validator(schema_path).validate(instance)


@pytest.mark.parametrize(
    "field",
    (
        "evidence_source_mode",
        "source_snapshot_digest",
        "collector_principal_digest",
        "source_snapshot_started_at",
        "source_snapshot_completed_at",
    ),
)
def test_inventory_requires_authenticated_source_provenance(field: str) -> None:
    inventory = _load(INVENTORY_FIXTURE)
    del inventory[field]
    with pytest.raises(ValidationError):
        _validator(INVENTORY_SCHEMA).validate(inventory)


@pytest.mark.parametrize(
    "field",
    ("source_snapshot_digest", "collector_principal_digest"),
)
def test_inventory_rejects_malformed_provenance_digests(field: str) -> None:
    inventory = _load(INVENTORY_FIXTURE)
    inventory[field] = "sha256:not-a-digest"
    with pytest.raises(ValidationError):
        _validator(INVENTORY_SCHEMA).validate(inventory)


def test_inventory_rejects_source_timestamp_from_the_future() -> None:
    inventory = _load(INVENTORY_FIXTURE)
    inventory["source_snapshot_completed_at"] = "2026-07-20T10:00:01Z"
    _reseal(inventory, "inventory_digest")

    assert _validator(INVENTORY_SCHEMA).is_valid(inventory)
    assert any(
        "monotonic" in error
        for error in validate_semantics(inventory, INVENTORY_SCHEMA)
    )


def test_inventory_rejects_stale_source_snapshot() -> None:
    inventory = _load(INVENTORY_FIXTURE)
    inventory["source_snapshot_started_at"] = "2026-07-20T09:53:00Z"
    inventory["source_snapshot_completed_at"] = "2026-07-20T09:54:00Z"
    _reseal(inventory, "inventory_digest")

    assert _validator(INVENTORY_SCHEMA).is_valid(inventory)
    assert "authenticated source snapshot must not be older than five minutes" in (
        validate_semantics(inventory, INVENTORY_SCHEMA)
    )


def test_inventory_digest_binds_source_snapshot_and_collector() -> None:
    inventory = _load(INVENTORY_FIXTURE)
    inventory["source_snapshot_digest"] = "sha256:" + "1" * 64
    inventory["collector_principal_digest"] = "sha256:" + "2" * 64

    assert _validator(INVENTORY_SCHEMA).is_valid(inventory)
    assert "inventory_digest must cover the complete sanitized snapshot" in (
        validate_semantics(inventory, INVENTORY_SCHEMA)
    )


@pytest.mark.parametrize(
    "field",
    (
        "evidence_source_mode",
        "source_snapshot_digest",
        "collector_principal_digest",
        "source_snapshot_started_at",
        "source_snapshot_completed_at",
        "reason_code",
    ),
)
def test_receipt_requires_bound_source_provenance(field: str) -> None:
    receipt = _load(RECEIPT_FIXTURE)
    del receipt[field]
    with pytest.raises(ValidationError):
        _validator(RECEIPT_SCHEMA).validate(receipt)


def test_receipt_rejects_future_source_timestamp() -> None:
    receipt = _load(RECEIPT_FIXTURE)
    receipt["source_snapshot_completed_at"] = "2026-07-20T10:01:11Z"
    _reseal(receipt, "receipt_digest")

    assert _validator(RECEIPT_SCHEMA).is_valid(receipt)
    assert any(
        "expire after its decision" in error
        for error in validate_semantics(receipt, RECEIPT_SCHEMA)
    )


def test_receipt_rejects_stale_source_snapshot() -> None:
    receipt = _load(RECEIPT_FIXTURE)
    receipt["source_snapshot_started_at"] = "2026-07-20T09:44:00Z"
    receipt["source_snapshot_completed_at"] = "2026-07-20T09:45:00Z"
    _reseal(receipt, "receipt_digest")

    assert _validator(RECEIPT_SCHEMA).is_valid(receipt)
    assert "guard receipt cannot rely on stale source evidence" in (
        validate_semantics(receipt, RECEIPT_SCHEMA)
    )


@pytest.mark.parametrize(
    ("target_scope", "principal_kind", "condition_class", "reason_code"),
    (
        ("UNQUALIFIED_FUNCTION", "LOCAL_ROLE", "MISSING", "UNQUALIFIED_FUNCTION"),
        ("LATEST_VERSION", "LOCAL_ROLE", "MISSING", "LATEST_VERSION"),
        ("NUMERIC_VERSION", "LOCAL_ROLE", "MISSING", "NUMERIC_VERSION"),
        ("ALTERNATE_ALIAS", "LOCAL_ROLE", "MISSING", "ALTERNATE_ALIAS"),
        ("WILDCARD", "WILDCARD", "WILDCARD", "WILDCARD_RESOURCE"),
        ("UNQUALIFIED_FUNCTION", "PUBLIC", "MISSING", "PUBLIC_PRINCIPAL"),
        ("UNQUALIFIED_FUNCTION", "CROSS_ACCOUNT", "MISSING", "CROSS_ACCOUNT_PRINCIPAL"),
        ("UNQUALIFIED_FUNCTION", "SERVICE", "MISSING", "SERVICE_PRINCIPAL"),
        ("UNQUALIFIED_FUNCTION", "FEDERATED", "MISSING", "FEDERATED_PRINCIPAL"),
    ),
)
def test_unsafe_authority_can_never_retain_report_safe_status(
    target_scope: str,
    principal_kind: str,
    condition_class: str,
    reason_code: str,
) -> None:
    inventory = _load(INVENTORY_FIXTURE)
    edge = inventory["authority_edges"][0]
    edge.update(
        {
            "duty": "none",
            "target_scope": target_scope,
            "condition_class": condition_class,
            "principal_kind": principal_kind,
            "verdict": "PROHIBITED",
            "reason_code": reason_code,
        }
    )
    inventory["expected_edge_count"] = 13
    inventory["prohibited_edge_count"] = 1
    _reseal(inventory, "inventory_digest")

    assert _validator(INVENTORY_SCHEMA).is_valid(inventory)
    errors = validate_semantics(inventory, INVENTORY_SCHEMA)
    assert any("report-only safe" in error for error in errors)


@pytest.mark.parametrize(
    ("source_type", "action_class", "reason_code"),
    (
        ("LAMBDA_AUTHORITY_MUTATION", "MUTATE_LAMBDA_AUTHORITY", "AUTHORITY_MUTATION"),
        ("IAM_AUTHORITY_MUTATION", "MUTATE_IAM_AUTHORITY", "AUTHORITY_MUTATION"),
        (
            "CLOUDFORMATION_AUTHORITY",
            "MUTATE_CLOUDFORMATION_AUTHORITY",
            "AUTHORITY_MUTATION",
        ),
        ("EVENT_SOURCE_MAPPING", "EVENT_SOURCE_INVOKE", "EVENT_SOURCE_MAPPING"),
    ),
)
def test_alternate_mutation_and_event_paths_are_never_allowlisted(
    source_type: str,
    action_class: str,
    reason_code: str,
) -> None:
    inventory = _load(INVENTORY_FIXTURE)
    edge = inventory["authority_edges"][0]
    edge.update(
        {
            "authority_class": "AUTHORITY_MUTATION",
            "source_type": source_type,
            "duty": "none",
            "target_scope": "UNQUALIFIED_FUNCTION",
            "action_class": action_class,
            "condition_class": "UNSUPPORTED",
            "principal_kind": "LOCAL_ROLE",
            "verdict": "PROHIBITED",
            "reason_code": reason_code,
        }
    )
    inventory["expected_edge_count"] = 13
    inventory["prohibited_edge_count"] = 1
    inventory["mutating_authority_count"] = 1
    _reseal(inventory, "inventory_digest")

    assert _validator(INVENTORY_SCHEMA).is_valid(inventory)
    assert validate_semantics(inventory, INVENTORY_SCHEMA)


@pytest.mark.parametrize(
    "coverage_status",
    ("ACCESS_DENIED", "INCOMPLETE", "AMBIGUOUS"),
)
def test_denied_incomplete_or_ambiguous_read_never_proves_safe(
    coverage_status: str,
) -> None:
    inventory = _load(INVENTORY_FIXTURE)
    inventory["coverage"]["iam_account_authorization"]["status"] = coverage_status
    _reseal(inventory, "inventory_digest")

    assert _validator(INVENTORY_SCHEMA).is_valid(inventory)
    assert "report-only safe status requires complete read coverage" in validate_semantics(
        inventory,
        INVENTORY_SCHEMA,
    )


def test_inventory_requires_a_fresh_five_minute_maximum_snapshot() -> None:
    inventory = _load(INVENTORY_FIXTURE)
    completed = datetime.fromisoformat(
        inventory["scan_completed_at"].replace("Z", "+00:00")
    )
    inventory["expires_at"] = (
        completed + timedelta(minutes=5, seconds=1)
    ).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    _reseal(inventory, "inventory_digest")

    assert _validator(INVENTORY_SCHEMA).is_valid(inventory)
    assert "inventory evidence lifetime must not exceed five minutes" in (
        validate_semantics(inventory, INVENTORY_SCHEMA)
    )


def test_safe_inventory_requires_reviewed_allowlist_and_trusted_clock() -> None:
    inventory = _clean(_load(INVENTORY_FIXTURE))

    errors = validate_semantics(inventory, INVENTORY_SCHEMA)

    assert "report-only safe status requires the reviewed allowlist context" in errors
    assert any("trusted timezone-aware evaluation_at" in error for error in errors)


def test_safe_inventory_rejects_public_principal_even_when_resealed() -> None:
    inventory = _clean(_load(INVENTORY_FIXTURE))
    inventory["authority_edges"][0]["principal_kind"] = "PUBLIC"
    _reseal(inventory, "inventory_digest")

    errors = validate_semantics(
        inventory,
        INVENTORY_SCHEMA,
        gug218_allowlist=_clean(_load(ALLOWLIST_FIXTURE)),
        evaluation_at=TRUSTED_EVALUATION_AT,
    )

    assert "report-only safe status requires the exact fourteen authority edges" in errors


@pytest.mark.parametrize(
    "evaluation_at",
    (
        datetime(2026, 7, 20, 10, 0, 59, tzinfo=timezone.utc),
        datetime(2026, 7, 20, 10, 6, tzinfo=timezone.utc),
        datetime(2036, 7, 20, 10, 2, tzinfo=timezone.utc),
    ),
)
def test_safe_inventory_rejects_future_or_expired_evaluation(
    evaluation_at: datetime,
) -> None:
    errors = validate_semantics(
        _clean(_load(INVENTORY_FIXTURE)),
        INVENTORY_SCHEMA,
        gug218_allowlist=_clean(_load(ALLOWLIST_FIXTURE)),
        evaluation_at=evaluation_at,
    )

    assert any(
        marker in error
        for error in errors
        for marker in (
            "cannot be accepted before collection completes",
            "evidence is expired at evaluation time",
        )
    )


def test_complete_evidence_bundle_is_valid_at_trusted_time() -> None:
    assert validate_gug218_evidence_bundle(
        allowlist=_clean(_load(ALLOWLIST_FIXTURE)),
        inventory=_clean(_load(INVENTORY_FIXTURE)),
        receipt=_clean(_load(RECEIPT_FIXTURE)),
        evaluation_at=TRUSTED_EVALUATION_AT,
    ) == []


def test_pass_receipt_rejects_detached_blocked_inventory() -> None:
    receipt = _clean(_load(RECEIPT_FIXTURE))
    blocked = _clean(_load(BLOCKED_INVENTORY_FIXTURE))
    receipt["inventory_digest"] = blocked["inventory_digest"]
    _reseal(receipt, "receipt_digest")

    errors = validate_gug218_evidence_bundle(
        allowlist=_clean(_load(ALLOWLIST_FIXTURE)),
        inventory=blocked,
        receipt=receipt,
        evaluation_at=TRUSTED_EVALUATION_AT,
    )

    assert any("must match the bound inventory decision" in error for error in errors)


@pytest.mark.parametrize(
    ("fixture_path", "schema_path", "digest_field"),
    (
        (ALLOWLIST_FIXTURE, ALLOWLIST_SCHEMA, "allowlist_digest"),
        (INVENTORY_FIXTURE, INVENTORY_SCHEMA, "inventory_digest"),
        (RECEIPT_FIXTURE, RECEIPT_SCHEMA, "receipt_digest"),
    ),
)
def test_complete_record_digests_reject_tampering(
    fixture_path: Path,
    schema_path: Path,
    digest_field: str,
) -> None:
    instance = _load(fixture_path)
    instance["target_region"] = "us-west-2"
    errors = validate_semantics(instance, schema_path)
    assert any(digest_field in error for error in errors)


@pytest.mark.parametrize(
    "raw_field",
    ("account_id", "caller_arn", "function_url", "policy_document", "profile"),
)
def test_sanitized_inventory_rejects_raw_identity_and_policy_fields(
    raw_field: str,
) -> None:
    inventory = _load(INVENTORY_FIXTURE)
    inventory[raw_field] = "synthetic-raw-value"
    with pytest.raises(ValidationError):
        _validator(INVENTORY_SCHEMA).validate(inventory)


def test_receipts_are_report_only_even_when_preflight_passes() -> None:
    for fixture_path in (
        RECEIPT_FIXTURE,
        BLOCKED_RECEIPT_FIXTURE,
        OFFLINE_RECEIPT_FIXTURE,
    ):
        receipt = _load(fixture_path)
        assert receipt["production"] is False
        assert receipt["aws_mutation_performed"] is False
        assert receipt["lambda_invocation_performed"] is False
        assert receipt["deployment_authorized"] is False
        assert receipt["live_retirement_authorized"] is False


def test_get_policy_scope_is_exact_function_plus_qualifiers_only() -> None:
    policy = _load(
        REPO_ROOT
        / "policies"
        / "iam"
        / "platform-authority-lambda-invocation-inventory-role.json"
    )
    statement = next(
        statement
        for statement in policy["Statement"]
        if statement.get("Action") == ["lambda:GetPolicy"]
    )
    assert statement["Resource"] == [
        "arn:${aws_partition}:lambda:${region}:${authority_account_id}:function:${broker_function_name}",
        "arn:${aws_partition}:lambda:${region}:${authority_account_id}:function:${broker_function_name}:*",
    ]
    assert all(
        not resource.endswith("${broker_function_name}*")
        for resource in statement["Resource"]
    )


def test_serialized_contracts_do_not_expose_raw_cloud_identifiers() -> None:
    serialized = json.dumps(
        {
            "allowlist": _load(ALLOWLIST_FIXTURE),
            "inventory": _load(INVENTORY_FIXTURE),
            "receipt": _load(RECEIPT_FIXTURE),
        },
        sort_keys=True,
    )
    for forbidden in (
        "arn:",
        "https://",
        "@example.com",
        "111122223333",
        "AWSReservedSSO_",
        "synthetic-profile",
    ):
        assert forbidden not in serialized


def test_fixture_prefixes_resolve_to_the_additive_v1_schemas() -> None:
    expected = {
        "platform-authority-lambda-invocation-allowlist-v1-synthetic": ALLOWLIST_SCHEMA,
        "platform-authority-lambda-invocation-inventory-v1-synthetic": INVENTORY_SCHEMA,
        "platform-authority-lambda-invocation-guard-receipt-v1-synthetic": RECEIPT_SCHEMA,
    }
    for fixture_name, schema_path in expected.items():
        assert find_schema_for_fixture(fixture_name, SCHEMAS) == schema_path
