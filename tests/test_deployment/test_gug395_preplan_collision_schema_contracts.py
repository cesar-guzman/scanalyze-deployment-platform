"""Schema and semantic ceilings for the public collision-probe receipt."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

from jsonschema import Draft202012Validator
import pytest

from tooling import platform_authority_gug395_preplan_collision_probe as subject
from tooling import validate_schema as schema_validator


ROOT = Path(__file__).resolve().parents[2]
SCHEMA = (
    ROOT
    / "schemas/platform-authority-gug395-preplan-collision-probe-receipt.v1.schema.json"
)
VALID_SYNTHETIC = (
    ROOT
    / "fixtures/valid/"
    "platform-authority-gug395-preplan-collision-probe-receipt-v1-synthetic.json"
)
VALID_BLOCKED = (
    ROOT
    / "fixtures/valid/"
    "platform-authority-gug395-preplan-collision-probe-receipt-v1-"
    "blocked-live-attempt.json"
)
INVALID_DIR = ROOT / "fixtures/invalid"
PREFIX = "platform-authority-gug395-preplan-collision-probe-receipt-v1-"
INVALID_EXPECTATIONS = {
    "production-overclaim.json": "COLLISION_PUBLIC_RECEIPT_SCOPE_INVALID",
    "mutation-overclaim.json": "COLLISION_PUBLIC_RECEIPT_SCOPE_INVALID",
    "impossible-counts.json": "COLLISION_PUBLIC_COUNT_INVALID",
    "unstable-absent-overclaim.json": (
        "COLLISION_PUBLIC_CLASSIFICATION_OVERCLAIM"
    ),
    "collision-ready-overclaim.json": (
        "COLLISION_PUBLIC_CLASSIFICATION_OVERCLAIM"
    ),
    "duplicate-snapshot.json": "COLLISION_PUBLIC_SESSION_BINDING_INVALID",
    "private-value-leak.json": "COLLISION_PUBLIC_RECEIPT_FIELDS_INVALID",
    "over-budget.json": "COLLISION_PUBLIC_COUNTER_INVALID",
}
SCHEMA_VALID_SEMANTIC_FAILURES = {"impossible-counts.json"}


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    value.pop("_test_metadata", None)
    return value


def _reseal(receipt: dict[str, Any]) -> None:
    receipt.pop("receipt_digest", None)
    receipt["receipt_digest"] = subject.canonical_digest(receipt)


def _live_receipt(classification: str) -> dict[str, Any]:
    receipt = copy.deepcopy(_load(VALID_SYNTHETIC))
    receipt.update(
        status="LIVE_READ_ONLY_PROBE_RECORDED",
        evidence_scope="LIVE_PROVIDER_DIGEST_ONLY",
        classification=classification,
        provider_calls=8,
        aws_calls=8,
        session_bootstrap_attempts=4,
        credential_vending_calls=4,
        network_calls=12,
        page_calls=6,
        projected_response_bytes=1024,
        modeled_cost_usd_upper="0.000061024",
        cost_status="WITHIN_REVIEWED_BOUND",
        live_provider_evidence=True,
    )
    if classification == subject.ABSENT_READY:
        receipt.update(
            provider_implementation_gate="READY_FOR_PROVIDER_IMPLEMENTATION",
            authority_classification=subject.ABSENT_READY,
            identity_center_classification=subject.ABSENT_READY,
            authority_collision_count=0,
            identity_center_collision_count=0,
            collision_count=0,
            evidence_complete=True,
            evidence_stable=True,
            reconciliation_only=False,
        )
    elif classification == subject.COLLISION_BLOCKED:
        receipt.update(
            provider_implementation_gate="BLOCKED_COLLISION",
            authority_classification=subject.COLLISION_BLOCKED,
            identity_center_classification=subject.ABSENT_READY,
            authority_collision_count=1,
            identity_center_collision_count=0,
            collision_count=1,
            evidence_complete=True,
            evidence_stable=True,
            reconciliation_only=False,
        )
    else:
        receipt.update(
            provider_implementation_gate="BLOCKED_RECONCILIATION_REQUIRED",
            authority_classification=subject.UNCERTAIN,
            identity_center_classification=subject.UNCERTAIN,
            authority_collision_count=0,
            identity_center_collision_count=0,
            collision_count=0,
            evidence_complete=False,
            evidence_stable=False,
            reconciliation_only=True,
        )
    _reseal(receipt)
    return receipt


def test_synthetic_receipt_passes_schema_core_and_global_semantics() -> None:
    receipt = _load(VALID_SYNTHETIC)

    assert schema_validator.validate_fixture(VALID_SYNTHETIC, SCHEMA) == (
        True,
        "PASS",
    )
    subject.validate_public_collision_probe_receipt(receipt)
    assert schema_validator.validate_semantics(receipt, SCHEMA) == []


def test_blocked_live_attempt_passes_schema_core_and_global_semantics() -> None:
    receipt = _load(VALID_BLOCKED)

    assert schema_validator.validate_fixture(VALID_BLOCKED, SCHEMA) == (
        True,
        "PASS",
    )
    subject.validate_public_collision_probe_receipt(receipt)
    assert schema_validator.validate_semantics(receipt, SCHEMA) == []
    assert receipt["aws_calls"] is None
    assert receipt["network_calls"] is None
    assert receipt["modeled_cost_usd_upper"] is None
    assert receipt["cost_status"] == "INCOMPLETE_UNBOUNDED"


def test_schema_is_exact_and_seals_reviewed_ceilings() -> None:
    schema = _load(SCHEMA)
    fixture = _load(VALID_SYNTHETIC)

    assert schema["additionalProperties"] is False
    assert set(fixture) == set(schema["required"])
    assert schema["properties"]["provider_calls"]["maximum"] == (
        subject.MAX_PROVIDER_CALLS
    )
    assert schema["properties"]["network_calls"]["maximum"] == (
        subject.MAX_NETWORK_CALLS
    )
    assert schema["properties"]["page_calls"]["maximum"] == (
        subject.MAX_PAGE_CALLS
    )
    assert schema["properties"]["projected_response_bytes"]["maximum"] == (
        subject.MAX_TOTAL_RESPONSE_BYTES
    )
    for field in (
        "authority_session_digests",
        "identity_center_session_digests",
        "authority_snapshot_digests",
        "identity_center_snapshot_digests",
    ):
        assert schema["properties"][field] == {"$ref": "#/$defs/digestList"}
    assert schema["$defs"]["digestList"]["minItems"] == 0
    assert schema["$defs"]["digestList"]["maxItems"] == 2
    assert schema["$defs"]["digestList"]["uniqueItems"] is True
    assert schema["$defs"]["digestPair"]["uniqueItems"] is True
    assert schema["properties"]["session_bootstrap_attempts"]["maximum"] == 4
    assert "LIVE_READ_ONLY_PROBE_BLOCKED" in schema["properties"]["status"][
        "enum"
    ]
    assert "LIVE_ATTEMPT_DIGEST_ONLY" in schema["properties"][
        "evidence_scope"
    ]["enum"]
    assert "INCOMPLETE_UNBOUNDED" in schema["properties"]["cost_status"][
        "enum"
    ]


def test_only_blocked_live_attempt_may_use_partial_digest_lists() -> None:
    schema = Draft202012Validator(_load(SCHEMA))
    blocked = _load(VALID_BLOCKED)
    blocked["authority_session_digests"] = [
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ]
    blocked["authority_snapshot_digests"] = [
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    ]
    _reseal(blocked)

    schema.validate(blocked)

    synthetic = _load(VALID_SYNTHETIC)
    synthetic["authority_session_digests"].pop()
    _reseal(synthetic)
    assert list(schema.iter_errors(synthetic))

    success = _live_receipt(subject.ABSENT_READY)
    success["authority_snapshot_digests"].pop()
    _reseal(success)
    assert list(schema.iter_errors(success))


def test_blocked_live_attempt_cannot_claim_complete_or_live_evidence() -> None:
    schema = Draft202012Validator(_load(SCHEMA))
    receipt = _load(VALID_BLOCKED)
    receipt.update(
        evidence_complete=True,
        evidence_stable=True,
        live_provider_evidence=True,
        reconciliation_only=False,
    )
    _reseal(receipt)

    assert list(schema.iter_errors(receipt))


@pytest.mark.parametrize("classification", sorted(subject.CLASSIFICATIONS))
def test_live_receipt_shape_accepts_the_closed_classification_lattice(
    classification: str,
) -> None:
    receipt = _live_receipt(classification)

    Draft202012Validator(_load(SCHEMA)).validate(receipt)
    subject.validate_public_collision_probe_receipt(receipt)
    assert schema_validator.validate_semantics(receipt, SCHEMA) == []


def test_uncertain_global_result_preserves_a_stable_domain_collision() -> None:
    receipt = _live_receipt(subject.UNCERTAIN)
    receipt.update(
        authority_classification=subject.COLLISION_BLOCKED,
        authority_collision_count=1,
        collision_count=1,
    )
    _reseal(receipt)

    Draft202012Validator(_load(SCHEMA)).validate(receipt)
    subject.validate_public_collision_probe_receipt(receipt)
    assert schema_validator.validate_semantics(receipt, SCHEMA) == []


def test_synthetic_receipt_cannot_overclaim_live_evidence() -> None:
    receipt = _load(VALID_SYNTHETIC)
    receipt.update(
        provider_calls=1,
        aws_calls=1,
        network_calls=1,
        live_provider_evidence=True,
    )
    _reseal(receipt)

    assert list(Draft202012Validator(_load(SCHEMA)).iter_errors(receipt))
    with pytest.raises(
        subject.CollisionProbeError,
        match="COLLISION_PUBLIC_SYNTHETIC_OVERCLAIM",
    ):
        subject.validate_public_collision_probe_receipt(receipt)


@pytest.mark.parametrize(
    ("suffix", "expected_code"),
    tuple(INVALID_EXPECTATIONS.items()),
)
def test_invalid_fixtures_are_resealed_and_fail_the_named_invariant(
    suffix: str,
    expected_code: str,
) -> None:
    path = INVALID_DIR / f"{PREFIX}{suffix}"
    receipt = _load(path)
    body = {key: value for key, value in receipt.items() if key != "receipt_digest"}
    assert receipt["receipt_digest"] == subject.canonical_digest(body)

    shape_errors = list(Draft202012Validator(_load(SCHEMA)).iter_errors(receipt))
    assert bool(shape_errors) is (suffix not in SCHEMA_VALID_SEMANTIC_FAILURES)
    with pytest.raises(subject.CollisionProbeError, match=expected_code):
        subject.validate_public_collision_probe_receipt(receipt)
    assert schema_validator.validate_semantics(receipt, SCHEMA) == [
        f"GUG-395 collision-probe receipt invalid: {expected_code}"
    ]
    passed, _ = schema_validator.validate_fixture(path, SCHEMA)
    assert passed is False


def test_global_validator_maps_all_collision_probe_fixtures_without_skips() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "tooling/validate_schema.py",
            "--schemas-dir",
            "schemas",
            "--fixtures-dir",
            "fixtures",
            "--filter",
            "platform-authority-gug395-preplan-collision-probe",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "SKIP:" not in completed.stdout
    assert completed.stdout.count("  PASS:") == 2
    assert completed.stdout.count("  EXPECTED FAIL:") == len(
        INVALID_EXPECTATIONS
    )
