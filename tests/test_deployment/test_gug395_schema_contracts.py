from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys

from jsonschema import Draft202012Validator
import pytest

from tooling import platform_authority_gug395_preplan_seed as subject
from tooling import validate_schema as schema_validator


REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = REPO_ROOT / "fixtures"
SCHEMAS = REPO_ROOT / "schemas"


def _load(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    value.pop("_test_metadata", None)
    return value


def _valid(name: str) -> dict[str, object]:
    return _load(FIXTURES / "valid" / name)


def _reseal(record: dict[str, object], field: str) -> None:
    record.pop(field, None)
    record[field] = subject.canonical_digest(record)


def test_valid_synthetic_receipts_pass_shape_validators() -> None:
    subject.validate_preplan_seed_receipt_shape(
        _valid("platform-authority-gug395-preplan-seed-receipt-v1-synthetic.json")
    )
    subject.validate_downstream_materialization_receipt_shape(
        _valid(
            "platform-authority-gug395-downstream-materialization-receipt-v1-synthetic.json"
        )
    )


def test_synthetic_seed_shape_cannot_validate_as_materialized() -> None:
    receipt = _valid(
        "platform-authority-gug395-preplan-seed-receipt-v1-synthetic.json"
    )
    with pytest.raises(
        subject.PreplanSeedError, match="SOURCE_VERIFICATION_REQUIRED"
    ):
        subject.validate_preplan_seed_receipt(receipt)


def test_synthetic_downstream_shape_cannot_validate_as_certified() -> None:
    receipt = _valid(
        "platform-authority-gug395-downstream-materialization-receipt-v1-synthetic.json"
    )
    with pytest.raises(
        subject.PreplanSeedError,
        match="TERMINAL_HANDOFF_VERIFICATION_REQUIRED",
    ):
        subject.validate_downstream_materialization_receipt(receipt)


def test_seed_schema_separates_synthetic_from_materialized_mode() -> None:
    schema = _load(
        SCHEMAS / "platform-authority-gug395-preplan-seed-receipt.v1.schema.json"
    )
    validator = Draft202012Validator(schema)
    synthetic = _valid(
        "platform-authority-gug395-preplan-seed-receipt-v1-synthetic.json"
    )
    assert not list(validator.iter_errors(synthetic))

    materialized = copy.deepcopy(synthetic)
    materialized.update(
        status="PRIVATE_PREPLAN_SEED_MATERIALIZED",
        evidence_scope="OFFLINE_DIGEST_ONLY",
        verified_source_capability_present=True,
    )
    _reseal(materialized, "receipt_digest")
    assert not list(validator.iter_errors(materialized))

    crossed = copy.deepcopy(materialized)
    crossed["evidence_scope"] = "SYNTHETIC_SCHEMA_EXAMPLE"
    _reseal(crossed, "receipt_digest")
    assert list(validator.iter_errors(crossed))
    with pytest.raises(
        subject.PreplanSeedError, match="SEED_RECEIPT_SCOPE_INVALID"
    ):
        subject.validate_preplan_seed_receipt_shape(crossed)


def test_downstream_schema_separates_synthetic_from_ready_mode() -> None:
    schema = _load(
        SCHEMAS
        / "platform-authority-gug395-downstream-materialization-receipt.v1.schema.json"
    )
    validator = Draft202012Validator(schema)
    synthetic = _valid(
        "platform-authority-gug395-downstream-materialization-receipt-v1-synthetic.json"
    )
    assert not list(validator.iter_errors(synthetic))

    ready = copy.deepcopy(synthetic)
    ready.update(
        status="READY_FOR_GUG365_FRESH_CHECKPOINT",
        evidence_scope="CERTIFIED_PRIVATE_HANDOFF_DIGEST_ONLY",
        checkpoint_builder_status="MATERIALIZED_FROM_VERIFIED_TERMINAL_HANDOFF",
        certified_terminal_capability_present=True,
    )
    ready["private_manifest_digest"] = subject.canonical_digest(
        subject._downstream_receipt_private_projection(ready)
    )
    _reseal(ready, "receipt_digest")
    assert not list(validator.iter_errors(ready))
    subject.validate_downstream_materialization_receipt_shape(ready)

    crossed = copy.deepcopy(ready)
    crossed["evidence_scope"] = "SYNTHETIC_SCHEMA_EXAMPLE"
    _reseal(crossed, "receipt_digest")
    assert list(validator.iter_errors(crossed))
    with pytest.raises(
        subject.PreplanSeedError, match="DOWNSTREAM_RECEIPT_SCOPE_INVALID"
    ):
        subject.validate_downstream_materialization_receipt_shape(crossed)


def test_global_semantic_validator_accepts_shape_only_for_synthetic() -> None:
    seed_receipt = _valid(
        "platform-authority-gug395-preplan-seed-receipt-v1-synthetic.json"
    )
    downstream_receipt = _valid(
        "platform-authority-gug395-downstream-materialization-receipt-v1-synthetic.json"
    )
    assert not schema_validator._validate_gug395_public_receipt(
        seed_receipt, downstream=False
    )
    assert not schema_validator._validate_gug395_public_receipt(
        downstream_receipt, downstream=True
    )

    seed_receipt.update(
        status="PRIVATE_PREPLAN_SEED_MATERIALIZED",
        evidence_scope="OFFLINE_DIGEST_ONLY",
        verified_source_capability_present=True,
    )
    _reseal(seed_receipt, "receipt_digest")
    assert schema_validator._validate_gug395_public_receipt(
        seed_receipt, downstream=False
    ) == ["GUG-395 receipt contract invalid: SOURCE_VERIFICATION_REQUIRED"]

    downstream_receipt.update(
        status="READY_FOR_GUG365_FRESH_CHECKPOINT",
        evidence_scope="CERTIFIED_PRIVATE_HANDOFF_DIGEST_ONLY",
        checkpoint_builder_status="MATERIALIZED_FROM_VERIFIED_TERMINAL_HANDOFF",
        certified_terminal_capability_present=True,
    )
    downstream_receipt["private_manifest_digest"] = subject.canonical_digest(
        subject._downstream_receipt_private_projection(downstream_receipt)
    )
    _reseal(downstream_receipt, "receipt_digest")
    assert schema_validator._validate_gug395_public_receipt(
        downstream_receipt, downstream=True
    ) == [
        "GUG-395 receipt contract invalid: "
        "TERMINAL_HANDOFF_VERIFICATION_REQUIRED"
    ]


@pytest.mark.parametrize(
    ("schema_name", "fixture_name"),
    (
        (
            "platform-authority-gug395-preplan-seed-receipt.v1.schema.json",
            "platform-authority-gug395-preplan-seed-receipt-v1-synthetic.json",
        ),
        (
            "platform-authority-gug395-downstream-materialization-receipt.v1.schema.json",
            "platform-authority-gug395-downstream-materialization-receipt-v1-synthetic.json",
        ),
    ),
)
def test_receipts_match_exact_schema_required_fields(
    schema_name: str, fixture_name: str
) -> None:
    schema = _load(SCHEMAS / schema_name)
    fixture = _valid(fixture_name)
    assert set(fixture) == set(schema["required"])
    assert schema["additionalProperties"] is False


def test_resealed_phase_splice_breaks_private_manifest_binding() -> None:
    receipt = _valid(
        "platform-authority-gug395-downstream-materialization-receipt-v1-synthetic.json"
    )
    original = copy.deepcopy(receipt)
    receipt["phase_certification_digests"][0] = subject.canonical_digest(
        {"foreign_run": True}
    )
    assert receipt["phase_certification_digests"] != original[
        "phase_certification_digests"
    ]
    _reseal(receipt, "receipt_digest")
    with pytest.raises(
        subject.PreplanSeedError,
        match="DOWNSTREAM_RECEIPT_PRIVATE_MANIFEST_MISMATCH",
    ):
        subject.validate_downstream_materialization_receipt_shape(receipt)


def test_resealed_premature_gug365_claim_fails_closed() -> None:
    receipt = _valid(
        "platform-authority-gug395-downstream-materialization-receipt-v1-synthetic.json"
    )
    receipt["gug365_plan_materialized"] = True
    receipt["gug365_plan_status"] = "MATERIALIZED"
    _reseal(receipt, "receipt_digest")
    with pytest.raises(
        subject.PreplanSeedError, match="DOWNSTREAM_RECEIPT_SCOPE_INVALID"
    ):
        subject.validate_downstream_materialization_receipt_shape(receipt)


def test_global_validator_maps_all_gug395_fixtures_without_skips() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "tooling/validate_schema.py",
            "--schemas-dir",
            "schemas",
            "--fixtures-dir",
            "fixtures",
            "--filter",
            "platform-authority-gug395",
        ],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "SKIP:" not in completed.stdout
    assert completed.stdout.count("  PASS:") == 2
    assert completed.stdout.count("  EXPECTED FAIL:") == 7
