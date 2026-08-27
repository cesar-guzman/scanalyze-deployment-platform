"""Schema and semantic ceilings for the public GUG-393 receipt."""

from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
import pytest

from tooling.validate_schema import validate_fixture, validate_semantics
from tooling import (
    platform_authority_gug393_private_input_discovery as discovery,
)


ROOT = Path(__file__).resolve().parents[2]
SCHEMA = (
    ROOT / "schemas/platform-authority-gug393-discovery-receipt.v1.schema.json"
)
VALID = (
    ROOT
    / "fixtures/valid/platform-authority-gug393-discovery-receipt-v1-synthetic.json"
)
OVER_CAP = (
    ROOT
    / "fixtures/invalid/platform-authority-gug393-discovery-receipt-v1-over-cap.json"
)
EXPECTED_MAXIMUMS = {
    "provider_calls": 5_000,
    "credential_vending_calls": 6,
    "network_calls": 5_006,
    "page_calls": 4_300,
    "projected_response_bytes": 33_554_432,
}


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _digest(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + sha256(payload).hexdigest()


def test_valid_receipt_passes_schema_and_semantics() -> None:
    assert validate_fixture(VALID, SCHEMA) == (True, "PASS")


def test_schema_seals_closed_receipt_ceilings() -> None:
    schema = _load(SCHEMA)

    assert {
        field: schema["properties"][field]["maximum"]
        for field in EXPECTED_MAXIMUMS
    } == EXPECTED_MAXIMUMS
    assert schema["properties"]["aws_calls"]["maximum"] == 5_000


def test_exact_receipt_ceilings_are_inclusive() -> None:
    receipt = _load(VALID)
    receipt.update(
        {
            "provider_calls": 5_000,
            "credential_vending_calls": 6,
            "network_calls": 5_006,
            "page_calls": 4_300,
            "projected_response_bytes": 33_554_432,
            "aws_calls": 5_000,
        }
    )
    receipt["receipt_digest"] = _digest(
        {key: value for key, value in receipt.items() if key != "receipt_digest"}
    )

    Draft202012Validator(_load(SCHEMA)).validate(receipt)
    assert validate_semantics(receipt, SCHEMA) == []


def test_resealed_over_cap_receipt_fails_shape_and_semantics() -> None:
    receipt = _load(OVER_CAP)
    assert receipt["receipt_digest"] == _digest(
        {key: value for key, value in receipt.items() if key != "receipt_digest"}
    )

    validator = Draft202012Validator(_load(SCHEMA))
    schema_error_paths = {
        str(error.path[0]) for error in validator.iter_errors(receipt) if error.path
    }
    assert set(EXPECTED_MAXIMUMS) <= schema_error_paths
    assert "aws_calls" in schema_error_paths

    semantic_errors = validate_semantics(receipt, SCHEMA)
    assert semantic_errors == [
        f"GUG-393 {field} must not exceed {maximum}"
        for field, maximum in EXPECTED_MAXIMUMS.items()
    ]

    with pytest.raises(
        discovery.PrivateInputDiscoveryError,
        match="PUBLIC_DISCOVERY_RECEIPT_INVALID",
    ):
        discovery.validate_public_discovery_receipt(receipt)

    passed, message = validate_fixture(OVER_CAP, SCHEMA)
    assert passed is False
    assert "greater than the maximum" in message
