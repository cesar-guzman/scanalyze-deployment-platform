"""Fail-closed tests for externally anchored ACCOUNT_READY v2 evidence."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

from tooling.verify_account_ready import canonical_digest, verify_account_ready


REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPO_ROOT / "schemas" / "account-ready.v2.schema.json"
SCRIPT_PATH = REPO_ROOT / "tooling" / "verify_account_ready.py"
CUSTOMER_ID = "cust_01J5A1B2C3D4E5F6G7H8J9K0M1"
OTHER_CUSTOMER_ID = "cust_01J5A1B2C3D4E5F6G7H8J9K0M2"
DEPLOYMENT_ID = "dep_01J5A1B2C3D4E5F6G7H8J9K0M1"
OTHER_DEPLOYMENT_ID = "dep_01J5A1B2C3D4E5F6G7H8J9K0M2"
ACCOUNT_ID = "111222333444"
OTHER_ACCOUNT_ID = "999888777666"
ROLE_NAMES = {
    "plan": "ScanalyzeCustomer-Plan",
    "apply": "ScanalyzeCustomer-Apply",
    "identity_plan": "ScanalyzeCustomer-Identity-Plan",
    "identity_apply": "ScanalyzeCustomer-Identity-Apply",
    "promotion": "ScanalyzeCustomer-Promotion",
    "validation": "ScanalyzeCustomer-Validation",
    "diagnostic": "ScanalyzeCustomer-Diagnostic",
    "state_recovery": "ScanalyzeCustomer-StateRecovery",
}
EXPECTED_CONTROLS = {
    "state_versioning_enabled": True,
    "state_default_encryption": "aws:kms",
    "state_bucket_key_enabled": True,
    "state_public_access_blocked": True,
    "state_object_lock_enabled": False,
    "native_lockfile_enabled": True,
}


@pytest.fixture
def schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _make_contract(
    *,
    partition: str = "aws",
    region: str = "us-east-1",
    account_id: str = ACCOUNT_ID,
) -> dict:
    role_tags = {
        "customer_id_tag": CUSTOMER_ID,
        "deployment_id_tag": DEPLOYMENT_ID,
        "account_id_tag": account_id,
        "region_tag": region,
        "environment_tag": "sandbox",
    }
    contract = {
        "schema_version": "2",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "account_id": account_id,
        "region": region,
        "environment": "sandbox",
        "baseline_version": "v2.0.0",
        "provisioned_at": "2026-08-16T00:00:00Z",
        "roles": {
            role: {
                "arn": f"arn:{partition}:iam::{account_id}:role/{name}",
                **role_tags,
            }
            for role, name in ROLE_NAMES.items()
        },
        "state_infrastructure": {
            "state_bucket": (
                f"arn:{partition}:s3:::scanalyze-{account_id}-tf-state"
            ),
            "evidence_bucket": (
                f"arn:{partition}:s3:::scanalyze-{account_id}-tf-evidence"
            ),
            "contracts_bucket": (
                f"arn:{partition}:s3:::scanalyze-{account_id}-contracts"
            ),
            "state_kms_key": (
                f"arn:{partition}:kms:{region}:{account_id}:"
                "key/00000000-0000-0000-0000-000000000001"
            ),
            "evidence_kms_key": (
                f"arn:{partition}:kms:{region}:{account_id}:"
                "key/00000000-0000-0000-0000-000000000002"
            ),
            "contracts_kms_key": (
                f"arn:{partition}:kms:{region}:{account_id}:"
                "key/00000000-0000-0000-0000-000000000003"
            ),
        },
        "controls": copy.deepcopy(EXPECTED_CONTROLS),
    }
    contract["contract_digest"] = canonical_digest(contract)
    return contract


def _make_anchor(contract: dict) -> dict:
    return {
        "customer_id": contract["customer_id"],
        "deployment_id": contract["deployment_id"],
        "account_id": contract["account_id"],
        "region": contract["region"],
        "environment": contract["environment"],
        "baseline_version": contract["baseline_version"],
        "expected_contract_digest": contract["contract_digest"],
    }


def _refresh_digest(contract: dict, anchor: dict) -> None:
    contract["contract_digest"] = canonical_digest(contract)
    anchor["expected_contract_digest"] = contract["contract_digest"]


def _failed_names(result) -> set[str]:
    return {check["name"] for check in result.checks if not check["passed"]}


def test_valid_v2_external_anchor_passes(schema):
    contract = _make_contract()
    result = verify_account_ready(contract, _make_anchor(contract), schema)

    assert result.passed, result.summary()
    assert {"required_roles", "role_bindings", "state_bindings", "state_controls"} <= {
        check["name"] for check in result.checks
    }


def test_consistent_govcloud_partition_passes(schema):
    contract = _make_contract(partition="aws-us-gov", region="us-gov-west-1")
    result = verify_account_ready(contract, _make_anchor(contract), schema)

    assert result.passed, result.summary()


def test_missing_schema_fails_closed():
    contract = _make_contract()
    result = verify_account_ready(contract, _make_anchor(contract), schema=None)

    assert not result.passed
    assert _failed_names(result) == {"schema_validation"}


def test_v1_schema_is_rejected():
    contract = _make_contract()
    v1_schema = json.loads(
        (REPO_ROOT / "schemas" / "account-ready.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    result = verify_account_ready(contract, _make_anchor(contract), v1_schema)

    assert not result.passed
    assert "approved ACCOUNT_READY v2" in result.summary()


def test_modified_schema_with_approved_id_is_rejected(schema):
    contract = _make_contract()
    schema["description"] = "locally altered schema"
    result = verify_account_ready(contract, _make_anchor(contract), schema)

    assert not result.passed
    assert _failed_names(result) == {"schema_validation"}


def test_schema_error_is_sanitized(schema):
    contract = _make_contract()
    sensitive_marker = "SENSITIVE-ACCOUNT-MARKER"
    contract["account_id"] = sensitive_marker
    result = verify_account_ready(contract, _make_anchor(contract), schema)

    assert not result.passed
    assert sensitive_marker not in result.summary()


@pytest.mark.parametrize(
    "missing_field",
    [
        "customer_id",
        "deployment_id",
        "account_id",
        "region",
        "environment",
        "baseline_version",
        "expected_contract_digest",
    ],
)
def test_missing_anchor_field_fails_closed(schema, missing_field):
    contract = _make_contract()
    anchor = _make_anchor(contract)
    del anchor[missing_field]

    result = verify_account_ready(contract, anchor, schema)

    assert not result.passed
    assert _failed_names(result) == {"anchor_validation"}


def test_unexpected_anchor_field_fails_closed(schema):
    contract = _make_contract()
    anchor = _make_anchor(contract)
    anchor["backend_bucket"] = "must-not-be-authoritative"

    result = verify_account_ready(contract, anchor, schema)

    assert not result.passed
    assert _failed_names(result) == {"anchor_validation"}


@pytest.mark.parametrize(
    ("field", "other_value"),
    [
        ("customer_id", OTHER_CUSTOMER_ID),
        ("deployment_id", OTHER_DEPLOYMENT_ID),
        ("account_id", OTHER_ACCOUNT_ID),
        ("region", "us-west-2"),
        ("environment", "dev"),
        ("baseline_version", "v2.1.0"),
    ],
)
def test_complete_tuple_mismatch_fails(schema, field, other_value):
    contract = _make_contract()
    anchor = _make_anchor(contract)
    anchor[field] = other_value

    result = verify_account_ready(contract, anchor, schema)

    assert not result.passed
    assert f"{field}_match" in _failed_names(result)
    assert other_value not in result.summary()


def test_external_digest_anchor_is_mandatory_and_exact(schema):
    contract = _make_contract()
    anchor = _make_anchor(contract)
    anchor["expected_contract_digest"] = "sha256:" + ("0" * 64)

    result = verify_account_ready(contract, anchor, schema)

    assert not result.passed
    assert "external_digest_match" in _failed_names(result)
    assert anchor["expected_contract_digest"] not in result.summary()


def test_tampered_canonical_digest_fails(schema):
    contract = _make_contract()
    anchor = _make_anchor(contract)
    contract["contract_digest"] = "sha256:" + ("f" * 64)

    result = verify_account_ready(contract, anchor, schema)

    assert not result.passed
    assert "digest_match" in _failed_names(result)


@pytest.mark.parametrize("role", ROLE_NAMES)
def test_all_eight_roles_are_required(schema, role):
    contract = _make_contract()
    anchor = _make_anchor(contract)
    del contract["roles"][role]
    _refresh_digest(contract, anchor)

    result = verify_account_ready(contract, anchor, schema)

    assert not result.passed
    assert _failed_names(result) == {"schema_validation"}


@pytest.mark.parametrize(
    ("tag", "other_value"),
    [
        ("customer_id_tag", OTHER_CUSTOMER_ID),
        ("deployment_id_tag", OTHER_DEPLOYMENT_ID),
        ("account_id_tag", OTHER_ACCOUNT_ID),
        ("region_tag", "us-west-2"),
        ("environment_tag", "dev"),
    ],
)
def test_role_resource_tag_mismatch_fails(schema, tag, other_value):
    contract = _make_contract()
    anchor = _make_anchor(contract)
    contract["roles"]["plan"][tag] = other_value
    _refresh_digest(contract, anchor)

    result = verify_account_ready(contract, anchor, schema)

    assert not result.passed
    assert "role_bindings" in _failed_names(result)
    assert other_value not in result.summary()


def test_foreign_role_arn_fails(schema):
    contract = _make_contract()
    anchor = _make_anchor(contract)
    contract["roles"]["plan"]["arn"] = (
        f"arn:aws:iam::{OTHER_ACCOUNT_ID}:role/ScanalyzeCustomer-Plan"
    )
    _refresh_digest(contract, anchor)

    result = verify_account_ready(contract, anchor, schema)

    assert not result.passed
    assert "role_bindings" in _failed_names(result)


def test_one_role_arn_cannot_satisfy_two_authorities(schema):
    contract = _make_contract()
    anchor = _make_anchor(contract)
    contract["roles"]["identity_plan"]["arn"] = contract["roles"]["plan"]["arn"]
    _refresh_digest(contract, anchor)

    result = verify_account_ready(contract, anchor, schema)

    assert not result.passed
    assert "role_bindings" in _failed_names(result)


@pytest.mark.parametrize(
    ("first", "second"),
    [
        ("plan", "apply"),
        ("identity_plan", "identity_apply"),
        ("promotion", "validation"),
        ("diagnostic", "state_recovery"),
    ],
)
def test_role_arns_cannot_be_swapped_between_authorities(schema, first, second):
    contract = _make_contract()
    anchor = _make_anchor(contract)
    first_arn = contract["roles"][first]["arn"]
    contract["roles"][first]["arn"] = contract["roles"][second]["arn"]
    contract["roles"][second]["arn"] = first_arn
    _refresh_digest(contract, anchor)

    result = verify_account_ready(contract, anchor, schema)

    assert not result.passed
    assert "role_bindings" in _failed_names(result)


@pytest.mark.parametrize(
    "kms_arn",
    [
        (
            f"arn:aws:kms:us-west-2:{ACCOUNT_ID}:"
            "key/00000000-0000-0000-0000-000000000001"
        ),
        (
            f"arn:aws:kms:us-east-1:{OTHER_ACCOUNT_ID}:"
            "key/00000000-0000-0000-0000-000000000001"
        ),
        (
            f"arn:aws-us-gov:kms:us-east-1:{ACCOUNT_ID}:"
            "key/00000000-0000-0000-0000-000000000001"
        ),
    ],
)
def test_state_kms_binding_mismatch_fails(schema, kms_arn):
    contract = _make_contract()
    anchor = _make_anchor(contract)
    contract["state_infrastructure"]["state_kms_key"] = kms_arn
    _refresh_digest(contract, anchor)

    result = verify_account_ready(contract, anchor, schema)

    assert not result.passed
    assert "state_bindings" in _failed_names(result)


def test_state_resources_must_be_distinct(schema):
    contract = _make_contract()
    anchor = _make_anchor(contract)
    contract["state_infrastructure"]["evidence_bucket"] = contract[
        "state_infrastructure"
    ]["state_bucket"]
    _refresh_digest(contract, anchor)

    result = verify_account_ready(contract, anchor, schema)

    assert not result.passed
    assert "state_bindings" in _failed_names(result)


@pytest.mark.parametrize(
    "field",
    ["state_bucket", "evidence_bucket", "contracts_bucket"],
)
def test_arbitrary_same_partition_bucket_name_fails(schema, field):
    contract = _make_contract()
    anchor = _make_anchor(contract)
    contract["state_infrastructure"][field] = (
        f"arn:aws:s3:::arbitrary-{field.replace('_', '-')}-{ACCOUNT_ID}"
    )
    _refresh_digest(contract, anchor)

    result = verify_account_ready(contract, anchor, schema)

    assert not result.passed
    assert "state_bindings" in _failed_names(result)


@pytest.mark.parametrize(
    ("control", "invalid_value"),
    [
        ("state_versioning_enabled", False),
        ("state_default_encryption", "AES256"),
        ("state_bucket_key_enabled", False),
        ("state_public_access_blocked", False),
        ("state_object_lock_enabled", True),
        ("native_lockfile_enabled", False),
    ],
)
def test_every_state_control_is_fail_closed(schema, control, invalid_value):
    contract = _make_contract()
    anchor = _make_anchor(contract)
    contract["controls"][control] = invalid_value
    _refresh_digest(contract, anchor)

    result = verify_account_ready(contract, anchor, schema)

    assert not result.passed
    assert _failed_names(result) == {"schema_validation"}


def test_cli_valid_output_is_sanitized(schema, tmp_path):
    contract = _make_contract()
    anchor = _make_anchor(contract)
    contract_path = tmp_path / "contract.json"
    anchor_path = tmp_path / "anchor.json"
    schema_path = tmp_path / "schema.json"
    contract_path.write_text(json.dumps(contract), encoding="utf-8")
    anchor_path.write_text(json.dumps(anchor), encoding="utf-8")
    schema_path.write_text(json.dumps(schema), encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT_PATH),
            str(contract_path),
            str(anchor_path),
            str(schema_path),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "Verification: PASS" in result.stdout
    for sensitive_value in (CUSTOMER_ID, DEPLOYMENT_ID, ACCOUNT_ID):
        assert sensitive_value not in result.stdout


def test_cli_rejects_duplicate_json_keys_without_echoing_inputs(schema, tmp_path):
    contract_path = tmp_path / "contract.json"
    anchor_path = tmp_path / "anchor.json"
    schema_path = tmp_path / "schema.json"
    contract_path.write_text(
        '{"schema_version":"2","schema_version":"2"}',
        encoding="utf-8",
    )
    anchor_path.write_text(json.dumps(_make_anchor(_make_contract())), encoding="utf-8")
    schema_path.write_text(json.dumps(schema), encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT_PATH),
            str(contract_path),
            str(anchor_path),
            str(schema_path),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert result.stderr.strip() == "ERROR: unable to load verification inputs"
    assert str(contract_path) not in result.stderr
