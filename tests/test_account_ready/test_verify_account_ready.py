"""Tests for ACCOUNT_READY external anchor verification — fail-closed.

Test matrix per user directive:
- valid external anchor            → PASS
- missing external anchor          → FAIL
- wrong account_id                 → FAIL
- wrong deployment_id              → FAIL
- wrong contract digest            → FAIL
- wrong contract version           → FAIL (baseline)
- wrong producer/baseline version  → FAIL
- missing required role            → FAIL
- role ARN from wrong account      → FAIL
"""

import json
import hashlib
import copy
import sys
from pathlib import Path

import pytest

from tooling.verify_account_ready import verify_account_ready, canonical_digest


SCHEMA_PATH = Path(__file__).resolve().parent.parent.parent / "schemas" / "account-ready.v1.schema.json"


@pytest.fixture
def schema():
    return json.loads(SCHEMA_PATH.read_text())


def _make_contract(account_id="111222333444", deployment_id="dep_01J5A1B2C3D4E5F6G7H8J9K0M1",
                   baseline="v1.0.0"):
    """Build a valid contract, then compute digest."""
    contract = {
        "schema_version": "1",
        "deployment_id": deployment_id,
        "account_id": account_id,
        "region": "us-east-1",
        "baseline_version": baseline,
        "provisioned_at": "2026-06-25T00:00:00Z",
        "roles": {
            role: {
                "arn": f"arn:aws:iam::{account_id}:role/ScanalyzeCustomer-{role.title().replace('_','')}",
                "deployment_id_tag": deployment_id,
            }
            for role in ["plan", "apply", "promotion", "validation", "diagnostic", "state_recovery"]
        },
        "state_infrastructure": {
            "state_bucket": f"arn:aws:s3:::scanalyze-{account_id}-tf-state",
            "evidence_bucket": f"arn:aws:s3:::scanalyze-{account_id}-tf-evidence",
            "contracts_bucket": f"arn:aws:s3:::scanalyze-{account_id}-contracts",
            "state_kms_key": f"arn:aws:kms:us-east-1:{account_id}:key/00000000-0000-0000-0000-000000000001",
            "evidence_kms_key": f"arn:aws:kms:us-east-1:{account_id}:key/00000000-0000-0000-0000-000000000002",
            "contracts_kms_key": f"arn:aws:kms:us-east-1:{account_id}:key/00000000-0000-0000-0000-000000000003",
        },
    }
    # Compute and add digest
    contract["contract_digest"] = canonical_digest(contract)
    return contract


def _make_anchor(account_id="111222333444", deployment_id="dep_01J5A1B2C3D4E5F6G7H8J9K0M1",
                 baseline="v1.0.0"):
    return {
        "account_id": account_id,
        "deployment_id": deployment_id,
        "baseline_version": baseline,
    }


class TestValidExternalAnchor:
    def test_valid_anchor_passes(self, schema):
        contract = _make_contract()
        anchor = _make_anchor()
        result = verify_account_ready(contract, anchor, schema)
        assert result.passed, result.summary()


class TestMissingAnchorFailsClosed:
    def test_no_schema_fails_closed(self):
        """Missing schema → fail closed."""
        contract = _make_contract()
        anchor = _make_anchor()
        result = verify_account_ready(contract, anchor, schema=None)
        assert not result.passed
        assert any("no schema provided" in c["reason"] for c in result.checks)

    def test_empty_anchor_account_fails(self, schema):
        contract = _make_contract()
        anchor = {"deployment_id": "dep_01J5A1B2C3D4E5F6G7H8J9K0M1"}
        result = verify_account_ready(contract, anchor, schema)
        assert not result.passed

    def test_empty_anchor_deployment_fails(self, schema):
        contract = _make_contract()
        anchor = {"account_id": "111222333444"}
        result = verify_account_ready(contract, anchor, schema)
        assert not result.passed


class TestWrongAccountId:
    def test_wrong_account_id(self, schema):
        contract = _make_contract(account_id="111222333444")
        anchor = _make_anchor(account_id="999888777666")
        result = verify_account_ready(contract, anchor, schema)
        assert not result.passed
        failed = [c for c in result.checks if not c["passed"]]
        assert any("account_id" in c["name"] for c in failed)


class TestWrongDeploymentId:
    def test_wrong_deployment_id(self, schema):
        contract = _make_contract()
        anchor = _make_anchor(deployment_id="dep_ZZZZZZZZZZZZZZZZZZZZZZZZZ1")
        result = verify_account_ready(contract, anchor, schema)
        assert not result.passed
        failed = [c for c in result.checks if not c["passed"]]
        assert any("deployment_id" in c["name"] for c in failed)


class TestWrongContractDigest:
    def test_tampered_digest(self, schema):
        contract = _make_contract()
        contract["contract_digest"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        anchor = _make_anchor()
        result = verify_account_ready(contract, anchor, schema)
        assert not result.passed
        failed = [c for c in result.checks if not c["passed"]]
        assert any("digest" in c["name"] for c in failed)

    def test_missing_digest_field(self, schema):
        """Removing contract_digest should fail schema validation."""
        contract = _make_contract()
        del contract["contract_digest"]
        anchor = _make_anchor()
        result = verify_account_ready(contract, anchor, schema)
        assert not result.passed


class TestWrongBaselineVersion:
    def test_wrong_baseline(self, schema):
        contract = _make_contract(baseline="v1.0.0")
        anchor = _make_anchor(baseline="v2.0.0")
        result = verify_account_ready(contract, anchor, schema)
        assert not result.passed
        failed = [c for c in result.checks if not c["passed"]]
        assert any("baseline" in c["name"] for c in failed)


class TestMissingRequiredRole:
    def test_missing_state_recovery(self, schema):
        contract = _make_contract()
        del contract["roles"]["state_recovery"]
        # Re-compute digest after modification
        contract["contract_digest"] = canonical_digest(contract)
        anchor = _make_anchor()
        result = verify_account_ready(contract, anchor, schema)
        assert not result.passed


class TestRoleArnWrongAccount:
    def test_role_from_different_account(self, schema):
        contract = _make_contract()
        # Tamper one role ARN to use different account
        contract["roles"]["plan"]["arn"] = "arn:aws:iam::999888777666:role/ScanalyzeCustomer-Plan"
        contract["contract_digest"] = canonical_digest(contract)
        anchor = _make_anchor()
        result = verify_account_ready(contract, anchor, schema)
        assert not result.passed
        failed = [c for c in result.checks if not c["passed"]]
        assert any("role_arn_account" in c["name"] for c in failed)
