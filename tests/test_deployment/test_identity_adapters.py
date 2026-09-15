"""Regression suite for identity-control-plane adapter verifiers.

Tests cover all 4 adapters:
  1. build_identity_runtime_artifact — release/v2 → identity-runtime-artifact.v1
  2. verify_m2m_registry — identity-contract/v2 → m2m-registry-projection.v1
  3. derive_policy_binding — canonical policy → (version, digest)
  4. verify_control_processor — explicit activation binding

Each adapter has positive and negative tests; negatives reject wrong digests,
foreign deployment tuples, empty bindings, missing artifacts, and schema
violations.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import subprocess
import sys
import textwrap
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from tooling.identity_adapters import (
    build_identity_runtime_artifact,
    _digest_of,
    derive_policy_binding,
    verify_control_processor,
    verify_m2m_registry,
    _canonical_bytes,
    _compute_digest,
)

REPO_ROOT = Path(__file__).resolve().parents[2]

# ---------------------------------------------------------------------------
# Fixtures: synthetic but schema-compliant
# ---------------------------------------------------------------------------

CUSTOMER_ID = "cust_01JBCDEFGHJKMNPQRSTVWXYZ01"
DEPLOYMENT_ID = "dep_01JBCDEFGHJKMNPQRSTVWXYZ02"
ACCOUNT_ID = "905418363887"
REGION = "us-east-1"

def _sha256_hex(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _make_s3_locator(label: str) -> dict:
    return {
        "bucket": f"scanalyze-artifacts-{ACCOUNT_ID}-{REGION}",
        "key": f"deployments/{DEPLOYMENT_ID}/artifacts/{label}/sha256/abcd1234",
        "object_version": "v1.test",
        "sha256_b64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    }


def _make_tool() -> dict:
    return {"name": "cosign", "version": "v2.0.0", "binary_digest": _sha256_hex(b"tool")}


def _make_sbom() -> dict:
    return {
        "status": "verified",
        "format": "spdx-2.3-json",
        "digest": _sha256_hex(b"sbom"),
        "subject_digest": _sha256_hex(b"subject"),
        "generator": {"name": "syft", "version": "v1.0.0", "binary_digest": _sha256_hex(b"syft-bin")},
    }


def _make_scan() -> dict:
    return {
        "status": "passed",
        "report_digest": _sha256_hex(b"scan-report"),
        "subject_digest": _sha256_hex(b"subject"),
        "scanner": {"name": "trivy", "version": "v0.50.0", "binary_digest": _sha256_hex(b"trivy-bin")},
        "database_digest": _sha256_hex(b"trivy-db"),
        "completed_at": "2026-01-01T00:00:00Z",
        "critical_findings": 0,
        "high_findings": 0,
        "findings": [],
    }


def _make_provenance() -> dict:
    return {
        "status": "verified",
        "digest": _sha256_hex(b"prov"),
        "predicate_type": "https://slsa.dev/provenance/v1",
        "subject_digest": _sha256_hex(b"subject"),
        "builder_id": "https://github.com/actions/runner",
        "build_type": "https://slsa.dev/container-based-build/v0.1",
        "source_repository": "scanalyze/scanalyze-deployment-platform",
        "source_commit": "a" * 40,
    }


def _make_signature() -> dict:
    return {
        "status": "verified",
        "bundle_digest": _sha256_hex(b"bundle"),
        "subject_digest": _sha256_hex(b"subject"),
        "issuer": "https://token.actions.githubusercontent.com",
        "identity": "https://github.com/scanalyze/scanalyze-deployment-platform/.github/workflows/build.yml@refs/heads/main",
        "key_id": "cosign-identity-token",
    }


def _make_archive_artifact(name: str) -> dict:
    return {
        "kind": "archive",
        "uri": f"s3://scanalyze-builds/sha256/{hashlib.sha256(name.encode()).hexdigest()}/{name}.zip",
        "digest": _sha256_hex(name.encode()),
        "media_type": "application/zip",
        "sbom": _make_sbom(),
        "scan": _make_scan(),
        "provenance": _make_provenance(),
        "signature": _make_signature(),
    }


def _make_container_artifact(name: str) -> dict:
    digest = hashlib.sha256(name.encode()).hexdigest()
    return {
        "kind": "container",
        "uri": f"ghcr.io/scanalyze/{name}@sha256:{digest}",
        "digest": f"sha256:{digest}",
        "media_type": "application/vnd.oci.image.index.v1+json",
        "sbom": _make_sbom(),
        "scan": _make_scan(),
        "provenance": _make_provenance(),
        "signature": _make_signature(),
        "base_image_uri": f"ghcr.io/scanalyze/base@sha256:{hashlib.sha256(b'base').hexdigest()}",
        "base_image_digest": _sha256_hex(b"base"),
    }


def _make_release() -> dict:
    release = {
        "schema_version": "release.v2",
        "release_id": "rel_01JBCDEFGHJKMNPQRSTVWXYZ03",
        "release_version": "1.0.0",
        "release_manifest_digest": _sha256_hex(b"manifest"),
        "policy_digest": _sha256_hex(b"policy"),
        "created_at": "2026-01-01T00:00:00Z",
        "source": {
            "repository": "scanalyze/scanalyze-deployment-platform",
            "commit": "a" * 40,
            "ref": "refs/tags/v1.0.0",
        },
        "builder": {
            "id": "https://github.com/actions/runner",
            "build_type": "https://slsa.dev/container-based-build/v0.1",
            "workflow_ref": "scanalyze/scanalyze-deployment-platform/.github/workflows/release.yml@" + "a" * 40,
            "runner_image": "ghcr.io/actions/runner@sha256:" + "b" * 64,
            "toolchain": {
                "syft": {"name": "syft", "version": "v1.0.0", "binary_digest": _sha256_hex(b"syft-bin")},
                "trivy": {"name": "trivy", "version": "v0.50.0", "binary_digest": _sha256_hex(b"trivy-bin")},
                "cosign": {"name": "cosign", "version": "v2.0.0", "binary_digest": _sha256_hex(b"cosign-bin")},
            },
        },
        "artifacts": {
            "scanalyze-ingest-api": _make_container_artifact("scanalyze-ingest-api"),
            "scanalyze-ocr-worker": _make_container_artifact("scanalyze-ocr-worker"),
            "scanalyze-postprocess-worker": _make_container_artifact("scanalyze-postprocess-worker"),
            "scanalyze-classifier-worker": _make_container_artifact("scanalyze-classifier-worker"),
            "scanalyze-bank-worker": _make_container_artifact("scanalyze-bank-worker"),
            "scanalyze-personal-worker": _make_container_artifact("scanalyze-personal-worker"),
            "scanalyze-gov-worker": _make_container_artifact("scanalyze-gov-worker"),
            "identity-pre-token-lambda": _make_archive_artifact("identity-pre-token-lambda"),
            "identity-control-processor-lambda": _make_archive_artifact("identity-control-processor-lambda"),
            "scanalyze-frontend-ui": _make_archive_artifact("scanalyze-frontend-ui"),
        },
        "waivers": [],
        "last_known_good": {
            "release_id": "rel_01JBCDEFGHJKMNPQRSTVWXYZ00",
            "release_manifest_digest": _sha256_hex(b"prev-manifest"),
            "approved_change_id": "chg_01JBCDEFGHJKMNPQRSTVWXYZ04",
        },
        "promotion": {
            "mode": "copy-by-digest",
            "rebuild": False,
        },
    }
    return release


def _release_digest(release: dict) -> str:
    digestible = {k: v for k, v in release.items() if k != "record_digest"}
    return _compute_digest(_canonical_bytes(digestible))


def _make_identity_contract() -> dict:
    return {
        "schema_version": "2",
        "deployment_id": DEPLOYMENT_ID,
        "customer_id": CUSTOMER_ID,
        "cognito": {
            "user_pool_id": "us-east-1_TestPool01",
            "client_ids": ["abc123ClientId"],
            "allowed_token_uses": ["access"],
            "m2m_client_ids": ["m2mClient001"],
        },
        "authorization": {
            "mode": "cognito_jwt",
            "deployment_claim": "custom:deployment_id",
            "enforce_deployment_binding": True,
            "customer_id_source": "client_identity_bindings_v1",
        },
        "claim_mapping": {
            "deployment_id": "custom:deployment_id",
            "customer_id": "custom:customerId",
        },
        "action_scope_sets": {
            "read": ["documents:read"],
            "write": ["documents:write"],
            "admin": ["admin:manage"],
        },
        "m2m_bindings": [
            {
                "client_id": "m2mClient001",
                "customer_id": CUSTOMER_ID,
                "deployment_id": DEPLOYMENT_ID,
                "required_scopes": ["documents:read"],
            }
        ],
        "allowed_domains": ["bank"],
        "restrictions": {
            "cross_account_access": False,
            "cross_deployment_access": False,
            "password_in_docs": False,
        },
    }


# ===================================================================
# 1. build_identity_runtime_artifact
# ===================================================================

class TestBuildIdentityRuntimeArtifact:
    """Tests for the release → identity-runtime-artifact projection."""

    @pytest.fixture
    def valid_release(self):
        import json
        with open(REPO_ROOT / "fixtures" / "valid" / "release-v2-complete.synthetic.json") as f:
            return json.load(f)

    @pytest.fixture
    def valid_attestation(self):
        import json
        with open(REPO_ROOT / "fixtures" / "valid" / "release-attestation-v2-complete.synthetic.json") as f:
            return json.load(f)

    @pytest.fixture
    def valid_policy(self):
        import json
        with open(REPO_ROOT / "fixtures" / "valid" / "release-trust-policy-v1-synthetic.json") as f:
            return json.load(f)

    @pytest.fixture
    def expected_policy_digest(self):
        return (REPO_ROOT / "fixtures" / "valid" / "release-trust-policy-v1-synthetic.sha256").read_text().strip()

    @pytest.fixture
    def valid_cicd_contract(self):
        import json
        with open(REPO_ROOT / "fixtures" / "valid" / "cicd-contract-v2-synthetic.json") as f:
            return json.load(f)

    @pytest.fixture
    def expected_cicd_contract_digest(self):
        return (REPO_ROOT / "fixtures" / "valid" / "cicd-contract-v2-synthetic.sha256").read_text().strip()

    @pytest.fixture
    def valid_publication_receipt(self):
        import json
        with open(REPO_ROOT / "fixtures" / "valid" / "identity-publication-receipt-v1-synthetic.json") as f:
            return json.load(f)

    @pytest.fixture
    def expected_publication_digest(self):
        return (REPO_ROOT / "fixtures" / "valid" / "identity-publication-receipt-v1-synthetic.sha256").read_text().strip()

    def test_valid_projection(self, valid_release, valid_attestation, valid_policy, expected_policy_digest, valid_cicd_contract, expected_cicd_contract_digest, valid_publication_receipt, expected_publication_digest):
        digest = _release_digest(valid_release)
        result = build_identity_runtime_artifact(
            release=valid_release,
            attestation=valid_attestation,
            policy=valid_policy,
            expected_policy_digest=expected_policy_digest,
            expected_release_document_digest=digest,
            expected_release_manifest_digest=valid_release["release_manifest_digest"],
            cicd_contract=valid_cicd_contract,
            expected_cicd_contract_digest=expected_cicd_contract_digest,
            publication_receipt=valid_publication_receipt,
            expected_publication_digest=expected_publication_digest,
            customer_id="cust_BBBBBBBBBBBBBBBBBBBBBBBBBB",
            deployment_id="dep_AAAAAAAAAAAAAAAAAAAAAAAAAA",
            account_id="123456789012",
            region="us-east-1",
            environment="staging",
            resolved_at=datetime(2026, 8, 28, 20, 4, tzinfo=UTC),
            max_contract_age_seconds=3600,
        )
        assert result["schema_version"] == "identity-runtime-artifact.v1"
        assert result["contract_id"] == "release-manifest/v1"
        assert result["customer_id"] == "cust_BBBBBBBBBBBBBBBBBBBBBBBBBB"
        assert result["deployment_id"] == "dep_AAAAAAAAAAAAAAAAAAAAAAAAAA"
        assert re.fullmatch(r"sha256:[a-f0-9]{64}", result["contract_digest"])

    def test_wrong_release_digest_rejected(self, valid_release, valid_attestation, valid_policy, expected_policy_digest, valid_cicd_contract, expected_cicd_contract_digest, valid_publication_receipt, expected_publication_digest):
        with pytest.raises(ValueError, match="release document digest mismatch"):
            build_identity_runtime_artifact(
                release=valid_release,
                attestation=valid_attestation,
                policy=valid_policy,
                expected_policy_digest=expected_policy_digest,
                expected_release_document_digest=_sha256_hex(b"wrong"),
                expected_release_manifest_digest=valid_release["release_manifest_digest"],
                cicd_contract=valid_cicd_contract,
                expected_cicd_contract_digest=expected_cicd_contract_digest,
                publication_receipt=valid_publication_receipt,
                expected_publication_digest=expected_publication_digest,
                customer_id="cust_BBBBBBBBBBBBBBBBBBBBBBBBBB",
                deployment_id="dep_AAAAAAAAAAAAAAAAAAAAAAAAAA",
                account_id="123456789012",
                region="us-east-1",
                environment="staging",
                resolved_at=datetime(2026, 8, 28, 20, 4, tzinfo=UTC),
                max_contract_age_seconds=3600,
            )

    def test_missing_pre_token_artifact_rejected(self, valid_release, valid_attestation, valid_policy, expected_policy_digest, valid_cicd_contract, expected_cicd_contract_digest, valid_publication_receipt, expected_publication_digest):
        del valid_release["artifacts"]["identity-pre-token-lambda"]
        digest = _release_digest(valid_release)
        with pytest.raises(ValueError, match="ARTIFACT_INVENTORY_MISMATCH|identity-pre-token-lambda"):
            build_identity_runtime_artifact(
                release=valid_release,
                attestation=valid_attestation,
                policy=valid_policy,
                expected_policy_digest=expected_policy_digest,
                expected_release_document_digest=digest,
                expected_release_manifest_digest=valid_release["release_manifest_digest"],
                cicd_contract=valid_cicd_contract,
                expected_cicd_contract_digest=expected_cicd_contract_digest,
                publication_receipt=valid_publication_receipt,
                expected_publication_digest=expected_publication_digest,
                customer_id="cust_BBBBBBBBBBBBBBBBBBBBBBBBBB",
                deployment_id="dep_AAAAAAAAAAAAAAAAAAAAAAAAAA",
                account_id="123456789012",
                region="us-east-1",
                environment="staging",
                resolved_at=datetime(2026, 8, 28, 20, 4, tzinfo=UTC),
                max_contract_age_seconds=3600,
            )

    def test_invalid_publication_missing_bucket(self, valid_release, valid_attestation, valid_policy, expected_policy_digest, valid_cicd_contract, expected_cicd_contract_digest, valid_publication_receipt, expected_publication_digest):
        digest = _release_digest(valid_release)
        del valid_publication_receipt["identity_pre_token_lambda_locator"]["bucket"]

        valid_publication_receipt["receipt_digest"] = _digest_of(valid_publication_receipt, exclude_key="receipt_digest")
        # Overwrite the expected_publication_digest so we only fail on missing bucket
        new_expected_digest = valid_publication_receipt["receipt_digest"]

        with pytest.raises(ValueError, match="schema validation failed.*'bucket' is a required property"):
            build_identity_runtime_artifact(
                release=valid_release,
                attestation=valid_attestation,
                policy=valid_policy,
                expected_policy_digest=expected_policy_digest,
                expected_release_document_digest=digest,
                expected_release_manifest_digest=valid_release["release_manifest_digest"],
                cicd_contract=valid_cicd_contract,
                expected_cicd_contract_digest=expected_cicd_contract_digest,
                publication_receipt=valid_publication_receipt,
                expected_publication_digest=new_expected_digest,
                customer_id="cust_BBBBBBBBBBBBBBBBBBBBBBBBBB",
                deployment_id="dep_AAAAAAAAAAAAAAAAAAAAAAAAAA",
                account_id="123456789012",
                region="us-east-1",
                environment="staging",
                resolved_at=datetime(2026, 8, 28, 20, 4, tzinfo=UTC),
                max_contract_age_seconds=3600,
            )

    def test_invalid_publication_null_object_version(self, valid_release, valid_attestation, valid_policy, expected_policy_digest, valid_cicd_contract, expected_cicd_contract_digest, valid_publication_receipt):
        digest = _release_digest(valid_release)
        valid_publication_receipt["identity_pre_token_lambda_locator"]["object_version"] = "null"
        valid_publication_receipt["receipt_digest"] = _digest_of(valid_publication_receipt, exclude_key="receipt_digest")
        new_expected_digest = valid_publication_receipt["receipt_digest"]

        with pytest.raises(ValueError, match="schema validation failed.*null"):
            build_identity_runtime_artifact(
                release=valid_release,
                attestation=valid_attestation,
                policy=valid_policy,
                expected_policy_digest=expected_policy_digest,
                expected_release_document_digest=digest,
                expected_release_manifest_digest=valid_release["release_manifest_digest"],
                cicd_contract=valid_cicd_contract,
                expected_cicd_contract_digest=expected_cicd_contract_digest,
                publication_receipt=valid_publication_receipt,
                expected_publication_digest=new_expected_digest,
                customer_id="cust_BBBBBBBBBBBBBBBBBBBBBBBBBB",
                deployment_id="dep_AAAAAAAAAAAAAAAAAAAAAAAAAA",
                account_id="123456789012",
                region="us-east-1",
                environment="staging",
                resolved_at=datetime(2026, 8, 28, 20, 4, tzinfo=UTC),
                max_contract_age_seconds=3600,
            )

    def test_invalid_publication_wrong_bucket(self, valid_release, valid_attestation, valid_policy, expected_policy_digest, valid_cicd_contract, expected_cicd_contract_digest, valid_publication_receipt):
        digest = _release_digest(valid_release)
        valid_publication_receipt["identity_pre_token_lambda_locator"]["bucket"] = "foreign-bucket-123"
        valid_publication_receipt["receipt_digest"] = _digest_of(valid_publication_receipt, exclude_key="receipt_digest")
        new_expected_digest = valid_publication_receipt["receipt_digest"]

        with pytest.raises(ValueError, match="not bound to CICD destination bucket"):
            build_identity_runtime_artifact(
                release=valid_release,
                attestation=valid_attestation,
                policy=valid_policy,
                expected_policy_digest=expected_policy_digest,
                expected_release_document_digest=digest,
                expected_release_manifest_digest=valid_release["release_manifest_digest"],
                cicd_contract=valid_cicd_contract,
                expected_cicd_contract_digest=expected_cicd_contract_digest,
                publication_receipt=valid_publication_receipt,
                expected_publication_digest=new_expected_digest,
                customer_id="cust_BBBBBBBBBBBBBBBBBBBBBBBBBB",
                deployment_id="dep_AAAAAAAAAAAAAAAAAAAAAAAAAA",
                account_id="123456789012",
                region="us-east-1",
                environment="staging",
                resolved_at=datetime(2026, 8, 28, 20, 4, tzinfo=UTC),
                max_contract_age_seconds=3600,
            )

    def test_invalid_publication_wrong_key(self, valid_release, valid_attestation, valid_policy, expected_policy_digest, valid_cicd_contract, expected_cicd_contract_digest, valid_publication_receipt):
        digest = _release_digest(valid_release)
        valid_publication_receipt["identity_pre_token_lambda_locator"]["key"] = "deployments/other-deployment/artifacts/x"
        valid_publication_receipt["receipt_digest"] = _digest_of(valid_publication_receipt, exclude_key="receipt_digest")
        new_expected_digest = valid_publication_receipt["receipt_digest"]

        with pytest.raises(ValueError, match="not bound to deployment_id"):
            build_identity_runtime_artifact(
                release=valid_release,
                attestation=valid_attestation,
                policy=valid_policy,
                expected_policy_digest=expected_policy_digest,
                expected_release_document_digest=digest,
                expected_release_manifest_digest=valid_release["release_manifest_digest"],
                cicd_contract=valid_cicd_contract,
                expected_cicd_contract_digest=expected_cicd_contract_digest,
                publication_receipt=valid_publication_receipt,
                expected_publication_digest=new_expected_digest,
                customer_id="cust_BBBBBBBBBBBBBBBBBBBBBBBBBB",
                deployment_id="dep_AAAAAAAAAAAAAAAAAAAAAAAAAA",
                account_id="123456789012",
                region="us-east-1",
                environment="staging",
                resolved_at=datetime(2026, 8, 28, 20, 4, tzinfo=UTC),
                max_contract_age_seconds=3600,
            )

    def test_invalid_publication_wrong_sha256_b64(self, valid_release, valid_attestation, valid_policy, expected_policy_digest, valid_cicd_contract, expected_cicd_contract_digest, valid_publication_receipt):
        digest = _release_digest(valid_release)
        valid_publication_receipt["identity_pre_token_lambda_locator"]["sha256_b64"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        valid_publication_receipt["receipt_digest"] = _digest_of(valid_publication_receipt, exclude_key="receipt_digest")
        new_expected_digest = valid_publication_receipt["receipt_digest"]

        with pytest.raises(ValueError, match="sha256_b64 mismatch with signed release artifact digest"):
            build_identity_runtime_artifact(
                release=valid_release,
                attestation=valid_attestation,
                policy=valid_policy,
                expected_policy_digest=expected_policy_digest,
                expected_release_document_digest=digest,
                expected_release_manifest_digest=valid_release["release_manifest_digest"],
                cicd_contract=valid_cicd_contract,
                expected_cicd_contract_digest=expected_cicd_contract_digest,
                publication_receipt=valid_publication_receipt,
                expected_publication_digest=new_expected_digest,
                customer_id="cust_BBBBBBBBBBBBBBBBBBBBBBBBBB",
                deployment_id="dep_AAAAAAAAAAAAAAAAAAAAAAAAAA",
                account_id="123456789012",
                region="us-east-1",
                environment="staging",
                resolved_at=datetime(2026, 8, 28, 20, 4, tzinfo=UTC),
                max_contract_age_seconds=3600,
            )

    def test_invalid_publication_recomputed_self_digest_does_not_override_expected(self, valid_release, valid_attestation, valid_policy, expected_policy_digest, valid_cicd_contract, expected_cicd_contract_digest, valid_publication_receipt, expected_publication_digest):
        digest = _release_digest(valid_release)
        valid_publication_receipt["identity_pre_token_lambda_locator"]["bucket"] = "hacked-bucket"
        valid_publication_receipt["receipt_digest"] = _digest_of(valid_publication_receipt, exclude_key="receipt_digest")
        # We recomputed the receipt self digest, but we pass the original expected_publication_digest!

        with pytest.raises(ValueError, match="publication_receipt recomputed digest mismatch"):
            build_identity_runtime_artifact(
                release=valid_release,
                attestation=valid_attestation,
                policy=valid_policy,
                expected_policy_digest=expected_policy_digest,
                expected_release_document_digest=digest,
                expected_release_manifest_digest=valid_release["release_manifest_digest"],
                cicd_contract=valid_cicd_contract,
                expected_cicd_contract_digest=expected_cicd_contract_digest,
                publication_receipt=valid_publication_receipt,
                expected_publication_digest=expected_publication_digest,
                customer_id="cust_BBBBBBBBBBBBBBBBBBBBBBBBBB",
                deployment_id="dep_AAAAAAAAAAAAAAAAAAAAAAAAAA",
                account_id="123456789012",
                region="us-east-1",
                environment="staging",
                resolved_at=datetime(2026, 8, 28, 20, 4, tzinfo=UTC),
                max_contract_age_seconds=3600,
            )

    def test_invalid_cicd_contract_digest(self, valid_release, valid_attestation, valid_policy, expected_policy_digest, valid_cicd_contract, expected_cicd_contract_digest, valid_publication_receipt, expected_publication_digest):
        digest = _release_digest(valid_release)
        with pytest.raises(ValueError, match="cicd_contract digest mismatch"):
            build_identity_runtime_artifact(
                release=valid_release,
                attestation=valid_attestation,
                policy=valid_policy,
                expected_policy_digest=expected_policy_digest,
                expected_release_document_digest=digest,
                expected_release_manifest_digest=valid_release["release_manifest_digest"],
                cicd_contract=valid_cicd_contract,
                expected_cicd_contract_digest=_sha256_hex(b"wrong"),
                publication_receipt=valid_publication_receipt,
                expected_publication_digest=expected_publication_digest,
                customer_id="cust_BBBBBBBBBBBBBBBBBBBBBBBBBB",
                deployment_id="dep_AAAAAAAAAAAAAAAAAAAAAAAAAA",
                account_id="123456789012",
                region="us-east-1",
                environment="staging",
                resolved_at=datetime(2026, 8, 28, 20, 4, tzinfo=UTC),
                max_contract_age_seconds=3600,
            )

    def test_contract_digest_is_deterministic(self, valid_release, valid_attestation, valid_policy, expected_policy_digest, valid_cicd_contract, expected_cicd_contract_digest, valid_publication_receipt, expected_publication_digest):
        digest = _release_digest(valid_release)
        kwargs = dict(
            release=valid_release,
            attestation=valid_attestation,
            policy=valid_policy,
            expected_policy_digest=expected_policy_digest,
            expected_release_document_digest=digest,
            expected_release_manifest_digest=valid_release["release_manifest_digest"],
            cicd_contract=valid_cicd_contract,
            expected_cicd_contract_digest=expected_cicd_contract_digest,
            publication_receipt=valid_publication_receipt,
            expected_publication_digest=expected_publication_digest,
            customer_id="cust_BBBBBBBBBBBBBBBBBBBBBBBBBB",
            deployment_id="dep_AAAAAAAAAAAAAAAAAAAAAAAAAA",
            account_id="123456789012",
            region="us-east-1",
            environment="staging",
            resolved_at=datetime(2026, 8, 28, 20, 4, tzinfo=UTC),
            max_contract_age_seconds=3600,
        )
        r1 = build_identity_runtime_artifact(**kwargs)
        r2 = build_identity_runtime_artifact(**kwargs)
        assert r1["contract_digest"] == r2["contract_digest"]

# ===================================================================
# 2. verify_m2m_registry
# ===================================================================

class TestVerifyM2MRegistry:
    """Tests for the identity-contract → m2m-registry-projection."""

    def _contract_digest(self, contract: dict) -> str:
        return _compute_digest(_canonical_bytes(contract))

    def test_valid_projection(self):
        contract = _make_identity_contract()
        digest = self._contract_digest(contract)
        result = verify_m2m_registry(
            identity_contract=contract,
            expected_identity_contract_digest=digest,
            customer_id=CUSTOMER_ID,
            deployment_id=DEPLOYMENT_ID,
        )
        assert result["schema_version"] == "m2m-registry-projection.v1"
        assert result["contract_id"] == "identity-contract/v2"
        assert result["contract_digest"] == digest
        assert len(result["m2m_bindings"]) >= 1

    def test_wrong_digest_rejected(self):
        contract = _make_identity_contract()
        with pytest.raises(ValueError, match="digest mismatch"):
            verify_m2m_registry(
                identity_contract=contract,
                expected_identity_contract_digest=_sha256_hex(b"wrong"),
                customer_id=CUSTOMER_ID,
                deployment_id=DEPLOYMENT_ID,
            )

    def test_wrong_customer_rejected(self):
        contract = _make_identity_contract()
        digest = self._contract_digest(contract)
        with pytest.raises(ValueError, match="customer_id does not match"):
            verify_m2m_registry(
                identity_contract=contract,
                expected_identity_contract_digest=digest,
                customer_id="cust_01JBCDEFGHJKMNPQRSTVWXYZ99",
                deployment_id=DEPLOYMENT_ID,
            )

    def test_wrong_deployment_rejected(self):
        contract = _make_identity_contract()
        digest = self._contract_digest(contract)
        with pytest.raises(ValueError, match="deployment_id does not match"):
            verify_m2m_registry(
                identity_contract=contract,
                expected_identity_contract_digest=digest,
                customer_id=CUSTOMER_ID,
                deployment_id="dep_01JBCDEFGHJKMNPQRSTVWXYZ99",
            )

    def test_cross_deployment_binding_rejected(self):
        contract = _make_identity_contract()
        contract["m2m_bindings"][0]["deployment_id"] = "dep_01JBCDEFGHJKMNPQRSTVWXYZ99"
        # Note: this will also fail schema validation because the identity-contract
        # schema itself doesn't restrict binding deployment_id to the root, but
        # our adapter does. Need to recompute digest after mutation.
        digest = self._contract_digest(contract)
        with pytest.raises(ValueError, match="wrong deployment_id"):
            verify_m2m_registry(
                identity_contract=contract,
                expected_identity_contract_digest=digest,
                customer_id=CUSTOMER_ID,
                deployment_id=DEPLOYMENT_ID,
            )

    def test_empty_bindings_rejected(self):
        contract = _make_identity_contract()
        contract["m2m_bindings"] = []
        # Schema requires minItems: 1
        digest = self._contract_digest(contract)
        with pytest.raises(ValueError, match="schema validation failed"):
            verify_m2m_registry(
                identity_contract=contract,
                expected_identity_contract_digest=digest,
                customer_id=CUSTOMER_ID,
                deployment_id=DEPLOYMENT_ID,
            )

    def test_projection_preserves_action_scope_sets(self):
        contract = _make_identity_contract()
        digest = self._contract_digest(contract)
        result = verify_m2m_registry(
            identity_contract=contract,
            expected_identity_contract_digest=digest,
            customer_id=CUSTOMER_ID,
            deployment_id=DEPLOYMENT_ID,
        )
        assert result["action_scope_sets"] == contract["action_scope_sets"]


# ===================================================================
# 3. derive_policy_binding
# ===================================================================

class TestDerivePolicyBinding:
    """Tests for canonical policy digest derivation."""

    def test_valid_binding(self):
        policy_path = REPO_ROOT / "policies" / "authorization" / "enterprise-authorization.v1.json"
        if not policy_path.exists():
            pytest.skip("canonical policy not found in repo")
        version, digest = derive_policy_binding(
            policy_path=policy_path,
            policy_version="1.0.0",
        )
        assert version == "1.0.0"
        assert re.fullmatch(r"sha256:[a-f0-9]{64}", digest)

    def test_invalid_version_rejected(self):
        with pytest.raises(ValueError, match="policy_version must be semantic"):
            derive_policy_binding(
                policy_version="v1.0",
            )

    def test_nonexistent_path_rejected(self):
        with pytest.raises(ValueError, match="policy file not found"):
            derive_policy_binding(
                policy_path=Path("/nonexistent/policy.json"),
                policy_version="1.0.0",
            )

    def test_deterministic_digest(self):
        policy_path = REPO_ROOT / "policies" / "authorization" / "enterprise-authorization.v1.json"
        if not policy_path.exists():
            pytest.skip("canonical policy not found in repo")
        _, d1 = derive_policy_binding(policy_path=policy_path, policy_version="1.0.0")
        _, d2 = derive_policy_binding(policy_path=policy_path, policy_version="1.0.0")
        assert d1 == d2


# ===================================================================
# 4. verify_control_processor
# ===================================================================

class TestVerifyControlProcessor:
    """Tests for the explicit activation binding."""

    def _valid_bindings(self) -> dict:
        return {
            "enabled": True,
            "policy_version": "1.0.0",
            "policy_digest": _sha256_hex(b"policy"),
            "m2m_registry_digest": _sha256_hex(b"registry"),
            "release_manifest_digest": _sha256_hex(b"release"),
        }

    def test_valid_activation(self):
        assert verify_control_processor(**self._valid_bindings()) is True

    def test_false_rejected(self):
        bindings = self._valid_bindings()
        bindings["enabled"] = False
        with pytest.raises(ValueError, match="requires control_processor_enabled = true"):
            verify_control_processor(**bindings)

    def test_missing_policy_digest_rejected(self):
        bindings = self._valid_bindings()
        bindings["policy_digest"] = "not-a-digest"
        with pytest.raises(ValueError, match="policy_digest binding is invalid"):
            verify_control_processor(**bindings)

    def test_missing_registry_digest_rejected(self):
        bindings = self._valid_bindings()
        bindings["m2m_registry_digest"] = ""
        with pytest.raises(ValueError, match="m2m_registry_digest binding is invalid"):
            verify_control_processor(**bindings)

    def test_missing_release_digest_rejected(self):
        bindings = self._valid_bindings()
        bindings["release_manifest_digest"] = "md5:abc"
        with pytest.raises(ValueError, match="release_manifest_digest binding is invalid"):
            verify_control_processor(**bindings)

    def test_invalid_version_rejected(self):
        bindings = self._valid_bindings()
        bindings["policy_version"] = "latest"
        with pytest.raises(ValueError, match="policy_version binding is invalid"):
            verify_control_processor(**bindings)


def _artifact_inputs():
    fixtures = REPO_ROOT / "fixtures/valid"
    load = lambda name: json.loads((fixtures / name).read_text())
    release = load("release-v2-complete.synthetic.json")
    return dict(
        release=release,
        attestation=load("release-attestation-v2-complete.synthetic.json"),
        policy=load("release-trust-policy-v1-synthetic.json"),
        expected_policy_digest=(fixtures / "release-trust-policy-v1-synthetic.sha256").read_text().strip(),
        expected_release_document_digest=_release_digest(release),
        expected_release_manifest_digest=release["release_manifest_digest"],
        cicd_contract=load("cicd-contract-v2-synthetic.json"),
        expected_cicd_contract_digest=(fixtures / "cicd-contract-v2-synthetic.sha256").read_text().strip(),
        publication_receipt=load("identity-publication-receipt-v1-synthetic.json"),
        expected_publication_digest=(fixtures / "identity-publication-receipt-v1-synthetic.sha256").read_text().strip(),
        customer_id="cust_BBBBBBBBBBBBBBBBBBBBBBBBBB",
        deployment_id="dep_AAAAAAAAAAAAAAAAAAAAAAAAAA", account_id="123456789012",
        region="us-east-1", environment="staging",
        resolved_at=datetime(2026, 8, 28, 20, 4, tzinfo=UTC), max_contract_age_seconds=3600,
    )


def test_policy_binding_cannot_relabel_the_reviewed_policy_version():
    with pytest.raises(ValueError, match="policy_version does not match"):
        derive_policy_binding(policy_version="99.0.0")


@pytest.mark.parametrize("locator", ["identity_pre_token_lambda_locator", "identity_control_processor_lambda_locator"])
@pytest.mark.parametrize("mutation", ["key_without_digest", "uppercase_null", "version_utf8_overflow", "noncanonical_hash"])
def test_real_artifact_cli_rejects_root_incompatible_locators(tmp_path, locator, mutation):
    inputs = _artifact_inputs()
    publication = inputs["publication_receipt"][locator]
    if mutation == "key_without_digest":
        publication["key"] = f"deployments/{inputs['deployment_id']}/artifacts/unversioned.zip"
    elif mutation == "uppercase_null":
        publication["object_version"] = "NULL"
    elif mutation == "noncanonical_hash":
        publication["sha256_b64"] = publication["sha256_b64"][:-2] + "B="
    else:
        publication["object_version"] = "é" * 512 + "a"  # 1025 UTF-8 bytes, only 513 characters.
    _repin_receipt(inputs)
    output = tmp_path / "root-incompatible.json"
    process = subprocess.run(_artifact_cli(tmp_path, inputs, output), capture_output=True, text=True)
    assert process.returncode == 1, process.stdout + process.stderr
    assert not output.exists()


@pytest.mark.parametrize("version", ["a" * 1024, "é" * 512])
def test_artifact_accepts_exact_1024_byte_opaque_version(version):
    inputs = _artifact_inputs()
    for locator in ("identity_pre_token_lambda_locator", "identity_control_processor_lambda_locator"):
        inputs["publication_receipt"][locator]["object_version"] = version
    _repin_receipt(inputs)
    projection = build_identity_runtime_artifact(**inputs)
    assert projection["pre_token_artifact"]["object_version"] == version
    assert projection["control_processor_artifact"]["object_version"] == version


def _repin_receipt(inputs):
    receipt = inputs["publication_receipt"]
    receipt["receipt_digest"] = _digest_of(receipt, exclude_key="receipt_digest")
    inputs["expected_publication_digest"] = receipt["receipt_digest"]


@pytest.mark.parametrize("locator", ["identity_pre_token_lambda_locator", "identity_control_processor_lambda_locator"])
@pytest.mark.parametrize("mutation", ["foreign_digest", "duplicate_digest", "conflicting_digest"])
def test_real_artifact_cli_rejects_inconsistent_content_address(tmp_path, locator, mutation):
    inputs = _artifact_inputs()
    publication = inputs["publication_receipt"][locator]
    original = publication["key"].rsplit("/", 1)[-1]
    foreign = "f" * 64
    assert original != foreign
    if mutation == "foreign_digest":
        publication["key"] = publication["key"].replace(original, foreign)
    else:
        suffix = original if mutation == "duplicate_digest" else foreign
        publication["key"] += "/sha256/" + suffix + "/artifact.zip"
    # Even a newly reviewed locator must agree with the signed content digest.
    _repin_receipt(inputs)
    output = tmp_path / "inconsistent-content-address.json"
    process = subprocess.run(_artifact_cli(tmp_path, inputs, output), capture_output=True, text=True)
    assert process.returncode == 1, process.stdout + process.stderr
    assert not output.exists()


@pytest.mark.parametrize("separator", ["/", "-", ":"])
def test_artifact_accepts_single_matching_content_address(separator):
    inputs = _artifact_inputs()
    for locator in ("identity_pre_token_lambda_locator", "identity_control_processor_lambda_locator"):
        publication = inputs["publication_receipt"][locator]
        publication["key"] = publication["key"].replace("/sha256/", "/sha256" + separator) + ".zip"
    _repin_receipt(inputs)
    projection = build_identity_runtime_artifact(**inputs)
    assert projection["pre_token_artifact"]["key"] == inputs["publication_receipt"]["identity_pre_token_lambda_locator"]["key"]


def _artifact_cli(tmp_path, inputs, output):
    args = [sys.executable, str(REPO_ROOT / "tooling/identity_adapters.py"), "release-manifest"]
    for key in ("release", "attestation", "policy", "cicd_contract", "publication_receipt"):
        path = tmp_path / (key + ".json")
        path.write_text(json.dumps(inputs[key]))
        args.extend(("--" + key.replace("_", "-"), str(path)))
    for key in ("expected_policy_digest", "expected_release_document_digest",
                "expected_release_manifest_digest", "expected_cicd_contract_digest",
                "expected_publication_digest", "customer_id", "deployment_id", "account_id",
                "region", "environment", "max_contract_age_seconds"):
        args.extend(("--" + key.replace("_", "-"), str(inputs[key])))
    args.extend(("--resolved-at", inputs["resolved_at"].isoformat(), "--output", str(output)))
    return args


def test_real_artifact_cli_accepts_full_cicd_envelope_and_writes_private_output(tmp_path):
    inputs = _artifact_inputs()
    output = tmp_path / "projection.json"
    args = _artifact_cli(tmp_path, inputs, output)
    process = subprocess.run(args, capture_output=True, text=True, cwd=REPO_ROOT)
    assert process.returncode == 0, process.stdout + process.stderr
    result = json.loads(output.read_text())
    assert result["manifest_digest"] == inputs["expected_release_manifest_digest"]
    assert inputs["expected_release_document_digest"] != inputs["expected_release_manifest_digest"]
    assert result["pre_token_artifact"]["bucket"] == inputs["cicd_contract"]["outputs"]["artifact_bucket_name"]
    assert result == build_identity_runtime_artifact(**inputs)
    assert output.stat().st_mode & 0o777 == 0o600
    original = output.read_bytes()
    repeated = subprocess.run(args, capture_output=True, text=True, cwd=REPO_ROOT)
    assert repeated.returncode == 1
    assert output.read_bytes() == original


@pytest.mark.parametrize("mutation", [
    "bare_cicd", "cicd_customer", "cicd_deployment", "cicd_account", "cicd_region",
    "cicd_release", "cicd_version", "cicd_producer", "cicd_state", "cicd_output_digest",
    "cicd_stale", "cicd_future", "publication_key", "publication_version",
    "receipt_version", "receipt_release", "receipt_environment", "receipt_hash",
    "receipt_extra_artifact", "signature", "document_pin", "manifest_pin", "missing_receipt",
    "missing_receipt_pin", "duplicate_json",
])
def test_real_artifact_cli_rejects_invalid_authority_without_output(tmp_path, mutation):
    inputs = _artifact_inputs()
    receipt = inputs["publication_receipt"]
    cicd = inputs["cicd_contract"]
    if mutation == "bare_cicd":
        inputs["cicd_contract"] = cicd["outputs"]
    elif mutation.startswith("cicd_"):
        field, value = {
            "cicd_customer": ("customer_id", "cust_CCCCCCCCCCCCCCCCCCCCCCCCCC"),
            "cicd_deployment": ("deployment_id", "dep_CCCCCCCCCCCCCCCCCCCCCCCCCC"),
            "cicd_account": ("aws_account_id", "111111111111"),
            "cicd_region": ("region", "us-west-2"),
            "cicd_release": ("release_digest", _sha256_hex(b"foreign-release")),
            "cicd_version": ("release_version", "99.0.0"),
            "cicd_producer": ("producer", "roots/services"),
            "cicd_state": ("state_key", "dep_AAAAAAAAAAAAAAAAAAAAAAAAAA/us-east-1/services/terraform.tfstate"),
            "cicd_output_digest": ("contract_digest", _sha256_hex(b"wrong-outputs")),
            "cicd_stale": ("produced_at", "2026-08-27T20:03:00Z"),
            "cicd_future": ("produced_at", "2026-08-29T20:03:00Z"),
        }[mutation]
        cicd[field] = value
    elif mutation in {"publication_key", "publication_version"}:
        locator = receipt["identity_pre_token_lambda_locator"]
        field = "key" if mutation == "publication_key" else "object_version"
        locator[field] = (f"deployments/{inputs['deployment_id']}/artifacts/unreviewed.zip"
                          if field == "key" else "UNREVIEWED-REPLACEMENT-VERSION")
        # Only the self-digest changes. The protected external pin stays fixed.
        receipt["receipt_digest"] = _digest_of(receipt, exclude_key="receipt_digest")
    elif mutation.startswith("receipt_"):
        if mutation == "receipt_version":
            receipt["signed_release_manifest_version"] = "99.0.0"
        elif mutation == "receipt_release":
            receipt["signed_release_manifest_digest"] = inputs["expected_release_document_digest"]
        elif mutation == "receipt_environment":
            receipt["environment"] = "production"
        elif mutation == "receipt_hash":
            receipt["identity_pre_token_lambda_locator"]["sha256_b64"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        else:
            receipt["unexpected_archive"] = receipt["identity_pre_token_lambda_locator"]
        _repin_receipt(inputs)
    elif mutation == "signature":
        inputs["attestation"]["signature"]["value"] = "invalid"
    elif mutation == "document_pin":
        inputs["expected_release_document_digest"] = inputs["expected_release_manifest_digest"]
    elif mutation == "manifest_pin":
        inputs["expected_release_manifest_digest"] = inputs["expected_release_document_digest"]
    if mutation == "bare_cicd" or mutation.startswith("cicd_"):
        # Deliberately re-pin this malformed document to exercise tuple/producer/
        # freshness/output checks independently of the external integrity check.
        inputs["expected_cicd_contract_digest"] = _compute_digest(_canonical_bytes(inputs["cicd_contract"]))
        receipt["cicd_contract_digest"] = inputs["expected_cicd_contract_digest"]
        _repin_receipt(inputs)
    output = tmp_path / "rejected.json"
    args = _artifact_cli(tmp_path, inputs, output)
    if mutation == "missing_receipt":
        (tmp_path / "publication_receipt.json").unlink()
    elif mutation == "missing_receipt_pin":
        index = args.index("--expected-publication-digest")
        del args[index:index + 2]
    elif mutation == "duplicate_json":
        path = tmp_path / "publication_receipt.json"
        path.write_text('{"schema_version":"invalid",' + path.read_text()[1:])
    process = subprocess.run(args, capture_output=True, text=True, cwd=REPO_ROOT)
    assert process.returncode in {1, 2}, process.stdout + process.stderr
    assert "Traceback" not in process.stderr
    assert not output.exists()
