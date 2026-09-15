"""Tests for the infrastructure selection verifier (GUG-396).

Validates the offline verification of infrastructure-selection/v1 documents
including ARN partition/region/account binding, layer allowlist, placeholder
rejection, collision detection, and digest integrity.

No AWS calls are made. ARN validation is syntactic only.
"""
from __future__ import annotations

import copy
import json
import hashlib
import os
import stat
import tempfile
from pathlib import Path

import pytest

from tooling.deployment_infrastructure_selection import (
    SELECTION_VARIABLE_MAP,
    verify_infrastructure_selection,
    bind_infrastructure_variables,
    emit_variables,
    write_selection_output,
    _canonical_bytes,
    _compute_digest,
    _partition_for_region,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_selection(
    *,
    account_id: str = "905418363887",
    region: str = "us-east-1",
    environment: str = "production",
    certificate_arn: str | None = None,
    log_group_arn: str | None = None,
    zone_id: str = "Z0123456789ABCDEFGHIJ",
    include_digest: bool = False,
    target_digest: str = "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    release_digest: str = "sha256:0000000000000000000000000000000000000000000000000000000000000000",
) -> dict:
    """Build a minimal valid infrastructure selection document."""
    if certificate_arn is None:
        certificate_arn = f"arn:aws:acm:{region}:{account_id}:certificate/12345678-1234-1234-1234-123456789abc"
    if log_group_arn is None:
        log_group_arn = f"arn:aws:logs:{region}:{account_id}:log-group:/scanalyze/api-access"

    doc = {
        "schema_version": "1",
        "record_type": "deployment_infrastructure_selection",
        "customer_id": "cust_01M260EYHD9Q3AQTM2N48Q4RW9",
        "deployment_id": "dep_01M260EYHD8VGSR9MB6Q32BP9K",
        "account_id": account_id,
        "region": region,
        "environment": environment,
        "partition": _partition_for_region(region),
        "layer": "platform",
        "target_digest": target_digest,
        "release_digest": release_digest,
        "account_id": account_id,
        "region": region,
        "environment": environment,
        "selections": {
            "internal_certificate_arn": {
                "arn": certificate_arn,
                "target_layer": "platform",
                "description": "ACM certificate for internal ALB HTTPS listener",
            },
            "api_access_log_group_arn": {
                "arn": log_group_arn,
                "target_layer": "edge-identity",
                "description": "CloudWatch log group for API Gateway access logs",
            },
            "route53_zone_id": {
                "zone_id": zone_id,
                "target_layer": "edge",
                "description": "Route53 public hosted zone for DNS records",
            },
        },
    }

    if include_digest:
        digestible = dict(doc)
        doc["record_digest"] = _compute_digest(_canonical_bytes(digestible))

    return doc


# ---------------------------------------------------------------------------
# Positive tests
# ---------------------------------------------------------------------------

class TestPositiveValidation:
    """Successful verification for valid selections."""

    def test_valid_aws_commercial_selection(self):
        doc = _make_selection()
        bindings = verify_infrastructure_selection(doc)

        assert "platform" in bindings
        assert "edge-identity" in bindings
        assert "edge" in bindings

        assert bindings["platform"]["internal_certificate_arn"].startswith("arn:aws:acm:us-east-1:")
        assert bindings["edge-identity"]["api_access_log_group_arn"].startswith("arn:aws:logs:us-east-1:")
        assert bindings["edge"]["route53_zone_id"] == "Z0123456789ABCDEFGHIJ"

    def test_valid_aws_china_selection(self):
        doc = _make_selection(
            region="cn-north-1",
            certificate_arn="arn:aws-cn:acm:cn-north-1:905418363887:certificate/12345678-1234-1234-1234-123456789abc",
            log_group_arn="arn:aws-cn:logs:cn-north-1:905418363887:log-group:/scanalyze/api-access",
        )
        bindings = verify_infrastructure_selection(doc)

        assert bindings["platform"]["internal_certificate_arn"].startswith("arn:aws-cn:acm:cn-north-1:")
        assert bindings["edge-identity"]["api_access_log_group_arn"].startswith("arn:aws-cn:logs:cn-north-1:")

    def test_valid_aws_govcloud_selection(self):
        doc = _make_selection(
            region="us-gov-west-1",
            certificate_arn="arn:aws-us-gov:acm:us-gov-west-1:905418363887:certificate/12345678-1234-1234-1234-123456789abc",
            log_group_arn="arn:aws-us-gov:logs:us-gov-west-1:905418363887:log-group:/scanalyze/api-access",
        )
        bindings = verify_infrastructure_selection(doc)

        assert bindings["platform"]["internal_certificate_arn"].startswith("arn:aws-us-gov:acm:us-gov-west-1:")

    def test_emit_variables_per_layer(self):
        doc = _make_selection()
        bindings = verify_infrastructure_selection(doc)

        platform_vars = emit_variables(bindings, "platform")
        assert len(platform_vars) == 1
        assert "internal_certificate_arn" in platform_vars

        edge_vars = emit_variables(bindings, "edge")
        assert len(edge_vars) == 1
        assert "route53_zone_id" in edge_vars

        # Layer with no selections
        services_vars = emit_variables(bindings, "services")
        assert services_vars == {}

    def test_digest_verification_matches(self):
        doc = _make_selection(include_digest=True)
        expected = doc["record_digest"]
        bindings = verify_infrastructure_selection(doc, expected_digest=expected)
        assert len(bindings) == 3

    def test_idempotent_digest(self):
        doc1 = _make_selection(include_digest=True)
        doc2 = _make_selection(include_digest=True)
        assert doc1["record_digest"] == doc2["record_digest"]


# ---------------------------------------------------------------------------
# Negative tests
# ---------------------------------------------------------------------------

class TestNegativeValidation:
    """Fail-closed verification for invalid selections."""

    def test_foreign_account_arn_rejected(self):
        doc = _make_selection(
            certificate_arn="arn:aws:acm:us-east-1:111111111111:certificate/12345678-1234-1234-1234-123456789abc",
        )
        with pytest.raises(ValueError, match="ARN account"):
            verify_infrastructure_selection(doc)

    @pytest.mark.parametrize("declared_partition", ["aws-cn", "aws-us-gov"])
    def test_declared_partition_must_match_region(self, declared_partition):
        doc = _make_selection()
        doc["partition"] = declared_partition
        doc["record_digest"] = _compute_digest(_canonical_bytes(doc))
        with pytest.raises(ValueError, match="partition does not match region"):
            verify_infrastructure_selection(doc, expected_digest=doc["record_digest"])

    def test_foreign_region_arn_rejected(self):
        doc = _make_selection(
            certificate_arn="arn:aws:acm:eu-west-1:905418363887:certificate/12345678-1234-1234-1234-123456789abc",
        )
        with pytest.raises(ValueError, match="ARN region"):
            verify_infrastructure_selection(doc)

    def test_wrong_partition_arn_rejected(self):
        doc = _make_selection(
            certificate_arn="arn:aws-cn:acm:us-east-1:905418363887:certificate/12345678-1234-1234-1234-123456789abc",
        )
        with pytest.raises(ValueError, match="ARN partition"):
            verify_infrastructure_selection(doc)

    def test_placeholder_arn_rejected(self):
        doc = _make_selection(
            certificate_arn="arn:aws:acm:us-east-1:905418363887:certificate/PLACEHOLDER-CERT-ID-XXXXXXXXXXX",
        )
        with pytest.raises((ValueError, Exception)):
            verify_infrastructure_selection(doc)

    def test_digest_mismatch_rejected(self):
        doc = _make_selection(include_digest=True)
        with pytest.raises(ValueError, match="external digest mismatch"):
            verify_infrastructure_selection(doc, expected_digest="sha256:0000000000000000000000000000000000000000000000000000000000000000")

    def test_self_digest_tampered_rejected(self):
        doc = _make_selection(include_digest=True)
        doc["selections"]["route53_zone_id"]["zone_id"] = "ZINVALIDZONE12345"
        with pytest.raises(ValueError, match="record_digest mismatch"):
            verify_infrastructure_selection(doc)

    def test_additional_properties_rejected(self):
        doc = _make_selection()
        doc["extra_field"] = "should not be here"
        with pytest.raises(Exception):
            verify_infrastructure_selection(doc)

    def test_missing_selection_rejected(self):
        doc = _make_selection()
        del doc["selections"]["route53_zone_id"]
        with pytest.raises(Exception):
            verify_infrastructure_selection(doc)

    def test_wrong_target_layer_rejected(self):
        doc = _make_selection()
        doc["selections"]["internal_certificate_arn"]["target_layer"] = "edge"
        with pytest.raises((ValueError, Exception)):
            verify_infrastructure_selection(doc)

    def test_wrong_schema_version_rejected(self):
        doc = _make_selection()
        doc["schema_version"] = "2"
        with pytest.raises(Exception):
            verify_infrastructure_selection(doc)

    def test_zero_account_in_arn_rejected(self):
        doc = _make_selection(
            account_id="123456789012",
            certificate_arn="arn:aws:acm:us-east-1:000000000000:certificate/12345678-1234-1234-1234-123456789abc",
        )
        with pytest.raises((ValueError, Exception)):
            verify_infrastructure_selection(doc)

    def test_invalid_zone_id_format_rejected(self):
        doc = _make_selection(zone_id="INVALID-ZONE-123")
        with pytest.raises(Exception):
            verify_infrastructure_selection(doc)


# ---------------------------------------------------------------------------
# Partition derivation tests
# ---------------------------------------------------------------------------

class TestPartitionDerivation:
    """Verify partition-from-region derivation logic."""

    def test_commercial(self):
        assert _partition_for_region("us-east-1") == "aws"
        assert _partition_for_region("eu-west-1") == "aws"
        assert _partition_for_region("ap-southeast-1") == "aws"

    def test_china(self):
        assert _partition_for_region("cn-north-1") == "aws-cn"
        assert _partition_for_region("cn-northwest-1") == "aws-cn"

    def test_govcloud(self):
        assert _partition_for_region("us-gov-west-1") == "aws-us-gov"
        assert _partition_for_region("us-gov-east-1") == "aws-us-gov"


# ---------------------------------------------------------------------------
# Binding and CLI tests
# ---------------------------------------------------------------------------

class TestBindingAndCLI:
    """Verify exact bindings to target/layer/release and CLI usage."""
    
    def _make_target(self, doc):
        return {
            "schema_version": "2",
            "record_type": "deployment_target",
            "customer_id": doc["customer_id"],
            "deployment_id": doc["deployment_id"],
            "account_id": doc["account_id"],
            "region": doc["region"],
            "environment": doc["environment"],
            "runtime_origin": {"schema_version": "1", "domain_name": "github.com"},
            "status": "ACTIVE",
            "account_ready": {"schema_version": "2", "baseline_version": "v1.0.0", "contract_digest": "sha256:1234567812345678123456781234567812345678123456781234567812345678"},
            "state_binding": {"state_bucket": "arn:aws:s3:::scanalyze-state-123", "state_kms_key": "arn:aws:kms:us-east-1:905418363887:key/12345678-1234-1234-1234-123456789abc"},
            "registry_version": 1
        }
        
    def _make_release(self, doc):
        return {
            "schema_version": "release-deployment-projection.v1",
            "target": doc["environment"],
            "release_id": "rel_01M260EYHD8VGSR9MB6Q32BP9K",
            "release_version": "v1.2.3",
            "release_manifest_digest": "sha256:1234567812345678123456781234567812345678123456781234567812345678",
            "release_attestation_digest": "sha256:1234567812345678123456781234567812345678123456781234567812345678",
            "service_images": {
                "ingest-api": "scanalyze-ingest-api@sha256:1234567812345678123456781234567812345678123456781234567812345678",
                "ocr-worker": "scanalyze-ocr-worker@sha256:1234567812345678123456781234567812345678123456781234567812345678",
                "postprocess-worker": "scanalyze-postprocess-worker@sha256:1234567812345678123456781234567812345678123456781234567812345678",
                "classifier-worker": "scanalyze-classifier-worker@sha256:1234567812345678123456781234567812345678123456781234567812345678",
                "bank-worker": "scanalyze-bank-worker@sha256:1234567812345678123456781234567812345678123456781234567812345678",
                "personal-worker": "scanalyze-personal-worker@sha256:1234567812345678123456781234567812345678123456781234567812345678",
                "gov-worker": "scanalyze-gov-worker@sha256:1234567812345678123456781234567812345678123456781234567812345678"
            },
            "runtime_artifacts": {
                "identity-pre-token-lambda": {
                    "uri": "s3://scanalyze-artifacts/sha256/1234567812345678123456781234567812345678123456781234567812345678/pre-token.zip",
                    "digest": "sha256:1234567812345678123456781234567812345678123456781234567812345678"
                },
                "identity-control-processor-lambda": {
                    "uri": "s3://scanalyze-artifacts/sha256/1234567812345678123456781234567812345678123456781234567812345678/control.zip",
                    "digest": "sha256:1234567812345678123456781234567812345678123456781234567812345678"
                },
                "scanalyze-frontend-ui": {
                    "uri": "s3://scanalyze-artifacts/sha256/1234567812345678123456781234567812345678123456781234567812345678/frontend.zip",
                    "digest": "sha256:1234567812345678123456781234567812345678123456781234567812345678"
                }
            },
            "promotion_mode": "copy-by-digest",
            "rebuild": False
        }
        
    def _digest(self, obj):
        digestible = {k: v for k, v in obj.items() if k != "record_digest"}
        computed = _compute_digest(_canonical_bytes(digestible))
        obj["record_digest"] = computed
        return computed

    def test_bind_success(self):
        doc = _make_selection()
        target = self._make_target(doc)
        tdig = self._digest(target)
        rel = self._make_release(doc)
        rdig = self._digest(rel)
        
        # Tie digests back into doc so they match
        doc["target_digest"] = tdig
        doc["release_digest"] = rdig
        doc["record_digest"] = self._digest(doc)

        variables = bind_infrastructure_variables(
            selection=doc,
            expected_digest=doc["record_digest"],
            target=target,
            expected_target_digest=tdig,
            layer="platform",
            release=rel,
            expected_release_digest=rdig,
        )
        assert len(variables) == 1
        assert "internal_certificate_arn" in variables

    @pytest.mark.parametrize("requested_layer", ["edge", "edge-identity"])
    def test_selection_cannot_authorize_another_layer(self, requested_layer):
        doc = _make_selection()
        target = self._make_target(doc)
        target_digest = self._digest(target)
        release = self._make_release(doc)
        release_digest = self._digest(release)
        doc["target_digest"] = target_digest
        doc["release_digest"] = release_digest
        selection_digest = self._digest(doc)

        with pytest.raises(ValueError, match="selection layer does not match"):
            bind_infrastructure_variables(
                doc, selection_digest, target, target_digest,
                requested_layer, release, release_digest,
            )

    @pytest.mark.parametrize("layer,variable", [
        ("platform", "internal_certificate_arn"),
        ("edge", "route53_zone_id"),
        ("edge-identity", "api_access_log_group_arn"),
    ])
    def test_emits_only_the_independently_bound_layer(self, layer, variable):
        doc = _make_selection()
        doc["layer"] = layer
        target = self._make_target(doc)
        target_digest = self._digest(target)
        release = self._make_release(doc)
        release_digest = self._digest(release)
        doc["target_digest"] = target_digest
        doc["release_digest"] = release_digest
        selection_digest = self._digest(doc)

        result = bind_infrastructure_variables(
            doc, selection_digest, target, target_digest,
            layer, release, release_digest,
        )
        assert set(result) == {variable}

    def test_bind_changed_target_rejected(self):
        doc = _make_selection()
        target = self._make_target(doc)
        tdig = self._digest(target)
        rel = self._make_release(doc)
        rdig = self._digest(rel)
        
        doc["target_digest"] = tdig
        doc["release_digest"] = rdig
        doc["record_digest"] = self._digest(doc)

        # Alter target AFTER generating valid doc
        target["account_id"] = "111122223333"
        tdig = self._digest(target)

        with pytest.raises(ValueError, match="identity mismatch on account_id"):
            bind_infrastructure_variables(
                selection=doc,
                expected_digest=doc["record_digest"],
                target=target,
                expected_target_digest=tdig,
                layer="platform",
                release=rel,
                expected_release_digest=rdig,
            )
            
    def test_bind_missing_anchor_rejected(self):
        doc = _make_selection()
        target = self._make_target(doc)
        tdig = self._digest(target)
        rel = self._make_release(doc)
        rdig = self._digest(rel)
        doc["target_digest"] = tdig
        doc["release_digest"] = rdig
        doc["record_digest"] = self._digest(doc)

        with pytest.raises(ValueError, match="target is required"):
            bind_infrastructure_variables(
                selection=doc,
                expected_digest=doc["record_digest"],
                target=None,
                expected_target_digest=tdig,
                layer="platform",
                release=rel,
                expected_release_digest=rdig,
            )

    def test_bind_changed_release_rejected(self):
        doc = _make_selection()
        target = self._make_target(doc)
        tdig = self._digest(target)
        rel = self._make_release(doc)
        rdig = self._digest(rel)
        
        doc["target_digest"] = tdig
        doc["release_digest"] = rdig
        doc["record_digest"] = self._digest(doc)

        rel["target"] = "sandbox" # wrong environment
        rdig = self._digest(rel)
        doc["release_digest"] = rdig
        doc["record_digest"] = self._digest(doc)
        
        with pytest.raises(ValueError, match="release target does not match"):
            bind_infrastructure_variables(
                selection=doc,
                expected_digest=doc["record_digest"],
                target=target,
                expected_target_digest=tdig,
                layer="platform",
                release=rel,
                expected_release_digest=rdig,
            )

    def test_cli_negative_missing_args(self, tmp_path):
        import subprocess, sys
        doc = _make_selection(include_digest=True)
        sel_path = tmp_path / "sel.json"
        sel_path.write_text(json.dumps(doc))
        
        result = subprocess.run([
            sys.executable, "-m", "tooling.deployment_infrastructure_selection",
            "--selection", str(sel_path),
            "--layer", "platform"
            # Missing target, expected-digest, etc.
        ], capture_output=True, text=True)
        assert result.returncode == 2
        assert "is required for variable emission" in result.stderr

# ---------------------------------------------------------------------------
# Output safety tests
# ---------------------------------------------------------------------------

class TestOutputSafety:
    """Verify safe file writing behavior."""

    def test_write_creates_private_file(self):
        doc = _make_selection()
        bindings = verify_infrastructure_selection(doc)
        variables = emit_variables(bindings, "platform")

        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = Path(tmpdir) / "infra-vars.json"
            write_selection_output(variables, out_path)

            assert out_path.exists()
            st = os.stat(out_path)
            assert stat.S_IMODE(st.st_mode) == 0o600

            data = json.loads(out_path.read_bytes())
            assert data == variables

    def test_overwrite_denied(self):
        doc = _make_selection()
        bindings = verify_infrastructure_selection(doc)
        variables = emit_variables(bindings, "platform")

        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = Path(tmpdir) / "infra-vars.json"
            write_selection_output(variables, out_path)

            with pytest.raises(ValueError, match="output already exists"):
                write_selection_output(variables, out_path)

    def test_canonical_bytes_deterministic(self):
        doc = _make_selection()
        b1 = _canonical_bytes(doc)
        b2 = _canonical_bytes(doc)
        assert b1 == b2
        assert _compute_digest(b1) == _compute_digest(b2)
