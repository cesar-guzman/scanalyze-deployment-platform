"""Tests for deployment manifest schema validation."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCHEMA_PATH = REPO_ROOT / "schemas" / "deployment-manifest.schema.json"


@pytest.fixture
def schema():
    with open(SCHEMA_PATH) as f:
        return json.load(f)


@pytest.fixture
def valid_manifest():
    return {
        "schema_version": "1",
        "customer_id": "synthetic-acme",
        "deployment_id": "dep_01SYNTH3T1CABC0XAMP0EHABCD",
        "environment": "sandbox",
        "aws_account_id": "123456789012",
        "aws_region": "us-east-1",
        "terraform_backend": {
            "bucket": "dep-01synth3t1cabc0xamp0ehabcd-tfstate",
            "lock_table": "dep_01SYNTH3T1CABC0XAMP0EHABCD-tflock",
            "key_prefix": "scanalyze/sandbox",
        },
        "github": {
            "environment": "synthetic-acme-sandbox",
            "oidc_role_arn": "arn:aws:iam::123456789012:role/github-oidc-deploy",
        },
        "ecr": {
            "prefix": "dep-01synth3t1cabc0xamp0ehabcd/scanalyze",
        },
        "base_image_uri": "123456789012.dkr.ecr.us-east-1.amazonaws.com/base:3.11@sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "enabled_domains": ["bank", "personal", "gov"],
    }


def _validate(schema, instance):
    import jsonschema

    validator = jsonschema.Draft202012Validator(schema)
    return list(validator.iter_errors(instance))


def test_valid_manifest_passes(schema, valid_manifest):
    errors = _validate(schema, valid_manifest)
    assert len(errors) == 0, f"Unexpected errors: {[str(e) for e in errors]}"


def test_missing_deployment_id_fails(schema, valid_manifest):
    del valid_manifest["deployment_id"]
    errors = _validate(schema, valid_manifest)
    assert any("deployment_id" in str(e) for e in errors)


def test_missing_account_id_fails(schema, valid_manifest):
    del valid_manifest["aws_account_id"]
    errors = _validate(schema, valid_manifest)
    assert any("aws_account_id" in str(e) for e in errors)


def test_missing_region_fails(schema, valid_manifest):
    del valid_manifest["aws_region"]
    errors = _validate(schema, valid_manifest)
    assert len(errors) > 0


def test_missing_base_image_fails(schema, valid_manifest):
    del valid_manifest["base_image_uri"]
    errors = _validate(schema, valid_manifest)
    assert len(errors) > 0


def test_latest_base_image_fails(schema, valid_manifest):
    valid_manifest["base_image_uri"] = "some-repo:latest"
    errors = _validate(schema, valid_manifest)
    assert len(errors) > 0, "'latest' should not match the digest pattern"


def test_zeroed_account_id_fails(schema, valid_manifest):
    valid_manifest["aws_account_id"] = "000000000000"
    errors = _validate(schema, valid_manifest)
    assert len(errors) > 0, "000000000000 should be rejected"


def test_invalid_environment_fails(schema, valid_manifest):
    valid_manifest["environment"] = "yolo"
    errors = _validate(schema, valid_manifest)
    assert len(errors) > 0


def test_empty_domains_fails(schema, valid_manifest):
    valid_manifest["enabled_domains"] = []
    errors = _validate(schema, valid_manifest)
    assert len(errors) > 0


def test_invalid_region_fails(schema, valid_manifest):
    valid_manifest["aws_region"] = "invalid"
    errors = _validate(schema, valid_manifest)
    assert len(errors) > 0


def test_account_id_not_12_digits_fails(schema, valid_manifest):
    valid_manifest["aws_account_id"] = "12345"
    errors = _validate(schema, valid_manifest)
    assert len(errors) > 0


def test_identity_configuration_rejects_id_tokens(schema, valid_manifest):
    valid_manifest["identity"] = {
        "cognito_user_pool_id": "us-east-1_SYNTHETIC01",
        "cognito_client_ids": ["synthetic-client"],
        "allowed_token_uses": ["access", "id"],
        "deployment_claim": "custom:deployment_id",
    }

    errors = _validate(schema, valid_manifest)

    assert errors
    assert any("allowed_token_uses" in error.json_path for error in errors)
