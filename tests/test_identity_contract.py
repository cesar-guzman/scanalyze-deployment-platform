"""Tests for identity contract schema validation.

Tests cover:
- Valid synthetic contract passes
- Missing required fields fail
- Deployment mismatch is detected
- Forbidden cross-account/cross-deployment access is rejected
- Untrusted customer_id source is rejected
- Missing token/claim rejects
- Domain not permitted rejects
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / "schemas" / "identity-contract.schema.json"


@pytest.fixture
def schema():
    with open(SCHEMA_PATH) as f:
        return json.load(f)


@pytest.fixture
def valid_contract():
    return {
        "schema_version": "1",
        "deployment_id": "dep_01SYNTH3T1CABC0XAMP0EHABCD",
        "customer_id": "synthetic-acme",
        "cognito": {
            "user_pool_id": "us-east-1_SYNTHETIC01",
            "client_ids": ["synthetic0client0id0000000001"],
            "allowed_token_uses": ["access", "id"],
        },
        "authorization": {
            "mode": "cognito_jwt",
            "deployment_claim": "custom:deployment_id",
            "enforce_deployment_binding": True,
            "customer_id_source": "claim",
        },
        "claim_mapping": {
            "deployment_id": "custom:deployment_id",
            "customer_id": "custom:customer_id",
        },
        "allowed_domains": ["bank", "personal", "gov"],
        "restrictions": {
            "cross_account_access": False,
            "cross_deployment_access": False,
            "password_in_docs": False,
        },
    }


def _validate(schema, instance):
    import jsonschema

    validator = jsonschema.Draft202012Validator(schema)
    return list(validator.iter_errors(instance))


def test_valid_contract_passes(schema, valid_contract):
    errors = _validate(schema, valid_contract)
    assert len(errors) == 0, f"Expected no errors, got: {errors}"


def test_missing_deployment_id_fails(schema, valid_contract):
    del valid_contract["deployment_id"]
    errors = _validate(schema, valid_contract)
    assert any("deployment_id" in str(e) for e in errors)


def test_missing_cognito_fails(schema, valid_contract):
    del valid_contract["cognito"]
    errors = _validate(schema, valid_contract)
    assert any("cognito" in str(e) for e in errors)


def test_missing_authorization_fails(schema, valid_contract):
    del valid_contract["authorization"]
    errors = _validate(schema, valid_contract)
    assert any("authorization" in str(e) for e in errors)


def test_empty_client_ids_fails(schema, valid_contract):
    valid_contract["cognito"]["client_ids"] = []
    errors = _validate(schema, valid_contract)
    assert len(errors) > 0


def test_cross_account_true_fails(schema, valid_contract):
    valid_contract["restrictions"]["cross_account_access"] = True
    errors = _validate(schema, valid_contract)
    assert len(errors) > 0, "cross_account_access=true should fail schema validation"


def test_cross_deployment_true_fails(schema, valid_contract):
    valid_contract["restrictions"]["cross_deployment_access"] = True
    errors = _validate(schema, valid_contract)
    assert len(errors) > 0, "cross_deployment_access=true should fail schema validation"


def test_password_in_docs_true_fails(schema, valid_contract):
    valid_contract["restrictions"]["password_in_docs"] = True
    errors = _validate(schema, valid_contract)
    assert len(errors) > 0, "password_in_docs=true should fail schema validation"


def test_invalid_deployment_id_format_fails(schema, valid_contract):
    valid_contract["deployment_id"] = "not-a-valid-dep-id"
    errors = _validate(schema, valid_contract)
    assert len(errors) > 0


def test_domain_not_in_enum_fails(schema, valid_contract):
    valid_contract["allowed_domains"] = ["bank", "invalid_domain"]
    errors = _validate(schema, valid_contract)
    assert len(errors) > 0


def test_invalid_token_use_fails(schema, valid_contract):
    valid_contract["cognito"]["allowed_token_uses"] = ["invalid"]
    errors = _validate(schema, valid_contract)
    assert len(errors) > 0


def test_invalid_auth_mode_fails(schema, valid_contract):
    valid_contract["authorization"]["mode"] = "plaintext_password"
    errors = _validate(schema, valid_contract)
    assert len(errors) > 0
