"""RED tests for the additive GUG-102 identity contract v2."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from tooling.validate_schema import validate_fixture, validate_semantics


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / "schemas" / "identity-contract.v2.schema.json"
VALID_FIXTURE = REPO_ROOT / "fixtures" / "valid" / "identity-contract-v2-m2m.json"
INVALID_FIXTURES = (
    REPO_ROOT
    / "fixtures"
    / "invalid"
    / "identity-contract-v2-missing-deployment-binding.json",
    REPO_ROOT
    / "fixtures"
    / "invalid"
    / "identity-contract-v2-missing-restrictions.json",
    REPO_ROOT
    / "fixtures"
    / "invalid"
    / "identity-contract-v2-legacy-customer-id.json",
    REPO_ROOT
    / "fixtures"
    / "invalid"
    / "identity-contract-v2-legacy-client-id-map-mode.json",
    REPO_ROOT
    / "fixtures"
    / "invalid"
    / "identity-contract-v2-m2m-without-access-token.json",
    REPO_ROOT
    / "fixtures"
    / "invalid"
    / "identity-contract-v2-missing-action-scope-policy.json",
)
SEMANTIC_INVALID_FIXTURE = (
    REPO_ROOT
    / "fixtures"
    / "invalid"
    / "identity-contract-v2-binding-mismatch.json"
)
CLIENT_COVERAGE_INVALID_FIXTURE = (
    REPO_ROOT
    / "fixtures"
    / "invalid"
    / "identity-contract-v2-client-coverage-mismatch.json"
)
ACTION_POLICY_SEMANTIC_FIXTURES = (
    (
        REPO_ROOT
        / "fixtures"
        / "invalid"
        / "identity-contract-v2-overlapping-action-scope-sets.json",
        "pairwise disjoint",
    ),
    (
        REPO_ROOT
        / "fixtures"
        / "invalid"
        / "identity-contract-v2-scope-outside-action-universe.json",
        "within the action scope universe",
    ),
    (
        REPO_ROOT
        / "fixtures"
        / "invalid"
        / "identity-contract-v2-partial-action-scope-set.json",
        "all-or-none",
    ),
    (
        REPO_ROOT
        / "fixtures"
        / "invalid"
        / "identity-contract-v2-binding-with-no-action.json",
        "at least one action",
    ),
)
VALIDATOR_SCRIPT = (
    REPO_ROOT / "scripts" / "deployment" / "validate-identity-contract.py"
)


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture
def validator() -> Draft202012Validator:
    assert SCHEMA_PATH.is_file(), "identity-contract v2 schema must be additive"
    schema = _load_json(SCHEMA_PATH)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def test_valid_m2m_contract_v2_passes(validator: Draft202012Validator) -> None:
    errors = list(validator.iter_errors(_load_json(VALID_FIXTURE)))
    assert errors == []


@pytest.mark.parametrize("fixture", INVALID_FIXTURES, ids=lambda path: path.stem)
def test_invalid_m2m_contract_v2_fails(
    validator: Draft202012Validator,
    fixture: Path,
) -> None:
    errors = list(validator.iter_errors(_load_json(fixture)))
    assert errors, f"{fixture.name} must fail closed"


def test_m2m_binding_must_match_contract_identity(
    validator: Draft202012Validator,
) -> None:
    assert list(validator.iter_errors(_load_json(SEMANTIC_INVALID_FIXTURE))) == []
    valid, message = validate_fixture(SEMANTIC_INVALID_FIXTURE, SCHEMA_PATH)
    assert not valid
    assert "customer_id must match" in message


@pytest.mark.parametrize(
    ("fixture", "expected_message"),
    ACTION_POLICY_SEMANTIC_FIXTURES,
    ids=lambda value: value.stem if isinstance(value, Path) else value,
)
def test_action_scope_policy_semantics_fail_closed(
    validator: Draft202012Validator,
    fixture: Path,
    expected_message: str,
) -> None:
    contract = _load_json(fixture)
    assert list(validator.iter_errors(contract)) == []
    errors = validate_semantics(contract, SCHEMA_PATH)
    assert any(expected_message in error for error in errors)
    valid, message = validate_fixture(fixture, SCHEMA_PATH)
    assert not valid
    assert message.startswith("FAIL:")


def _run_validator(fixture: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(VALIDATOR_SCRIPT), str(fixture)],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def test_operational_validator_dispatches_v2_contract() -> None:
    result = _run_validator(VALID_FIXTURE)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "valid identity contract" in result.stdout


def test_operational_validator_preserves_v1_dispatch(tmp_path: Path) -> None:
    fixture = tmp_path / "identity-v1.json"
    fixture.write_text(
        json.dumps(
            {
                "schema_version": "1",
                "deployment_id": "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV",
                "customer_id": "synthetic-acme",
                "cognito": {
                    "user_pool_id": "us-east-1_SYNTHETIC01",
                    "client_ids": ["syntheticspaclient000000000001"],
                    "allowed_token_uses": ["access"],
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
                "allowed_domains": ["bank"],
                "restrictions": {
                    "cross_account_access": False,
                    "cross_deployment_access": False,
                    "password_in_docs": False,
                },
            }
        ),
        encoding="utf-8",
    )
    result = _run_validator(fixture)
    assert result.returncode == 0, result.stdout + result.stderr


def test_operational_validator_rejects_m2m_without_access_token_use() -> None:
    fixture = (
        REPO_ROOT
        / "fixtures"
        / "invalid"
        / "identity-contract-v2-m2m-without-access-token.json"
    )
    result = _run_validator(fixture)
    assert result.returncode == 1
    assert "cognito.allowed_token_uses" in result.stdout


def test_operational_validator_requires_action_scope_policy() -> None:
    fixture = (
        REPO_ROOT
        / "fixtures"
        / "invalid"
        / "identity-contract-v2-missing-action-scope-policy.json"
    )
    result = _run_validator(fixture)
    assert result.returncode == 1
    assert "action_scope_sets" in result.stdout


@pytest.mark.parametrize(
    ("fixture", "expected_message"),
    (
        (SEMANTIC_INVALID_FIXTURE, "customer_id must match"),
        (CLIENT_COVERAGE_INVALID_FIXTURE, "cover each declared m2m_client_id"),
        *ACTION_POLICY_SEMANTIC_FIXTURES,
    ),
)
def test_operational_validator_rejects_v2_semantic_mismatch(
    fixture: Path,
    expected_message: str,
) -> None:
    result = _run_validator(fixture)
    assert result.returncode == 1
    assert expected_message in result.stdout
