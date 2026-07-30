"""GUG-217 identity-context proof and durable ledger contract tests."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

from tooling.platform_authority_identity_context_pep import (
    IdentityContextProofReceipt,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = REPO_ROOT / "schemas"
VALID = REPO_ROOT / "fixtures" / "valid"
INVALID = REPO_ROOT / "fixtures" / "invalid"

BINDING_SCHEMA = SCHEMAS / "platform-authority-identity-context-pep-binding.v1.schema.json"
COMPATIBILITY_SCHEMA = (
    SCHEMAS
    / "platform-authority-identity-context-pep-compatibility-receipt.v1.schema.json"
)
PROOF_SCHEMA = (
    SCHEMAS / "platform-authority-identity-context-proof-receipt.v1.schema.json"
)
LEDGER_SCHEMA = (
    SCHEMAS / "platform-authority-change-set-retirement-ledger.v2.schema.json"
)

BINDING_FIXTURE = (
    VALID / "platform-authority-identity-context-pep-binding-v1-synthetic.json"
)
COMPATIBILITY_FIXTURE = (
    VALID
    / "platform-authority-identity-context-pep-compatibility-receipt-v1-synthetic.json"
)
PROOF_FIXTURE = (
    VALID / "platform-authority-identity-context-proof-receipt-v1-synthetic.json"
)
CLASSIFIED_FIXTURE = (
    VALID
    / "platform-authority-change-set-retirement-ledger-v2-classified-synthetic.json"
)
RETIRED_FIXTURE = (
    VALID / "platform-authority-change-set-retirement-ledger-v2-retired-synthetic.json"
)

BINDING_DIGEST_FIELDS = (
    "authority_account_id",
    "region",
    "identity_center_application_arn",
    "identity_center_instance_arn",
    "identity_store_arn",
    "redirect_uri",
    "broker_execution_role_arn",
    "classifier_user_id",
    "approver_user_id",
    "classifier_proof_role_arn",
    "approver_proof_role_arn",
    "proof_duration_seconds",
    "max_token_lifetime_seconds",
)
LEDGER_IDENTITY_BINDING_FIELDS = (
    "identity_store_arn_digest",
    "identity_center_instance_arn_digest",
    "identity_center_application_arn_digest",
    "classifier_identity_store_user_id_digest",
    "approver_identity_store_user_id_digest",
    "classifier_assignment_sha256",
    "approver_assignment_sha256",
    "classifier_invoker_policy_sha256",
    "approver_invoker_policy_sha256",
    "classifier_proof_policy_sha256",
    "approver_proof_policy_sha256",
    "identity_center_application_actor_policy_sha256",
)


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _canonical_digest(value: object) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _validator(path: Path) -> Draft202012Validator:
    schema = _load(path)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


@pytest.mark.parametrize(
    "schema_path",
    (BINDING_SCHEMA, COMPATIBILITY_SCHEMA, PROOF_SCHEMA, LEDGER_SCHEMA),
)
def test_gug217_schemas_are_valid_draft_2020_12(schema_path: Path) -> None:
    _validator(schema_path)


@pytest.mark.parametrize(
    ("schema_path", "fixture_path"),
    (
        (BINDING_SCHEMA, BINDING_FIXTURE),
        (COMPATIBILITY_SCHEMA, COMPATIBILITY_FIXTURE),
        (PROOF_SCHEMA, PROOF_FIXTURE),
        (LEDGER_SCHEMA, CLASSIFIED_FIXTURE),
        (LEDGER_SCHEMA, RETIRED_FIXTURE),
    ),
)
def test_synthetic_gug217_fixtures_validate(
    schema_path: Path,
    fixture_path: Path,
) -> None:
    _validator(schema_path).validate(_load(fixture_path))


@pytest.mark.parametrize(
    ("schema_path", "fixture_path"),
    (
        (
            BINDING_SCHEMA,
            INVALID
            / "platform-authority-identity-context-pep-binding-v1-live-effect-overclaim.json",
        ),
        (
            COMPATIBILITY_SCHEMA,
            INVALID
            / "platform-authority-identity-context-pep-compatibility-receipt-v1-effect-overclaim.json",
        ),
        (
            PROOF_SCHEMA,
            INVALID
            / "platform-authority-identity-context-proof-receipt-v1-proof-used.json",
        ),
        (
            PROOF_SCHEMA,
            INVALID
            / "platform-authority-identity-context-proof-receipt-v1-classifier-retire.json",
        ),
        (
            LEDGER_SCHEMA,
            INVALID
            / "platform-authority-change-set-retirement-ledger-v2-classified-missing-proof.json",
        ),
    ),
)
def test_gug217_overclaims_fail_closed(
    schema_path: Path,
    fixture_path: Path,
) -> None:
    with pytest.raises(ValidationError):
        _validator(schema_path).validate(_load(fixture_path))


def test_binding_digest_covers_every_runtime_binding_and_users_are_distinct() -> None:
    binding = _load(BINDING_FIXTURE)
    digest_input = {
        field: (
            binding[field].lower()
            if field in {"classifier_user_id", "approver_user_id"}
            else binding[field]
        )
        for field in BINDING_DIGEST_FIELDS
    }
    assert binding["binding_digest"] == _canonical_digest(digest_input)
    assert binding["classifier_user_id"].lower() != binding["approver_user_id"].lower()
    assert binding["live_effect_authorized"] is False


@pytest.mark.parametrize("port", (0, 1023, 65536))
def test_binding_rejects_redirect_ports_outside_the_runtime_boundary(port: int) -> None:
    binding = _load(BINDING_FIXTURE)
    binding["redirect_uri"] = f"http://127.0.0.1:{port}/callback"
    with pytest.raises(ValidationError):
        _validator(BINDING_SCHEMA).validate(binding)


@pytest.mark.parametrize("fixture_path", (COMPATIBILITY_FIXTURE, PROOF_FIXTURE))
def test_receipt_digest_covers_the_complete_sanitized_receipt(
    fixture_path: Path,
) -> None:
    receipt = _load(fixture_path)
    expected = _canonical_digest(
        {key: value for key, value in receipt.items() if key != "receipt_digest"}
    )
    assert receipt["receipt_digest"] == expected
    encoded = json.dumps(receipt, sort_keys=True)
    for forbidden in (
        "authorization_code",
        "code_verifier",
        "accessToken",
        "refreshToken",
        "identityContext",
        "ContextAssertion",
        "AccessKeyId",
        "SecretAccessKey",
        "SessionToken",
        "email",
    ):
        assert forbidden not in encoded


def test_proof_receipt_binds_both_role_and_exact_sts_session_digests() -> None:
    receipt = _load(PROOF_FIXTURE)
    assert receipt["proof_role_arn_digest"] != receipt["proof_session_arn_digest"]
    assert receipt["expected_user_id_digest"] != receipt["peer_user_id_digest"]
    missing_session = dict(receipt)
    missing_session.pop("proof_session_arn_digest")
    with pytest.raises(ValidationError):
        _validator(PROOF_SCHEMA).validate(missing_session)


def test_runtime_proof_receipt_matches_the_versioned_contract() -> None:
    fixture = _load(PROOF_FIXTURE)
    receipt = IdentityContextProofReceipt(
        status=fixture["status"],
        binding_digest=fixture["binding_digest"],
        policy_version=fixture["managed_policy_version"],
        policy_digest=fixture["managed_policy_digest"],
        required_action=fixture["required_action"],
        role_kind=fixture["role_kind"],
        broker_alias=fixture["broker_alias"],
        expected_user_id_digest=fixture["expected_user_id_digest"],
        peer_user_id_digest=fixture["peer_user_id_digest"],
        proof_role_arn_digest=fixture["proof_role_arn_digest"],
        proof_session_arn_digest=fixture["proof_session_arn_digest"],
        proof_expires_at=fixture["proof_expires_at"],
    ).to_dict()
    _validator(PROOF_SCHEMA).validate(receipt)
    assert set(receipt) == set(fixture)


@pytest.mark.parametrize("fixture_path", (CLASSIFIED_FIXTURE, RETIRED_FIXTURE))
def test_ledger_v2_digests_cover_identity_proof_contract_and_record(
    fixture_path: Path,
) -> None:
    ledger = _load(fixture_path)
    identity_binding = {
        field: ledger[field] for field in LEDGER_IDENTITY_BINDING_FIELDS
    }
    assert ledger["identity_binding_digest"] == _canonical_digest(identity_binding)
    assert ledger["classifier_identity_store_user_id_digest"] != ledger[
        "approver_identity_store_user_id_digest"
    ]
    assert ledger["ledger_digest"] == _canonical_digest(
        {key: value for key, value in ledger.items() if key != "ledger_digest"}
    )


@pytest.mark.parametrize(
    ("mutation", "expected_path"),
    (
        (lambda value: value.update({"schema_version": "1"}), ["schema_version"]),
        (lambda value: value.update({"native_on_behalf_of": True}), ["native_on_behalf_of"]),
        (
            lambda value: value.update(
                {"classifier_identity_proof_sha256": None}
            ),
            ["classifier_identity_proof_sha256"],
        ),
    ),
)
def test_classification_never_accepts_legacy_or_unproven_identity(
    mutation,
    expected_path: list[str],
) -> None:
    ledger = _load(CLASSIFIED_FIXTURE)
    mutation(ledger)
    errors = list(_validator(LEDGER_SCHEMA).iter_errors(ledger))
    assert errors
    assert any(list(error.absolute_path) == expected_path for error in errors)


def test_terminal_state_requires_reconciliation_proof_and_broker_attribution() -> None:
    validator = _validator(LEDGER_SCHEMA)
    terminal = _load(RETIRED_FIXTURE)
    for field, invalid in (
        ("reconciliation_identity_proof_sha256", None),
        ("effect_attribution", None),
        ("aws_effect_principal", "HUMAN_PROOF_ROLE"),
    ):
        candidate = dict(terminal)
        candidate[field] = invalid
        with pytest.raises(ValidationError):
            validator.validate(candidate)
