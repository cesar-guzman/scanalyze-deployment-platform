"""GUG-221 Phase B identity materialization remains a live-only blocker."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tooling import platform_authority_lambda_audit_repair_change_set as module
from tooling.validate_schema import find_schema_for_fixture, validate_fixture


ROOT = Path(__file__).resolve().parents[2]
VALID_FIXTURE = (
    ROOT
    / "fixtures/valid/"
    "platform-authority-lambda-audit-repair-"
    "phase-b-identity-materialization-receipt-v1-synthetic.json"
)
INVALID_FIXTURE = (
    ROOT
    / "fixtures/invalid/"
    "platform-authority-lambda-audit-repair-"
    "phase-b-identity-materialization-receipt-v1-application-unverified.json"
)
SCHEMA = (
    ROOT
    / "schemas/"
    "platform-authority-lambda-audit-repair-"
    "phase-b-identity-materialization-receipt.v1.schema.json"
)


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _unexpected_post_identity_step(*_args: object, **_kwargs: object) -> None:
    raise AssertionError("a post-identity step ran before the live blocker")


def test_identity_materialization_schema_mapping_and_shape_contract() -> None:
    assert (
        find_schema_for_fixture(VALID_FIXTURE.name, ROOT / "schemas")
        == SCHEMA
    )
    valid, valid_message = validate_fixture(VALID_FIXTURE, SCHEMA)
    assert valid, valid_message
    invalid, _ = validate_fixture(INVALID_FIXTURE, SCHEMA)
    assert not invalid


def test_shape_valid_self_digest_is_not_live_materialization() -> None:
    receipt = _load(VALID_FIXTURE)
    assert receipt["receipt_sha256"] == (
        module._phase_b_identity_materialization_receipt_digest(receipt)
    )

    with pytest.raises(
        module.ChangeSetHandoffError,
        match="BLOCKED_IDENTITY_PRECONDITION_NOT_MATERIALIZED",
    ):
        module.validate_phase_b_identity_materialization_receipt(
            receipt,
            source_commit=receipt["source_commit"],
        )


def test_shape_invalid_receipt_fails_before_live_blocker() -> None:
    receipt = _load(INVALID_FIXTURE)
    with pytest.raises(
        module.ChangeSetHandoffError,
        match="PHASE_B_IDENTITY_MATERIALIZATION_RECEIPT_INVALID",
    ):
        module.validate_phase_b_identity_materialization_receipt(
            receipt,
            source_commit=receipt["source_commit"],
        )


def test_build_pep_blocks_before_parameter_or_policy_derivation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = _load(VALID_FIXTURE)
    monkeypatch.setattr(
        module,
        "_signed_parameter_values",
        lambda _receipt: {"SourceCommit": receipt["source_commit"]},
    )
    monkeypatch.setattr(
        module,
        "validate_deployment_contract",
        lambda _contract: None,
    )
    monkeypatch.setattr(
        module,
        "validate_gug220_evidence_chain",
        lambda **_kwargs: {},
    )
    monkeypatch.setattr(
        module,
        "validate_delegation_live_receipt",
        lambda **_kwargs: None,
    )
    monkeypatch.setattr(
        module,
        "_repair_invoker_policy",
        _unexpected_post_identity_step,
    )

    with pytest.raises(
        module.ChangeSetHandoffError,
        match="BLOCKED_IDENTITY_PRECONDITION_NOT_MATERIALIZED",
    ):
        module.build_pep_parameter_handoff(
            source_root=ROOT,
            signed_receipt={},
            deployment_contract={"source_commit": receipt["source_commit"]},
            gug220_intent={},
            gug220_ledger={},
            gug220_receipt={},
            gug220_evidence={},
            delegation_live_receipt={},
            phase_b_identity_materialization_receipt=receipt,
            template_bytes=b"must not be parsed",
        )


def test_build_pre_b_blocks_before_change_set_binding_or_effect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = _load(VALID_FIXTURE)
    monkeypatch.setattr(
        module,
        "_signed_parameter_values",
        lambda _receipt: {"SourceCommit": receipt["source_commit"]},
    )
    monkeypatch.setattr(
        module,
        "validate_deployment_contract",
        lambda _contract: None,
    )
    monkeypatch.setattr(
        module,
        "_validate_pep_change_set_receipt_binding",
        _unexpected_post_identity_step,
    )

    with pytest.raises(
        module.ChangeSetHandoffError,
        match="BLOCKED_IDENTITY_PRECONDITION_NOT_MATERIALIZED",
    ):
        module.build_phase_b_precondition_parameter_handoff(
            source_root=ROOT,
            signed_receipt={},
            deployment_contract={"source_commit": receipt["source_commit"]},
            phase_b_identity_materialization_receipt=receipt,
            pep_parameter_handoff={},
            pep_change_set_receipt={},
            reviewed_template_bytes=b"must not be parsed",
        )
