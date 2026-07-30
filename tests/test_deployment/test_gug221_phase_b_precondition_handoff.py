"""Fail-closed PRE_B DAG tests for GUG-221."""

from __future__ import annotations

import inspect
import json
from pathlib import Path

import pytest

from tooling import platform_authority_lambda_audit_repair_change_set as module
from tooling.validate_schema import validate_fixture


ROOT = Path(__file__).resolve().parents[2]
IDENTITY_FIXTURE = (
    ROOT
    / "fixtures/valid/"
    "platform-authority-lambda-audit-repair-"
    "phase-b-identity-materialization-receipt-v1-synthetic.json"
)
PRE_B_HANDOFF_FIXTURE = (
    ROOT
    / "fixtures/valid/"
    "platform-authority-lambda-audit-repair-"
    "phase-b-precondition-parameters-v1-synthetic.json"
)
PRE_B_HANDOFF_SCHEMA = (
    ROOT
    / "schemas/"
    "platform-authority-lambda-audit-repair-"
    "phase-b-precondition-parameters.v1.schema.json"
)
PRE_B_RECEIPT_FIXTURE = (
    ROOT
    / "fixtures/valid/"
    "platform-authority-lambda-audit-repair-"
    "phase-b-precondition-change-set-receipt-v1-synthetic.json"
)
PRE_B_RECEIPT_SCHEMA = (
    ROOT
    / "schemas/"
    "platform-authority-lambda-audit-repair-"
    "phase-b-precondition-change-set-receipt.v1.schema.json"
)


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_pre_b_builder_has_no_free_provider_parameter_surface() -> None:
    parameters = inspect.signature(
        module.build_phase_b_precondition_parameter_handoff
    ).parameters
    assert "provider_parameters" not in parameters
    assert {
        "signed_receipt",
        "deployment_contract",
        "phase_b_identity_materialization_receipt",
        "pep_parameter_handoff",
        "pep_change_set_receipt",
        "reviewed_template_bytes",
    } <= set(parameters)


def test_pre_b_target_contract_binds_identity_pep_and_exact_inventory() -> None:
    handoff = _load(PRE_B_HANDOFF_FIXTURE)
    receipt = _load(PRE_B_RECEIPT_FIXTURE)
    valid, message = validate_fixture(
        PRE_B_HANDOFF_FIXTURE, PRE_B_HANDOFF_SCHEMA
    )
    assert valid, message
    valid, message = validate_fixture(
        PRE_B_RECEIPT_FIXTURE, PRE_B_RECEIPT_SCHEMA
    )
    assert valid, message
    assert len(handoff["parameters"]) == 37
    assert {
        "phase_b_identity_materialization_receipt_sha256",
        "pep_parameter_handoff_sha256",
        "pep_change_set_receipt_sha256",
    } <= set(handoff)
    assert receipt["phase_b_identity_materialization_receipt_sha256"] == (
        handoff["phase_b_identity_materialization_receipt_sha256"]
    )
    assert receipt["pep_parameter_handoff_sha256"] == (
        handoff["pep_parameter_handoff_sha256"]
    )
    assert receipt["pep_change_set_receipt_sha256"] == (
        handoff["pep_change_set_receipt_sha256"]
    )
    assert len(receipt["change_set"]["resource_changes"]) == 9


def test_pre_b_verify_blocks_before_any_provider_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = _load(IDENTITY_FIXTURE)
    calls: list[str] = []

    class Sts:
        def get_caller_identity(self) -> dict:
            calls.append("sts")
            raise AssertionError("provider client reached before identity proof")

    monkeypatch.setattr(
        module,
        "_signed_parameter_values",
        lambda _receipt: {"SourceCommit": identity["source_commit"]},
    )
    monkeypatch.setattr(
        module,
        "validate_deployment_contract",
        lambda _contract: None,
    )

    with pytest.raises(
        module.ChangeSetHandoffError,
        match="BLOCKED_IDENTITY_PRECONDITION_NOT_MATERIALIZED",
    ):
        module.verify_phase_b_precondition_change_set_read_only(
            source_root=ROOT,
            profile_name=module.EXPECTED_PROFILE,
            region=module.REGION,
            change_set_arn="not-reached",
            parameter_handoff={},
            signed_receipt={},
            deployment_contract={
                "source_commit": identity["source_commit"],
            },
            phase_b_identity_materialization_receipt=identity,
            pep_parameter_handoff={},
            pep_change_set_receipt={},
            reviewed_template_bytes=b"not reached",
            sts_client=Sts(),
            cloudformation_client=object(),
            cloudtrail_client=object(),
        )
    assert calls == []


def test_pre_b_builder_rejects_omitted_identity_receipt() -> None:
    parameters = inspect.signature(
        module.build_phase_b_precondition_parameter_handoff
    ).parameters
    assert (
        parameters["phase_b_identity_materialization_receipt"].default
        is inspect.Parameter.empty
    )
