"""GUG-221 broker-bound Phase B execution contract regressions."""

from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import inspect
import json
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import tooling.platform_authority_lambda_audit_repair_change_set as module  # noqa: E402
from tooling.platform_authority_lambda_audit_repair_phase_b_pep import (  # noqa: E402
    broker_topology_signature_digest,
    canonical_digest,
)


def _load(relative: str) -> dict:
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    ("fixture_name", "digest_field"),
    (
        (
            "platform-authority-lambda-audit-repair-phase-b-"
            "broker-effect-receipt-v1-synthetic.json",
            "receipt_digest",
        ),
        (
            "platform-authority-lambda-audit-repair-phase-b-"
            "broker-topology-evidence-v1-synthetic.json",
            "receipt_digest",
        ),
        (
            "platform-authority-lambda-audit-repair-phase-b-"
            "closure-pending-receipt-v1-synthetic.json",
            "receipt_digest",
        ),
        (
            "platform-authority-lambda-audit-repair-phase-b-"
            "one-shot-execution-ledger-v1-synthetic.json",
            "ledger_digest",
        ),
        (
            "platform-authority-lambda-audit-repair-phase-b-"
            "proof-receipt-v1-synthetic.json",
            "receipt_digest",
        ),
    ),
)
def test_valid_phase_b_fixture_digest_is_semantically_canonical(
    fixture_name: str,
    digest_field: str,
) -> None:
    value = _load(f"fixtures/valid/{fixture_name}")
    claimed = value.pop(digest_field)
    if "broker-topology-evidence" in fixture_name:
        assert claimed == broker_topology_signature_digest(value)
    else:
        assert claimed == canonical_digest(value)


def _contract() -> dict:
    return _load(
        "fixtures/valid/"
        "platform-authority-lambda-audit-repair-deployment-contract-v1-"
        "synthetic.json"
    )


def _identity_materialization_receipt(contract: dict | None = None) -> dict:
    deployment_contract = contract or _contract()
    receipt = {
        "artifact_type": (
            module.PHASE_B_IDENTITY_MATERIALIZATION_RECEIPT_TYPE
        ),
        "schema_version": 1,
        "work_package": "GUG-221",
        "phase": "PRE_B_IDENTITY_MATERIALIZATION",
        "source_commit": deployment_contract["source_commit"],
        "authority_account_id": module.AUTHORITY_ACCOUNT_ID,
        "management_account_id": module.MANAGEMENT_ACCOUNT_ID,
        "region": module.REGION,
        "identity_center_application_arn": (
            "arn:aws:sso::839393571433:application/"
            "ssoins-1234567890abcdef/apl-abcdef1234567890"
        ),
        "identity_center_instance_arn": (
            "arn:aws:sso:::instance/ssoins-1234567890abcdef"
        ),
        "identity_store_arn": (
            "arn:aws:identitystore::839393571433:"
            "identitystore/d-0123456789"
        ),
        "identity_center_redirect_uri": (
            "http://127.0.0.1:49152/callback"
        ),
        "operator_identity_store_user_id": (
            "0123456789-12345678-1234-1234-1234-1234567890ab"
        ),
        "invoker_principal_arn": (
            "arn:aws:iam::042360977644:role/aws-reserved/"
            "sso.amazonaws.com/us-east-1/"
            "AWSReservedSSO_ScanalyzeGug221PhaseBInvoker_"
            "0123456789abcdef"
        ),
        "broker_code_signing_config_arn": (
            "arn:aws:lambda:us-east-1:042360977644:"
            "code-signing-config:csc-0123456789abcdef0"
        ),
        "broker_topology_signing_key_arn": (
            "arn:aws:kms:us-east-1:042360977644:key/"
            "11111111-2222-4333-8444-555555555555"
        ),
        "oauth_state_digest": "sha256:" + "a" * 64,
        "provider_state_sha256": "b" * 64,
        "checks": {
            "application_verified": True,
            "single_operator_assignment_verified": True,
            "invoker_role_verified": True,
            "code_signing_config_verified": True,
            "topology_signing_key_verified": True,
            "pending_operations_absent": True,
            "alternate_assignments_absent": True,
        },
        "verifiers": {
            "management": {
                "profile": module.EXPECTED_MANAGEMENT_PROFILE,
                "account_id": module.MANAGEMENT_ACCOUNT_ID,
                "caller_arn": (
                    "arn:aws:sts::839393571433:assumed-role/"
                    "AWSReservedSSO_AWSReadOnlyAccess_0123456789abcdef/"
                    "synthetic@example.invalid"
                ),
            },
            "authority": {
                "profile": module.EXPECTED_PROFILE,
                "account_id": module.AUTHORITY_ACCOUNT_ID,
                "caller_arn": (
                    "arn:aws:sts::042360977644:assumed-role/"
                    "AWSReservedSSO_AWSReadOnlyAccess_0123456789abcdef/"
                    "synthetic@example.invalid"
                ),
            },
        },
        "evaluated_at": "2026-07-23T12:00:00Z",
        "evidence_status": (
            "PHASE_B_IDENTITY_MATERIALIZATION_PROVIDER_VERIFIED"
        ),
        "authority_status": "PROVIDER_DERIVED_NOT_EXECUTION_AUTHORITY",
        "production_status": "NO-GO",
    }
    receipt["receipt_sha256"] = (
        module._phase_b_identity_materialization_receipt_digest(receipt)
    )
    return receipt


def _review_receipt(contract: dict | None = None) -> dict:
    deployment_contract = contract or _contract()
    identity_receipt = _identity_materialization_receipt(
        deployment_contract
    )
    receipt = _load(
        "fixtures/valid/"
        "platform-authority-lambda-audit-repair-pep-change-set-receipt-v1-"
        "synthetic.json"
    )
    receipt["source_commit"] = deployment_contract["source_commit"]
    receipt["deployment_contract_sha256"] = module._digest(
        deployment_contract
    )
    receipt["phase_b_identity_materialization_receipt_sha256"] = (
        module._phase_b_identity_materialization_receipt_digest(
            identity_receipt
        )
    )
    receipt["change_set"]["tags"] = module._permission_set_tags(
        deployment_contract["source_commit"]
    )
    receipt["execution_contract"] = module._pep_execution_contract(
        source_commit=receipt["source_commit"],
        deployment_contract_sha256=receipt["deployment_contract_sha256"],
        parameter_handoff_sha256=receipt["parameter_handoff_sha256"],
        template_sha256=receipt["template_sha256"],
        change_set=receipt["change_set"],
        phase_b_identity_materialization_receipt_sha256=receipt[
            "phase_b_identity_materialization_receipt_sha256"
        ],
    )
    return receipt


def _broker_effect_receipt(
    *,
    contract: dict | None = None,
    review_receipt: dict | None = None,
) -> dict:
    deployment_contract = contract or _contract()
    review = review_receipt or _review_receipt(deployment_contract)
    execution = review["execution_contract"]
    change_set = review["change_set"]
    receipt = {
        "schema_version": "1",
        "record_type": (
            "platform_authority_lambda_audit_repair_phase_b_broker_effect_receipt"
        ),
        "environment": "non-production",
        "production": False,
        "status": "DISPATCH_ACCEPTED",
        "execution_id": "gug221-phase-b-" + "8" * 64,
        "binding_digest": "sha256:" + "1" * 64,
        "proof_receipt_digest": "sha256:" + "2" * 64,
        "ledger_digest": "sha256:" + "3" * 64,
        "closure_pending_receipt_digest": "sha256:" + "4" * 64,
        "execution_request_digest": (
            "sha256:" + execution["execute_request_sha256"]
        ),
        "broker_topology_sha256": "sha256:" + "a" * 64,
        "broker_topology_provider_evidence_digest": "sha256:" + "5" * 64,
        "invoker_policy_sha256": "6" * 64,
        "broker_policy_sha256": "7" * 64,
        "proof_policy_sha256": "8" * 64,
        "application_actor_policy_sha256": "9" * 64,
        "stack_arn": change_set["stack_arn"],
        "change_set_arn": change_set["arn"],
        "client_request_token": execution["client_request_token"],
        "effect_principal_type": "AWS_SERVICE_ROLE",
        "effect_principal_arn": module.PHASE_B_BROKER_EXECUTION_ROLE_ARN,
        "proof_credentials_used_for_effect": False,
        "attempts": 1,
        "execution_ambiguous": False,
        "retry_permitted": False,
        "one_shot_execution_gate_consumed": True,
        "native_on_behalf_of": False,
        "provider_revocation_pending": True,
        "authority_revoked": False,
        "production_status": "NO-GO",
    }
    receipt["receipt_digest"] = canonical_digest(receipt)
    return receipt


def test_deployment_contract_rejects_legacy_broker_fields_and_executor() -> None:
    contract = _contract()
    module.validate_deployment_contract(contract)

    for field, value in (
        (
            "phase_b_broker_execution_role_arn",
            module.PHASE_B_BROKER_EXECUTION_ROLE_ARN,
        ),
        ("phase_b_broker_topology_sha256", "a" * 64),
    ):
        forged = deepcopy(contract)
        forged[field] = value
        with pytest.raises(
            module.ChangeSetHandoffError, match="DEPLOYMENT_CONTRACT_INVALID"
        ):
            module.validate_deployment_contract(forged)

    legacy = deepcopy(contract)
    legacy["pep_change_set_executor_arn"] = (
        "arn:aws:sts::042360977644:assumed-role/"
        "AWSReservedSSO_ScanalyzeFounderBootstrapApply_0123456789abcdef/"
        "synthetic@example.invalid"
    )
    with pytest.raises(
        module.ChangeSetHandoffError, match="DEPLOYMENT_CONTRACT_INVALID"
    ):
        module.validate_deployment_contract(legacy)


def test_review_receipt_is_deterministic_broker_input_not_authority() -> None:
    contract = _contract()
    receipt = _review_receipt(contract)
    execution = receipt["execution_contract"]

    assert set(execution) == {
        "client_request_token",
        "client_request_token_sha256",
        "execute_request_sha256",
        "effect_principal_arn_sha256",
        "phase_b_identity_materialization_receipt_sha256",
    }
    assert execution["phase_b_identity_materialization_receipt_sha256"] == (
        receipt["phase_b_identity_materialization_receipt_sha256"]
    )
    assert execution["effect_principal_arn_sha256"] == sha256(
        module.PHASE_B_BROKER_EXECUTION_ROLE_ARN.encode("utf-8")
    ).hexdigest()
    assert receipt["authority_status"] == (
        "REVIEW_EVIDENCE_ONLY_NOT_EXECUTION_AUTHORITY"
    )
    assert "executor_authority" not in receipt
    with pytest.raises(
        module.ChangeSetHandoffError,
        match="BLOCKED_IDENTITY_PRECONDITION_NOT_MATERIALIZED",
    ):
        module._validate_pep_change_set_receipt_binding(
            receipt=receipt,
            deployment_contract=contract,
            phase_b_identity_materialization_receipt=(
                _identity_materialization_receipt(contract)
            ),
        )

    forged = deepcopy(receipt)
    forged["execution_contract"][
        "phase_b_identity_materialization_receipt_sha256"
    ] = "f" * 64
    with pytest.raises(
        module.ChangeSetHandoffError,
        match="BLOCKED_IDENTITY_PRECONDITION_NOT_MATERIALIZED",
    ):
        module._validate_pep_change_set_receipt_binding(
            receipt=forged,
            deployment_contract=contract,
            phase_b_identity_materialization_receipt=(
                _identity_materialization_receipt(contract)
            ),
        )


def test_private_broker_effect_receipt_requires_pre_b_chain() -> None:
    contract = _contract()
    review = _review_receipt(contract)
    effect = _broker_effect_receipt(
        contract=contract,
        review_receipt=review,
    )
    parameters = inspect.signature(
        module._validate_phase_b_broker_effect_receipt
    ).parameters
    assert "deployment_contract" not in parameters
    assert {
        "phase_b_precondition_parameter_handoff",
        "phase_b_precondition_change_set_receipt",
    } <= set(parameters)
    assert effect["attempts"] == 1
    assert effect["native_on_behalf_of"] is False


def test_direct_sso_executor_surface_is_absent() -> None:
    source = Path(module.__file__).read_text(encoding="utf-8")
    deployment_schema = (
        ROOT
        / "schemas/"
        "platform-authority-lambda-audit-repair-deployment-contract.v1.schema.json"
    ).read_text(encoding="utf-8")
    review_schema = (
        ROOT
        / "schemas/"
        "platform-authority-lambda-audit-repair-pep-change-set-receipt.v1.schema.json"
    ).read_text(encoding="utf-8")
    for forbidden in (
        "pep_change_set_executor",
        "pep_executor_",
        "IDENTITY_ENHANCED_IAM_SESSION",
        "executor_authority",
    ):
        assert forbidden not in source
        assert forbidden not in deployment_schema
        assert forbidden not in review_schema
    assert not (
        ROOT
        / "policies/iam/"
        "platform-authority-lambda-audit-repair-pep-change-set-executor-role.json"
    ).exists()
