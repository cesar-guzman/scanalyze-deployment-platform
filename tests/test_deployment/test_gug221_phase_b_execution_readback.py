"""GUG-221 execution/readback consumes PRE_B evidence fail closed."""

from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import inspect
import json
from pathlib import Path

import pytest

from tooling import platform_authority_lambda_audit_repair_change_set as module
from tooling.platform_authority_lambda_audit_repair_broker import (
    canonical_digest,
)


ROOT = Path(__file__).resolve().parents[2]
IDENTITY_FIXTURE = (
    ROOT
    / "fixtures/valid/"
    "platform-authority-lambda-audit-repair-"
    "phase-b-identity-materialization-receipt-v1-synthetic.json"
)
UUID = "11111111-2222-4333-8444-555555555555"


def _identity() -> dict:
    return json.loads(IDENTITY_FIXTURE.read_text(encoding="utf-8"))


def _contract(source_commit: str) -> dict:
    return {
        "artifact_type": module.DEPLOYMENT_CONTRACT_TYPE,
        "schema_version": 1,
        "work_package": "GUG-221",
        "authority_account_id": module.AUTHORITY_ACCOUNT_ID,
        "management_account_id": module.MANAGEMENT_ACCOUNT_ID,
        "source_commit": source_commit,
        "repair_not_before": "2026-07-23T12:00:00Z",
        "repair_not_after": "2026-07-23T12:15:00Z",
        "delegation_change_set_creator_arn": (
            "arn:aws:sts::839393571433:assumed-role/"
            "AWSReservedSSO_ScanalyzeFounderPepSeed_0123456789abcdef/"
            "synthetic@example.invalid"
        ),
        "delegation_change_set_executor_arn": (
            "arn:aws:sts::839393571433:assumed-role/"
            "AWSReservedSSO_ScanalyzeFounderPepSeed_0123456789abcdef/"
            "synthetic@example.invalid"
        ),
        "pep_change_set_creator_arn": (
            "arn:aws:sts::042360977644:assumed-role/"
            "AWSReservedSSO_ScanalyzeFounderBootstrapPlan_0123456789abcdef/"
            "synthetic@example.invalid"
        ),
        "production_status": "NO-GO",
    }


def _change_set(contract: dict) -> dict:
    return {
        "arn": (
            "arn:aws:cloudformation:us-east-1:042360977644:changeSet/"
            + module.CHANGE_SET_NAME
            + "/"
            + UUID
        ),
        "uuid": UUID,
        "name": module.CHANGE_SET_NAME,
        "stack_arn": (
            "arn:aws:cloudformation:us-east-1:042360977644:stack/"
            + module.STACK_NAME
            + "/"
            + UUID
        ),
        "stack_name": module.STACK_NAME,
        "type": "CREATE",
        "status": "CREATE_COMPLETE",
        "execution_status": "AVAILABLE",
        "on_stack_failure": "ROLLBACK",
        "capabilities": list(module.EXPECTED_CAPABILITIES),
        "tags": module._permission_set_tags(contract["source_commit"]),
        "parameters_sha256": "1" * 64,
        "resource_changes": [
            {
                "logical_resource_id": logical_id,
                "resource_type": resource_type,
                "action": "Add",
                "replacement": "False",
            }
            for logical_id, resource_type in sorted(
                module._pep_expected_resource_types().items()
            )
        ],
        "create_event": {
            "event_id": "synthetic-create",
            "event_time": "2026-07-23T12:00:30Z",
            "event_digest": "2" * 64,
        },
    }


def _review_receipt(contract: dict, identity: dict) -> dict:
    change_set = _change_set(contract)
    identity_digest = (
        module._phase_b_identity_materialization_receipt_digest(identity)
    )
    receipt = {
        "artifact_type": module.PEP_CHANGE_SET_RECEIPT_TYPE,
        "schema_version": 1,
        "work_package": "GUG-221",
        "phase": "B_PEP_CHANGE_SET",
        "source_commit": contract["source_commit"],
        "signed_artifact_receipt_sha256": "3" * 64,
        "deployment_contract_sha256": module._digest(contract),
        "gug220_intent_sha256": "4" * 64,
        "gug220_ledger_sha256": "5" * 64,
        "gug220_receipt_sha256": "6" * 64,
        "gug220_evidence_sha256": "7" * 64,
        "gug220_provider_state_sha256": "8" * 64,
        "delegation_live_receipt_sha256": "9" * 64,
        "parameter_handoff_sha256": "a" * 64,
        "phase_b_identity_materialization_receipt_sha256": identity_digest,
        "template_sha256": "b" * 64,
        "change_set": change_set,
        "execution_contract": {},
        "verifier": {
            "profile": module.EXPECTED_PROFILE,
            "account_id": module.AUTHORITY_ACCOUNT_ID,
            "caller_arn": (
                "arn:aws:sts::042360977644:assumed-role/"
                "AWSReservedSSO_AWSReadOnlyAccess_0123456789abcdef/"
                "synthetic@example.invalid"
            ),
        },
        "evaluated_at": "2026-07-23T12:01:00Z",
        "evidence_status": (
            "PEP_CHANGE_SET_READ_ONLY_VERIFIED_AFTER_LIVE_DELEGATION"
        ),
        "authority_status": "REVIEW_EVIDENCE_ONLY_NOT_EXECUTION_AUTHORITY",
        "production_status": "NO-GO",
    }
    receipt["execution_contract"] = module._pep_execution_contract(
        source_commit=receipt["source_commit"],
        deployment_contract_sha256=receipt["deployment_contract_sha256"],
        parameter_handoff_sha256=receipt["parameter_handoff_sha256"],
        phase_b_identity_materialization_receipt_sha256=identity_digest,
        template_sha256=receipt["template_sha256"],
        change_set=change_set,
    )
    return receipt


def _pre_b(review: dict) -> tuple[dict, dict]:
    values = {key: "synthetic" for key in module.PHASE_B_PRECONDITION_PARAMETER_KEYS}
    values.update(
        {
            "ExactExecutionId": "gug221-phase-b-" + "c" * 64,
            "ExpectedBrokerTopologySha256": "sha256:" + "d" * 64,
            "InvokerPolicySha256": "e" * 64,
            "BrokerPolicySha256": "f" * 64,
            "ProofPolicySha256": "0" * 64,
            "ApplicationActorPolicySha256": "1" * 64,
        }
    )
    handoff = {
        "parameters": [
            {"ParameterKey": key, "ParameterValue": values[key]}
            for key in module.PHASE_B_PRECONDITION_PARAMETER_KEYS
        ],
        "broker_topology_sha256": values["ExpectedBrokerTopologySha256"],
    }
    receipt = {
        "parameter_handoff_sha256": module._digest(handoff),
        "pep_change_set_receipt_sha256": module._digest(review),
        "broker_topology_sha256": handoff["broker_topology_sha256"],
    }
    receipt["receipt_digest"] = module._digest(receipt)
    return handoff, receipt


def _effect(review: dict, handoff: dict) -> dict:
    values = {
        item["ParameterKey"]: item["ParameterValue"]
        for item in handoff["parameters"]
    }
    execution = review["execution_contract"]
    receipt = {
        "schema_version": "1",
        "record_type": (
            "platform_authority_lambda_audit_repair_phase_b_"
            "broker_effect_receipt"
        ),
        "environment": "non-production",
        "production": False,
        "status": "DISPATCH_ACCEPTED",
        "execution_id": values["ExactExecutionId"],
        "binding_digest": "sha256:" + "2" * 64,
        "proof_receipt_digest": "sha256:" + "3" * 64,
        "ledger_digest": "sha256:" + "4" * 64,
        "closure_pending_receipt_digest": "sha256:" + "5" * 64,
        "execution_request_digest": (
            "sha256:" + execution["execute_request_sha256"]
        ),
        "broker_topology_sha256": values["ExpectedBrokerTopologySha256"],
        "broker_topology_provider_evidence_digest": "sha256:" + "6" * 64,
        "invoker_policy_sha256": values["InvokerPolicySha256"],
        "broker_policy_sha256": values["BrokerPolicySha256"],
        "proof_policy_sha256": values["ProofPolicySha256"],
        "application_actor_policy_sha256": values[
            "ApplicationActorPolicySha256"
        ],
        "stack_arn": review["change_set"]["stack_arn"],
        "change_set_arn": review["change_set"]["arn"],
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
    receipt["receipt_digest"] = "sha256:" + canonical_digest(receipt)
    return receipt


def test_deployment_contract_rejects_operator_broker_authority() -> None:
    identity = _identity()
    contract = _contract(identity["source_commit"])
    module.validate_deployment_contract(contract)
    for field, value in (
        (
            "phase_b_broker_execution_role_arn",
            module.PHASE_B_BROKER_EXECUTION_ROLE_ARN,
        ),
        ("phase_b_broker_topology_sha256", "a" * 64),
    ):
        forged = {**contract, field: value}
        with pytest.raises(
            module.ChangeSetHandoffError,
            match="DEPLOYMENT_CONTRACT_INVALID",
        ):
            module.validate_deployment_contract(forged)


def test_base_execution_contract_has_no_pre_b_fixed_point() -> None:
    identity = _identity()
    contract = _contract(identity["source_commit"])
    receipt = _review_receipt(contract, identity)
    execution = receipt["execution_contract"]
    assert "broker_topology_sha256" not in execution
    assert execution["effect_principal_arn_sha256"] == sha256(
        module.PHASE_B_BROKER_EXECUTION_ROLE_ARN.encode("utf-8")
    ).hexdigest()
    assert execution == _review_receipt(contract, identity)["execution_contract"]


def test_broker_effect_mirrors_are_derived_only_from_pre_b() -> None:
    identity = _identity()
    review = _review_receipt(_contract(identity["source_commit"]), identity)
    handoff, pre_receipt = _pre_b(review)
    effect = _effect(review, handoff)
    assert module._validate_phase_b_broker_effect_receipt(
        receipt=effect,
        pep_change_set_receipt=review,
        phase_b_precondition_parameter_handoff=handoff,
        phase_b_precondition_change_set_receipt=pre_receipt,
    ) == module._digest(effect)

    for mutation in ("topology", "policy", "pre_receipt"):
        forged_effect = deepcopy(effect)
        forged_pre = deepcopy(pre_receipt)
        if mutation == "topology":
            forged_effect["broker_topology_sha256"] = "sha256:" + "9" * 64
            stable = {
                key: value
                for key, value in forged_effect.items()
                if key != "receipt_digest"
            }
            forged_effect["receipt_digest"] = (
                "sha256:" + canonical_digest(stable)
            )
        elif mutation == "policy":
            forged_effect["broker_policy_sha256"] = "9" * 64
            stable = {
                key: value
                for key, value in forged_effect.items()
                if key != "receipt_digest"
            }
            forged_effect["receipt_digest"] = (
                "sha256:" + canonical_digest(stable)
            )
        else:
            forged_pre["receipt_digest"] = "9" * 64
        with pytest.raises(module.ChangeSetHandoffError):
            module._validate_phase_b_broker_effect_receipt(
                receipt=forged_effect,
                pep_change_set_receipt=review,
                phase_b_precondition_parameter_handoff=handoff,
                phase_b_precondition_change_set_receipt=forged_pre,
            )


def test_readback_requires_pre_b_and_blocks_before_provider_calls() -> None:
    identity = _identity()
    calls: list[str] = []

    class Sts:
        def get_caller_identity(self) -> dict:
            calls.append("sts")
            raise AssertionError("provider readback reached")

    with pytest.raises(
        module.ChangeSetHandoffError,
        match="BLOCKED_IDENTITY_PRECONDITION_NOT_MATERIALIZED",
    ):
        module.readback_pep_execution_read_only(
            source_root=ROOT,
            profile_name=module.EXPECTED_PROFILE,
            region=module.REGION,
            signed_receipt={},
            deployment_contract=_contract(identity["source_commit"]),
            gug220_intent={},
            gug220_ledger={},
            gug220_receipt={},
            gug220_evidence={},
            delegation_live_receipt={},
            phase_b_identity_materialization_receipt=identity,
            pep_handoff={},
            pep_change_set_receipt={},
            phase_b_precondition_parameter_handoff={},
            phase_b_precondition_change_set_receipt={},
            broker_effect_receipt={},
            reviewed_template_bytes=b"",
            reviewed_phase_b_precondition_template_bytes=b"",
            sts_client=Sts(),
            cloudformation_client=object(),
            cloudtrail_client=object(),
            dynamodb_client=object(),
        )
    assert calls == []


def test_execution_readback_pre_b_arguments_are_mandatory() -> None:
    parameters = inspect.signature(
        module.readback_pep_execution_read_only
    ).parameters
    for name in (
        "phase_b_identity_materialization_receipt",
        "phase_b_precondition_parameter_handoff",
        "phase_b_precondition_change_set_receipt",
        "reviewed_phase_b_precondition_template_bytes",
    ):
        assert parameters[name].default is inspect.Parameter.empty
