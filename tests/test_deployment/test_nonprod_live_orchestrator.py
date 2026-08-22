"""GUG-382 pure protected live-orchestrator security tests."""
from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta

import pytest

from tooling.authorize_deployment_backend import AuthorizationError, canonical_digest
from tooling.nonprod_live_engine import (
    build_saved_plan_approval,
    build_saved_plan_record,
)
from tooling.nonprod_live_orchestrator import (
    build_apply_intent,
    build_live_context,
    build_plan_intent,
    classify_apply_observation,
    derive_source_revision_digest,
    validate_apply_intent,
    validate_plan_intent,
)


NOW = datetime(2026, 8, 21, 18, 0, tzinfo=UTC)
CUSTOMER_ID = "cust_" + ("A" * 26)
DEPLOYMENT_ID = "dep_" + ("A" * 26)
EXECUTION_ID = "exec_" + ("A" * 26)
CHANGE_ID = "chg_" + ("A" * 26)
DESTINATION_ACCOUNT = "1" * 12
AUTHORITY_ACCOUNT = "2" * 12
REGION = "us-east-1"
WORKFLOW_SHA = "4" * 40
WORKFLOW_REF = (
    "owner/repository/.github/workflows/nonprod-release.yml@refs/heads/main"
)
GITHUB_ENVIRONMENT = f"scanalyze-{DEPLOYMENT_ID}-dev"


def _sha(character: str) -> str:
    return "sha256:" + (character * 64)


def _context_arguments() -> dict:
    return {
        "event_name": "workflow_dispatch",
        "git_ref": "refs/heads/main",
        "workflow_ref": WORKFLOW_REF,
        "workflow_sha": WORKFLOW_SHA,
        "main_sha": WORKFLOW_SHA,
        "repository_owner_id": 11,
        "repository_id": 22,
        "workflow_run_id": 33,
        "initiator_user_id": 44,
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "execution_id": EXECUTION_ID,
        "change_id": CHANGE_ID,
        "destination_account_id": DESTINATION_ACCOUNT,
        "platform_authority_account_id": AUTHORITY_ACCOUNT,
        "region": REGION,
        "environment": "dev",
        "github_environment": GITHUB_ENVIRONMENT,
        "layer": "network",
        "release_digest": _sha("a"),
        "source_revision_digest": derive_source_revision_digest(WORKFLOW_SHA),
        "github_deployment_identity_digest": _sha("9"),
        "environment_configuration_digest": _sha("5"),
        "platform_authority_digest": _sha("0"),
        "registry_record_digest": _sha("b"),
        "account_ready_digest": _sha("c"),
        "orchestrator_role_arn": (
            f"arn:aws:iam::{AUTHORITY_ACCOUNT}:role/"
            f"ScanalyzeOrchestrator-{DEPLOYMENT_ID}"
        ),
        "plan_role_arn": (
            f"arn:aws:iam::{DESTINATION_ACCOUNT}:role/ScanalyzeCustomer-Plan"
        ),
        "apply_role_arn": (
            f"arn:aws:iam::{DESTINATION_ACCOUNT}:role/ScanalyzeCustomer-Apply"
        ),
        "oidc_audience": "sts.amazonaws.com",
        "session_duration_seconds": 900,
    }


def _context() -> dict:
    return build_live_context(**_context_arguments())


def _bindings() -> dict:
    context = _context()
    return {
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "account_id": DESTINATION_ACCOUNT,
        "region": REGION,
        "environment": "dev",
        "execution_id": EXECUTION_ID,
        "change_id": CHANGE_ID,
        "layer": "network",
        "release_version": "2026.08.21-gug382",
        "release_digest": context["release_digest"],
        "release_policy_digest": _sha("6"),
        "release_projection_digest": _sha("7"),
        "plan_policy_digest": _sha("8"),
        "github_environment": GITHUB_ENVIRONMENT,
        "github_deployment_identity_digest": context[
            "github_deployment_identity_digest"
        ],
        "environment_configuration_digest": context[
            "environment_configuration_digest"
        ],
        "platform_authority_digest": context["platform_authority_digest"],
        "registry_record_digest": context["registry_record_digest"],
        "account_ready_digest": context["account_ready_digest"],
        "execution_lock_digest": _sha("d"),
        "backend_binding_digest": _sha("e"),
        "contract_resolution_digest": _sha("f"),
        "toolchain_digest": _sha("1"),
        "root_module_digest": _sha("2"),
        "source_revision_digest": context["source_revision_digest"],
        "state_lineage": "synthetic-lineage-0001",
        "state_serial": 7,
    }


def _plan() -> dict:
    return build_saved_plan_record(
        bindings=_bindings(),
        plan_sha256=_sha("3"),
        plan_size_bytes=4096,
        bucket=f"scanalyze-{DESTINATION_ACCOUNT}-tf-state",
        object_key=(
            f"plan-execution/{DEPLOYMENT_ID}/{CHANGE_ID}/network/plan.tfplan"
        ),
        object_version_id="synthetic-version-0001",
        created_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )


def _approval() -> dict:
    return build_saved_plan_approval(
        plan_record=_plan(),
        repository_owner_id=11,
        repository_id=22,
        workflow_ref=WORKFLOW_REF,
        workflow_sha=WORKFLOW_SHA,
        workflow_run_id=33,
        github_environment=GITHUB_ENVIRONMENT,
        environment_configuration_digest=_sha("5"),
        initiator_user_id=44,
        approver_user_id=55,
        approved_at=NOW + timedelta(minutes=2),
        expires_at=NOW + timedelta(minutes=45),
    )


def _approved_ledger() -> dict:
    document = {
        "schema_version": "1",
        "record_type": "live_execution_layer",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "account_id": DESTINATION_ACCOUNT,
        "region": REGION,
        "environment": "dev",
        "execution_id": EXECUTION_ID,
        "change_id": CHANGE_ID,
        "layer": "network",
        "status": "APPROVED",
        "ledger_version": 4,
        "plan_record_digest": _plan()["record_digest"],
        "updated_at": (NOW + timedelta(minutes=3)).isoformat().replace(
            "+00:00", "Z"
        ),
        "attempt_count": 0,
        "approval_digest": _approval()["approval_digest"],
    }
    document["ledger_digest"] = canonical_digest(document)
    return document


def _plan_readback() -> dict:
    plan = _plan()
    return {
        "bucket": plan["storage"]["bucket"],
        "object_key": plan["storage"]["object_key"],
        "object_version_id": plan["storage"]["object_version_id"],
        "sha256": plan["plan_sha256"],
        "size_bytes": plan["plan_size_bytes"],
    }


def _state_readback() -> dict:
    return {"lineage": "synthetic-lineage-0001", "serial": 7}


def _plan_inputs() -> dict:
    return {
        "plan_dir": "/runner/private/plan",
        "resolved_input": "/runner/private/contracts/resolution.json",
        "manifest": "/runner/private/release/manifest.json",
        "target_record": "/runner/private/registry/target.json",
        "target_anchor": "/runner/private/registry/anchor.json",
        "account_ready": "/runner/private/contracts/account-ready.json",
        "execution_lock": "/runner/private/locks/execution.json",
    }


def _apply_inputs() -> dict:
    return {
        "apply_intent": "/runner/private/apply/intent.json",
        "context": "/runner/private/apply/context.json",
        "approved_ledger": "/runner/private/apply/approved-ledger.json",
        "applying_ledger": "/runner/private/apply/applying-ledger.json",
        "plan_record": "/runner/private/apply/plan-record.json",
        "approval_record": "/runner/private/apply/approval.json",
        "plan_readback": "/runner/private/apply/plan-readback.json",
        "state_readback": "/runner/private/apply/state-readback.json",
        "manifest": "/runner/private/release/manifest.json",
        "target_record": "/runner/private/registry/target.json",
        "target_anchor": "/runner/private/registry/anchor.json",
        "account_ready": "/runner/private/contracts/account-ready.json",
        "execution_lock": "/runner/private/locks/execution.json",
    }


def _apply_intent() -> dict:
    return build_apply_intent(
        context=_context(),
        plan_record=_plan(),
        ledger=_approved_ledger(),
        approval_record=_approval(),
        expected_bindings=_bindings(),
        plan_readback=_plan_readback(),
        state_readback=_state_readback(),
        plan_binary_path="/runner/private/apply/network.tfplan",
        apply_inputs=_apply_inputs(),
        now=NOW + timedelta(minutes=10),
    )


def test_exact_dev_context_is_digest_bound_to_main_and_authority() -> None:
    context = _context()

    assert context["authorized"] is True
    assert context["environment"] == "dev"
    assert context["workflow_sha"] == context["main_sha"]
    assert context["platform_authority_account_id"] != context[
        "destination_account_id"
    ]
    assert context["context_digest"] == canonical_digest(
        {key: value for key, value in context.items() if key != "context_digest"}
    )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("environment", "staging", "dev"),
        ("git_ref", "refs/heads/feature", "main"),
        ("main_sha", "5" * 40, "SHA"),
        ("platform_authority_account_id", DESTINATION_ACCOUNT, "separate"),
        ("oidc_audience", "example.invalid", "audience"),
        ("session_duration_seconds", 3600, "900"),
        (
            "github_environment",
            "scanalyze-foreign-dev",
            "Environment",
        ),
        (
            "source_revision_digest",
            _sha("8"),
            "source revision",
        ),
    ],
)
def test_live_context_fails_closed_on_authority_drift(
    field: str, value: object, message: str
) -> None:
    arguments = _context_arguments()
    arguments[field] = value

    with pytest.raises(AuthorizationError, match=message):
        build_live_context(**arguments)


def test_identity_layer_requires_identity_terminal_roles() -> None:
    arguments = _context_arguments()
    arguments["layer"] = "identity-control-plane"

    with pytest.raises(AuthorizationError, match="Plan"):
        build_live_context(**arguments)

    arguments["plan_role_arn"] = (
        f"arn:aws:iam::{DESTINATION_ACCOUNT}:role/"
        "ScanalyzeCustomer-Identity-Plan"
    )
    arguments["apply_role_arn"] = (
        f"arn:aws:iam::{DESTINATION_ACCOUNT}:role/"
        "ScanalyzeCustomer-Identity-Apply"
    )
    assert build_live_context(**arguments)["layer"] == "identity-control-plane"


def test_plan_intent_uses_complete_fixed_wrapper_command() -> None:
    intent = build_plan_intent(
        context=_context(),
        expected_bindings=_bindings(),
        plan_inputs=_plan_inputs(),
    )

    assert intent["command"]["program"] == (
        "scripts/deployment/terraform-saved-plan.sh"
    )
    argv = intent["command"]["argv"]
    for option in (
        "--plan-out",
        "--resolved-input",
        "--manifest",
        "--target-record",
        "--target-anchor",
        "--account-ready",
        "--execution-lock",
        "--expected-role-arn",
        "--expected-source-sha",
    ):
        assert option in argv
    assert intent["expected_plan_path"] == "/runner/private/plan/network.tfplan"
    assert intent["storage_mode"] == "CREATE_ONLY_KMS_VERSIONED"
    assert intent["replan_allowed"] is False
    assert intent["intent_digest"] == canonical_digest(
        {key: value for key, value in intent.items() if key != "intent_digest"}
    )


def test_plan_intent_rejects_binding_and_path_substitution() -> None:
    bindings = _bindings()
    bindings["backend_binding_digest"] = "untrusted"
    with pytest.raises(AuthorizationError, match="digest"):
        build_plan_intent(
            context=_context(),
            expected_bindings=bindings,
            plan_inputs=_plan_inputs(),
        )


def test_plan_intent_is_rebuilt_before_terminal_role_execution() -> None:
    intent = build_plan_intent(
        context=_context(),
        expected_bindings=_bindings(),
        plan_inputs=_plan_inputs(),
    )

    result = validate_plan_intent(
        intent=intent,
        context=_context(),
        expected_bindings=_bindings(),
    )
    assert result["allowed"] is True
    assert result["intent_digest"] == intent["intent_digest"]

    tampered = copy.deepcopy(intent)
    tampered["command"]["program"] = "/bin/sh"
    with pytest.raises(AuthorizationError, match="digest"):
        validate_plan_intent(
            intent=tampered,
            context=_context(),
            expected_bindings=_bindings(),
        )

    redigested = copy.deepcopy(tampered)
    redigested["intent_digest"] = canonical_digest(
        {key: value for key, value in redigested.items() if key != "intent_digest"}
    )
    with pytest.raises(AuthorizationError, match="binding"):
        validate_plan_intent(
            intent=redigested,
            context=_context(),
            expected_bindings=_bindings(),
        )

    paths = _plan_inputs()
    paths["manifest"] = "relative/manifest.json"
    with pytest.raises(AuthorizationError, match="absolute"):
        build_plan_intent(
            context=_context(),
            expected_bindings=_bindings(),
            plan_inputs=paths,
        )


def test_apply_intent_requires_exact_approval_and_prepares_apply_once_cas() -> None:
    intent = _apply_intent()

    assert intent["proposed_ledger_status"] == "APPLYING"
    assert intent["proposed_ledger_version"] == 5
    assert intent["proposed_ledger"]["attempt_count"] == 1
    assert intent["retry_allowed"] is False
    assert intent["replan_allowed"] is False
    assert intent["required_sequence"][:3] == [
        "COMMIT_APPLYING_CAS",
        "READ_BACK_APPLYING_LEDGER",
        "VALIDATE_APPLY_INTENT",
    ]
    assert "ledger_version = :expected_version" in intent["cas_condition"][
        "condition_expression"
    ]
    assert intent["command"]["program"] == (
        "scripts/deployment/terraform-saved-plan.sh"
    )
    assert "--apply-intent" in intent["command"]["argv"]
    assert "--context" in intent["command"]["argv"]
    assert "--applying-ledger" in intent["command"]["argv"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("workflow_sha", "5" * 40),
        ("workflow_run_id", 34),
        ("initiator_user_id", 99),
        ("repository_id", 23),
    ],
)
def test_apply_intent_rejects_approval_from_another_run(
    field: str, value: object
) -> None:
    approval = _approval()
    approval[field] = value
    approval["approval_digest"] = canonical_digest(
        {key: item for key, item in approval.items() if key != "approval_digest"}
    )

    with pytest.raises(AuthorizationError, match="current run"):
        build_apply_intent(
            context=_context(),
            plan_record=_plan(),
            ledger=_approved_ledger(),
            approval_record=approval,
            expected_bindings=_bindings(),
            plan_readback=_plan_readback(),
            state_readback=_state_readback(),
            plan_binary_path="/runner/private/apply/network.tfplan",
            apply_inputs=_apply_inputs(),
            now=NOW + timedelta(minutes=10),
        )


def test_apply_intent_is_revalidated_after_exact_applying_cas_readback() -> None:
    intent = _apply_intent()
    result = validate_apply_intent(
        intent=intent,
        context=_context(),
        plan_record=_plan(),
        approval_record=_approval(),
        approved_ledger=_approved_ledger(),
        applying_ledger=intent["proposed_ledger"],
        plan_readback=_plan_readback(),
        state_readback=_state_readback(),
        now=NOW + timedelta(minutes=11),
    )

    assert result["allowed"] is True
    assert result["code"] == "EXACT_SAVED_PLAN_APPLY_INTENT_VALIDATED"
    assert result["applying_ledger_digest"] == intent["proposed_ledger_digest"]


def test_apply_validation_rejects_tampered_intent_or_non_cas_ledger() -> None:
    intent = _apply_intent()
    tampered = copy.deepcopy(intent)
    tampered["retry_allowed"] = True
    with pytest.raises(AuthorizationError, match="digest"):
        validate_apply_intent(
            intent=tampered,
            context=_context(),
            plan_record=_plan(),
            approval_record=_approval(),
            approved_ledger=_approved_ledger(),
            applying_ledger=intent["proposed_ledger"],
            plan_readback=_plan_readback(),
            state_readback=_state_readback(),
            now=NOW + timedelta(minutes=11),
        )

    foreign_ledger = copy.deepcopy(intent["proposed_ledger"])
    foreign_ledger["outcome_code"] = "SUBSTITUTED"
    foreign_ledger["ledger_digest"] = canonical_digest(
        {key: value for key, value in foreign_ledger.items() if key != "ledger_digest"}
    )
    with pytest.raises(AuthorizationError, match="CAS"):
        validate_apply_intent(
            intent=intent,
            context=_context(),
            plan_record=_plan(),
            approval_record=_approval(),
            approved_ledger=_approved_ledger(),
            applying_ledger=foreign_ledger,
            plan_readback=_plan_readback(),
            state_readback=_state_readback(),
            now=NOW + timedelta(minutes=11),
        )


def test_apply_validation_rechecks_approval_expiry_immediately_before_execute() -> None:
    intent = _apply_intent()

    with pytest.raises(AuthorizationError, match="approval"):
        validate_apply_intent(
            intent=intent,
            context=_context(),
            plan_record=_plan(),
            approval_record=_approval(),
            approved_ledger=_approved_ledger(),
            applying_ledger=intent["proposed_ledger"],
            plan_readback=_plan_readback(),
            state_readback=_state_readback(),
            now=NOW + timedelta(minutes=46),
        )


@pytest.mark.parametrize(
    ("observation", "status", "reconciliation_required"),
    [
        ("SUCCESS", "APPLIED", False),
        ("FAILURE", "FAILED", False),
        ("RESPONSE_LOST", "UNCERTAIN", True),
    ],
)
def test_apply_observation_is_single_use_and_uncertainty_never_retries(
    observation: str, status: str, reconciliation_required: bool
) -> None:
    applying = _apply_intent()["proposed_ledger"]
    outcome = classify_apply_observation(
        applying_ledger=applying,
        observation=observation,
        at=NOW + timedelta(minutes=20),
    )

    assert outcome["next_status"] == status
    assert outcome["proposed_ledger"]["attempt_count"] == 1
    assert outcome["retry_allowed"] is False
    assert outcome["replan_allowed"] is False
    assert outcome["reconciliation_required"] is reconciliation_required


def test_unknown_or_repeated_apply_outcome_is_denied() -> None:
    applying = _apply_intent()["proposed_ledger"]
    with pytest.raises(AuthorizationError, match="observation"):
        classify_apply_observation(
            applying_ledger=applying,
            observation="RETRY",
            at=NOW + timedelta(minutes=20),
        )

    applied = classify_apply_observation(
        applying_ledger=applying,
        observation="SUCCESS",
        at=NOW + timedelta(minutes=20),
    )["proposed_ledger"]
    with pytest.raises(AuthorizationError, match="forbidden"):
        classify_apply_observation(
            applying_ledger=applied,
            observation="SUCCESS",
            at=NOW + timedelta(minutes=21),
        )
