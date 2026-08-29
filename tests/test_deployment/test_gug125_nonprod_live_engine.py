"""GUG-125 exact saved-plan and resumable live-engine security tests."""
from __future__ import annotations

import copy
import importlib.util
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from tooling.authorize_deployment_backend import AuthorizationError, canonical_digest
from tooling.nonprod_live_engine import (
    authorize_saved_plan_apply,
    build_health_receipt,
    build_reconciliation_receipt,
    build_saved_plan_approval,
    build_saved_plan_record,
    build_saved_plan_reviewer_packet,
    classify_plan,
    derive_approval_authority_digest,
    prepare_ledger_transition,
    prepare_pre_apply_reapproval,
    recover_stale_applying,
    require_downstream_health,
    require_terminal_role_for_layer,
    summarize_terraform_plan,
    validate_saved_plan_cost_binding,
    validate_dry_run_boundary,
    validate_execution_ledger_document,
)


NOW = datetime(2026, 7, 15, 18, 0, tzinfo=UTC)
CUSTOMER_ID = "cust_" + ("A" * 26)
DEPLOYMENT_ID = "dep_" + ("A" * 26)
ACCOUNT_ID = "1" * 12
REGION = "us-east-1"
REPO_ROOT = Path(__file__).resolve().parents[2]
LIVE_ENGINE_CLI = REPO_ROOT / "scripts/deployment/nonprod-live-engine.py"


def _sha(character: str) -> str:
    return "sha256:" + (character * 64)


def _post_apply_state(*, lineage: str, serial: int) -> dict:
    return {
        "status": "PRESENT",
        "lineage": lineage,
        "serial": serial,
        "object_version_id": f"state-version-{serial}",
        "sha256": canonical_digest({"serial": serial}),
        "size_bytes": 128,
    }


def _health_kwargs(plan: dict, *, lineage: str, serial: int) -> dict:
    observed = _post_apply_state(lineage=lineage, serial=serial)
    return {
        "state_before": observed,
        "state_after": dict(observed),
        "speculative_plan_summary": plan["plan_summary"],
        "outputs_digest": canonical_digest({"outputs": {}}),
        "output_count": 0,
        "expected_contract_digest": canonical_digest(
            {"contract": plan["record_digest"]}
        ),
    }


def _publication(health: dict) -> dict:
    body = {
        "schema_version": "1",
        "record_type": "live_contract_publication",
        "status": "EXACT_READBACK_VERIFIED",
        "health_receipt_digest": health["receipt_digest"],
        "contract_digest": health["expected_contract_digest"],
        "readback_contract_digest": health["expected_contract_digest"],
    }
    return {**body, "publication_receipt_digest": canonical_digest(body)}


def _change_summary() -> dict:
    summary = copy.deepcopy(_plan()["plan_summary"])
    summary.update(
        {
            "add_count": 1,
            "applyable": True,
            "resource_change_count": 1,
            "resource_actions": [
                {
                    "resource_type": "fixture_resource",
                    "resource_name": "fixture",
                    "action": "create",
                    "address_digest": canonical_digest(
                        {"address": "fixture_resource.fixture"}
                    ),
                }
            ],
            "classification": "CHANGE",
        }
    )
    summary["summary_digest"] = canonical_digest(
        {key: value for key, value in summary.items() if key != "summary_digest"}
    )
    return summary


def _bindings() -> dict:
    bindings = {
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "account_id": ACCOUNT_ID,
        "region": REGION,
        "environment": "sandbox",
        "execution_id": "exec_" + ("A" * 26),
        "change_id": "chg_" + ("A" * 26),
        "layer": "network",
        "release_version": "2026.07.15-gug125",
        "release_digest": _sha("a"),
        "release_policy_digest": _sha("6"),
        "release_projection_digest": _sha("7"),
        "plan_policy_digest": _sha("8"),
        "github_environment": "fixture-deployment-environment",
        "github_deployment_identity_digest": _sha("9"),
        "environment_configuration_digest": _sha("5"),
        "expected_approver_user_id": 55,
        "platform_authority_digest": _sha("0"),
        "registry_record_digest": _sha("b"),
        "account_ready_digest": _sha("c"),
        "execution_lock_digest": _sha("d"),
        "backend_binding_digest": _sha("e"),
        "contract_resolution_digest": _sha("f"),
        "toolchain_digest": _sha("1"),
        "root_module_digest": _sha("2"),
        "source_revision_digest": _sha("4"),
        "state_status": "PRESENT",
        "state_lineage": "fixture-lineage-0001",
        "state_serial": 7,
    }
    bindings["approval_authority_digest"] = derive_approval_authority_digest(
        github_environment=bindings["github_environment"],
        expected_approver_user_id=bindings["expected_approver_user_id"],
        github_deployment_identity_digest=bindings[
            "github_deployment_identity_digest"
        ],
        environment_configuration_digest=bindings[
            "environment_configuration_digest"
        ],
    )
    return bindings


def _plan() -> dict:
    bindings = _bindings()
    summary = summarize_terraform_plan(
        dict(
            format_version="1.2",
            terraform_version="1.14.6",
            applyable=False,
            complete=True,
            errored=False,
            resource_changes=[],
        )
    )
    return build_saved_plan_record(
        bindings=bindings,
        plan_environment_anchor_digest=_sha("3"),
        plan_sha256=_sha("3"),
        plan_size_bytes=4096,
        bucket=f"scanalyze-{ACCOUNT_ID}-tf-plan",
        object_key=(
            f"plan-execution/{DEPLOYMENT_ID}/{bindings['change_id']}/"
            "network/plan.tfplan"
        ),
        object_version_id="version-0001",
        state_readback={"status": "PRESENT", "lineage": "fixture-lineage-0001", "serial": 7, "object_version_id": "state-version-7", "sha256": _sha("6"), "size_bytes": 128},
        plan_summary=summary,
        cost_binding={
            "cost_model_digest": _sha("5"),
            "maximum_cost_usd_micros": 10_000_000,
            "modeled_cost_upper_bound_usd_micros": 5_000_000,
        },
        created_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )


def _absent_plan() -> dict:
    bindings = {
        **_bindings(),
        "state_status": "ABSENT",
        "state_lineage": None,
        "state_serial": None,
    }
    summary = summarize_terraform_plan(
        dict(
            format_version="1.2",
            terraform_version="1.14.6",
            applyable=False,
            complete=True,
            errored=False,
            resource_changes=[],
        )
    )
    return build_saved_plan_record(
        bindings=bindings,
        plan_environment_anchor_digest=_sha("3"),
        plan_sha256=_sha("3"),
        plan_size_bytes=4096,
        bucket=f"scanalyze-{ACCOUNT_ID}-tf-plan",
        object_key=(
            f"plan-execution/{DEPLOYMENT_ID}/{bindings['change_id']}/"
            "network/plan.tfplan"
        ),
        object_version_id="version-absent-0001",
        state_readback={"status": "ABSENT", "lineage": None, "serial": None, "object_version_id": None, "sha256": None, "size_bytes": None},
        plan_summary=summary,
        cost_binding={
            "cost_model_digest": _sha("5"),
            "maximum_cost_usd_micros": 10_000_000,
            "modeled_cost_upper_bound_usd_micros": 5_000_000,
        },
        created_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )


def _ledger(status: str = "APPROVED", version: int = 4) -> dict:
    document = {
        "schema_version": "1",
        "record_type": "live_execution_layer",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "account_id": ACCOUNT_ID,
        "region": REGION,
        "environment": "sandbox",
        "execution_id": _bindings()["execution_id"],
        "change_id": _bindings()["change_id"],
        "layer": "network",
        "status": status,
        "ledger_version": version,
        "plan_record_digest": _plan()["record_digest"],
        "plan_environment_anchor_digest": _plan()[
            "plan_environment_anchor_digest"
        ],
        "expected_approver_user_id": _plan()["expected_approver_user_id"],
        "approval_authority_digest": _plan()["approval_authority_digest"],
        "updated_at": NOW.isoformat().replace("+00:00", "Z"),
        "attempt_count": 0 if status in {"PLANNED", "APPROVED"} else 1,
    }
    if status != "PLANNED":
        document["approval_digest"] = _approval()["approval_digest"]
    document["ledger_digest"] = canonical_digest(document)
    return document


def _ledger_for_plan(plan: dict, *, status: str, version: int) -> dict:
    ledger = _ledger(status=status, version=version)
    ledger["plan_record_digest"] = plan["record_digest"]
    ledger["ledger_digest"] = canonical_digest(
        {key: value for key, value in ledger.items() if key != "ledger_digest"}
    )
    return ledger


def _approval() -> dict:
    plan = _plan()
    return build_saved_plan_approval(
        plan_record=plan,
        repository_owner_id=11,
        repository_id=22,
        workflow_ref=(
            "owner/repository/.github/workflows/nonprod-release.yml@refs/heads/main"
        ),
        workflow_sha="4" * 40,
        workflow_run_id=33,
        workflow_run_attempt=1,
        github_environment="fixture-deployment-environment",
        environment_configuration_digest=_sha("5"),
        apply_environment_anchor_digest=_sha("4"),
        initiator_user_id=44,
        expected_approver_user_id=55,
        approver_user_id=55,
        reviewer_packet_digest=build_saved_plan_reviewer_packet(plan)[
            "packet_digest"
        ],
        approval_evidence_digest=_sha("a"),
        approval_window_started_at=NOW + timedelta(minutes=1),
        approval_observed_at=NOW + timedelta(minutes=2),
        freshness_basis="WORKFLOW_RUN_CREATED_AT_CONSERVATIVE_BOUND",
        expires_at=NOW + timedelta(minutes=7),
    )


def _readback(plan: dict) -> dict:
    return {
        "bucket": plan["storage"]["bucket"],
        "object_key": plan["storage"]["object_key"],
        "object_version_id": plan["storage"]["object_version_id"],
        "sha256": plan["plan_sha256"],
        "size_bytes": plan["plan_size_bytes"],
    }


def _authorize(**overrides: object) -> dict:
    plan = overrides.pop("plan_record", _plan())
    return authorize_saved_plan_apply(
        plan_record=plan,
        ledger=overrides.pop("ledger", _ledger()),
        approval_record=overrides.pop("approval_record", _approval()),
        expected_bindings=overrides.pop("expected_bindings", _bindings()),
        plan_readback=overrides.pop("plan_readback", _readback(plan)),
        state_readback=overrides.pop(
            "state_readback",
            {
                "status": "PRESENT",
                "lineage": _bindings()["state_lineage"],
                "serial": 7,
                "object_version_id": "state-version-7",
                "sha256": _sha("6"),
                "size_bytes": 128,
            },
        ),
        now=overrides.pop("now", NOW + timedelta(minutes=5)),
    )


def test_exact_fresh_saved_plan_is_authorized_once() -> None:
    plan = _plan()
    assert _authorize(plan_record=plan) == {
        "allowed": True,
        "code": "EXACT_SAVED_PLAN_AUTHORIZED",
        "plan_record_digest": plan["record_digest"],
    }


def test_greenfield_saved_plan_binds_explicit_absent_state() -> None:
    plan = _absent_plan()
    approval = build_saved_plan_approval(
        plan_record=plan,
        repository_owner_id=11,
        repository_id=22,
        workflow_ref=(
            "owner/repository/.github/workflows/nonprod-release.yml@refs/heads/main"
        ),
        workflow_sha="4" * 40,
        workflow_run_id=33,
        workflow_run_attempt=1,
        github_environment="fixture-deployment-environment",
        environment_configuration_digest=_sha("5"),
        apply_environment_anchor_digest=_sha("4"),
        initiator_user_id=44,
        expected_approver_user_id=55,
        approver_user_id=55,
        reviewer_packet_digest=build_saved_plan_reviewer_packet(plan)[
            "packet_digest"
        ],
        approval_evidence_digest=_sha("a"),
        approval_window_started_at=NOW + timedelta(minutes=1),
        approval_observed_at=NOW + timedelta(minutes=2),
        freshness_basis="WORKFLOW_RUN_CREATED_AT_CONSERVATIVE_BOUND",
        expires_at=NOW + timedelta(minutes=7),
    )
    ledger = _ledger_for_plan(plan, status="APPROVED", version=4)
    ledger["approval_digest"] = approval["approval_digest"]
    ledger["ledger_digest"] = canonical_digest(
        {key: value for key, value in ledger.items() if key != "ledger_digest"}
    )

    decision = _authorize(
        plan_record=plan,
        ledger=ledger,
        approval_record=approval,
        expected_bindings={
            **_bindings(),
            "state_status": "ABSENT",
            "state_lineage": None,
            "state_serial": None,
        },
        state_readback={"status": "ABSENT", "lineage": None, "serial": None, "object_version_id": None, "sha256": None, "size_bytes": None},
    )

    assert decision["allowed"] is True


def test_saved_plan_cost_binding_cannot_be_lowered_at_apply() -> None:
    plan = _plan()
    validate_saved_plan_cost_binding(plan, plan["cost_binding"])
    understated = {
        **plan["cost_binding"],
        "modeled_cost_upper_bound_usd_micros": 1,
    }
    with pytest.raises(AuthorizationError, match="cost binding mismatch"):
        validate_saved_plan_cost_binding(plan, understated)


def test_saved_plan_approval_requires_independent_reviewer_and_exact_plan() -> None:
    with pytest.raises(AuthorizationError, match="independent"):
        build_saved_plan_approval(
            plan_record=_plan(),
            repository_owner_id=11,
            repository_id=22,
            workflow_ref=(
                "owner/repository/.github/workflows/nonprod-release.yml@refs/heads/main"
            ),
            workflow_sha="4" * 40,
            workflow_run_id=33,
            workflow_run_attempt=1,
            github_environment="fixture-deployment-environment",
            environment_configuration_digest=_sha("5"),
            apply_environment_anchor_digest=_sha("4"),
            initiator_user_id=44,
            expected_approver_user_id=55,
            approver_user_id=44,
            reviewer_packet_digest=build_saved_plan_reviewer_packet(_plan())[
                "packet_digest"
            ],
            approval_evidence_digest=_sha("a"),
            approval_window_started_at=NOW + timedelta(minutes=1),
            approval_observed_at=NOW + timedelta(minutes=2),
            freshness_basis="WORKFLOW_RUN_CREATED_AT_CONSERVATIVE_BOUND",
            expires_at=NOW + timedelta(minutes=7),
        )

    foreign = copy.deepcopy(_approval())
    foreign["plan_record_digest"] = _sha("9")
    foreign["approval_digest"] = canonical_digest(
        {key: value for key, value in foreign.items() if key != "approval_digest"}
    )
    with pytest.raises(AuthorizationError, match="approval"):
        _authorize(approval_record=foreign)


def test_saved_plan_approval_rejects_rerun_attempt() -> None:
    with pytest.raises(AuthorizationError, match="run attempt 1"):
        build_saved_plan_approval(
            plan_record=_plan(),
            repository_owner_id=11,
            repository_id=22,
            workflow_ref=(
                "owner/repository/.github/workflows/nonprod-release.yml@refs/heads/main"
            ),
            workflow_sha="4" * 40,
            workflow_run_id=33,
            workflow_run_attempt=2,
            github_environment="fixture-deployment-environment",
            environment_configuration_digest=_sha("5"),
            apply_environment_anchor_digest=_sha("4"),
            initiator_user_id=44,
            expected_approver_user_id=55,
            approver_user_id=55,
            reviewer_packet_digest=build_saved_plan_reviewer_packet(_plan())[
                "packet_digest"
            ],
            approval_evidence_digest=_sha("a"),
            approval_window_started_at=NOW + timedelta(minutes=1),
            approval_observed_at=NOW + timedelta(minutes=2),
            freshness_basis="WORKFLOW_RUN_CREATED_AT_CONSERVATIVE_BOUND",
            expires_at=NOW + timedelta(minutes=7),
        )

    rerun = _approval()
    rerun["workflow_run_attempt"] = 2
    rerun["approval_digest"] = canonical_digest(
        {key: value for key, value in rerun.items() if key != "approval_digest"}
    )
    with pytest.raises(AuthorizationError, match="approval schema|run attempt"):
        _authorize(approval_record=rerun)


@pytest.mark.parametrize(
    ("layer", "operation", "role"),
    [
        ("network", "plan", "ScanalyzeCustomer-Plan"),
        ("network", "apply", "ScanalyzeCustomer-Apply"),
        (
            "identity-control-plane",
            "plan",
            "ScanalyzeCustomer-Identity-Plan",
        ),
        (
            "identity-control-plane",
            "apply",
            "ScanalyzeCustomer-Identity-Apply",
        ),
    ],
)
def test_terminal_role_matches_exact_layer(
    layer: str, operation: str, role: str
) -> None:
    require_terminal_role_for_layer(layer=layer, operation=operation, role=role)


@pytest.mark.parametrize(
    ("layer", "operation", "role"),
    [
        ("identity-control-plane", "plan", "ScanalyzeCustomer-Plan"),
        ("identity-control-plane", "apply", "ScanalyzeCustomer-Apply"),
        ("network", "plan", "ScanalyzeCustomer-Identity-Plan"),
        ("network", "apply", "ScanalyzeCustomer-Identity-Apply"),
        ("artifact-publication", "plan", "ScanalyzeCustomer-Plan"),
        ("network", "promotion", "ScanalyzeCustomer-Apply"),
    ],
)
def test_terminal_role_or_nonterraform_layer_confusion_is_denied(
    layer: str, operation: str, role: str
) -> None:
    with pytest.raises(AuthorizationError, match="layer|operation"):
        require_terminal_role_for_layer(layer=layer, operation=operation, role=role)


def test_malformed_approval_fails_closed_without_key_error() -> None:
    with pytest.raises(AuthorizationError, match="approval schema"):
        _authorize(approval_record={})


def test_expired_saved_plan_approval_is_denied() -> None:
    with pytest.raises(AuthorizationError, match="approval"):
        _authorize(now=NOW + timedelta(minutes=46))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("customer_id", "cust_" + ("B" * 26)),
        ("deployment_id", "dep_" + ("B" * 26)),
        ("account_id", "2" * 12),
        ("region", "us-west-2"),
        ("release_digest", _sha("b")),
        ("github_deployment_identity_digest", _sha("a")),
        ("platform_authority_digest", _sha("a")),
        ("contract_resolution_digest", _sha("a")),
        ("execution_lock_digest", _sha("a")),
        ("source_revision_digest", _sha("9")),
    ],
)
def test_cross_boundary_or_drifted_binding_is_denied(field: str, value: object) -> None:
    expected = _bindings()
    expected[field] = value
    with pytest.raises(AuthorizationError, match="binding"):
        _authorize(expected_bindings=expected)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("sha256", _sha("9")),
        ("size_bytes", 4097),
        ("object_version_id", "substituted"),
        ("object_key", "plan-execution/foreign/plan.tfplan"),
    ],
)
def test_plan_substitution_is_denied(field: str, value: object) -> None:
    plan = _plan()
    readback = _readback(plan)
    readback[field] = value
    with pytest.raises(AuthorizationError, match="readback"):
        _authorize(plan_record=plan, plan_readback=readback)


def test_expired_plan_is_denied() -> None:
    with pytest.raises(AuthorizationError, match="expired"):
        _authorize(now=NOW + timedelta(hours=1))


@pytest.mark.parametrize("status", ["APPLYING", "APPLIED", "UNCERTAIN", "HEALTHY"])
def test_consumed_or_uncertain_plan_cannot_be_reused(status: str) -> None:
    with pytest.raises(AuthorizationError, match="APPROVED"):
        _authorize(ledger=_ledger(status=status))


@pytest.mark.parametrize(
    "state",
    [
        {"lineage": "foreign-lineage", "serial": 7},
        {"lineage": _bindings()["state_lineage"], "serial": 8},
    ],
)
def test_state_drift_invalidates_saved_plan(state: dict) -> None:
    with pytest.raises(AuthorizationError, match="state"):
        _authorize(state_readback=state)


def test_ledger_transition_is_compare_and_swap_and_single_use() -> None:
    current = _ledger()
    transitioned, condition = prepare_ledger_transition(
        current=current,
        next_status="APPLYING",
        expected_version=current["ledger_version"],
        expected_digest=current["ledger_digest"],
        at=NOW + timedelta(minutes=11),
    )
    assert transitioned["status"] == "APPLYING"
    assert transitioned["ledger_version"] == 5
    assert transitioned["attempt_count"] == 1
    assert "ledger_version = :expected_version" in condition["condition_expression"]
    with pytest.raises(AuthorizationError, match="version conflict"):
        prepare_ledger_transition(
            current=current,
            next_status="APPLYING",
            expected_version=3,
            expected_digest=current["ledger_digest"],
            at=NOW + timedelta(minutes=11),
        )


def test_planned_to_approved_requires_exact_approval_evidence() -> None:
    planned = _ledger(status="PLANNED", version=1)
    with pytest.raises(AuthorizationError, match="approval"):
        prepare_ledger_transition(
            current=planned,
            next_status="APPROVED",
            expected_version=1,
            expected_digest=planned["ledger_digest"],
            at=NOW + timedelta(minutes=3),
        )

    approved, _ = prepare_ledger_transition(
        current=planned,
        next_status="APPROVED",
        expected_version=1,
        expected_digest=planned["ledger_digest"],
        at=NOW + timedelta(minutes=3),
        approval_record=_approval(),
    )
    assert approved["approval_digest"] == _approval()["approval_digest"]


def test_pre_apply_reapproval_is_cas_bound_and_never_consumes_an_attempt() -> None:
    planned = _ledger(status="PLANNED", version=1)
    first = _approval()
    approved, _ = prepare_ledger_transition(
        current=planned,
        next_status="APPROVED",
        expected_version=1,
        expected_digest=planned["ledger_digest"],
        at=NOW + timedelta(minutes=3),
        approval_record=first,
    )
    second = copy.deepcopy(first)
    second["workflow_run_id"] += 1
    second["approval_digest"] = canonical_digest(
        {key: value for key, value in second.items() if key != "approval_digest"}
    )

    reapproved, condition = prepare_pre_apply_reapproval(
        current=approved,
        approval_record=second,
        expected_version=approved["ledger_version"],
        expected_digest=approved["ledger_digest"],
        at=NOW + timedelta(minutes=4),
    )

    assert reapproved["status"] == "APPROVED"
    assert reapproved["attempt_count"] == 0
    assert reapproved["ledger_version"] == approved["ledger_version"] + 1
    assert reapproved["approval_digest"] == second["approval_digest"]
    assert condition["expression_attribute_values"][":expected_status"] == "APPROVED"

    with pytest.raises(AuthorizationError, match="new evidence"):
        prepare_pre_apply_reapproval(
            current=approved,
            approval_record=first,
            expected_version=approved["ledger_version"],
            expected_digest=approved["ledger_digest"],
            at=NOW + timedelta(minutes=4),
        )

    for status in ("APPLYING", "APPLIED", "UNCERTAIN"):
        consumed = _ledger(status=status, version=5)
        with pytest.raises(AuthorizationError, match="APPROVED unused"):
            prepare_pre_apply_reapproval(
                current=consumed,
                approval_record=second,
                expected_version=consumed["ledger_version"],
                expected_digest=consumed["ledger_digest"],
                at=NOW + timedelta(minutes=4),
            )


def test_response_loss_becomes_uncertain_and_blocks_resume() -> None:
    applying = _ledger(status="APPLYING", version=5)
    uncertain, _ = prepare_ledger_transition(
        current=applying,
        next_status="UNCERTAIN",
        expected_version=5,
        expected_digest=applying["ledger_digest"],
        at=NOW + timedelta(minutes=20),
        outcome_code="APPLY_RESPONSE_LOST",
    )
    assert uncertain["status"] == "UNCERTAIN"
    with pytest.raises(AuthorizationError, match="health"):
        require_downstream_health(
            uncertain,
            plan_record=_plan(),
            expected_layer="network",
        )


def test_expired_runner_lease_recovers_applying_once_without_new_attempt() -> None:
    applying = _ledger(status="APPLYING", version=5)
    with pytest.raises(AuthorizationError, match="not safely stale"):
        recover_stale_applying(current=applying, now=NOW + timedelta(minutes=64))

    uncertain, condition = recover_stale_applying(
        current=applying,
        now=NOW + timedelta(minutes=65),
    )

    assert uncertain["status"] == "UNCERTAIN"
    assert uncertain["attempt_count"] == 1
    assert uncertain["ledger_version"] == 6
    assert uncertain["outcome_code"] == "RUNNER_LOST_AFTER_ATTEMPT"
    assert condition["expression_attribute_values"][":expected_status"] == "APPLYING"
    with pytest.raises(AuthorizationError, match="not safely stale"):
        recover_stale_applying(
            current=uncertain,
            now=NOW + timedelta(minutes=130),
        )


def test_uncertain_success_is_reconciled_read_only_before_health() -> None:
    uncertain = _ledger(status="UNCERTAIN", version=6)
    observed = _post_apply_state(
        lineage=_bindings()["state_lineage"],
        serial=8,
    )
    receipt = build_reconciliation_receipt(
        plan_record=_plan(),
        ledger=uncertain,
        state_before=observed,
        state_after=dict(observed),
        speculative_plan_result="NO_CHANGE",
        speculative_plan_summary=_plan()["plan_summary"],
        contract_verified=True,
        checked_at=NOW + timedelta(minutes=25),
    )

    assert receipt["decision"] == "RECONCILED_APPLIED"
    assert receipt["cloud_writes"] is False
    with pytest.raises(AuthorizationError, match="reconciliation"):
        prepare_ledger_transition(
            current=uncertain,
            next_status="RECONCILED_APPLIED",
            expected_version=6,
            expected_digest=uncertain["ledger_digest"],
            at=NOW + timedelta(minutes=26),
        )
    reconciled, _ = prepare_ledger_transition(
        current=uncertain,
        next_status="RECONCILED_APPLIED",
        expected_version=6,
        expected_digest=uncertain["ledger_digest"],
        at=NOW + timedelta(minutes=26),
        reconciliation_receipt=receipt,
    )
    assert reconciled["outcome_receipt_digest"] == receipt["receipt_digest"]


def test_greenfield_reconciliation_requires_a_real_new_present_state() -> None:
    plan = _absent_plan()
    uncertain = _ledger_for_plan(plan, status="UNCERTAIN", version=6)
    observed = _post_apply_state(
        lineage="new-greenfield-lineage",
        serial=0,
    )
    receipt = build_reconciliation_receipt(
        plan_record=plan,
        ledger=uncertain,
        state_before=observed,
        state_after=dict(observed),
        speculative_plan_result="NO_CHANGE",
        speculative_plan_summary=plan["plan_summary"],
        contract_verified=True,
        checked_at=NOW + timedelta(minutes=25),
    )
    assert receipt["decision"] == "RECONCILED_APPLIED"
    assert receipt["observed_state_serial"] == 0

    with pytest.raises(AuthorizationError, match="real present state"):
        build_reconciliation_receipt(
            plan_record=plan,
            ledger=uncertain,
            state_before={
                "status": "ABSENT",
                "lineage": None,
                "serial": None,
                "object_version_id": None,
                "sha256": None,
                "size_bytes": None,
            },
            state_after={
                "status": "ABSENT",
                "lineage": None,
                "serial": None,
                "object_version_id": None,
                "sha256": None,
                "size_bytes": None,
            },
            speculative_plan_result="NO_CHANGE",
            speculative_plan_summary=plan["plan_summary"],
            contract_verified=True,
            checked_at=NOW + timedelta(minutes=25),
        )


@pytest.mark.parametrize(
    ("state", "plan_result", "contract_verified"),
    [
        ({"status": "PRESENT", "lineage": "foreign-lineage", "serial": 8}, "NO_CHANGE", True),
        ({"status": "PRESENT", "lineage": _bindings()["state_lineage"], "serial": 7}, "CHANGE", False),
        ({"status": "PRESENT", "lineage": _bindings()["state_lineage"], "serial": 8}, "CHANGE", True),
        ({"status": "PRESENT", "lineage": _bindings()["state_lineage"], "serial": 8}, "ERROR", True),
    ],
)
def test_ambiguous_uncertain_outcome_requires_forward_recovery(
    state: dict, plan_result: str, contract_verified: bool
) -> None:
    observed = _post_apply_state(
        lineage=state["lineage"],
        serial=state["serial"],
    )
    receipt = build_reconciliation_receipt(
        plan_record=_plan(),
        ledger=_ledger(status="UNCERTAIN", version=6),
        state_before=observed,
        state_after=dict(observed),
        speculative_plan_result=plan_result,
        speculative_plan_summary=(
            _plan()["plan_summary"]
            if plan_result == "NO_CHANGE"
            else _change_summary()
            if plan_result == "CHANGE"
            else None
        ),
        contract_verified=contract_verified,
        checked_at=NOW + timedelta(minutes=25),
    )

    assert receipt["decision"] == "RECONCILIATION_REQUIRED"
    assert receipt["cloud_writes"] is False


def test_reconciliation_refuses_non_uncertain_execution() -> None:
    with pytest.raises(AuthorizationError, match="UNCERTAIN"):
        build_reconciliation_receipt(
            plan_record=_plan(),
            ledger=_ledger(status="APPLIED", version=6),
            state_before=_post_apply_state(
                lineage=_bindings()["state_lineage"], serial=8
            ),
            state_after=_post_apply_state(
                lineage=_bindings()["state_lineage"], serial=8
            ),
            speculative_plan_result="NO_CHANGE",
            speculative_plan_summary=_plan()["plan_summary"],
            contract_verified=True,
            checked_at=NOW + timedelta(minutes=25),
        )


def test_health_failure_stops_downstream_and_exact_health_allows_it() -> None:
    plan = _plan()
    applied = _ledger(status="APPLIED", version=6)
    failed = build_health_receipt(
        plan_record=plan,
        ledger=applied,
        **_health_kwargs(
            plan,
            lineage=_bindings()["state_lineage"],
            serial=7,
        ),
        checked_at=NOW + timedelta(minutes=30),
        checks=[{"name": "runtime", "passed": False, "code": "UNHEALTHY"}],
    )
    with pytest.raises(AuthorizationError, match="health"):
        require_downstream_health(
            _ledger(status="APPLIED", version=6),
            plan_record=plan,
            health_receipt=failed,
            expected_layer="network",
        )

    with pytest.raises(AuthorizationError, match="no-change"):
        build_health_receipt(
            plan_record=plan,
            ledger=applied,
            **_health_kwargs(
                plan,
                lineage=_bindings()["state_lineage"],
                serial=plan["state_serial"] + 1,
            ),
            checked_at=NOW + timedelta(minutes=30),
            checks=[{"name": "runtime", "passed": True, "code": "HEALTHY"}],
        )

    passed = build_health_receipt(
        plan_record=plan,
        ledger=applied,
        **_health_kwargs(
            plan,
            lineage=_bindings()["state_lineage"],
            serial=7,
        ),
        checked_at=NOW + timedelta(minutes=30),
        checks=[{"name": "runtime", "passed": True, "code": "HEALTHY"}],
    )
    healthy, _ = prepare_ledger_transition(
        current=applied,
        next_status="HEALTHY",
        expected_version=applied["ledger_version"],
        expected_digest=applied["ledger_digest"],
        at=NOW + timedelta(minutes=31),
        health_receipt=passed,
        contract_publication_receipt=_publication(passed),
    )
    require_downstream_health(
        healthy,
        plan_record=plan,
        health_receipt=passed,
        expected_layer="network",
    )
    foreign = copy.deepcopy(passed)
    foreign["deployment_id"] = "dep_" + ("B" * 26)
    foreign["receipt_digest"] = canonical_digest(
        {key: value for key, value in foreign.items() if key != "receipt_digest"}
    )
    with pytest.raises(AuthorizationError, match="binding"):
        require_downstream_health(
            healthy,
            plan_record=plan,
            health_receipt=foreign,
            expected_layer="network",
        )


def test_greenfield_health_requires_present_state_without_inventing_lineage() -> None:
    plan = _absent_plan()
    applied = _ledger_for_plan(plan, status="APPLIED", version=6)
    receipt = build_health_receipt(
        plan_record=plan,
        ledger=applied,
        **_health_kwargs(
            plan,
            lineage="new-greenfield-lineage",
            serial=0,
        ),
        checked_at=NOW + timedelta(minutes=30),
        checks=[{"name": "runtime", "passed": True, "code": "HEALTHY"}],
    )
    assert receipt["state_lineage"] == "new-greenfield-lineage"
    assert receipt["state_serial"] == 0

    with pytest.raises(AuthorizationError, match="real present state"):
        build_health_receipt(
            plan_record=plan,
            ledger=applied,
            state_before={
                "status": "ABSENT",
                "lineage": None,
                "serial": None,
                "object_version_id": None,
                "sha256": None,
                "size_bytes": None,
            },
            state_after={
                "status": "ABSENT",
                "lineage": None,
                "serial": None,
                "object_version_id": None,
                "sha256": None,
                "size_bytes": None,
            },
            speculative_plan_summary=plan["plan_summary"],
            outputs_digest=canonical_digest({"outputs": {}}),
            output_count=0,
            expected_contract_digest=canonical_digest(
                {"contract": plan["record_digest"]}
            ),
            checked_at=NOW + timedelta(minutes=30),
            checks=[{"name": "runtime", "passed": True, "code": "HEALTHY"}],
        )

def test_health_transition_requires_receipt_bound_to_source_ledger_and_plan() -> None:
    plan = _plan()
    applied = _ledger(status="APPLIED", version=6)
    passed = build_health_receipt(
        plan_record=plan,
        ledger=applied,
        **_health_kwargs(
            plan,
            lineage=plan["state_lineage"],
            serial=7,
        ),
        checked_at=NOW + timedelta(minutes=30),
        checks=[{"name": "runtime", "passed": True, "code": "HEALTHY"}],
    )
    with pytest.raises(AuthorizationError, match="health"):
        prepare_ledger_transition(
            current=applied,
            next_status="HEALTHY",
            expected_version=6,
            expected_digest=applied["ledger_digest"],
            at=NOW + timedelta(minutes=31),
        )

    with pytest.raises(AuthorizationError, match="publication"):
        prepare_ledger_transition(
            current=applied,
            next_status="HEALTHY",
            expected_version=6,
            expected_digest=applied["ledger_digest"],
            at=NOW + timedelta(minutes=31),
            health_receipt=passed,
        )

    healthy, _ = prepare_ledger_transition(
        current=applied,
        next_status="HEALTHY",
        expected_version=6,
        expected_digest=applied["ledger_digest"],
        at=NOW + timedelta(minutes=31),
        health_receipt=passed,
        contract_publication_receipt=_publication(passed),
    )
    assert healthy["status"] == "HEALTHY"


def test_publication_evidence_is_terminal_to_a_healthy_ledger() -> None:
    applied = _ledger(status="APPLIED", version=6)
    applied["contract_publication_receipt_digest"] = _sha("9")
    applied["ledger_digest"] = canonical_digest(
        {key: value for key, value in applied.items() if key != "ledger_digest"}
    )
    with pytest.raises(AuthorizationError, match="non-healthy"):
        validate_execution_ledger_document(applied)

    incomplete_healthy = _ledger(status="APPLIED", version=6)
    incomplete_healthy["status"] = "HEALTHY"
    incomplete_healthy["ledger_digest"] = canonical_digest(
        {
            key: value
            for key, value in incomplete_healthy.items()
            if key != "ledger_digest"
        }
    )
    with pytest.raises(AuthorizationError, match="post-apply evidence"):
        validate_execution_ledger_document(incomplete_healthy)


@pytest.mark.parametrize(
    "credential_name",
    [
        "AWS_PROFILE",
        "AWS_DEFAULT_PROFILE",
        "AWS_SHARED_CREDENTIALS_FILE",
        "AWS_CONFIG_FILE",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "AWS_CONTAINER_AUTHORIZATION_TOKEN",
        "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
    ],
)
def test_dry_run_has_zero_cloud_write_surface(credential_name: str) -> None:
    validate_dry_run_boundary(dry_run=True, allow_live=False, environment={})
    with pytest.raises(AuthorizationError, match="credential"):
        validate_dry_run_boundary(
            dry_run=True,
            allow_live=False,
            environment={credential_name: "synthetic-value"},
        )


def test_no_change_rerun_is_a_distinct_successful_outcome() -> None:
    assert classify_plan(add=0, change=0, destroy=0, replace=0) == "NO_CHANGE"
    assert classify_plan(add=2, change=1, destroy=0, replace=0) == "CHANGE"
    with pytest.raises(AuthorizationError, match="destructive"):
        classify_plan(add=0, change=0, destroy=1, replace=0)


def test_plan_summary_requires_successful_complete_status() -> None:
    plan = dict(
        format_version="1.2",
        terraform_version="1.14.6",
        applyable=False,
        complete=False,
        errored=False,
        resource_changes=[],
    )
    with pytest.raises(AuthorizationError, match="complete and successful"):
        summarize_terraform_plan(plan)


@pytest.mark.parametrize(
    "plan",
    [
        dict(
            format_version="1.2",
            terraform_version="1.14.6",
            applyable=True,
            complete=True,
            errored=False,
            resource_changes=[
                dict(
                    address="data.fixture.current",
                    type="fixture",
                    name="current",
                    change=dict(actions=["read"]),
                )
            ],
        ),
        dict(
            format_version="1.2",
            terraform_version="1.14.6",
            applyable=True,
            complete=True,
            errored=False,
            resource_changes=[],
            output_changes={"reviewed": {"actions": ["update"]}},
        ),
    ],
)
def test_read_or_output_only_plan_is_reviewed_as_change(plan: dict) -> None:
    summary = summarize_terraform_plan(plan)
    assert summary["classification"] == "CHANGE"
    assert summary["applyable"] is True
    assert summary["read_count"] + summary["output_update_count"] == 1


def test_equal_counts_still_bind_distinct_review_manifests() -> None:
    def inspect(name: str, output: str) -> dict:
        return summarize_terraform_plan(
            dict(
                format_version="1.2",
                terraform_version="1.14.6",
                applyable=True,
                complete=True,
                errored=False,
                resource_changes=[
                    dict(
                        address=f"fixture.{name}",
                        type="fixture",
                        name=name,
                        change=dict(actions=["create"]),
                    )
                ],
                output_changes={output: dict(actions=["create"])},
            )
        )

    first = inspect("first", "first_result")
    second = inspect("second", "second_result")

    assert first["add_count"] == second["add_count"] == 1
    assert first["resource_actions"] != second["resource_actions"]
    assert first["output_actions"] != second["output_actions"]
    assert first["summary_digest"] != second["summary_digest"]
    assert set(first["resource_actions"][0]) == {
        "resource_type",
        "resource_name",
        "action",
        "address_digest",
    }
    first_plan = copy.deepcopy(_plan())
    first_plan["plan_summary"] = first
    first_plan["record_digest"] = canonical_digest(
        {key: value for key, value in first_plan.items() if key != "record_digest"}
    )
    second_plan = copy.deepcopy(_plan())
    second_plan["plan_summary"] = second
    second_plan["record_digest"] = canonical_digest(
        {key: value for key, value in second_plan.items() if key != "record_digest"}
    )
    assert build_saved_plan_reviewer_packet(first_plan)["packet_digest"] != (
        build_saved_plan_reviewer_packet(second_plan)["packet_digest"]
    )


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("applyable", True, "applyable flag"),
        ("errored", True, "complete and successful"),
        ("resource_drift", [dict(address="fixture.drift")], "resource drift"),
        ("deferred_changes", [dict(reason="unknown")], "deferred changes"),
        ("action_invocations", [dict(address="fixture.run")], "action invocations"),
    ],
)
def test_plan_summary_rejects_inconsistent_or_unmodeled_plan_semantics(
    field: str, value: object, error: str
) -> None:
    plan = dict(
        format_version="1.2",
        terraform_version="1.14.6",
        applyable=False,
        complete=True,
        errored=False,
        resource_changes=[],
    )
    plan[field] = value
    with pytest.raises(AuthorizationError, match=error):
        summarize_terraform_plan(plan)


@pytest.mark.parametrize(
    "unsupported",
    [
        dict(previous_address="fixture.old"),
        dict(deposed="deadbeef"),
        dict(change=dict(actions=["create"], importing=dict(id="fixture"))),
    ],
)
def test_plan_summary_rejects_moves_deposed_objects_and_imports(
    unsupported: dict[str, object],
) -> None:
    resource_change: dict[str, object] = dict(
        address="fixture.current",
        type="fixture",
        name="current",
        change=dict(actions=["create"]),
    )
    resource_change.update(unsupported)
    plan = dict(
        format_version="1.2",
        terraform_version="1.14.6",
        applyable=True,
        complete=True,
        errored=False,
        resource_changes=[resource_change],
    )
    with pytest.raises(AuthorizationError, match="resource change is malformed"):
        summarize_terraform_plan(plan)


def test_cli_dry_run_executes_without_aws_credentials_or_writes() -> None:
    clean_environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("AWS_")
    }
    result = subprocess.run(
        [sys.executable, str(LIVE_ENGINE_CLI), "dry-run-check"],
        cwd=REPO_ROOT,
        env=clean_environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert "zero" not in result.stderr.lower()
    assert "PASS" in result.stdout


def test_cli_has_no_profile_override_or_raw_secret_output_path() -> None:
    source = LIVE_ENGINE_CLI.read_text(encoding="utf-8")

    assert 'add_argument("--profile"' not in source
    assert "AWS_SECRET_ACCESS_KEY" not in source
    assert "AWS_SESSION_TOKEN" not in source
    assert "print(readback" not in source
    assert "print(plan_record" not in source


def test_legacy_terminal_apply_command_stops_before_inputs_or_aws(
    monkeypatch,
) -> None:
    spec = importlib.util.spec_from_file_location(
        "nonprod_live_engine_cli", LIVE_ENGINE_CLI
    )
    assert spec is not None and spec.loader is not None
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    calls: list[str] = []
    monkeypatch.setattr(
        cli,
        "load_json_strict",
        lambda _path: calls.append("input-read"),
    )
    monkeypatch.setattr(
        cli,
        "AwsCliTerminalSession",
        lambda **_kwargs: calls.append("terminal-session"),
    )

    with pytest.raises(AuthorizationError, match="disabled before destination access"):
        cli._cmd_run_terminal_apply(object())

    assert calls == []
