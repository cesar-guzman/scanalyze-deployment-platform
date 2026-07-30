"""GUG-125 exact saved-plan and resumable live-engine security tests."""
from __future__ import annotations

import copy
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
    classify_plan,
    prepare_ledger_transition,
    require_downstream_health,
    require_terminal_role_for_layer,
    validate_dry_run_boundary,
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


def _bindings() -> dict:
    return {
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
        "platform_authority_digest": _sha("0"),
        "registry_record_digest": _sha("b"),
        "account_ready_digest": _sha("c"),
        "execution_lock_digest": _sha("d"),
        "backend_binding_digest": _sha("e"),
        "contract_resolution_digest": _sha("f"),
        "toolchain_digest": _sha("1"),
        "root_module_digest": _sha("2"),
        "source_revision_digest": _sha("4"),
        "state_lineage": "fixture-lineage-0001",
        "state_serial": 7,
    }


def _plan() -> dict:
    bindings = _bindings()
    return build_saved_plan_record(
        bindings=bindings,
        plan_sha256=_sha("3"),
        plan_size_bytes=4096,
        bucket=f"scanalyze-{ACCOUNT_ID}-tf-evidence",
        object_key=(
            f"plan-execution/{DEPLOYMENT_ID}/{bindings['change_id']}/"
            "network/plan.tfplan"
        ),
        object_version_id="version-0001",
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
        "updated_at": NOW.isoformat().replace("+00:00", "Z"),
        "attempt_count": 0 if status in {"PLANNED", "APPROVED"} else 1,
    }
    if status != "PLANNED":
        document["approval_digest"] = _approval()["approval_digest"]
    document["ledger_digest"] = canonical_digest(document)
    return document


def _approval() -> dict:
    return build_saved_plan_approval(
        plan_record=_plan(),
        repository_owner_id=11,
        repository_id=22,
        workflow_ref=(
            "owner/repository/.github/workflows/nonprod-release.yml@refs/heads/main"
        ),
        workflow_sha="4" * 40,
        workflow_run_id=33,
        github_environment="fixture-deployment-environment",
        environment_configuration_digest=_sha("5"),
        initiator_user_id=44,
        approver_user_id=55,
        approved_at=NOW + timedelta(minutes=2),
        expires_at=NOW + timedelta(minutes=45),
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
            {"lineage": _bindings()["state_lineage"], "serial": 7},
        ),
        now=overrides.pop("now", NOW + timedelta(minutes=10)),
    )


def test_exact_fresh_saved_plan_is_authorized_once() -> None:
    plan = _plan()
    assert _authorize(plan_record=plan) == {
        "allowed": True,
        "code": "EXACT_SAVED_PLAN_AUTHORIZED",
        "plan_record_digest": plan["record_digest"],
    }


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
            github_environment="fixture-deployment-environment",
            environment_configuration_digest=_sha("5"),
            initiator_user_id=44,
            approver_user_id=44,
            approved_at=NOW + timedelta(minutes=2),
            expires_at=NOW + timedelta(minutes=45),
        )

    foreign = copy.deepcopy(_approval())
    foreign["plan_record_digest"] = _sha("9")
    foreign["approval_digest"] = canonical_digest(
        {key: value for key, value in foreign.items() if key != "approval_digest"}
    )
    with pytest.raises(AuthorizationError, match="approval"):
        _authorize(approval_record=foreign)


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


def test_uncertain_success_is_reconciled_read_only_before_health() -> None:
    uncertain = _ledger(status="UNCERTAIN", version=6)
    receipt = build_reconciliation_receipt(
        plan_record=_plan(),
        ledger=uncertain,
        observed_state={"lineage": _bindings()["state_lineage"], "serial": 8},
        speculative_plan_result="NO_CHANGE",
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


@pytest.mark.parametrize(
    ("state", "plan_result", "contract_verified"),
    [
        ({"lineage": "foreign-lineage", "serial": 8}, "NO_CHANGE", True),
        ({"lineage": _bindings()["state_lineage"], "serial": 7}, "CHANGE", False),
        ({"lineage": _bindings()["state_lineage"], "serial": 8}, "CHANGE", True),
        ({"lineage": _bindings()["state_lineage"], "serial": 8}, "ERROR", True),
    ],
)
def test_ambiguous_uncertain_outcome_requires_forward_recovery(
    state: dict, plan_result: str, contract_verified: bool
) -> None:
    receipt = build_reconciliation_receipt(
        plan_record=_plan(),
        ledger=_ledger(status="UNCERTAIN", version=6),
        observed_state=state,
        speculative_plan_result=plan_result,
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
            observed_state={"lineage": _bindings()["state_lineage"], "serial": 8},
            speculative_plan_result="NO_CHANGE",
            contract_verified=True,
            checked_at=NOW + timedelta(minutes=25),
        )


def test_health_failure_stops_downstream_and_exact_health_allows_it() -> None:
    plan = _plan()
    applied = _ledger(status="APPLIED", version=6)
    failed = build_health_receipt(
        plan_record=plan,
        ledger=applied,
        state_readback={"lineage": _bindings()["state_lineage"], "serial": 8},
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

    passed = build_health_receipt(
        plan_record=plan,
        ledger=applied,
        state_readback={"lineage": _bindings()["state_lineage"], "serial": 8},
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


def test_health_transition_requires_receipt_bound_to_source_ledger_and_plan() -> None:
    plan = _plan()
    applied = _ledger(status="APPLIED", version=6)
    passed = build_health_receipt(
        plan_record=plan,
        ledger=applied,
        state_readback={"lineage": plan["state_lineage"], "serial": 8},
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

    healthy, _ = prepare_ledger_transition(
        current=applied,
        next_status="HEALTHY",
        expected_version=6,
        expected_digest=applied["ledger_digest"],
        at=NOW + timedelta(minutes=31),
        health_receipt=passed,
    )
    assert healthy["status"] == "HEALTHY"


def test_dry_run_has_zero_cloud_write_surface() -> None:
    validate_dry_run_boundary(dry_run=True, allow_live=False, environment={})
    with pytest.raises(AuthorizationError, match="credential"):
        validate_dry_run_boundary(
            dry_run=True,
            allow_live=False,
            environment={"AWS_PROFILE": "fixture-profile"},
        )


def test_no_change_rerun_is_a_distinct_successful_outcome() -> None:
    assert classify_plan(add=0, change=0, destroy=0, replace=0) == "NO_CHANGE"
    assert classify_plan(add=2, change=1, destroy=0, replace=0) == "CHANGE"
    with pytest.raises(AuthorizationError, match="destructive"):
        classify_plan(add=0, change=0, destroy=1, replace=0)


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
