from __future__ import annotations

import hashlib
import json
import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Mapping

import pytest

import tooling.nonprod_live_controller as live_controller
from tooling.authorize_deployment_backend import AuthorizationError, canonical_digest
from tooling.nonprod_live_controller import (
    AwsCliReadError,
    LiveInputPackage,
    _private_json,
    inspect_terraform_saved_plan,
    read_exact_state,
    run_apply_controller,
    run_plan_controller,
    run_terminal_apply,
    run_terminal_fetch,
    run_terminal_plan,
    write_private_json_once,
)
from tooling.nonprod_live_engine import (
    build_initial_ledger,
    build_saved_plan_record,
    build_saved_plan_reviewer_packet,
    derive_approval_authority_digest,
    summarize_terraform_plan,
)
from tooling.nonprod_live_github_approval import (
    build_approval_evidence,
    persist_approval_evidence,
)
from tooling.nonprod_live_input_materializer import SOURCE_FILENAMES
from tooling.nonprod_live_orchestrator import (
    build_live_context,
    build_plan_intent,
    derive_source_revision_digest,
)


NOW = datetime(2026, 8, 28, 18, 0, tzinfo=UTC)
CUSTOMER_ID = "cust_" + ("A" * 26)
DEPLOYMENT_ID = "dep_" + ("A" * 26)
EXECUTION_ID = "exec_" + ("A" * 26)
CHANGE_ID = "chg_" + ("A" * 26)
DESTINATION_ACCOUNT = "1" * 12
AUTHORITY_ACCOUNT = "2" * 12
WORKFLOW_SHA = "4" * 40
WORKFLOW_REF = "owner/repository/.github/workflows/nonprod-release.yml@refs/heads/main"
GITHUB_ENVIRONMENT = f"scanalyze-{DEPLOYMENT_ID}-dev"


def _sha(character: str) -> str:
    return "sha256:" + (character * 64)


def _plan_summary() -> dict[str, Any]:
    body = {
        "add_count": 1,
        "change_count": 0,
        "read_count": 0,
        "no_op_count": 0,
        "destroy_count": 0,
        "replace_count": 0,
        "output_create_count": 0,
        "output_update_count": 0,
        "output_delete_count": 0,
        "output_no_op_count": 0,
        "output_change_count": 0,
        "output_actions": [],
        "applyable": True,
        "resource_change_count": 1,
        "resource_actions": [
            {
                "resource_type": "synthetic_resource",
                "resource_name": "fixture",
                "action": "create",
                "address_digest": canonical_digest(
                    {"address": "synthetic_resource.fixture"}
                ),
            }
        ],
        "classification": "CHANGE",
    }
    return {**body, "summary_digest": canonical_digest(body)}


def _cost_binding() -> dict[str, Any]:
    return {
        "cost_model_digest": _sha("3"),
        "maximum_cost_usd_micros": 10_000_000,
        "modeled_cost_upper_bound_usd_micros": 5_000_000,
    }


def _empty_plan_show_document() -> dict[str, Any]:
    return dict(
        format_version="1.2",
        terraform_version="1.14.6",
        applyable=False,
        complete=True,
        errored=False,
        resource_changes=[],
    )


def _plan_show_document(*actions: tuple[str, ...]) -> dict[str, Any]:
    document = _empty_plan_show_document()
    document["resource_changes"] = [
        dict(
            address=f"synthetic_resource.fixture_{index}",
            type="synthetic_resource",
            name=f"fixture_{index}",
            change=dict(actions=list(action)),
        )
        for index, action in enumerate(actions)
    ]
    document["applyable"] = any(action != ("no-op",) for action in actions)
    return document


def _context(*, workflow_run_id: int = 33) -> dict[str, Any]:
    github_deployment_identity_digest = _sha("9")
    environment_configuration_digest = _sha("5")
    github_environment_anchor_digest = _sha("3")
    return build_live_context(
        event_name="workflow_dispatch",
        git_ref="refs/heads/main",
        workflow_ref=WORKFLOW_REF,
        workflow_sha=WORKFLOW_SHA,
        main_sha=WORKFLOW_SHA,
        repository_owner_id=11,
        repository_id=22,
        workflow_run_id=workflow_run_id,
        workflow_run_attempt=1,
        initiator_user_id=44,
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
        execution_id=EXECUTION_ID,
        change_id=CHANGE_ID,
        destination_account_id=DESTINATION_ACCOUNT,
        platform_authority_account_id=AUTHORITY_ACCOUNT,
        region="us-east-1",
        environment="dev",
        github_environment=GITHUB_ENVIRONMENT,
        layer="network",
        release_digest=_sha("a"),
        source_revision_digest=derive_source_revision_digest(WORKFLOW_SHA),
        github_deployment_identity_digest=github_deployment_identity_digest,
        environment_configuration_digest=environment_configuration_digest,
        github_environment_anchor_digest=github_environment_anchor_digest,
        expected_approver_user_id=55,
        approval_authority_digest=derive_approval_authority_digest(
            github_environment=GITHUB_ENVIRONMENT,
            expected_approver_user_id=55,
            github_deployment_identity_digest=github_deployment_identity_digest,
            environment_configuration_digest=environment_configuration_digest,
        ),
        platform_authority_digest=_sha("0"),
        registry_record_digest=_sha("b"),
        account_ready_digest=_sha("c"),
        orchestrator_role_arn=(
            f"arn:aws:iam::{AUTHORITY_ACCOUNT}:role/"
            f"ScanalyzeOrchestrator-{DEPLOYMENT_ID}"
        ),
        plan_role_arn=f"arn:aws:iam::{DESTINATION_ACCOUNT}:role/ScanalyzeCustomer-Plan",
        apply_role_arn=f"arn:aws:iam::{DESTINATION_ACCOUNT}:role/ScanalyzeCustomer-Apply",
        oidc_audience="sts.amazonaws.com",
        control_plane_session_duration_seconds=3600,
        terminal_session_duration_seconds=3600,
    )


def _bindings() -> dict[str, Any]:
    context = _context()
    return {
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "account_id": DESTINATION_ACCOUNT,
        "region": "us-east-1",
        "environment": "dev",
        "execution_id": EXECUTION_ID,
        "change_id": CHANGE_ID,
        "layer": "network",
        "release_version": "2026.08.28-controller",
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
        "expected_approver_user_id": context["expected_approver_user_id"],
        "approval_authority_digest": context["approval_authority_digest"],
        "platform_authority_digest": context["platform_authority_digest"],
        "registry_record_digest": context["registry_record_digest"],
        "account_ready_digest": context["account_ready_digest"],
        "execution_lock_digest": _sha("d"),
        "backend_binding_digest": _sha("e"),
        "contract_resolution_digest": _sha("f"),
        "toolchain_digest": _sha("1"),
        "root_module_digest": _sha("2"),
        "source_revision_digest": context["source_revision_digest"],
        "state_status": "PRESENT",
        "state_lineage": "synthetic-lineage-0001",
        "state_serial": 7,
    }


def _materialized_bindings() -> dict[str, Any]:
    bindings = _bindings()
    for field in ("state_status", "state_lineage", "state_serial"):
        bindings.pop(field)
    return bindings


def _input_maps(root: Path) -> tuple[dict[str, str], dict[str, str]]:
    materialized = root / "materialized"
    sources = materialized / "sources"
    controller = materialized / "controller"
    plan = {
        "plan_dir": str(materialized / "plan"),
        "resolved_input": str(sources / "contract-resolution.json"),
        "manifest": str(sources / "manifest.json"),
        "target_record": str(sources / "target-record.json"),
        "target_anchor": str(sources / "target-anchor.json"),
        "account_ready": str(sources / "account-ready.json"),
        "execution_lock": str(sources / "execution-lock.json"),
    }
    apply = {
        "apply_intent": str(controller / "apply-intent.json"),
        "context": str(materialized / "context.json"),
        "approved_ledger": str(controller / "approved-ledger.json"),
        "applying_ledger": str(controller / "applying-ledger.json"),
        "plan_record": str(controller / "plan-record.json"),
        "approval_record": str(controller / "approval-record.json"),
        "plan_readback": str(controller / "plan-readback.json"),
        "state_readback": str(controller / "state-readback.json"),
        "manifest": str(sources / "manifest.json"),
        "target_record": str(sources / "target-record.json"),
        "target_anchor": str(sources / "target-anchor.json"),
        "account_ready": str(sources / "account-ready.json"),
        "execution_lock": str(sources / "execution-lock.json"),
    }
    return plan, apply


def _source_documents() -> dict[str, dict[str, Any]]:
    documents = {
        key: {"record_type": f"synthetic_{key}", "source_key": key}
        for key in SOURCE_FILENAMES
    }
    documents["account_ready"] = {
        "state_infrastructure": {
            "plan_bucket": f"arn:aws:s3:::scanalyze-{DESTINATION_ACCOUNT}-tf-plan",
            "evidence_kms_key": (
                f"arn:aws:kms:us-east-1:{DESTINATION_ACCOUNT}:key/"
                "evidence-key-0001"
            ),
        }
    }
    return documents


def _private_root(tmp_path: Path) -> Path:
    root = tmp_path / "private"
    for path in (
        root,
        root / "materialized",
        root / "materialized/sources",
        root / "materialized/controller",
        root / "materialized/plan",
    ):
        path.mkdir(mode=0o700) if not path.exists() else None
        path.chmod(0o700)
    return root


def _package(
    tmp_path: Path,
    operation: str,
    *,
    workflow_run_id: int = 33,
) -> LiveInputPackage:
    root = _private_root(tmp_path)
    plan, apply = _input_maps(root)
    source_documents = _source_documents()
    for key, filename in SOURCE_FILENAMES.items():
        write_private_json_once(
            root / "materialized/sources" / filename,
            source_documents[key],
        )
    manifest = {
        "source_document_digests": {
            key: canonical_digest(document)
            for key, document in source_documents.items()
        }
    }
    receipt = {**_cost_binding(), "source_count": len(source_documents)}
    write_private_json_once(root / "materialized/manifest.json", manifest)
    write_private_json_once(root / "materialized/receipt.json", receipt)
    return LiveInputPackage(
        private_root=root,
        operation=operation,
        claim={"claim_digest": _sha("a"), "expires_at": "2026-08-28T19:00:00Z"},
        context=_context(workflow_run_id=workflow_run_id),
        bindings=_materialized_bindings(),
        backend_binding={},
        plan_inputs=plan,
        apply_inputs=apply,
        manifest=manifest,
        receipt=receipt,
    )


def _plan_record(*, plan_bytes: bytes = b"exact-plan") -> dict[str, Any]:
    digest = "sha256:" + hashlib.sha256(plan_bytes).hexdigest()
    return build_saved_plan_record(
        bindings=_bindings(),
        plan_environment_anchor_digest=_context()[
            "github_environment_anchor_digest"
        ],
        plan_sha256=digest,
        plan_size_bytes=len(plan_bytes),
        bucket=f"scanalyze-{DESTINATION_ACCOUNT}-tf-plan",
        object_key=(
            f"plan-execution/{DEPLOYMENT_ID}/{CHANGE_ID}/network/plan.tfplan"
        ),
        object_version_id="version-0001",
        state_readback={"status": "PRESENT", "lineage": "synthetic-lineage-0001", "serial": 7, "object_version_id": "state-version-7", "sha256": _sha("6"), "size_bytes": 128},
        plan_summary=_plan_summary(),
        cost_binding=_cost_binding(),
        created_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )


def _reviewer_packet_digest(plan: Mapping[str, Any] | None = None) -> str:
    return build_saved_plan_reviewer_packet(plan or _plan_record())["packet_digest"]


class FakeLedgerStore:
    def __init__(
        self,
        plan_record: Mapping[str, Any] | None = None,
        *,
        lose_after_commit: set[str] | None = None,
        lose_read_once_for_status: set[str] | None = None,
        lose_read_count_for_status: Mapping[str, int] | None = None,
        conflict_after_replace: set[str] | None = None,
    ) -> None:
        self.plan_record = dict(plan_record) if plan_record else None
        self.approvals: dict[str, dict[str, Any]] = {}
        self.health_receipt: dict[str, Any] | None = None
        self.reconciliation_receipt: dict[str, Any] | None = None
        self.ledger: dict[str, Any] | None = (
            build_initial_ledger(plan_record=plan_record, at=NOW)
            if plan_record
            else None
        )
        self.calls: list[str] = []
        self.lose_after_commit = set(lose_after_commit or ())
        self.lose_read_once_for_status = set(lose_read_once_for_status or ())
        self.lose_read_count_for_status = dict(lose_read_count_for_status or {})
        self.conflict_after_replace = set(conflict_after_replace or ())

    def verify_destination_separation(self, _destination: str) -> dict[str, str]:
        self.calls.append("verify-separation")
        return {}

    def verify_orchestrator_identity(self, _role: str, *, deployment_id: str) -> dict[str, str]:
        assert deployment_id == DEPLOYMENT_ID
        self.calls.append("verify-orchestrator")
        return {}

    def put_plan_record_once(self, plan_record: Mapping[str, Any]) -> None:
        assert self.plan_record is None
        self.plan_record = dict(plan_record)
        self.calls.append("put-plan")
        if "PLAN_RECORD" in self.lose_after_commit:
            self.lose_after_commit.remove("PLAN_RECORD")
            raise AuthorizationError("simulated lost plan-record response")

    def get_plan_record(self, **_kwargs: Any) -> dict[str, Any]:
        assert self.plan_record is not None
        self.calls.append("get-plan")
        return dict(self.plan_record)

    def create_ledger(self, ledger: Mapping[str, Any]) -> None:
        assert self.ledger is None
        self.ledger = dict(ledger)
        self.calls.append("create-ledger")
        if "PLANNED_CREATE" in self.lose_after_commit:
            self.lose_after_commit.remove("PLANNED_CREATE")
            raise AuthorizationError("simulated lost PLANNED response")

    def get_ledger(self, **_kwargs: Any) -> dict[str, Any]:
        assert self.ledger is not None
        self.calls.append("get-ledger")
        status = str(self.ledger["status"])
        if status in self.lose_read_once_for_status:
            self.lose_read_once_for_status.remove(status)
            raise AuthorizationError("simulated lost ledger read response")
        remaining = self.lose_read_count_for_status.get(status, 0)
        if remaining > 0:
            self.lose_read_count_for_status[status] = remaining - 1
            raise AuthorizationError("simulated repeated lost ledger read response")
        return dict(self.ledger)

    def put_approval_record_once(self, approval_record: Mapping[str, Any], *, now: datetime) -> None:
        digest = str(approval_record["approval_digest"])
        assert now.tzinfo is not None and digest not in self.approvals
        self.approvals[digest] = dict(approval_record)
        self.calls.append("put-approval")
        if "APPROVAL_RECORD" in self.lose_after_commit:
            self.lose_after_commit.remove("APPROVAL_RECORD")
            raise AuthorizationError("simulated lost approval response")

    def get_approval_record(self, **kwargs: Any) -> dict[str, Any]:
        digest = str(kwargs["approval_digest"])
        assert digest in self.approvals
        self.calls.append("get-approval")
        return dict(self.approvals[digest])

    def put_health_receipt_once(self, receipt: Mapping[str, Any]) -> None:
        assert self.health_receipt is None
        self.health_receipt = dict(receipt)
        self.calls.append("put-health")
        if "HEALTH_RECEIPT" in self.lose_after_commit:
            self.lose_after_commit.remove("HEALTH_RECEIPT")
            raise AuthorizationError("simulated lost health receipt response")

    def get_health_receipt(self, **_kwargs: Any) -> dict[str, Any]:
        assert self.health_receipt is not None
        self.calls.append("get-health")
        return dict(self.health_receipt)

    def find_health_receipt(self, **_kwargs: Any) -> dict[str, Any] | None:
        self.calls.append("find-health")
        return (
            None
            if self.health_receipt is None
            else dict(self.health_receipt)
        )

    def put_reconciliation_receipt_once(
        self, receipt: Mapping[str, Any]
    ) -> None:
        assert self.reconciliation_receipt is None
        self.reconciliation_receipt = dict(receipt)
        self.calls.append("put-reconciliation")
        if "RECONCILIATION_RECEIPT" in self.lose_after_commit:
            self.lose_after_commit.remove("RECONCILIATION_RECEIPT")
            raise AuthorizationError(
                "simulated lost reconciliation receipt response"
            )

    def get_reconciliation_receipt(self, **_kwargs: Any) -> dict[str, Any]:
        assert self.reconciliation_receipt is not None
        self.calls.append("get-reconciliation")
        return dict(self.reconciliation_receipt)

    def find_reconciliation_receipt(
        self, **_kwargs: Any
    ) -> dict[str, Any] | None:
        self.calls.append("find-reconciliation")
        return (
            None
            if self.reconciliation_receipt is None
            else dict(self.reconciliation_receipt)
        )

    def replace_ledger(self, *, ledger: Mapping[str, Any], expected_version: int, expected_digest: str, expected_status: str, **_kwargs: Any) -> None:
        assert self.ledger is not None
        assert self.ledger["ledger_version"] == expected_version
        assert self.ledger["ledger_digest"] == expected_digest
        assert self.ledger["status"] == expected_status
        self.ledger = dict(ledger)
        self.calls.append(f"replace-{ledger['status']}")
        status = str(ledger["status"])
        if status in self.conflict_after_replace:
            self.conflict_after_replace.remove(status)
            self.ledger["status"] = "CONCURRENT"
            raise AuthorizationError("simulated concurrent ledger transition")
        if status in self.lose_after_commit:
            self.lose_after_commit.remove(status)
            raise AuthorizationError("simulated lost ledger write response")


class FakePlanTerminal:
    def __init__(self, package: LiveInputPackage) -> None:
        self.package = package
        self.calls: list[str] = []

    def run_terminal_phase(self, **kwargs: Any) -> None:
        command = list(kwargs["command"])
        assert "_terminal-plan" in command
        self.calls.append("plan")
        write_private_json_once(
            self.package.controller_root / "plan-record.json", _plan_record()
        )


class FakeApplyTerminal:
    def __init__(
        self,
        package: LiveInputPackage,
        *,
        fail_apply: bool = False,
        fail_fetch: bool = False,
    ) -> None:
        self.package = package
        self.fail_apply = fail_apply
        self.fail_fetch = fail_fetch
        self.calls: list[str] = []

    def run_terminal_phase(self, **kwargs: Any) -> None:
        command = list(kwargs["command"])
        if "_terminal-fetch" in command:
            self.calls.append("fetch")
            if self.fail_fetch:
                raise AuthorizationError("simulated cancellation before apply")
            plan = _plan_record()
            plan_path = self.package.controller_root / "controlled.tfplan"
            plan_path.write_bytes(b"exact-plan")
            plan_path.chmod(0o600)
            write_private_json_once(
                self.package.controller_root / "plan-readback.json",
                {
                    "bucket": plan["storage"]["bucket"],
                    "object_key": plan["storage"]["object_key"],
                    "object_version_id": plan["storage"]["object_version_id"],
                    "sha256": plan["plan_sha256"],
                    "size_bytes": plan["plan_size_bytes"],
                },
            )
            write_private_json_once(
                self.package.controller_root / "state-readback.json",
                {
                    "status": "PRESENT",
                    "lineage": "synthetic-lineage-0001",
                    "serial": 7,
                    "object_version_id": "state-version-7",
                    "sha256": _sha("6"),
                    "size_bytes": 128,
                },
            )
            return
        assert "_terminal-apply" in command
        self.calls.append("apply")
        if self.fail_apply:
            raise AuthorizationError("simulated lost response")


def _approval(package: LiveInputPackage) -> None:
    workflow_run_id = package.context["workflow_run_id"]
    evidence = build_approval_evidence(
        repository="owner/repository",
        repository_id=22,
        workflow_sha=WORKFLOW_SHA,
        workflow_run_id=workflow_run_id,
        workflow_run_attempt=1,
        github_environment=GITHUB_ENVIRONMENT,
        reviewer_packet_digest=_reviewer_packet_digest(),
        apply_environment_anchor_digest=package.context[
            "github_environment_anchor_digest"
        ],
        approval_authority_digest=package.context["approval_authority_digest"],
        initiator_user_id=44,
        expected_approver_user_id=55,
        workflow_run=dict(
            id=workflow_run_id,
            run_attempt=1,
            event="workflow_dispatch",
            status="in_progress",
            head_branch="main",
            head_sha=WORKFLOW_SHA,
            created_at="2026-08-28T18:05:00Z",
            repository=dict(id=22),
            actor=dict(id=44),
        ),
        reviews=[
            {
                "state": "approved",
                "environments": [{"id": 77, "name": GITHUB_ENVIRONMENT}],
                "user": {"id": 55},
            }
        ],
        observed_at=NOW + timedelta(minutes=10),
    )
    persist_approval_evidence(package.private_root, evidence)


def _set_ledger_status(store: FakeLedgerStore, status: str) -> None:
    assert store.ledger is not None
    ledger = dict(store.ledger)
    ledger.update(
        {
            "status": status,
            "ledger_version": 6,
            "attempt_count": 1,
            "approval_digest": _sha("7"),
            "updated_at": "2026-08-28T18:09:00Z",
        }
    )
    ledger.pop("outcome_code", None)
    ledger.pop("outcome_receipt_digest", None)
    ledger["ledger_digest"] = canonical_digest(
        {key: value for key, value in ledger.items() if key != "ledger_digest"}
    )
    store.ledger = ledger


def _post_apply_state(*, serial: int = 8, version: str | None = None) -> dict[str, Any]:
    return {
        "status": "PRESENT",
        "lineage": "synthetic-lineage-0001",
        "serial": serial,
        "object_version_id": version or f"state-version-{serial}",
        "sha256": canonical_digest({"state_serial": serial}),
        "size_bytes": 256,
    }


def _post_apply_observation(
    *,
    state_before: Mapping[str, Any] | None = None,
    state_after: Mapping[str, Any] | None = None,
    result: str = "NO_CHANGE",
    checks_pass: bool = True,
) -> dict[str, Any]:
    before = dict(state_before or _post_apply_state())
    after = dict(state_after or before)
    summary = None
    if result != "ERROR":
        summary = summarize_terraform_plan(
            _empty_plan_show_document()
            if result == "NO_CHANGE"
            else _plan_show_document(("create",))
        )
    return {
        "state_before": before,
        "state_after": after,
        "speculative_plan_result": result,
        "speculative_plan_summary": summary,
        "checks": [
            {
                "name": "input_contracts",
                "passed": checks_pass,
                "code": "CONTRACTS_VERIFIED" if checks_pass else "CONTRACTS_FAILED",
            },
            {"name": "runtime", "passed": True, "code": "RUNTIME_HEALTHY"},
        ],
        "outputs": {
            "endpoint": {"sensitive": False, "value": "https://example.invalid"},
            "private_token": {"sensitive": True, "value": "never-persist"},
        },
    }


def _reconciliation_observation(
    *,
    state_before: Mapping[str, Any] | None = None,
    state_after: Mapping[str, Any] | None = None,
    result: str = "NO_CHANGE",
    contract_verified: bool = True,
) -> dict[str, Any]:
    health = _post_apply_observation(
        state_before=state_before,
        state_after=state_after,
        result=result,
    )
    return {
        "state_before": health["state_before"],
        "state_after": health["state_after"],
        "speculative_plan_result": result,
        "speculative_plan_summary": health["speculative_plan_summary"],
        "contract_verified": contract_verified,
    }


def _exact_publisher(**kwargs: Any) -> dict[str, Any]:
    health = kwargs["health_receipt"]
    body = {
        "schema_version": "1",
        "record_type": "live_contract_publication",
        "status": "EXACT_READBACK_VERIFIED",
        "health_receipt_digest": health["receipt_digest"],
        "contract_digest": health["expected_contract_digest"],
        "readback_contract_digest": health["expected_contract_digest"],
    }
    return {**body, "publication_receipt_digest": canonical_digest(body)}


def test_plan_controller_composes_terminal_then_create_only_readbacks(tmp_path: Path) -> None:
    package = _package(tmp_path, "plan")
    terminal = FakePlanTerminal(package)
    store = FakeLedgerStore()

    result = run_plan_controller(
        package,
        receipt_digest=_sha("b"),
        terminal_session=terminal,
        ledger_store=store,
        now=NOW,
    )

    assert terminal.calls == ["plan"]
    assert store.calls == [
        "verify-separation",
        "verify-orchestrator",
        "put-plan",
        "get-plan",
        "create-ledger",
        "get-ledger",
    ]
    assert result["status"] == "PLANNED"
    assert result["production_authorized"] is False


def test_plan_controller_records_the_post_terminal_observation_time(
    tmp_path: Path,
) -> None:
    package = _package(tmp_path, "plan")
    terminal = FakePlanTerminal(package)
    store = FakeLedgerStore()
    observed = NOW + timedelta(minutes=3)

    run_plan_controller(
        package,
        receipt_digest=_sha("b"),
        terminal_session=terminal,
        ledger_store=store,
        now=NOW,
        clock=lambda: observed,
    )

    assert store.ledger is not None
    assert store.ledger["updated_at"] == "2026-08-28T18:03:00Z"


@pytest.mark.parametrize("lost_boundary", ["PLAN_RECORD", "PLANNED_CREATE"])
def test_plan_controller_recovers_create_commit_with_lost_response(
    tmp_path: Path, lost_boundary: str
) -> None:
    package = _package(tmp_path, "plan")
    terminal = FakePlanTerminal(package)
    store = FakeLedgerStore(lose_after_commit={lost_boundary})

    result = run_plan_controller(
        package,
        receipt_digest=_sha("b"),
        terminal_session=terminal,
        ledger_store=store,
        now=NOW,
    )

    assert result["status"] == "PLANNED"
    assert terminal.calls == ["plan"]


def test_apply_controller_recovers_approval_commit_with_lost_response(
    tmp_path: Path,
) -> None:
    package = _package(tmp_path, "apply")
    _approval(package)
    plan = _plan_record()
    store = FakeLedgerStore(plan, lose_after_commit={"APPROVAL_RECORD"})
    terminal = FakeApplyTerminal(package)

    result = run_apply_controller(
        package,
        receipt_digest=_sha("b"),
        plan_record_digest=plan["record_digest"],
        reviewer_packet_digest=_reviewer_packet_digest(plan),
        expected_approver_user_id=55,
        terminal_session=terminal,
        ledger_store=store,
        now=NOW + timedelta(minutes=10),
    )

    assert result["status"] == "APPLIED"
    assert terminal.calls.count("apply") == 1


def test_cancelled_pre_apply_run_can_select_fresh_approval_by_cas(
    tmp_path: Path,
) -> None:
    plan = _plan_record()
    store = FakeLedgerStore(plan)
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir(mode=0o700)
    second_root.mkdir(mode=0o700)
    first_package = _package(first_root, "apply", workflow_run_id=33)
    _approval(first_package)

    with pytest.raises(AuthorizationError, match="cancellation"):
        run_apply_controller(
            first_package,
            receipt_digest=_sha("b"),
            plan_record_digest=plan["record_digest"],
            reviewer_packet_digest=_reviewer_packet_digest(plan),
            expected_approver_user_id=55,
            terminal_session=FakeApplyTerminal(first_package, fail_fetch=True),
            ledger_store=store,
            now=NOW + timedelta(minutes=10),
        )

    assert store.ledger is not None
    first_approval_digest = store.ledger["approval_digest"]
    assert store.ledger["status"] == "APPROVED"
    assert store.ledger["attempt_count"] == 0

    second_package = _package(second_root, "apply", workflow_run_id=34)
    _approval(second_package)
    result = run_apply_controller(
        second_package,
        receipt_digest=_sha("b"),
        plan_record_digest=plan["record_digest"],
        reviewer_packet_digest=_reviewer_packet_digest(plan),
        expected_approver_user_id=55,
        terminal_session=FakeApplyTerminal(second_package),
        ledger_store=store,
        now=NOW + timedelta(minutes=10),
    )

    assert result["status"] == "APPLIED"
    assert len(store.approvals) == 2
    assert result["approval_digest"] != first_approval_digest
    assert store.calls.count("replace-APPROVED") == 2


def test_apply_controller_records_action_and_terminal_outcome_times(
    tmp_path: Path,
) -> None:
    package = _package(tmp_path, "apply")
    _approval(package)
    plan = _plan_record()
    store = FakeLedgerStore(plan)
    terminal = FakeApplyTerminal(package)
    observations = iter(
        [NOW + timedelta(minutes=12), NOW + timedelta(minutes=14)]
    )

    result = run_apply_controller(
        package,
        receipt_digest=_sha("b"),
        plan_record_digest=plan["record_digest"],
        reviewer_packet_digest=_reviewer_packet_digest(plan),
        expected_approver_user_id=55,
        terminal_session=terminal,
        ledger_store=store,
        now=NOW + timedelta(minutes=10),
        clock=lambda: next(observations),
    )

    assert result["status"] == "APPLIED"
    assert store.ledger is not None
    assert store.ledger["updated_at"] == "2026-08-28T18:14:00Z"


@pytest.mark.parametrize(
    ("fail_apply", "expected_status"), [(False, "APPLIED"), (True, "UNCERTAIN")]
)
def test_apply_controller_consumes_once_and_never_replans(
    tmp_path: Path, fail_apply: bool, expected_status: str
) -> None:
    package = _package(tmp_path, "apply")
    _approval(package)
    plan = _plan_record()
    store = FakeLedgerStore(plan)
    terminal = FakeApplyTerminal(package, fail_apply=fail_apply)

    if fail_apply:
        with pytest.raises(AuthorizationError, match="uncertain"):
            run_apply_controller(
                package,
                receipt_digest=_sha("b"),
                plan_record_digest=plan["record_digest"],
                reviewer_packet_digest=_reviewer_packet_digest(plan),
                expected_approver_user_id=55,
                terminal_session=terminal,
                ledger_store=store,
                now=NOW + timedelta(minutes=10),
            )
    else:
        result = run_apply_controller(
            package,
            receipt_digest=_sha("b"),
                plan_record_digest=plan["record_digest"],
                reviewer_packet_digest=_reviewer_packet_digest(plan),
                expected_approver_user_id=55,
            terminal_session=terminal,
            ledger_store=store,
            now=NOW + timedelta(minutes=10),
        )
        assert result["status"] == "APPLIED"

    assert terminal.calls == ["fetch", "apply"]
    assert store.ledger is not None
    assert store.ledger["status"] == expected_status
    assert store.ledger["attempt_count"] == 1
    assert "replace-APPROVED" in store.calls
    assert "replace-APPLYING" in store.calls
    assert f"replace-{expected_status}" in store.calls


@pytest.mark.parametrize(
    ("fail_apply", "lost_status", "expected_status"),
    [
        (False, "APPLIED", "APPLIED"),
        (True, "UNCERTAIN", "UNCERTAIN"),
    ],
)
def test_apply_reconciles_committed_ledger_write_with_lost_response(
    tmp_path: Path,
    fail_apply: bool,
    lost_status: str,
    expected_status: str,
) -> None:
    package = _package(tmp_path, "apply")
    _approval(package)
    plan = _plan_record()
    store = FakeLedgerStore(plan, lose_after_commit={lost_status})
    terminal = FakeApplyTerminal(package, fail_apply=fail_apply)

    if fail_apply:
        with pytest.raises(AuthorizationError, match="uncertain"):
            run_apply_controller(
                package,
                receipt_digest=_sha("b"),
                plan_record_digest=plan["record_digest"],
                reviewer_packet_digest=_reviewer_packet_digest(plan),
                expected_approver_user_id=55,
                terminal_session=terminal,
                ledger_store=store,
                now=NOW + timedelta(minutes=10),
            )
    else:
        result = run_apply_controller(
            package,
            receipt_digest=_sha("b"),
                plan_record_digest=plan["record_digest"],
                reviewer_packet_digest=_reviewer_packet_digest(plan),
                expected_approver_user_id=55,
            terminal_session=terminal,
            ledger_store=store,
            now=NOW + timedelta(minutes=10),
        )
        assert result["status"] == "APPLIED"

    assert store.ledger is not None
    assert store.ledger["status"] == expected_status
    assert terminal.calls.count("apply") == 1


def test_apply_reconciles_lost_consistent_read_after_applied_cas(
    tmp_path: Path,
) -> None:
    package = _package(tmp_path, "apply")
    _approval(package)
    plan = _plan_record()
    store = FakeLedgerStore(plan, lose_read_once_for_status={"APPLIED"})
    terminal = FakeApplyTerminal(package)

    result = run_apply_controller(
        package,
        receipt_digest=_sha("b"),
       plan_record_digest=plan["record_digest"],
        reviewer_packet_digest=_reviewer_packet_digest(plan),
       expected_approver_user_id=55,
        terminal_session=terminal,
        ledger_store=store,
        now=NOW + timedelta(minutes=10),
    )

    assert result["status"] == "APPLIED"
    assert terminal.calls.count("apply") == 1


def test_apply_reconciles_late_strong_read_after_all_confirmation_reads_fail(
    tmp_path: Path,
) -> None:
    package = _package(tmp_path, "apply")
    _approval(package)
    plan = _plan_record()
    store = FakeLedgerStore(plan, lose_read_count_for_status={"APPLIED": 4})
    terminal = FakeApplyTerminal(package)

    result = run_apply_controller(
        package,
        receipt_digest=_sha("b"),
        plan_record_digest=plan["record_digest"],
        reviewer_packet_digest=_reviewer_packet_digest(plan),
        expected_approver_user_id=55,
        terminal_session=terminal,
        ledger_store=store,
        now=NOW + timedelta(minutes=10),
    )

    assert result["status"] == "APPLIED"
    assert store.ledger is not None
    assert store.ledger["status"] == "APPLIED"
    assert store.calls.count("replace-APPLIED") == 1
    assert terminal.calls.count("apply") == 1


def test_apply_reconciles_late_strong_uncertain_read_after_confirmation_loss(
    tmp_path: Path,
) -> None:
    package = _package(tmp_path, "apply")
    _approval(package)
    plan = _plan_record()
    store = FakeLedgerStore(
        plan,
        lose_read_count_for_status={"UNCERTAIN": 4},
    )
    terminal = FakeApplyTerminal(package, fail_apply=True)

    with pytest.raises(AuthorizationError, match="uncertain"):
        run_apply_controller(
            package,
            receipt_digest=_sha("b"),
            plan_record_digest=plan["record_digest"],
            reviewer_packet_digest=_reviewer_packet_digest(plan),
            expected_approver_user_id=55,
            terminal_session=terminal,
            ledger_store=store,
            now=NOW + timedelta(minutes=10),
        )

    assert store.ledger is not None
    assert store.ledger["status"] == "UNCERTAIN"
    assert store.calls.count("replace-UNCERTAIN") == 1
    assert terminal.calls.count("apply") == 1


def test_apply_never_reruns_after_unexpected_concurrent_ledger_state(
    tmp_path: Path,
) -> None:
    package = _package(tmp_path, "apply")
    _approval(package)
    plan = _plan_record()
    store = FakeLedgerStore(plan, conflict_after_replace={"APPLIED"})
    terminal = FakeApplyTerminal(package)

    with pytest.raises(AuthorizationError, match="could not be confirmed"):
        run_apply_controller(
            package,
            receipt_digest=_sha("b"),
           plan_record_digest=plan["record_digest"],
            reviewer_packet_digest=_reviewer_packet_digest(plan),
           expected_approver_user_id=55,
            terminal_session=terminal,
            ledger_store=store,
            now=NOW + timedelta(minutes=10),
        )

    assert terminal.calls.count("apply") == 1


def test_failure_after_applying_cas_before_terminal_is_durably_uncertain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package = _package(tmp_path, "apply")
    _approval(package)
    plan = _plan_record()
    store = FakeLedgerStore(plan)
    terminal = FakeApplyTerminal(package)
    original = live_controller._revalidate_materialized_sources
    validations = 0

    def fail_second_validation(candidate: LiveInputPackage) -> None:
        nonlocal validations
        validations += 1
        if validations == 2:
            raise AuthorizationError("simulated pre-terminal source failure")
        original(candidate)

    monkeypatch.setattr(
        live_controller,
        "_revalidate_materialized_sources",
        fail_second_validation,
    )

    with pytest.raises(AuthorizationError, match="uncertain"):
        run_apply_controller(
            package,
            receipt_digest=_sha("b"),
           plan_record_digest=plan["record_digest"],
            reviewer_packet_digest=_reviewer_packet_digest(plan),
           expected_approver_user_id=55,
            terminal_session=terminal,
            ledger_store=store,
            now=NOW + timedelta(minutes=10),
        )

    assert terminal.calls == ["fetch"]
    assert store.ledger is not None
    assert store.ledger["status"] == "UNCERTAIN"
    assert store.ledger["attempt_count"] == 1
    assert store.calls.count("replace-UNCERTAIN") == 1


def test_failure_after_terminal_is_durably_uncertain_without_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package = _package(tmp_path, "apply")
    _approval(package)
    plan = _plan_record()
    store = FakeLedgerStore(plan)
    terminal = FakeApplyTerminal(package)
    original = live_controller.classify_apply_observation

    def fail_success_classification(**kwargs: Any) -> dict[str, Any]:
        if kwargs["observation"] == "SUCCESS":
            raise AuthorizationError("simulated post-terminal failure")
        return original(**kwargs)

    monkeypatch.setattr(
        live_controller,
        "classify_apply_observation",
        fail_success_classification,
    )

    with pytest.raises(AuthorizationError, match="uncertain"):
        run_apply_controller(
            package,
            receipt_digest=_sha("b"),
           plan_record_digest=plan["record_digest"],
            reviewer_packet_digest=_reviewer_packet_digest(plan),
           expected_approver_user_id=55,
            terminal_session=terminal,
            ledger_store=store,
            now=NOW + timedelta(minutes=10),
        )

    assert terminal.calls == ["fetch", "apply"]
    assert store.ledger is not None
    assert store.ledger["status"] == "UNCERTAIN"
    assert store.ledger["attempt_count"] == 1
    assert store.calls.count("replace-UNCERTAIN") == 1


def test_apply_closes_to_healthy_only_after_exact_contract_readback(
    tmp_path: Path,
) -> None:
    package = _package(tmp_path, "apply")
    _approval(package)
    plan = _plan_record()
    store = FakeLedgerStore(plan)
    terminal = FakeApplyTerminal(package)
    events: list[str] = []

    def probe(**_kwargs: Any) -> dict[str, Any]:
        events.append("probe")
        return _post_apply_observation()

    def publish(**kwargs: Any) -> dict[str, Any]:
        assert store.health_receipt is not None
        assert store.ledger is not None and store.ledger["status"] == "APPLIED"
        events.append("publish")
        return _exact_publisher(**kwargs)

    result = run_apply_controller(
        package,
        receipt_digest=_sha("b"),
        plan_record_digest=plan["record_digest"],
        reviewer_packet_digest=_reviewer_packet_digest(plan),
        expected_approver_user_id=55,
        terminal_session=terminal,
        ledger_store=store,
        now=NOW + timedelta(minutes=10),
        health_probe=probe,
        contract_publisher=publish,
    )

    assert result["status"] == "HEALTHY"
    assert events == ["probe", "publish"]
    assert terminal.calls == ["fetch", "apply"]
    assert store.ledger is not None and store.ledger["status"] == "HEALTHY"
    assert store.calls.index("put-health") < store.calls.index("replace-HEALTHY")
    private_outputs = _private_json(
        package.controller_root / "verified-non-sensitive-outputs.json"
    )
    assert private_outputs["outputs"] == {
        "endpoint": "https://example.invalid"
    }


@pytest.mark.parametrize("status", ["APPLIED", "RECONCILED_APPLIED"])
def test_applied_reentry_never_reapproves_fetches_or_applies(
    tmp_path: Path,
    status: str,
) -> None:
    package = _package(tmp_path, "apply")
    plan = _plan_record()
    store = FakeLedgerStore(plan)
    _set_ledger_status(store, status)
    terminal = FakeApplyTerminal(package)

    result = run_apply_controller(
        package,
        receipt_digest=_sha("b"),
        plan_record_digest=plan["record_digest"],
        reviewer_packet_digest=_reviewer_packet_digest(plan),
        expected_approver_user_id=55,
        terminal_session=terminal,
        ledger_store=store,
        now=NOW + timedelta(minutes=10),
        health_probe=lambda **_kwargs: _post_apply_observation(),
        contract_publisher=_exact_publisher,
    )

    assert result["status"] == "HEALTHY"
    assert terminal.calls == []
    assert "put-approval" not in store.calls
    assert "replace-APPROVING" not in store.calls
    assert "replace-APPLYING" not in store.calls


def test_applied_reentry_without_post_apply_adapter_is_a_read_only_pending_noop(
    tmp_path: Path,
) -> None:
    package = _package(tmp_path, "apply")
    plan = _plan_record()
    store = FakeLedgerStore(plan)
    _set_ledger_status(store, "APPLIED")
    terminal = FakeApplyTerminal(package)

    result = run_apply_controller(
        package,
        receipt_digest=_sha("b"),
        plan_record_digest=plan["record_digest"],
        reviewer_packet_digest=_reviewer_packet_digest(plan),
        expected_approver_user_id=55,
        terminal_session=terminal,
        ledger_store=store,
        now=NOW + timedelta(minutes=10),
    )

    assert result["status"] == "APPLIED"
    assert result["post_apply_pending"] is True
    assert terminal.calls == []
    assert "put-approval" not in store.calls


def test_applying_reentry_has_no_hidden_recovery_mutation(
    tmp_path: Path,
) -> None:
    package = _package(tmp_path, "apply")
    plan = _plan_record()
    store = FakeLedgerStore(plan)
    _set_ledger_status(store, "APPLYING")
    original_ledger = dict(store.ledger or {})
    terminal = FakeApplyTerminal(package)

    with pytest.raises(AuthorizationError, match="no recovery authority"):
        run_apply_controller(
            package,
            receipt_digest=_sha("b"),
            plan_record_digest=plan["record_digest"],
            reviewer_packet_digest=_reviewer_packet_digest(plan),
            expected_approver_user_id=55,
            terminal_session=terminal,
            ledger_store=store,
            now=NOW + timedelta(hours=2),
        )

    assert store.ledger == original_ledger
    assert terminal.calls == []
    assert not any(call.startswith("replace-") for call in store.calls)


def test_post_apply_state_change_blocks_publish_and_keeps_applied(
    tmp_path: Path,
) -> None:
    package = _package(tmp_path, "apply")
    plan = _plan_record()
    store = FakeLedgerStore(plan)
    _set_ledger_status(store, "APPLIED")
    published: list[bool] = []

    def publish(**kwargs: Any) -> dict[str, Any]:
        published.append(True)
        return _exact_publisher(**kwargs)

    with pytest.raises(AuthorizationError, match="state changed"):
        run_apply_controller(
            package,
            receipt_digest=_sha("b"),
            plan_record_digest=plan["record_digest"],
            reviewer_packet_digest=_reviewer_packet_digest(plan),
            expected_approver_user_id=55,
            terminal_session=FakeApplyTerminal(package),
            ledger_store=store,
            now=NOW + timedelta(minutes=10),
            health_probe=lambda **_kwargs: _post_apply_observation(
                state_after=_post_apply_state(serial=9)
            ),
            contract_publisher=publish,
        )

    assert published == []
    assert store.ledger is not None and store.ledger["status"] == "APPLIED"


@pytest.mark.parametrize("result", ["CHANGE", "ERROR"])
def test_post_apply_non_no_change_plan_never_publishes(
    tmp_path: Path,
    result: str,
) -> None:
    package = _package(tmp_path, "apply")
    plan = _plan_record()
    store = FakeLedgerStore(plan)
    _set_ledger_status(store, "APPLIED")
    published: list[bool] = []

    with pytest.raises(AuthorizationError, match="observation"):
        run_apply_controller(
            package,
            receipt_digest=_sha("b"),
            plan_record_digest=plan["record_digest"],
            reviewer_packet_digest=_reviewer_packet_digest(plan),
            expected_approver_user_id=55,
            terminal_session=FakeApplyTerminal(package),
            ledger_store=store,
            now=NOW + timedelta(minutes=10),
            health_probe=lambda **_kwargs: _post_apply_observation(result=result),
            contract_publisher=lambda **kwargs: (
                published.append(True) or _exact_publisher(**kwargs)
            ),
        )

    assert published == []
    assert store.health_receipt is None
    assert store.ledger is not None and store.ledger["status"] == "APPLIED"


def test_published_contract_response_loss_resumes_without_reapply(
    tmp_path: Path,
) -> None:
    package = _package(tmp_path, "apply")
    plan = _plan_record()
    store = FakeLedgerStore(plan)
    _set_ledger_status(store, "APPLIED")
    terminal = FakeApplyTerminal(package)
    attempts = 0

    def publisher(**kwargs: Any) -> dict[str, Any]:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise AuthorizationError("simulated lost publication response")
        return _exact_publisher(**kwargs)

    with pytest.raises(AuthorizationError, match="lost publication"):
        run_apply_controller(
            package,
            receipt_digest=_sha("b"),
            plan_record_digest=plan["record_digest"],
            reviewer_packet_digest=_reviewer_packet_digest(plan),
            expected_approver_user_id=55,
            terminal_session=terminal,
            ledger_store=store,
            now=NOW + timedelta(minutes=10),
            health_probe=lambda **_kwargs: _post_apply_observation(),
            contract_publisher=publisher,
        )
    assert store.health_receipt is not None
    assert store.ledger is not None and store.ledger["status"] == "APPLIED"

    result = run_apply_controller(
        package,
        receipt_digest=_sha("b"),
        plan_record_digest=plan["record_digest"],
        reviewer_packet_digest=_reviewer_packet_digest(plan),
        expected_approver_user_id=55,
        terminal_session=terminal,
        ledger_store=store,
        now=NOW + timedelta(minutes=11),
        health_probe=lambda **_kwargs: _post_apply_observation(),
        contract_publisher=publisher,
    )

    assert result["status"] == "HEALTHY"
    assert attempts == 2
    assert terminal.calls == []


def test_health_receipt_and_healthy_cas_lost_responses_are_reconciled(
    tmp_path: Path,
) -> None:
    package = _package(tmp_path, "apply")
    plan = _plan_record()
    store = FakeLedgerStore(
        plan,
        lose_after_commit={"HEALTH_RECEIPT", "HEALTHY"},
    )
    _set_ledger_status(store, "APPLIED")

    result = run_apply_controller(
        package,
        receipt_digest=_sha("b"),
        plan_record_digest=plan["record_digest"],
        reviewer_packet_digest=_reviewer_packet_digest(plan),
        expected_approver_user_id=55,
        terminal_session=FakeApplyTerminal(package),
        ledger_store=store,
        now=NOW + timedelta(minutes=10),
        health_probe=lambda **_kwargs: _post_apply_observation(),
        contract_publisher=_exact_publisher,
    )

    assert result["status"] == "HEALTHY"
    assert store.calls.count("replace-HEALTHY") == 1


def test_contract_digest_mismatch_keeps_applied_after_health_evidence(
    tmp_path: Path,
) -> None:
    package = _package(tmp_path, "apply")
    plan = _plan_record()
    store = FakeLedgerStore(plan)
    _set_ledger_status(store, "APPLIED")

    def mismatched_publisher(**kwargs: Any) -> dict[str, Any]:
        publication = _exact_publisher(**kwargs)
        publication["readback_contract_digest"] = _sha("1")
        publication["publication_receipt_digest"] = canonical_digest(
            {
                key: value
                for key, value in publication.items()
                if key != "publication_receipt_digest"
            }
        )
        return publication

    with pytest.raises(AuthorizationError, match="readback is not exact"):
        run_apply_controller(
            package,
            receipt_digest=_sha("b"),
            plan_record_digest=plan["record_digest"],
            reviewer_packet_digest=_reviewer_packet_digest(plan),
            expected_approver_user_id=55,
            terminal_session=FakeApplyTerminal(package),
            ledger_store=store,
            now=NOW + timedelta(minutes=10),
            health_probe=lambda **_kwargs: _post_apply_observation(),
            contract_publisher=mismatched_publisher,
        )

    assert store.health_receipt is not None
    assert store.ledger is not None and store.ledger["status"] == "APPLIED"


def test_uncertain_reconciliation_is_read_only_and_requires_separate_health_run(
    tmp_path: Path,
) -> None:
    package = _package(tmp_path, "apply")
    plan = _plan_record()
    store = FakeLedgerStore(plan)
    _set_ledger_status(store, "UNCERTAIN")
    terminal = FakeApplyTerminal(package)
    published: list[bool] = []

    result = run_apply_controller(
        package,
        receipt_digest=_sha("b"),
        plan_record_digest=plan["record_digest"],
        reviewer_packet_digest=_reviewer_packet_digest(plan),
        expected_approver_user_id=55,
        terminal_session=terminal,
        ledger_store=store,
        now=NOW + timedelta(minutes=10),
        health_probe=lambda **_kwargs: _post_apply_observation(),
        contract_publisher=lambda **kwargs: (
            published.append(True) or _exact_publisher(**kwargs)
        ),
        reconciliation_probe=lambda **_kwargs: _reconciliation_observation(),
    )

    assert result["status"] == "RECONCILED_APPLIED"
    assert published == []
    assert terminal.calls == []
    assert "put-approval" not in store.calls
    assert "replace-APPLYING" not in store.calls


def test_reconciliation_receipt_and_cas_lost_responses_are_reconciled(
    tmp_path: Path,
) -> None:
    package = _package(tmp_path, "apply")
    plan = _plan_record()
    store = FakeLedgerStore(
        plan,
        lose_after_commit={
            "RECONCILIATION_RECEIPT",
            "RECONCILED_APPLIED",
        },
    )
    _set_ledger_status(store, "UNCERTAIN")

    result = run_apply_controller(
        package,
        receipt_digest=_sha("b"),
        plan_record_digest=plan["record_digest"],
        reviewer_packet_digest=_reviewer_packet_digest(plan),
        expected_approver_user_id=55,
        terminal_session=FakeApplyTerminal(package),
        ledger_store=store,
        now=NOW + timedelta(minutes=10),
        reconciliation_probe=lambda **_kwargs: _reconciliation_observation(),
    )

    assert result["status"] == "RECONCILED_APPLIED"
    assert store.calls.count("replace-RECONCILED_APPLIED") == 1


def test_uncertain_state_change_cannot_be_reconciled(
    tmp_path: Path,
) -> None:
    package = _package(tmp_path, "apply")
    plan = _plan_record()
    store = FakeLedgerStore(plan)
    _set_ledger_status(store, "UNCERTAIN")

    with pytest.raises(AuthorizationError, match="state changed"):
        run_apply_controller(
            package,
            receipt_digest=_sha("b"),
            plan_record_digest=plan["record_digest"],
            reviewer_packet_digest=_reviewer_packet_digest(plan),
            expected_approver_user_id=55,
            terminal_session=FakeApplyTerminal(package),
            ledger_store=store,
            now=NOW + timedelta(minutes=10),
            reconciliation_probe=lambda **_kwargs: _reconciliation_observation(
                state_after=_post_apply_state(serial=9)
            ),
        )

    assert store.reconciliation_receipt is None
    assert store.ledger is not None and store.ledger["status"] == "UNCERTAIN"


def test_uncertain_change_becomes_forward_recovery_without_publish_or_apply(
    tmp_path: Path,
) -> None:
    package = _package(tmp_path, "apply")
    plan = _plan_record()
    store = FakeLedgerStore(plan)
    _set_ledger_status(store, "UNCERTAIN")
    terminal = FakeApplyTerminal(package)
    published: list[bool] = []

    result = run_apply_controller(
        package,
        receipt_digest=_sha("b"),
        plan_record_digest=plan["record_digest"],
        reviewer_packet_digest=_reviewer_packet_digest(plan),
        expected_approver_user_id=55,
        terminal_session=terminal,
        ledger_store=store,
        now=NOW + timedelta(minutes=10),
        contract_publisher=lambda **kwargs: (
            published.append(True) or _exact_publisher(**kwargs)
        ),
        reconciliation_probe=lambda **_kwargs: _reconciliation_observation(
            result="CHANGE"
        ),
    )

    assert result["status"] == "RECONCILIATION_REQUIRED"
    assert result["reconciliation_required"] is True
    assert published == []
    assert terminal.calls == []
    assert store.ledger is not None
    assert store.ledger["status"] == "RECONCILIATION_REQUIRED"


def test_healthy_reentry_is_durable_readback_only(
    tmp_path: Path,
) -> None:
    package = _package(tmp_path, "apply")
    plan = _plan_record()
    store = FakeLedgerStore(plan)
    _set_ledger_status(store, "APPLIED")
    terminal = FakeApplyTerminal(package)
    first = run_apply_controller(
        package,
        receipt_digest=_sha("b"),
        plan_record_digest=plan["record_digest"],
        reviewer_packet_digest=_reviewer_packet_digest(plan),
        expected_approver_user_id=55,
        terminal_session=terminal,
        ledger_store=store,
        now=NOW + timedelta(minutes=10),
        health_probe=lambda **_kwargs: _post_apply_observation(),
        contract_publisher=_exact_publisher,
    )
    calls_after_first = list(store.calls)

    second = run_apply_controller(
        package,
        receipt_digest=_sha("b"),
        plan_record_digest=plan["record_digest"],
        reviewer_packet_digest=_reviewer_packet_digest(plan),
        expected_approver_user_id=55,
        terminal_session=terminal,
        ledger_store=store,
        now=NOW + timedelta(minutes=11),
    )

    assert first["status"] == second["status"] == "HEALTHY"
    assert terminal.calls == []
    assert "put-health" not in store.calls[len(calls_after_first):]
    assert "replace-HEALTHY" not in store.calls[len(calls_after_first):]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("cost_model_digest", _sha("4")),
        ("maximum_cost_usd_micros", 9_000_000),
        ("modeled_cost_upper_bound_usd_micros", 1),
    ],
)
def test_apply_rejects_cost_model_switch_or_understatement(
    tmp_path: Path, field: str, value: Any
) -> None:
    package = _package(tmp_path, "apply")
    changed_receipt = {**package.receipt, field: value}
    receipt_path = package.materialized_root / "receipt.json"
    receipt_path.unlink()
    write_private_json_once(receipt_path, changed_receipt)
    package = replace(package, receipt=changed_receipt)
    plan = _plan_record()
    store = FakeLedgerStore(plan)
    terminal = FakeApplyTerminal(package)

    with pytest.raises(AuthorizationError, match="cost binding mismatch"):
        run_apply_controller(
            package,
            receipt_digest=_sha("b"),
           plan_record_digest=plan["record_digest"],
            reviewer_packet_digest=_reviewer_packet_digest(plan),
           expected_approver_user_id=55,
            terminal_session=terminal,
            ledger_store=store,
            now=NOW + timedelta(minutes=10),
        )

    assert terminal.calls == []
    assert store.calls == ["verify-separation", "verify-orchestrator", "get-plan"]


def test_apply_rejects_approval_not_bound_to_protected_expected_reviewer(
    tmp_path: Path,
) -> None:
    package = _package(tmp_path, "apply")
    _approval(package)
    plan = _plan_record()
    store = FakeLedgerStore(plan)
    terminal = FakeApplyTerminal(package)

    with pytest.raises(AuthorizationError, match="reviewer selector is not sealed"):
        run_apply_controller(
            package,
            receipt_digest=_sha("b"),
           plan_record_digest=plan["record_digest"],
            reviewer_packet_digest=_reviewer_packet_digest(plan),
           expected_approver_user_id=56,
            terminal_session=terminal,
            ledger_store=store,
            now=NOW + timedelta(minutes=10),
        )

    assert terminal.calls == []


def test_private_json_rejects_duplicate_keys_and_symlink_substitution(
    tmp_path: Path,
) -> None:
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    duplicate = root / "duplicate.json"
    duplicate.write_text('{"value":1,"value":2}\n', encoding="utf-8")
    duplicate.chmod(0o600)

    with pytest.raises(AuthorizationError, match="duplicate JSON keys"):
        _private_json(duplicate)

    target = root / "target.json"
    target.write_text('{"value":1}\n', encoding="utf-8")
    target.chmod(0o600)
    link = root / "link.json"
    link.symlink_to(target)
    with pytest.raises(AuthorizationError, match="custody is invalid"):
        _private_json(link)


def test_private_create_only_write_preserves_preexisting_bytes(tmp_path: Path) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    destination = private / "record.json"
    destination.write_text('{"original":true}\n', encoding="utf-8")
    destination.chmod(0o600)
    original = destination.read_bytes()

    with pytest.raises(AuthorizationError, match="output write failed"):
        write_private_json_once(destination, {"substitute": True})

    assert destination.read_bytes() == original
    assert _private_json(destination) == {"original": True}


def test_source_mutation_blocks_terminal_plan_before_aws_or_terraform(
    tmp_path: Path,
) -> None:
    package = _package(tmp_path, "plan")
    source = package.materialized_root / "sources/target-anchor.json"
    source.write_text('{"tampered":true}\n', encoding="utf-8")
    source.chmod(0o600)
    calls: list[str] = []

    def command_runner(_command: Any) -> str:
        calls.append("aws")
        raise AssertionError("AWS must not be reached")

    def process_runner(_command: Any) -> int:
        calls.append("terraform")
        raise AssertionError("Terraform must not be reached")

    with pytest.raises(AuthorizationError, match="source digest mismatch"):
        run_terminal_plan(
            package,
            now=NOW,
            command_runner=command_runner,
            process_runner=process_runner,
        )

    assert calls == []


def test_source_replacement_blocks_terminal_fetch_before_aws(
    tmp_path: Path,
) -> None:
    package = _package(tmp_path, "apply")
    source = package.materialized_root / "sources/target-record.json"
    replacement = package.private_root / "replacement.json"
    replacement.write_text('{"source_key":"target_record"}\n', encoding="utf-8")
    replacement.chmod(0o600)
    source.unlink()
    source.symlink_to(replacement)
    calls: list[str] = []

    def command_runner(_command: Any) -> str:
        calls.append("aws")
        raise AssertionError("AWS must not be reached")

    with pytest.raises(AuthorizationError, match="source custody is invalid"):
        run_terminal_fetch(package, command_runner=command_runner)

    assert calls == []


def test_source_mutation_blocks_terminal_apply_before_aws_or_terraform(
    tmp_path: Path,
) -> None:
    package = _package(tmp_path, "apply")
    source = package.materialized_root / "sources/execution-lock.json"
    source.write_text('{"tampered":true}\n', encoding="utf-8")
    source.chmod(0o600)
    calls: list[str] = []

    def command_runner(_command: Any) -> str:
        calls.append("aws")
        raise AssertionError("AWS must not be reached")

    def process_runner(_command: Any) -> int:
        calls.append("terraform")
        raise AssertionError("Terraform must not be reached")

    with pytest.raises(AuthorizationError, match="source digest mismatch"):
        run_terminal_apply(
            package,
            now=NOW,
            command_runner=command_runner,
            process_runner=process_runner,
        )

    assert calls == []


@pytest.mark.parametrize(
    "actions",
    [
        (("delete",),),
        (("delete", "create"),),
        (("create", "delete"),),
        (("forget",),),
    ],
)
def test_structural_plan_inspection_fails_closed_and_deletes_raw_json(
    tmp_path: Path, actions: tuple[tuple[str, ...], ...]
) -> None:
    root = _private_root(tmp_path)
    plan_path = root / "materialized/plan/network.tfplan"
    plan_path.write_bytes(b"exact-plan")
    plan_path.chmod(0o600)
    scratch = root / "materialized/controller/.terraform-plan-inspection.json"

    def show_runner(_command: Any, output_descriptor: int) -> int:
        os.write(
            output_descriptor,
            json.dumps(_plan_show_document(*actions)).encode("utf-8"),
        )
        return 0

    with pytest.raises(AuthorizationError, match="destructive|unknown"):
        inspect_terraform_saved_plan(
            plan_path=plan_path,
            scratch_path=scratch,
            runner=show_runner,
        )

    assert not scratch.exists()


def test_structural_plan_inspection_rejects_malformed_output_without_retention(
    tmp_path: Path,
) -> None:
    root = _private_root(tmp_path)
    plan_path = root / "materialized/plan/network.tfplan"
    plan_path.write_bytes(b"exact-plan")
    plan_path.chmod(0o600)
    scratch = root / "materialized/controller/.terraform-plan-inspection.json"

    def malformed(_command: Any, output_descriptor: int) -> int:
        os.write(output_descriptor, b"{malformed")
        return 0

    with pytest.raises(AuthorizationError, match="JSON is invalid"):
        inspect_terraform_saved_plan(
            plan_path=plan_path,
            scratch_path=scratch,
            runner=malformed,
        )

    assert not scratch.exists()


def test_exact_state_read_uses_one_immutable_version_and_deletes_payload(tmp_path: Path) -> None:
    controller = tmp_path / "controller"
    controller.mkdir(mode=0o700)
    commands: list[list[str]] = []

    state_payload = json.dumps(
        {"lineage": "synthetic-lineage-0001", "serial": 7}
    ).encode("utf-8")

    def runner(command: Any) -> str:
        values = list(command)
        commands.append(values)
        if "head-object" in values:
            return json.dumps({"VersionId": "state-version-7"})
        destination = Path(values[-1])
        destination.write_bytes(state_payload)
        destination.chmod(0o600)
        return json.dumps({"VersionId": "state-version-7"})

    scratch = controller / ".state.json"
    state = read_exact_state(
        backend_binding={
            "account_id": DESTINATION_ACCOUNT,
            "backend": {
                "bucket": f"scanalyze-{DESTINATION_ACCOUNT}-tf-state",
                "key": f"{DEPLOYMENT_ID}/us-east-1/network/terraform.tfstate",
                "region": "us-east-1",
                "encrypt": True,
                "use_lockfile": True,
                "allowed_account_ids": [DESTINATION_ACCOUNT],
            },
        },
        account_id=DESTINATION_ACCOUNT,
        region="us-east-1",
        scratch_path=scratch,
        runner=runner,
    )

    assert state == {
        "status": "PRESENT",
        "lineage": "synthetic-lineage-0001",
        "serial": 7,
        "object_version_id": "state-version-7",
        "sha256": "sha256:" + hashlib.sha256(state_payload).hexdigest(),
        "size_bytes": len(state_payload),
    }
    assert not scratch.exists()
    assert commands[1][commands[1].index("--version-id") + 1] == "state-version-7"


def test_state_access_denied_is_never_reinterpreted_as_absence(tmp_path: Path) -> None:
    controller = tmp_path / "controller"
    controller.mkdir(mode=0o700)

    def denied(_command: Any) -> str:
        raise AuthorizationError("access denied")

    with pytest.raises(AuthorizationError, match="access denied"):
        read_exact_state(
            backend_binding={
                "account_id": DESTINATION_ACCOUNT,
                "backend": {
                    "bucket": f"scanalyze-{DESTINATION_ACCOUNT}-tf-state",
                    "key": f"{DEPLOYMENT_ID}/network/terraform.tfstate",
                    "region": "us-east-1",
                    "encrypt": True,
                    "use_lockfile": True,
                    "allowed_account_ids": [DESTINATION_ACCOUNT],
                },
            },
            account_id=DESTINATION_ACCOUNT,
            region="us-east-1",
            scratch_path=controller / ".state.json",
            runner=denied,
        )


@pytest.mark.parametrize("error_code", ["404", "NoSuchKey", "NotFound"])
def test_exact_state_read_accepts_only_unambiguous_absence(
    tmp_path: Path, error_code: str
) -> None:
    controller = tmp_path / "controller"
    controller.mkdir(mode=0o700)
    calls = 0

    def missing(command: Any) -> str:
        nonlocal calls
        calls += 1
        if "head-object" in command:
            raise AwsCliReadError(error_code)
        return json.dumps(
            {"IsTruncated": False, "Versions": [], "DeleteMarkers": []}
        )

    scratch = controller / ".state.json"
    state = read_exact_state(
        backend_binding={
            "account_id": DESTINATION_ACCOUNT,
            "backend": {
                "bucket": f"scanalyze-{DESTINATION_ACCOUNT}-tf-state",
                "key": f"{DEPLOYMENT_ID}/network/terraform.tfstate",
                "region": "us-east-1",
                "encrypt": True,
                "use_lockfile": True,
                "allowed_account_ids": [DESTINATION_ACCOUNT],
            },
        },
        account_id=DESTINATION_ACCOUNT,
        region="us-east-1",
        scratch_path=scratch,
        runner=missing,
    )

    assert state == {
        "status": "ABSENT",
        "lineage": None,
        "serial": None,
        "object_version_id": None,
        "sha256": None,
        "size_bytes": None,
    }
    assert calls == 2
    assert not scratch.exists()


def test_exact_state_read_rejects_delete_marker_as_greenfield_absence(
    tmp_path: Path,
) -> None:
    controller = tmp_path / "controller"
    controller.mkdir(mode=0o700)
    key = f"{DEPLOYMENT_ID}/network/terraform.tfstate"

    def deleted(command: Any) -> str:
        if "head-object" in command:
            raise AwsCliReadError("404")
        return json.dumps(
            {
                "IsTruncated": False,
                "Versions": [],
                "DeleteMarkers": [
                    {"Key": key, "VersionId": "delete-marker-1", "IsLatest": True}
                ],
            }
        )

    with pytest.raises(AuthorizationError, match="absence is ambiguous"):
        read_exact_state(
            backend_binding={
                "account_id": DESTINATION_ACCOUNT,
                "backend": {
                    "bucket": f"scanalyze-{DESTINATION_ACCOUNT}-tf-state",
                    "key": key,
                    "region": "us-east-1",
                    "encrypt": True,
                    "use_lockfile": True,
                    "allowed_account_ids": [DESTINATION_ACCOUNT],
                },
            },
            account_id=DESTINATION_ACCOUNT,
            region="us-east-1",
            scratch_path=controller / ".state.json",
            runner=deleted,
        )


@pytest.mark.parametrize("error_code", ["403", "AccessDenied", "Unknown"])
def test_exact_state_read_never_maps_denial_or_unknown_failure_to_absence(
    tmp_path: Path, error_code: str
) -> None:
    controller = tmp_path / "controller"
    controller.mkdir(mode=0o700)

    def failed(_command: Any) -> str:
        raise AwsCliReadError(error_code)

    with pytest.raises(AuthorizationError, match="metadata read failed"):
        read_exact_state(
            backend_binding={
                "account_id": DESTINATION_ACCOUNT,
                "backend": {
                    "bucket": f"scanalyze-{DESTINATION_ACCOUNT}-tf-state",
                    "key": f"{DEPLOYMENT_ID}/network/terraform.tfstate",
                    "region": "us-east-1",
                    "encrypt": True,
                    "use_lockfile": True,
                    "allowed_account_ids": [DESTINATION_ACCOUNT],
                },
            },
            account_id=DESTINATION_ACCOUNT,
            region="us-east-1",
            scratch_path=controller / ".state.json",
            runner=failed,
        )


def test_terminal_plan_reads_state_but_stores_plan_in_separate_plan_bucket(
    tmp_path: Path,
) -> None:
    package = _package(tmp_path, "plan")
    backend_body = {
        "account_id": DESTINATION_ACCOUNT,
        "backend": {
            "bucket": f"scanalyze-{DESTINATION_ACCOUNT}-tf-state",
            "key": f"{DEPLOYMENT_ID}/us-east-1/network/terraform.tfstate",
            "region": "us-east-1",
            "encrypt": True,
            "use_lockfile": True,
            "allowed_account_ids": [DESTINATION_ACCOUNT],
        },
    }
    backend = {**backend_body, "binding_digest": canonical_digest(backend_body)}
    package = replace(package, backend_binding=backend)
    observed_commands: list[list[str]] = []

    def command_runner(command: Any) -> str:
        values = list(command)
        observed_commands.append(values)
        if "get-caller-identity" in values:
            return json.dumps(
                {
                    "Account": DESTINATION_ACCOUNT,
                    "Arn": (
                        f"arn:aws:sts::{DESTINATION_ACCOUNT}:assumed-role/"
                        "ScanalyzeCustomer-Plan/session"
                    ),
                }
            )
        if "head-object" in values:
            return json.dumps({"VersionId": "state-version-7"})
        if "get-object" in values:
            destination = Path(values[-1])
            destination.write_text(
                json.dumps(
                    {"lineage": "synthetic-lineage-0001", "serial": 7}
                ),
                encoding="utf-8",
            )
            destination.chmod(0o600)
            return json.dumps({"VersionId": "state-version-7"})
        assert "put-object" in values
        return json.dumps({"VersionId": "plan-version-1"})

    def process_runner(_command: Any) -> int:
        intent = _private_json(package.controller_root / "plan-intent.json")
        plan_path = Path(intent["expected_plan_path"])
        plan_path.write_bytes(b"terminal-plan")
        plan_path.chmod(0o600)
        return 0

    show_commands: list[list[str]] = []

    def plan_show_runner(command: Any, output_descriptor: int) -> int:
        show_commands.append(list(command))
        os.write(
            output_descriptor,
            json.dumps(_plan_show_document(("create",))).encode("utf-8"),
        )
        return 0

    run_terminal_plan(
        package,
        now=NOW,
        command_runner=command_runner,
        process_runner=process_runner,
        plan_show_runner=plan_show_runner,
        clock=lambda: NOW + timedelta(minutes=2),
    )

    plan_record = json.loads(
        (package.controller_root / "plan-record.json").read_text(encoding="utf-8")
    )
    intent = _private_json(package.controller_root / "plan-intent.json")
    assert plan_record["storage"]["bucket"].endswith("-tf-plan")
    assert plan_record["plan_summary"]["classification"] == "CHANGE"
    assert plan_record["cost_binding"] == _cost_binding()
    assert plan_record["created_at"] == "2026-08-28T18:02:00Z"
    assert show_commands == [
        ["terraform", "show", "-json", str(intent["expected_plan_path"])]
    ]
    assert not (package.controller_root / ".terraform-plan-inspection.json").exists()
    put = next(command for command in observed_commands if "put-object" in command)
    assert put[put.index("--bucket") + 1].endswith("-tf-plan")
    assert "evidence-key-0001" in put[put.index("--ssekms-key-id") + 1]
    assert all(
        command[command.index("--bucket") + 1].endswith("-tf-state")
        for command in observed_commands
        if "head-object" in command or "get-object" in command
    )
