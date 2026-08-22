#!/usr/bin/env python3
"""Protected CLI for exact saved plans, conditional ledger, and health receipts.

This CLI is designed for GitHub Actions terminal-role jobs. It has no profile
option, emits only sanitized status lines, and writes operational JSON only to
exclusive mode-0600 paths outside the repository.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tooling.authorize_deployment_backend import (  # noqa: E402
    AuthorizationError,
    load_json_strict,
    write_private_file,
)
from tooling.nonprod_live_engine import (  # noqa: E402
    authorize_saved_plan_apply,
    build_health_receipt,
    build_initial_ledger,
    build_reconciliation_receipt,
    build_saved_plan_approval,
    build_saved_plan_record,
    prepare_ledger_transition,
    require_downstream_health,
    require_terminal_role_for_layer,
    validate_dry_run_boundary,
)
from tooling.nonprod_live_store import (  # noqa: E402
    AwsCliExecutionLedgerStore,
    AwsCliPlanStore,
    AwsCliTerminalSession,
)
from tooling.nonprod_live_orchestrator import (  # noqa: E402
    build_apply_intent,
    build_live_context,
    build_plan_intent,
    classify_apply_observation,
    validate_apply_intent,
    validate_plan_intent,
)


SAVED_PLAN_RUNNER = REPO_ROOT / "scripts/deployment/terraform-saved-plan.sh"


def _time(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AuthorizationError(f"{label} is not a valid timestamp") from exc
    if parsed.tzinfo is None:
        raise AuthorizationError(f"{label} must be timezone-aware")
    return parsed.astimezone(UTC)


def _outside_repo(path: Path) -> Path:
    destination = path.expanduser().resolve(strict=False)
    try:
        destination.relative_to(REPO_ROOT.resolve())
    except ValueError:
        pass
    else:
        raise AuthorizationError("operational output must be outside the repository")
    if destination.exists() or destination.is_symlink():
        raise AuthorizationError("operational output must be exclusive")
    if not destination.parent.is_dir():
        raise AuthorizationError("operational output directory does not exist")
    return destination


def _write_json(path: Path, document: dict[str, Any]) -> None:
    destination = _outside_repo(path)
    write_private_file(destination, json.dumps(document, sort_keys=True, indent=2) + "\n")


def _plan_store(args: argparse.Namespace) -> AwsCliPlanStore:
    return AwsCliPlanStore(
        region=args.region,
        account_id=args.account_id,
    )


def _ledger_store(args: argparse.Namespace) -> AwsCliExecutionLedgerStore:
    return AwsCliExecutionLedgerStore(
        region=args.region,
        shared_services_account_id=args.shared_services_account_id,
        ledger_table="scanalyze-deployment-executions",
    )


def _optional_json(path: Path | None) -> dict[str, Any] | None:
    return load_json_strict(path) if path is not None else None


def _cmd_dry_run(args: argparse.Namespace) -> None:
    validate_dry_run_boundary(
        dry_run=True,
        allow_live=False,
        environment=os.environ,
    )
    print("PASS: dry-run boundary contains no AWS credential material")


def _cmd_build_live_context(args: argparse.Namespace) -> None:
    context = build_live_context(**load_json_strict(args.context_inputs))
    _write_json(args.context_out, context)
    print("PASS: exact protected live dev context authorized")


def _cmd_build_plan_intent(args: argparse.Namespace) -> None:
    intent = build_plan_intent(
        context=load_json_strict(args.context),
        expected_bindings=load_json_strict(args.bindings),
        plan_inputs=load_json_strict(args.plan_inputs),
        domain_name=args.domain_name,
    )
    _write_json(args.intent_out, intent)
    print("PASS: exact terminal Plan intent constructed")


def _cmd_validate_plan_intent(args: argparse.Namespace) -> None:
    decision = validate_plan_intent(
        intent=load_json_strict(args.plan_intent),
        context=load_json_strict(args.context),
        expected_bindings=load_json_strict(args.bindings),
    )
    _write_json(args.decision_out, decision)
    print("PASS: exact terminal Plan intent revalidated")


def _cmd_build_apply_intent(args: argparse.Namespace) -> None:
    intent = build_apply_intent(
        context=load_json_strict(args.context),
        plan_record=load_json_strict(args.plan_record),
        ledger=load_json_strict(args.approved_ledger),
        approval_record=load_json_strict(args.approval_record),
        expected_bindings=load_json_strict(args.bindings),
        plan_readback=load_json_strict(args.plan_readback),
        state_readback=load_json_strict(args.state_readback),
        plan_binary_path=str(args.plan),
        apply_inputs=load_json_strict(args.apply_inputs),
        now=_time(args.now, "now"),
    )
    _write_json(args.intent_out, intent)
    print("PASS: exact saved-plan Apply intent constructed")


def _cmd_validate_apply_intent(args: argparse.Namespace) -> None:
    decision = validate_apply_intent(
        intent=load_json_strict(args.apply_intent),
        context=load_json_strict(args.context),
        plan_record=load_json_strict(args.plan_record),
        approval_record=load_json_strict(args.approval_record),
        approved_ledger=load_json_strict(args.approved_ledger),
        applying_ledger=load_json_strict(args.applying_ledger),
        plan_readback=load_json_strict(args.plan_readback),
        state_readback=load_json_strict(args.state_readback),
        now=_time(args.now, "now"),
    )
    _write_json(args.decision_out, decision)
    print("PASS: exact saved-plan Apply intent revalidated after CAS")


def _cmd_classify_apply_observation(args: argparse.Namespace) -> None:
    outcome = classify_apply_observation(
        applying_ledger=load_json_strict(args.applying_ledger),
        observation=args.observation,
        at=_time(args.at, "at"),
    )
    _write_json(args.outcome_out, outcome)
    print(f"PASS: Apply outcome classified as {outcome['next_status']}")


def _cmd_run_terminal_apply(args: argparse.Namespace) -> None:
    context = load_json_strict(args.context)
    intent = load_json_strict(args.apply_intent)
    validate_apply_intent(
        intent=intent,
        context=context,
        plan_record=load_json_strict(args.plan_record),
        approval_record=load_json_strict(args.approval_record),
        approved_ledger=load_json_strict(args.approved_ledger),
        applying_ledger=load_json_strict(args.applying_ledger),
        plan_readback=load_json_strict(args.plan_readback),
        state_readback=load_json_strict(args.state_readback),
        now=_time(args.now, "now"),
    )
    command_spec = intent["command"]
    if command_spec["program"] != SAVED_PLAN_RUNNER.relative_to(REPO_ROOT).as_posix():
        raise AuthorizationError("terminal Apply program is not canonical")
    command = ("/bin/bash", str(SAVED_PLAN_RUNNER), *command_spec["argv"])
    AwsCliTerminalSession(
        region=context["region"],
        account_id=context["destination_account_id"],
    ).run_terminal_phase(
        orchestrator_role_arn=context["orchestrator_role_arn"],
        role_arn=context["apply_role_arn"],
        customer_id=context["customer_id"],
        deployment_id=context["deployment_id"],
        execution_id=context["execution_id"],
        change_id=context["change_id"],
        environment=context["environment"],
        operation="apply",
        layer=context["layer"],
        command=command,
        base_environment=os.environ,
    )
    print("PASS: exact saved-plan Apply phase completed once")


def _cmd_verify_identity(args: argparse.Namespace) -> None:
    _plan_store(args).verify_terminal_identity(args.expected_role)
    print("PASS: exact terminal role and account binding verified")


def _cmd_run_terminal_plan(args: argparse.Namespace) -> None:
    context = load_json_strict(args.context)
    intent = load_json_strict(args.plan_intent)
    bindings = load_json_strict(args.bindings)
    validate_plan_intent(
        intent=intent,
        context=context,
        expected_bindings=bindings,
    )
    command_spec = intent["command"]
    if command_spec["program"] != SAVED_PLAN_RUNNER.relative_to(REPO_ROOT).as_posix():
        raise AuthorizationError("terminal plan program is not canonical")
    command = ("/bin/bash", str(SAVED_PLAN_RUNNER), *command_spec["argv"])
    AwsCliTerminalSession(
        region=context["region"],
        account_id=context["destination_account_id"],
    ).run_terminal_phase(
        orchestrator_role_arn=context["orchestrator_role_arn"],
        role_arn=context["plan_role_arn"],
        customer_id=context["customer_id"],
        deployment_id=context["deployment_id"],
        execution_id=context["execution_id"],
        change_id=context["change_id"],
        environment=context["environment"],
        operation="plan",
        layer=context["layer"],
        command=command,
        base_environment=os.environ,
    )
    print("PASS: exact terminal Plan phase completed")


def _cmd_store_plan(args: argparse.Namespace) -> None:
    bindings = load_json_strict(args.bindings)
    created_at = _time(args.created_at, "created_at")
    expires_at = _time(args.expires_at, "expires_at")
    placeholder = build_saved_plan_record(
        bindings=bindings,
        plan_sha256="sha256:" + ("0" * 64),
        plan_size_bytes=1,
        bucket=args.bucket,
        object_key=args.object_key,
        object_version_id="pending-write",
        created_at=created_at,
        expires_at=expires_at,
    )
    del placeholder

    require_terminal_role_for_layer(
        layer=bindings["layer"],
        role=args.expected_role,
        operation="plan",
    )
    store = _plan_store(args)
    store.verify_terminal_identity(args.expected_role)
    readback = store.put_plan_once(
        path=args.plan,
        bucket=args.bucket,
        object_key=args.object_key,
        kms_key_arn=args.kms_key_arn,
    )
    plan_record = build_saved_plan_record(
        bindings=bindings,
        plan_sha256=readback["sha256"],
        plan_size_bytes=readback["size_bytes"],
        bucket=readback["bucket"],
        object_key=readback["object_key"],
        object_version_id=readback["object_version_id"],
        created_at=created_at,
        expires_at=expires_at,
    )
    _write_json(args.plan_record_out, plan_record)
    print("PASS: encrypted versioned plan stored by exact Plan terminal role")


def _cmd_create_ledger(args: argparse.Namespace) -> None:
    plan_record = load_json_strict(args.plan_record)
    ledger = build_initial_ledger(
        plan_record=plan_record,
        at=_time(args.at, "at"),
    )
    store = _ledger_store(args)
    store.verify_destination_separation(plan_record["account_id"])
    store.verify_orchestrator_identity(
        args.orchestrator_role_arn,
        deployment_id=plan_record["deployment_id"],
    )
    durable_plan = store.get_plan_record(
        deployment_id=plan_record["deployment_id"],
        execution_id=plan_record["execution_id"],
        layer=plan_record["layer"],
    )
    if durable_plan != plan_record:
        raise AuthorizationError("durable saved plan record mismatch")
    store.create_ledger(ledger)
    _write_json(args.ledger_out, ledger)
    print("PASS: create-only execution ledger stored by shared-services orchestrator")


def _cmd_persist_plan_record(args: argparse.Namespace) -> None:
    plan_record = load_json_strict(args.plan_record)
    store = _ledger_store(args)
    store.verify_destination_separation(plan_record["account_id"])
    store.verify_orchestrator_identity(
        args.orchestrator_role_arn,
        deployment_id=plan_record["deployment_id"],
    )
    store.put_plan_record_once(plan_record)
    print("PASS: create-only saved-plan control record persisted")


def _cmd_get_plan_record(args: argparse.Namespace) -> None:
    store = _ledger_store(args)
    store.verify_destination_separation(args.account_id)
    store.verify_orchestrator_identity(
        args.orchestrator_role_arn,
        deployment_id=args.deployment_id,
    )
    plan_record = store.get_plan_record(
        deployment_id=args.deployment_id,
        execution_id=args.execution_id,
        layer=args.layer,
    )
    if plan_record["account_id"] != args.account_id:
        raise AuthorizationError("saved plan destination binding mismatch")
    _write_json(args.plan_record_out, plan_record)
    print("PASS: exact saved-plan control record read back")


def _cmd_build_approval(args: argparse.Namespace) -> None:
    approval = build_saved_plan_approval(
        plan_record=load_json_strict(args.plan_record),
        repository_owner_id=args.repository_owner_id,
        repository_id=args.repository_id,
        workflow_ref=args.workflow_ref,
        workflow_sha=args.workflow_sha,
        workflow_run_id=args.workflow_run_id,
        github_environment=args.github_environment,
        environment_configuration_digest=args.environment_configuration_digest,
        initiator_user_id=args.initiator_user_id,
        approver_user_id=args.approver_user_id,
        approved_at=_time(args.approved_at, "approved_at"),
        expires_at=_time(args.expires_at, "expires_at"),
    )
    _write_json(args.approval_out, approval)
    print("PASS: exact independent saved-plan approval constructed")


def _cmd_persist_approval(args: argparse.Namespace) -> None:
    approval = load_json_strict(args.approval_record)
    store = _ledger_store(args)
    store.verify_destination_separation(approval["account_id"])
    store.verify_orchestrator_identity(
        args.orchestrator_role_arn,
        deployment_id=approval["deployment_id"],
    )
    store.put_approval_record_once(
        approval,
        now=_time(args.now, "now"),
    )
    print("PASS: create-only saved-plan approval persisted")


def _cmd_get_approval(args: argparse.Namespace) -> None:
    store = _ledger_store(args)
    store.verify_destination_separation(args.account_id)
    store.verify_orchestrator_identity(
        args.orchestrator_role_arn,
        deployment_id=args.deployment_id,
    )
    approval = store.get_approval_record(
        deployment_id=args.deployment_id,
        execution_id=args.execution_id,
        layer=args.layer,
        now=_time(args.now, "now"),
    )
    if approval["account_id"] != args.account_id:
        raise AuthorizationError("saved plan approval destination binding mismatch")
    _write_json(args.approval_out, approval)
    print("PASS: exact saved-plan approval read back")


def _cmd_fetch_plan(args: argparse.Namespace) -> None:
    plan_record = load_json_strict(args.plan_record)
    storage = plan_record["storage"]
    destination = _outside_repo(args.plan_out)
    require_terminal_role_for_layer(
        layer=plan_record["layer"],
        role=args.expected_role,
        operation="apply",
    )
    store = _plan_store(args)
    store.verify_terminal_identity(args.expected_role)
    readback = store.get_plan_version(
        bucket=storage["bucket"],
        object_key=storage["object_key"],
        object_version_id=storage["object_version_id"],
        destination=destination,
    )
    _write_json(args.readback_out, readback)
    print("PASS: exact saved-plan version read back")


def _cmd_authorize_apply(args: argparse.Namespace) -> None:
    decision = authorize_saved_plan_apply(
        plan_record=load_json_strict(args.plan_record),
        ledger=load_json_strict(args.ledger),
        approval_record=load_json_strict(args.approval_record),
        expected_bindings=load_json_strict(args.bindings),
        plan_readback=load_json_strict(args.plan_readback),
        state_readback=load_json_strict(args.state_readback),
        now=_time(args.now, "now"),
    )
    _write_json(args.decision_out, decision)
    print("PASS: exact fresh unused saved plan authorized")


def _cmd_transition(args: argparse.Namespace) -> None:
    store = _ledger_store(args)
    store.verify_orchestrator_identity(
        args.orchestrator_role_arn,
        deployment_id=args.deployment_id,
    )
    current = store.get_ledger(
        deployment_id=args.deployment_id,
        execution_id=args.execution_id,
        layer=args.layer,
    )
    store.verify_destination_separation(current["account_id"])
    at = _time(args.at, "at")
    approval_record = _optional_json(args.approval_record)
    health_receipt = _optional_json(args.health_receipt)
    reconciliation_receipt = _optional_json(args.reconciliation_receipt)
    if args.next_status == "APPROVED":
        if approval_record is None:
            raise AuthorizationError("saved plan approval evidence is required")
        durable_approval = store.get_approval_record(
            deployment_id=args.deployment_id,
            execution_id=args.execution_id,
            layer=args.layer,
            now=at,
        )
        if durable_approval != approval_record:
            raise AuthorizationError("durable saved plan approval mismatch")
    if args.next_status == "HEALTHY":
        if health_receipt is None:
            raise AuthorizationError("health receipt is required")
        durable_health = store.get_health_receipt(
            deployment_id=args.deployment_id,
            execution_id=args.execution_id,
            layer=args.layer,
        )
        if durable_health != health_receipt:
            raise AuthorizationError("durable health receipt mismatch")
    if args.next_status in {"RECONCILED_APPLIED", "RECONCILIATION_REQUIRED"}:
        if reconciliation_receipt is None:
            raise AuthorizationError("reconciliation receipt is required")
        durable_reconciliation = store.get_reconciliation_receipt(
            deployment_id=args.deployment_id,
            execution_id=args.execution_id,
            layer=args.layer,
        )
        if durable_reconciliation != reconciliation_receipt:
            raise AuthorizationError("durable reconciliation receipt mismatch")
    proposed, _ = prepare_ledger_transition(
        current=current,
        next_status=args.next_status,
        expected_version=args.expected_version,
        expected_digest=args.expected_digest,
        at=at,
        outcome_code=args.outcome_code,
        approval_record=approval_record,
        health_receipt=health_receipt,
        reconciliation_receipt=reconciliation_receipt,
    )
    store.replace_ledger(
        ledger=proposed,
        expected_deployment_id=args.deployment_id,
        expected_execution_id=args.execution_id,
        expected_layer=args.layer,
        expected_version=args.expected_version,
        expected_digest=args.expected_digest,
        expected_status=current["status"],
    )
    _write_json(args.ledger_out, proposed)
    print("PASS: execution ledger compare-and-swap transition committed")


def _cmd_health(args: argparse.Namespace) -> None:
    checks = load_json_strict(args.checks)
    values = checks.get("checks")
    if not isinstance(values, list):
        raise AuthorizationError("health check input is invalid")
    receipt = build_health_receipt(
        plan_record=load_json_strict(args.plan_record),
        ledger=load_json_strict(args.ledger),
        state_readback=load_json_strict(args.state_readback),
        checked_at=_time(args.checked_at, "checked_at"),
        checks=values,
    )
    _write_json(args.receipt_out, receipt)
    print(f"PASS: health receipt created with status {receipt['status']}")


def _cmd_reconcile(args: argparse.Namespace) -> None:
    receipt = build_reconciliation_receipt(
        plan_record=load_json_strict(args.plan_record),
        ledger=load_json_strict(args.ledger),
        observed_state=load_json_strict(args.state_readback),
        speculative_plan_result=args.speculative_plan_result,
        contract_verified=args.contract_verified,
        checked_at=_time(args.checked_at, "checked_at"),
    )
    _write_json(args.receipt_out, receipt)
    print(f"PASS: uncertain outcome classified as {receipt['decision']}")


def _cmd_persist_health(args: argparse.Namespace) -> None:
    receipt = load_json_strict(args.health_receipt)
    store = _ledger_store(args)
    store.verify_destination_separation(receipt["account_id"])
    store.verify_orchestrator_identity(
        args.orchestrator_role_arn,
        deployment_id=receipt["deployment_id"],
    )
    store.put_health_receipt_once(receipt)
    print("PASS: create-only health receipt persisted")


def _cmd_get_health(args: argparse.Namespace) -> None:
    store = _ledger_store(args)
    store.verify_destination_separation(args.account_id)
    store.verify_orchestrator_identity(
        args.orchestrator_role_arn,
        deployment_id=args.deployment_id,
    )
    receipt = store.get_health_receipt(
        deployment_id=args.deployment_id,
        execution_id=args.execution_id,
        layer=args.layer,
    )
    if receipt["account_id"] != args.account_id:
        raise AuthorizationError("health receipt destination binding mismatch")
    _write_json(args.health_receipt_out, receipt)
    print("PASS: exact health receipt read back")


def _cmd_persist_reconciliation(args: argparse.Namespace) -> None:
    receipt = load_json_strict(args.reconciliation_receipt)
    store = _ledger_store(args)
    store.verify_destination_separation(receipt["account_id"])
    store.verify_orchestrator_identity(
        args.orchestrator_role_arn,
        deployment_id=receipt["deployment_id"],
    )
    store.put_reconciliation_receipt_once(receipt)
    print("PASS: create-only reconciliation receipt persisted")


def _cmd_get_reconciliation(args: argparse.Namespace) -> None:
    store = _ledger_store(args)
    store.verify_destination_separation(args.account_id)
    store.verify_orchestrator_identity(
        args.orchestrator_role_arn,
        deployment_id=args.deployment_id,
    )
    receipt = store.get_reconciliation_receipt(
        deployment_id=args.deployment_id,
        execution_id=args.execution_id,
        layer=args.layer,
    )
    if receipt["account_id"] != args.account_id:
        raise AuthorizationError("reconciliation receipt destination binding mismatch")
    _write_json(args.reconciliation_receipt_out, receipt)
    print("PASS: exact reconciliation receipt read back")


def _cmd_verify_health(args: argparse.Namespace) -> None:
    require_downstream_health(
        load_json_strict(args.ledger),
        plan_record=load_json_strict(args.plan_record),
        expected_layer=args.expected_layer,
        health_receipt=load_json_strict(args.health_receipt),
    )
    print("PASS: exact healthy predecessor authorized downstream execution")


def _common_destination(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--region", required=True)


def _common_ledger(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--shared-services-account-id", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--orchestrator-role-arn", required=True)


def _common_control_read(parser: argparse.ArgumentParser) -> None:
    _common_ledger(parser)
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--deployment-id", required=True)
    parser.add_argument("--execution-id", required=True)
    parser.add_argument("--layer", required=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    dry_run = commands.add_parser("dry-run-check")
    dry_run.set_defaults(handler=_cmd_dry_run)

    live_context = commands.add_parser("build-live-context")
    live_context.add_argument("--context-inputs", type=Path, required=True)
    live_context.add_argument("--context-out", type=Path, required=True)
    live_context.set_defaults(handler=_cmd_build_live_context)

    plan_intent = commands.add_parser("build-plan-intent")
    plan_intent.add_argument("--context", type=Path, required=True)
    plan_intent.add_argument("--bindings", type=Path, required=True)
    plan_intent.add_argument("--plan-inputs", type=Path, required=True)
    plan_intent.add_argument("--domain-name")
    plan_intent.add_argument("--intent-out", type=Path, required=True)
    plan_intent.set_defaults(handler=_cmd_build_plan_intent)

    check_plan_intent = commands.add_parser("validate-plan-intent")
    check_plan_intent.add_argument("--plan-intent", type=Path, required=True)
    check_plan_intent.add_argument("--context", type=Path, required=True)
    check_plan_intent.add_argument("--bindings", type=Path, required=True)
    check_plan_intent.add_argument("--decision-out", type=Path, required=True)
    check_plan_intent.set_defaults(handler=_cmd_validate_plan_intent)

    apply_intent = commands.add_parser("build-apply-intent")
    apply_intent.add_argument("--context", type=Path, required=True)
    apply_intent.add_argument("--plan-record", type=Path, required=True)
    apply_intent.add_argument("--approved-ledger", type=Path, required=True)
    apply_intent.add_argument("--approval-record", type=Path, required=True)
    apply_intent.add_argument("--bindings", type=Path, required=True)
    apply_intent.add_argument("--plan-readback", type=Path, required=True)
    apply_intent.add_argument("--state-readback", type=Path, required=True)
    apply_intent.add_argument("--plan", type=Path, required=True)
    apply_intent.add_argument("--apply-inputs", type=Path, required=True)
    apply_intent.add_argument("--now", required=True)
    apply_intent.add_argument("--intent-out", type=Path, required=True)
    apply_intent.set_defaults(handler=_cmd_build_apply_intent)

    check_apply_intent = commands.add_parser("validate-apply-intent")
    check_apply_intent.add_argument("--apply-intent", type=Path, required=True)
    check_apply_intent.add_argument("--context", type=Path, required=True)
    check_apply_intent.add_argument("--plan-record", type=Path, required=True)
    check_apply_intent.add_argument("--approval-record", type=Path, required=True)
    check_apply_intent.add_argument("--approved-ledger", type=Path, required=True)
    check_apply_intent.add_argument("--applying-ledger", type=Path, required=True)
    check_apply_intent.add_argument("--plan-readback", type=Path, required=True)
    check_apply_intent.add_argument("--state-readback", type=Path, required=True)
    check_apply_intent.add_argument("--now", required=True)
    check_apply_intent.add_argument("--decision-out", type=Path, required=True)
    check_apply_intent.set_defaults(handler=_cmd_validate_apply_intent)

    classify_apply = commands.add_parser("classify-apply-observation")
    classify_apply.add_argument("--applying-ledger", type=Path, required=True)
    classify_apply.add_argument(
        "--observation",
        choices=("SUCCESS", "FAILURE", "RESPONSE_LOST"),
        required=True,
    )
    classify_apply.add_argument("--at", required=True)
    classify_apply.add_argument("--outcome-out", type=Path, required=True)
    classify_apply.set_defaults(handler=_cmd_classify_apply_observation)

    identity = commands.add_parser("verify-identity")
    _common_destination(identity)
    identity.add_argument("--expected-role", required=True)
    identity.set_defaults(handler=_cmd_verify_identity)

    terminal_plan = commands.add_parser("run-terminal-plan")
    terminal_plan.add_argument("--context", type=Path, required=True)
    terminal_plan.add_argument("--plan-intent", type=Path, required=True)
    terminal_plan.add_argument("--bindings", type=Path, required=True)
    terminal_plan.set_defaults(handler=_cmd_run_terminal_plan)

    terminal_apply = commands.add_parser("run-terminal-apply")
    terminal_apply.add_argument("--context", type=Path, required=True)
    terminal_apply.add_argument("--apply-intent", type=Path, required=True)
    terminal_apply.add_argument("--plan-record", type=Path, required=True)
    terminal_apply.add_argument("--approval-record", type=Path, required=True)
    terminal_apply.add_argument("--approved-ledger", type=Path, required=True)
    terminal_apply.add_argument("--applying-ledger", type=Path, required=True)
    terminal_apply.add_argument("--plan-readback", type=Path, required=True)
    terminal_apply.add_argument("--state-readback", type=Path, required=True)
    terminal_apply.add_argument("--now", required=True)
    terminal_apply.set_defaults(handler=_cmd_run_terminal_apply)

    store_plan = commands.add_parser("store-plan")
    _common_destination(store_plan)
    store_plan.add_argument("--expected-role", required=True)
    store_plan.add_argument("--bindings", type=Path, required=True)
    store_plan.add_argument("--plan", type=Path, required=True)
    store_plan.add_argument("--bucket", required=True)
    store_plan.add_argument("--object-key", required=True)
    store_plan.add_argument("--kms-key-arn", required=True)
    store_plan.add_argument("--created-at", required=True)
    store_plan.add_argument("--expires-at", required=True)
    store_plan.add_argument("--plan-record-out", type=Path, required=True)
    store_plan.set_defaults(handler=_cmd_store_plan)

    create_ledger = commands.add_parser("create-ledger")
    _common_ledger(create_ledger)
    create_ledger.add_argument("--plan-record", type=Path, required=True)
    create_ledger.add_argument("--at", required=True)
    create_ledger.add_argument("--ledger-out", type=Path, required=True)
    create_ledger.set_defaults(handler=_cmd_create_ledger)

    persist_plan = commands.add_parser("persist-plan-record")
    _common_ledger(persist_plan)
    persist_plan.add_argument("--plan-record", type=Path, required=True)
    persist_plan.set_defaults(handler=_cmd_persist_plan_record)

    get_plan = commands.add_parser("get-plan-record")
    _common_control_read(get_plan)
    get_plan.add_argument("--plan-record-out", type=Path, required=True)
    get_plan.set_defaults(handler=_cmd_get_plan_record)

    build_approval = commands.add_parser("build-approval")
    build_approval.add_argument("--plan-record", type=Path, required=True)
    build_approval.add_argument("--repository-owner-id", type=int, required=True)
    build_approval.add_argument("--repository-id", type=int, required=True)
    build_approval.add_argument("--workflow-ref", required=True)
    build_approval.add_argument("--workflow-sha", required=True)
    build_approval.add_argument("--workflow-run-id", type=int, required=True)
    build_approval.add_argument("--github-environment", required=True)
    build_approval.add_argument("--environment-configuration-digest", required=True)
    build_approval.add_argument("--initiator-user-id", type=int, required=True)
    build_approval.add_argument("--approver-user-id", type=int, required=True)
    build_approval.add_argument("--approved-at", required=True)
    build_approval.add_argument("--expires-at", required=True)
    build_approval.add_argument("--approval-out", type=Path, required=True)
    build_approval.set_defaults(handler=_cmd_build_approval)

    persist_approval = commands.add_parser("persist-approval")
    _common_ledger(persist_approval)
    persist_approval.add_argument("--approval-record", type=Path, required=True)
    persist_approval.add_argument("--now", required=True)
    persist_approval.set_defaults(handler=_cmd_persist_approval)

    get_approval = commands.add_parser("get-approval")
    _common_control_read(get_approval)
    get_approval.add_argument("--now", required=True)
    get_approval.add_argument("--approval-out", type=Path, required=True)
    get_approval.set_defaults(handler=_cmd_get_approval)

    fetch = commands.add_parser("fetch-plan")
    _common_destination(fetch)
    fetch.add_argument("--expected-role", required=True)
    fetch.add_argument("--plan-record", type=Path, required=True)
    fetch.add_argument("--plan-out", type=Path, required=True)
    fetch.add_argument("--readback-out", type=Path, required=True)
    fetch.set_defaults(handler=_cmd_fetch_plan)

    authorize = commands.add_parser("authorize-apply")
    authorize.add_argument("--plan-record", type=Path, required=True)
    authorize.add_argument("--ledger", type=Path, required=True)
    authorize.add_argument("--approval-record", type=Path, required=True)
    authorize.add_argument("--bindings", type=Path, required=True)
    authorize.add_argument("--plan-readback", type=Path, required=True)
    authorize.add_argument("--state-readback", type=Path, required=True)
    authorize.add_argument("--now", required=True)
    authorize.add_argument("--decision-out", type=Path, required=True)
    authorize.set_defaults(handler=_cmd_authorize_apply)

    transition = commands.add_parser("transition-ledger")
    _common_ledger(transition)
    transition.add_argument("--deployment-id", required=True)
    transition.add_argument("--execution-id", required=True)
    transition.add_argument("--layer", required=True)
    transition.add_argument("--next-status", required=True)
    transition.add_argument("--expected-version", type=int, required=True)
    transition.add_argument("--expected-digest", required=True)
    transition.add_argument("--at", required=True)
    transition.add_argument("--outcome-code")
    transition.add_argument("--approval-record", type=Path)
    transition.add_argument("--health-receipt", type=Path)
    transition.add_argument("--reconciliation-receipt", type=Path)
    transition.add_argument("--ledger-out", type=Path, required=True)
    transition.set_defaults(handler=_cmd_transition)

    health = commands.add_parser("build-health-receipt")
    health.add_argument("--plan-record", type=Path, required=True)
    health.add_argument("--ledger", type=Path, required=True)
    health.add_argument("--state-readback", type=Path, required=True)
    health.add_argument("--checks", type=Path, required=True)
    health.add_argument("--checked-at", required=True)
    health.add_argument("--receipt-out", type=Path, required=True)
    health.set_defaults(handler=_cmd_health)

    persist_health = commands.add_parser("persist-health-receipt")
    _common_ledger(persist_health)
    persist_health.add_argument("--health-receipt", type=Path, required=True)
    persist_health.set_defaults(handler=_cmd_persist_health)

    get_health = commands.add_parser("get-health-receipt")
    _common_control_read(get_health)
    get_health.add_argument("--health-receipt-out", type=Path, required=True)
    get_health.set_defaults(handler=_cmd_get_health)

    reconcile = commands.add_parser("reconcile-uncertain")
    reconcile.add_argument("--plan-record", type=Path, required=True)
    reconcile.add_argument("--ledger", type=Path, required=True)
    reconcile.add_argument("--state-readback", type=Path, required=True)
    reconcile.add_argument(
        "--speculative-plan-result",
        choices=("NO_CHANGE", "CHANGE", "ERROR"),
        required=True,
    )
    reconcile.add_argument("--contract-verified", action="store_true")
    reconcile.add_argument("--checked-at", required=True)
    reconcile.add_argument("--receipt-out", type=Path, required=True)
    reconcile.set_defaults(handler=_cmd_reconcile)

    persist_reconciliation = commands.add_parser("persist-reconciliation-receipt")
    _common_ledger(persist_reconciliation)
    persist_reconciliation.add_argument(
        "--reconciliation-receipt",
        type=Path,
        required=True,
    )
    persist_reconciliation.set_defaults(handler=_cmd_persist_reconciliation)

    get_reconciliation = commands.add_parser("get-reconciliation-receipt")
    _common_control_read(get_reconciliation)
    get_reconciliation.add_argument(
        "--reconciliation-receipt-out",
        type=Path,
        required=True,
    )
    get_reconciliation.set_defaults(handler=_cmd_get_reconciliation)

    verify_health = commands.add_parser("verify-health")
    verify_health.add_argument("--ledger", type=Path, required=True)
    verify_health.add_argument("--plan-record", type=Path, required=True)
    verify_health.add_argument("--health-receipt", type=Path, required=True)
    verify_health.add_argument("--expected-layer", required=True)
    verify_health.set_defaults(handler=_cmd_verify_health)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        args.handler(args)
    except (AuthorizationError, KeyError, OSError, TypeError, ValueError):
        print("DENY: non-production live-engine authorization failed", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
