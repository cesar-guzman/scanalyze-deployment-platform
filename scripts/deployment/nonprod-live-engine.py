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
    build_saved_plan_record,
    prepare_ledger_transition,
    require_downstream_health,
    require_terminal_role_for_layer,
    validate_dry_run_boundary,
)
from tooling.nonprod_live_store import (  # noqa: E402
    AwsCliExecutionLedgerStore,
    AwsCliPlanStore,
)


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


def _cmd_verify_identity(args: argparse.Namespace) -> None:
    _plan_store(args).verify_terminal_identity(args.expected_role)
    print("PASS: exact terminal role and account binding verified")


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
    store.create_ledger(ledger)
    _write_json(args.ledger_out, ledger)
    print("PASS: create-only execution ledger stored by shared-services orchestrator")


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
    proposed, _ = prepare_ledger_transition(
        current=current,
        next_status=args.next_status,
        expected_version=args.expected_version,
        expected_digest=args.expected_digest,
        at=_time(args.at, "at"),
        outcome_code=args.outcome_code,
        approval_record=_optional_json(args.approval_record),
        health_receipt=_optional_json(args.health_receipt),
        reconciliation_receipt=_optional_json(args.reconciliation_receipt),
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


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    dry_run = commands.add_parser("dry-run-check")
    dry_run.set_defaults(handler=_cmd_dry_run)

    identity = commands.add_parser("verify-identity")
    _common_destination(identity)
    identity.add_argument("--expected-role", required=True)
    identity.set_defaults(handler=_cmd_verify_identity)

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
