#!/usr/bin/env python3
"""Protected controller for one exact non-production saved-plan phase."""
from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tooling.authorize_deployment_backend import AuthorizationError  # noqa: E402
from tooling.nonprod_live_controller import (  # noqa: E402
    load_live_input_package,
    real_dependencies,
    run_apply_controller,
    run_plan_controller,
    run_terminal_apply,
    run_terminal_fetch,
    run_terminal_plan,
)


INTERNAL_OPERATIONS = {
    "_terminal-plan": "plan",
    "_terminal-fetch": "apply",
    "_terminal-apply": "apply",
}


def _utc_now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("plan", "apply", *INTERNAL_OPERATIONS):
        command = commands.add_parser(name)
        command.add_argument("--private-root", type=Path, required=True)
        command.add_argument("--claim-digest", required=True)
        command.add_argument("--receipt-digest", required=True)
        command.add_argument("--deployment-id", required=True)
        command.add_argument("--execution-id", required=True)
        command.add_argument("--change-id", required=True)
        command.add_argument("--layer", required=True)
        command.add_argument("--main-sha", required=True)
        command.add_argument("--region", required=True)
        if name == "apply":
            command.add_argument("--plan-record-digest", required=True)
            command.add_argument("--reviewer-packet-digest", required=True)
            command.add_argument(
                "--expected-approver-user-id", type=int, required=True
            )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    now = _utc_now()
    operation = INTERNAL_OPERATIONS.get(args.command, args.command)
    try:
        package = load_live_input_package(
            private_root=args.private_root,
            operation=operation,
            deployment_id=args.deployment_id,
            execution_id=args.execution_id,
            change_id=args.change_id,
            layer=args.layer,
            main_sha=args.main_sha,
            region=args.region,
            claim_digest=args.claim_digest,
            receipt_digest=args.receipt_digest,
            now=now,
        )
        if args.command == "_terminal-plan":
            run_terminal_plan(package, now=now, clock=_utc_now)
            return 0
        if args.command == "_terminal-fetch":
            run_terminal_fetch(package)
            return 0
        if args.command == "_terminal-apply":
            run_terminal_apply(package, now=now, clock=_utc_now)
            return 0
        terminal_session, ledger_store = real_dependencies(package)
        if args.command == "plan":
            result = run_plan_controller(
                package,
                receipt_digest=args.receipt_digest,
                terminal_session=terminal_session,
                ledger_store=ledger_store,
                now=now,
                clock=_utc_now,
            )
            print(
                "PASS: exact protected DEV plan stored; "
                f"plan_record_digest={result['plan_record_digest']}"
            )
            return 0
        result = run_apply_controller(
            package,
            receipt_digest=args.receipt_digest,
            plan_record_digest=args.plan_record_digest,
            reviewer_packet_digest=args.reviewer_packet_digest,
            expected_approver_user_id=args.expected_approver_user_id,
            terminal_session=terminal_session,
            ledger_store=ledger_store,
            now=now,
            clock=_utc_now,
        )
        if result["status"] != "HEALTHY":
            print(
                "STOP: saved-plan mutation is durable but post-apply health, "
                "contract publication, and exact readback are not closed; "
                f"status={result['status']}",
                file=sys.stderr,
            )
            return 2
        print(
            "PASS: exact protected DEV saved plan and post-apply closure verified; "
            "status=HEALTHY"
        )
        return 0
    except AuthorizationError as exc:
        print(f"FAIL: protected live phase stopped: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
