#!/usr/bin/env python3
"""Offline record and policy renderer for the bounded founder exception.

This tool deliberately has no AWS CLI adapter, no Identity Center mutation,
and no CloudFormation execution command. It creates only private mode-0600
offline artifacts outside the repository. Those artifacts are not immutable
and cannot authorize an Apply. A future reviewed live PEP must use a durable
compare-and-swap ledger before any AWS effect, re-read the exact Change Set,
template, and resource inventory, and collect revocation evidence from
authoritative read APIs.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tooling.founder_bootstrap_exception import (  # noqa: E402
    BootstrapAuthorizationError,
    build_founder_bootstrap_exception,
    build_founder_execution_ledger,
    render_founder_bootstrap_policy,
)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BootstrapAuthorizationError("operational JSON has duplicate keys")
        result[key] = value
    return result


def _outside_repo(path: Path, *, must_exist: bool) -> Path:
    destination = path.expanduser().resolve(strict=False)
    try:
        destination.relative_to(REPO_ROOT.resolve())
    except ValueError:
        pass
    else:
        raise BootstrapAuthorizationError("operational artifact path must be outside the repository")
    if must_exist:
        if destination.is_symlink() or not destination.is_file():
            raise BootstrapAuthorizationError("operational input must be a regular private file")
        if stat.S_IMODE(destination.stat().st_mode) & 0o077:
            raise BootstrapAuthorizationError("operational input must not be group- or world-readable")
    else:
        if destination.exists() or destination.is_symlink():
            raise BootstrapAuthorizationError("operational output path must not already exist")
        if not destination.parent.is_dir():
            raise BootstrapAuthorizationError("operational output parent does not exist")
    return destination


def _read_json(path: Path) -> dict[str, Any]:
    source = _outside_repo(path, must_exist=True)
    try:
        value = json.loads(source.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (OSError, json.JSONDecodeError) as exc:
        raise BootstrapAuthorizationError("operational JSON is invalid") from exc
    if not isinstance(value, dict):
        raise BootstrapAuthorizationError("operational JSON must be an object")
    return value


def _read_private_line(path: Path) -> str:
    source = _outside_repo(path, must_exist=True)
    try:
        value = source.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise BootstrapAuthorizationError("private operational input cannot be read") from exc
    if not value or "\n" in value or "\r" in value:
        raise BootstrapAuthorizationError("private operational input must contain exactly one value")
    return value


def _write_private(path: Path, content: str) -> None:
    destination = _outside_repo(path, must_exist=False)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(destination, flags, 0o600)
    try:
        os.write(descriptor, content.encode("utf-8"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    _write_private(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def _parse_time(value: str, label: str) -> datetime:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise BootstrapAuthorizationError(f"{label} is invalid") from exc
    if result.tzinfo is None:
        raise BootstrapAuthorizationError(f"{label} must be timezone-aware")
    return result.astimezone(UTC)


def _cmd_prepare(args: argparse.Namespace) -> None:
    exception = build_founder_bootstrap_exception(
        plan=_read_json(args.plan),
        exception_id=args.exception_id,
        operator_id=args.operator_id,
        operator_identity_store_user_id=_read_private_line(args.operator_subject_file),
        founder_plan_principal_arn=_read_private_line(args.founder_plan_principal_file),
        founder_apply_principal_arn=_read_private_line(args.founder_apply_principal_file),
        risk_acceptance_id=args.risk_acceptance_id,
        created_at=_parse_time(args.created_at, "created_at"),
        standard_plan_access_revoked_at=_parse_time(
            args.standard_plan_access_revoked_at, "standard Plan access revoked_at"
        ),
        standard_plan_session_quarantine_until=_parse_time(
            args.standard_plan_session_quarantine_until,
            "standard Plan session quarantine_until",
        ),
        founder_plan_not_before=_parse_time(args.founder_plan_not_before, "founder Plan not_before"),
        founder_plan_expires_at=_parse_time(args.founder_plan_expires_at, "founder Plan expires_at"),
        founder_apply_not_before=_parse_time(args.founder_apply_not_before, "founder Apply not_before"),
        founder_apply_expires_at=_parse_time(args.founder_apply_expires_at, "founder Apply expires_at"),
    )
    _write_json(args.exception_out, exception)
    print("PASS: founder exception record created offline")
    print("NO_AWS_CHANGE: no permission set, assignment, Change Set, or infrastructure was modified")


def _cmd_render_policy(args: argparse.Namespace) -> None:
    policy = render_founder_bootstrap_policy(
        mode=args.mode,
        exception=_read_json(args.exception),
        operator_identity_store_user_id=_read_private_line(args.operator_subject_file),
    )
    _write_json(args.policy_out, policy)
    print("PASS: founder time-bound IAM policy rendered offline")
    print("NO_AWS_CHANGE: policy was not attached, provisioned, or assigned")


def _cmd_prepare_ledger(args: argparse.Namespace) -> None:
    ledger = build_founder_execution_ledger(
        exception=_read_json(args.exception),
        created_at=_parse_time(args.created_at, "ledger created_at"),
    )
    _write_json(args.ledger_out, ledger)
    print("PASS: founder offline ledger model prepared")
    print("LIVE_EXECUTION_BLOCKED: this artifact is not a durable CAS ledger or Apply authorization")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Offline-only bounded founder bootstrap exception artifacts"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser("prepare", help="Build a private founder exception record")
    prepare.add_argument("--plan", type=Path, required=True)
    prepare.add_argument("--exception-id", required=True)
    prepare.add_argument("--operator-id", required=True)
    prepare.add_argument("--operator-subject-file", type=Path, required=True)
    prepare.add_argument("--founder-plan-principal-file", type=Path, required=True)
    prepare.add_argument("--founder-apply-principal-file", type=Path, required=True)
    prepare.add_argument("--risk-acceptance-id", required=True)
    prepare.add_argument("--created-at", required=True)
    prepare.add_argument("--standard-plan-access-revoked-at", required=True)
    prepare.add_argument("--standard-plan-session-quarantine-until", required=True)
    prepare.add_argument("--founder-plan-not-before", required=True)
    prepare.add_argument("--founder-plan-expires-at", required=True)
    prepare.add_argument("--founder-apply-not-before", required=True)
    prepare.add_argument("--founder-apply-expires-at", required=True)
    prepare.add_argument("--exception-out", type=Path, required=True)
    prepare.set_defaults(handler=_cmd_prepare)

    render = subparsers.add_parser("render-policy", help="Render a private, time-bound IAM policy")
    render.add_argument("--mode", choices=("plan", "apply"), required=True)
    render.add_argument("--exception", type=Path, required=True)
    render.add_argument("--operator-subject-file", type=Path, required=True)
    render.add_argument("--policy-out", type=Path, required=True)
    render.set_defaults(handler=_cmd_render_policy)

    ledger = subparsers.add_parser(
        "prepare-ledger",
        help="Build an offline ledger model; it cannot authorize CloudFormation",
    )
    ledger.add_argument("--exception", type=Path, required=True)
    ledger.add_argument("--created-at", required=True)
    ledger.add_argument("--ledger-out", type=Path, required=True)
    ledger.set_defaults(handler=_cmd_prepare_ledger)

    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        args.handler(args)
    except BootstrapAuthorizationError as exc:
        print(f"DENY: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
