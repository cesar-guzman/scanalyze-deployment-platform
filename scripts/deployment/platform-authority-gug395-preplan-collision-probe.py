#!/usr/bin/env python3
"""Private CLI for the GUG-395/GUG-376 pre-plan collision probe."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import json
from pathlib import Path
import sys
from typing import Any, Sequence


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _stamp_now() -> str:
    return (
        datetime.now(UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be canonical UTC") from exc
    if (
        parsed.tzinfo is None
        or parsed.astimezone(UTC).replace(microsecond=0).isoformat().replace(
            "+00:00", "Z"
        )
        != value
    ):
        raise ValueError("timestamp must be canonical UTC")
    return parsed.astimezone(UTC).replace(microsecond=0)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    materialize = commands.add_parser(
        "materialize-request",
        help="Materialize one private zero-AWS collision request.",
    )
    materialize.add_argument("--private-root", type=Path, required=True)
    materialize.add_argument("--seed-file", default="gug395-preplan-seed.json")
    materialize.add_argument("--plan-file", default="gug395-mutation-plan.json")
    materialize.add_argument(
        "--profile-bindings-file",
        default="gug395-preplan-collision-profile-bindings.json",
    )
    materialize.add_argument("--sdk-runtime-root", required=True)
    materialize.add_argument("--source-commit-sha", required=True)
    materialize.add_argument("--source-tree-sha", required=True)
    materialize.add_argument("--approval-reference-digest", required=True)
    materialize.add_argument("--not-before", required=True)
    materialize.add_argument("--expires-at", required=True)
    materialize.add_argument("--created-at", default=None)

    probe = commands.add_parser(
        "probe",
        help="Claim and execute the attested four-session read-only probe.",
    )
    probe.add_argument("--private-root", type=Path, required=True)
    probe.add_argument("--request-digest", required=True)
    probe.add_argument("--source-commit-sha", required=True)
    probe.add_argument("--source-tree-sha", required=True)
    probe.add_argument("--now", required=True)

    validate = commands.add_parser(
        "validate-receipt",
        help="Validate one digest-only public receipt from private custody.",
    )
    validate.add_argument("--private-root", type=Path, required=True)
    validate.add_argument(
        "--result-file", default="gug395-preplan-collision-result.json"
    )
    return parser


def _emit(value: Any) -> None:
    sys.stdout.write(json.dumps(value, sort_keys=True, separators=(",", ":")))
    sys.stdout.write("\n")


def _materialize(args: argparse.Namespace) -> dict[str, Any]:
    from tooling.platform_authority_gug376_authority_inventory_collector import (
        read_private_json,
    )
    from tooling.platform_authority_gug395_preplan_collision_probe import (
        materialize_collision_probe_request,
        operational_host_digest,
        persist_collision_probe_request,
        private_root_digest,
        verify_collision_probe_source,
    )

    created_at = args.created_at or _stamp_now()
    _time(args.not_before)
    _time(args.expires_at)
    _time(created_at)
    seed = read_private_json(args.private_root, args.seed_file)
    plan = read_private_json(args.private_root, args.plan_file)
    profiles = read_private_json(args.private_root, args.profile_bindings_file)
    verified = verify_collision_probe_source(
        repo_root=REPO_ROOT,
        expected_commit_sha=args.source_commit_sha,
        expected_tree_sha=args.source_tree_sha,
    )
    custody_digest = private_root_digest(args.private_root)
    if seed.get("private_custody_digest") != custody_digest:
        raise ValueError("seed private custody binding does not match this root")
    request = materialize_collision_probe_request(
        seed=seed,
        plan=plan,
        verified_source=verified,
        profiles=profiles,
        sdk_runtime_root=args.sdk_runtime_root,
        private_custody_digest=custody_digest,
        operational_host_binding_digest=operational_host_digest(),
        approval_reference_digest=args.approval_reference_digest,
        not_before=args.not_before,
        expires_at=args.expires_at,
        created_at=created_at,
    )
    persist_collision_probe_request(
        private_root=args.private_root,
        request=request,
    )
    return {
        "record_type": (
            "scanalyze.platform_authority."
            "gug395_preplan_collision_request_materialization_result.v1"
        ),
        "status": "PRIVATE_COLLISION_REQUEST_MATERIALIZED",
        "request_digest": request["request_digest"],
        "target_catalog_digest": request["target_catalog_digest"],
        "policy_set_digest": request["policy_set_digest"],
        "budget_digest": request["budget_digest"],
        "aws_calls": 0,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "production_status": "NO-GO",
    }


def _probe(args: argparse.Namespace) -> dict[str, Any]:
    from tooling.platform_authority_gug376_live_provider import (
        build_collision_probe_provider_factory,
    )
    from tooling.platform_authority_gug395_preplan_collision_executor import (
        execute_preplan_collision_probe,
        persist_pre_execution_collision_probe_failure,
    )
    from tooling.platform_authority_gug395_preplan_collision_probe import (
        CollisionProbeBudget,
        approved_collision_probe_request,
        read_and_claim_collision_probe_request,
        verify_collision_probe_source,
    )

    now = _time(args.now)
    verified = verify_collision_probe_source(
        repo_root=REPO_ROOT,
        expected_commit_sha=args.source_commit_sha,
        expected_tree_sha=args.source_tree_sha,
    )
    capability = read_and_claim_collision_probe_request(
        private_root=args.private_root,
        verified_source=verified,
        expected_request_digest=args.request_digest,
        now=now,
    )
    request = approved_collision_probe_request(capability)
    budget = CollisionProbeBudget(request)
    authority = request["profiles"]["authority"]
    identity = request["profiles"]["identity_center"]
    try:
        provider = build_collision_probe_provider_factory(
            sdk_runtime_root=request["sdk_runtime_root"],
            authority_profile=authority["name"],
            identity_center_profile=identity["name"],
            authority_expected_account_id=authority["expected_account_id"],
            authority_expected_principal_digest=authority[
                "expected_principal_digest"
            ],
            authority_expected_sso_role_name_digest=authority[
                "expected_sso_role_name_digest"
            ],
            identity_expected_account_id=identity["expected_account_id"],
            identity_expected_principal_digest=identity[
                "expected_principal_digest"
            ],
            identity_expected_sso_role_name_digest=identity[
                "expected_sso_role_name_digest"
            ],
            authority_verification_digest=authority[
                "authority_verification_digest"
            ],
            identity_authority_verification_digest=identity[
                "authority_verification_digest"
            ],
            collision_budget=budget,
            execution_capability=capability,
        )
    except Exception as exc:
        return persist_pre_execution_collision_probe_failure(
            execution_capability=capability,
            private_root=args.private_root,
            budget=budget,
            blocker=exc,
            sealed_at=now,
        ).public_receipt
    result = execute_preplan_collision_probe(
        provider_factory=provider,
        execution_capability=capability,
        private_root=args.private_root,
        now=now,
    )
    return result.public_receipt


def _validate(args: argparse.Namespace) -> dict[str, Any]:
    from tooling.platform_authority_gug395_preplan_collision_probe import (
        read_collision_probe_result,
    )

    receipt = read_collision_probe_result(
        private_root=args.private_root,
        result_file=args.result_file,
    ).public_receipt
    return {
        "record_type": (
            "scanalyze.platform_authority."
            "gug395_preplan_collision_receipt_validation.v1"
        ),
        "status": "COLLISION_RECEIPT_VALIDATED",
        "classification": receipt["classification"],
        "receipt_digest": receipt["receipt_digest"],
        "aws_calls": 0,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "production_status": "NO-GO",
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        result = {
            "materialize-request": _materialize,
            "probe": _probe,
            "validate-receipt": _validate,
        }[args.command](args)
    except Exception as exc:
        code = getattr(exc, "code", None)
        if isinstance(code, str):
            parser.error(code)
        if isinstance(exc, ValueError) and str(exc) in {
            "timestamp must be canonical UTC",
            "seed private custody binding does not match this root",
        }:
            parser.error(str(exc))
        parser.error("COLLISION_PROBE_BLOCKED")
    _emit(result)
    if (
        args.command == "probe"
        and result.get("status") == "LIVE_READ_ONLY_PROBE_BLOCKED"
    ):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
