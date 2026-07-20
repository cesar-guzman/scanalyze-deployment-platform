#!/usr/bin/env python3
"""Read-only GUG-218 Lambda invocation-authority inventory.

The command has two modes: analyze a supplied offline discovery snapshot or
collect a fresh snapshot with an explicit named profile that resolves to the
allowlisted assumed role and read-only AWS APIs.  It
prints only the sanitized inventory and guard receipt.  It never invokes a
function, mutates IAM/Lambda/CloudFormation, or authorizes deployment.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tooling.platform_authority_lambda_invocation_authority import (  # noqa: E402
    EVIDENCE_SOURCE_AWS_READ_ONLY,
    EVIDENCE_SOURCE_OFFLINE_UNVERIFIED,
    RECEIPT_REVIEW_REQUIRED,
    AuthorityInventoryError,
    AwsReadOnlyInventoryAdapter,
    TargetBinding,
    analyze_authority_inventory,
    validate_reviewed_allowlist,
)
from tooling.validate_schema import validate_gug218_evidence_bundle  # noqa: E402


FORBIDDEN_CREDENTIAL_ENV = frozenset(
    {
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_ROLE_ARN",
    }
)
FORBIDDEN_AWS_TRANSPORT_ENV = frozenset(
    {
        "AWS_ENDPOINT_URL",
        "AWS_ENDPOINT_URL_STS",
        "AWS_ENDPOINT_URL_EC2",
        "AWS_ENDPOINT_URL_LAMBDA",
        "AWS_ENDPOINT_URL_IAM",
        "AWS_CA_BUNDLE",
        "REQUESTS_CA_BUNDLE",
        "SSL_CERT_FILE",
    }
)
def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise AuthorityInventoryError("JSON_DUPLICATE_KEY")
        value[key] = item
    return value


def _read_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise AuthorityInventoryError("INPUT_JSON_INVALID") from exc
    if not isinstance(value, dict):
        raise AuthorityInventoryError("INPUT_JSON_INVALID")
    return value


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _binding(args: argparse.Namespace) -> TargetBinding:
    return TargetBinding(
        authority_account_id=args.authority_account_id,
        region=args.region,
        function_name=args.function_name,
        partition=args.partition,
    )


def _require_assumed_role_environment(*, profile: str, region: str) -> None:
    if not profile:
        raise AuthorityInventoryError("AWS_PROFILE_REQUIRED")
    if any(os.environ.get(name) for name in FORBIDDEN_CREDENTIAL_ENV):
        raise AuthorityInventoryError("STATIC_AWS_CREDENTIALS_FORBIDDEN")
    if any(os.environ.get(name) for name in FORBIDDEN_AWS_TRANSPORT_ENV):
        raise AuthorityInventoryError("AWS_TRANSPORT_OVERRIDE_FORBIDDEN")
    configured = {
        value
        for name in ("AWS_REGION", "AWS_DEFAULT_REGION")
        if (value := os.environ.get(name))
    }
    if configured and configured != {region}:
        raise AuthorityInventoryError("AMBIENT_REGION_CONFLICT")


def _offline_snapshot(args: argparse.Namespace) -> dict[str, Any]:
    return _read_object(args.snapshot)


def _aws_snapshot(args: argparse.Namespace) -> dict[str, Any]:
    _require_assumed_role_environment(profile=args.profile, region=args.region)
    adapter = AwsReadOnlyInventoryAdapter.from_boto3(
        profile_name=args.profile,
        region=args.region,
        partition=args.partition,
    )
    return adapter.collect(
        binding=_binding(args),
        scan_id=args.scan_id,
        expected_collector_principal_digest=args.expected_collector_principal_digest,
        ttl_minutes=args.ttl_minutes,
    )


def _run(args: argparse.Namespace) -> int:
    allowlist = _read_object(args.allowlist)
    args.expected_collector_principal_digest = validate_reviewed_allowlist(
        allowlist=allowlist,
        binding=_binding(args),
        expected_allowlist_digest=args.expected_allowlist_digest,
    )
    snapshot = args.snapshot_loader(args)
    decision = datetime.now(tz=UTC).replace(microsecond=0)
    inventory, receipt = analyze_authority_inventory(
        allowlist=allowlist,
        snapshot=snapshot,
        binding=_binding(args),
        evidence_source_mode=args.evidence_source_mode,
        decision_at=_timestamp(decision),
    )
    if validate_gug218_evidence_bundle(
        allowlist=allowlist,
        inventory=inventory,
        receipt=receipt,
        evaluation_at=decision,
    ):
        raise AuthorityInventoryError("EVIDENCE_BUNDLE_INVALID")
    print(json.dumps({"inventory": inventory, "receipt": receipt}, sort_keys=True, indent=2))
    return 0 if receipt["status"] == RECEIPT_REVIEW_REQUIRED else 2


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--allowlist", type=Path, required=True)
    parser.add_argument(
        "--expected-allowlist-digest",
        required=True,
        help=(
            "Canonical digest supplied independently by the reviewed release "
            "or deployment contract"
        ),
    )
    parser.add_argument("--authority-account-id", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--function-name", required=True)
    parser.add_argument(
        "--partition",
        choices=("aws", "aws-us-gov", "aws-cn"),
        default="aws",
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate a sanitized, report-only GUG-218 authority receipt"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    offline = subparsers.add_parser(
        "snapshot-check",
        help="Analyze an existing raw read-only snapshot without AWS access",
    )
    _common(offline)
    offline.add_argument("--snapshot", type=Path, required=True)
    offline.set_defaults(
        snapshot_loader=_offline_snapshot,
        evidence_source_mode=EVIDENCE_SOURCE_OFFLINE_UNVERIFIED,
    )

    aws_readonly = subparsers.add_parser(
        "aws-readonly",
        help=(
            "Collect only List/Get/Describe evidence with an explicit profile "
            "that resolves to the allowlisted assumed role"
        ),
    )
    _common(aws_readonly)
    aws_readonly.add_argument("--profile", required=True)
    aws_readonly.add_argument(
        "--ttl-minutes", type=int, choices=range(1, 6), default=5
    )
    aws_readonly.add_argument(
        "--scan-id",
        default=None,
        help="Opaque scan nonce; generated locally when omitted",
    )
    aws_readonly.set_defaults(
        snapshot_loader=_aws_snapshot,
        evidence_source_mode=EVIDENCE_SOURCE_AWS_READ_ONLY,
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    if getattr(args, "scan_id", None) is None:
        args.scan_id = "gug218-" + uuid.uuid4().hex
    try:
        return _run(args)
    except AuthorityInventoryError as exc:
        print(f"BLOCKED: {exc.code}", file=sys.stderr)
        return 1
    except Exception:
        # Never expose SDK exception payloads, local paths, profiles, policy
        # documents, or credential-provider diagnostics.
        print("BLOCKED: AUTHORITY_INVENTORY_FAILED", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
