#!/usr/bin/env python3
"""Capture candidate evidence and materialize a reviewed GUG-219 release.

Only ``candidate-aws-readonly`` creates AWS clients, and those clients expose
the GUG-218 List/Get/Describe inventory surface. ``materialize`` is offline.
Inputs and outputs remain private files outside the repository. Console output
contains only status and digests, never identities, policies or snapshots.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import uuid
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tooling.platform_authority_lambda_invocation_authority import (  # noqa: E402
    AuthorityInventoryError,
    AwsReadOnlyInventoryAdapter,
    TargetBinding,
)
from tooling.platform_authority_lambda_invocation_materializer import (  # noqa: E402
    LambdaAuthorityMaterializationError,
    build_collector_contract,
    materialize_allowlist_release,
    render_collector_inline_policy,
    validate_candidate_capture,
    validate_private_output_path,
    validate_source_commit_binding,
    write_private_bundle,
)


FORBIDDEN_CREDENTIAL_ENV = frozenset(
    {
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_ROLE_ARN",
    }
)
FORBIDDEN_TRANSPORT_ENV = frozenset(
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


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise LambdaAuthorityMaterializationError("INPUT_JSON_DUPLICATE_KEY")
        result[key] = value
    return result


def _private_input(path: Path) -> dict[str, Any]:
    candidate = Path(path)
    if candidate.is_symlink():
        raise LambdaAuthorityMaterializationError("PRIVATE_INPUT_SYMLINK_FORBIDDEN")
    resolved = candidate.resolve(strict=False)
    repo = REPO_ROOT.resolve()
    if resolved == repo or repo in resolved.parents:
        raise LambdaAuthorityMaterializationError("PRIVATE_INPUT_INSIDE_REPOSITORY")
    descriptor = -1
    try:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(resolved, flags)
        metadata = os.fstat(descriptor)
        mode = metadata.st_mode & 0o777
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or mode & 0o077
        ):
            raise LambdaAuthorityMaterializationError("PRIVATE_INPUT_MODE_INVALID")
        with os.fdopen(descriptor, "r", encoding="utf-8", closefd=True) as stream:
            descriptor = -1
            value = json.load(stream, object_pairs_hook=_reject_duplicates)
    except LambdaAuthorityMaterializationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LambdaAuthorityMaterializationError("PRIVATE_INPUT_INVALID") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not isinstance(value, dict):
        raise LambdaAuthorityMaterializationError("PRIVATE_INPUT_INVALID")
    return value


def _binding(args: argparse.Namespace) -> TargetBinding:
    return TargetBinding(
        authority_account_id=args.authority_account_id,
        region=args.region,
        function_name=args.function_name,
        partition=args.partition,
    )


def _collector_contract(args: argparse.Namespace) -> dict[str, Any]:
    collector = _private_input(args.collector_binding)
    if set(collector) != {
        "identity_center_region",
        "collector_iam_role_arn",
        "collector_sts_session_arn",
    } or not all(isinstance(value, str) and value for value in collector.values()):
        raise LambdaAuthorityMaterializationError("COLLECTOR_BINDING_INPUT_INVALID")
    return build_collector_contract(
        binding=_binding(args),
        identity_center_region=collector["identity_center_region"],
        collector_iam_role_arn=collector["collector_iam_role_arn"],
        collector_sts_session_arn=collector["collector_sts_session_arn"],
        created_at=args.created_at,
        repo_root=REPO_ROOT,
    )


def _require_aws_environment(args: argparse.Namespace) -> None:
    if not args.profile:
        raise LambdaAuthorityMaterializationError("AWS_PROFILE_REQUIRED")
    if any(os.environ.get(name) for name in FORBIDDEN_CREDENTIAL_ENV):
        raise LambdaAuthorityMaterializationError("STATIC_AWS_CREDENTIALS_FORBIDDEN")
    if any(os.environ.get(name) for name in FORBIDDEN_TRANSPORT_ENV):
        raise LambdaAuthorityMaterializationError("AWS_TRANSPORT_OVERRIDE_FORBIDDEN")
    ambient = {
        value
        for name in ("AWS_REGION", "AWS_DEFAULT_REGION")
        if (value := os.environ.get(name))
    }
    if ambient and ambient != {args.region}:
        raise LambdaAuthorityMaterializationError("AMBIENT_REGION_CONFLICT")


def _candidate_aws_readonly(args: argparse.Namespace) -> int:
    """Collect A under the exact collector; never classify it as safe."""

    _require_aws_environment(args)
    validate_private_output_path(output_dir=args.output_dir, repo_root=REPO_ROOT)
    binding = _binding(args)
    contract = _collector_contract(args)
    adapter = AwsReadOnlyInventoryAdapter.from_boto3(
        profile_name=args.profile,
        region=args.region,
        partition=args.partition,
    )
    snapshot = adapter.collect(
        binding=binding,
        scan_id=args.scan_id,
        expected_collector_principal_digest=contract[
            "collector_role_sts_arn_digest"
        ],
        ttl_minutes=args.ttl_minutes,
    )
    validate_candidate_capture(
        snapshot=snapshot,
        binding=binding,
        collector_contract=contract,
        repo_root=REPO_ROOT,
    )
    write_private_bundle(
        output_dir=args.output_dir,
        repo_root=REPO_ROOT,
        artifacts={
            "candidate-snapshot.json": snapshot,
            "collector-contract.json": contract,
            "collector-inline-policy.json": render_collector_inline_policy(
                binding=binding, repo_root=REPO_ROOT
            ),
        },
    )
    print(
        json.dumps(
            {
                "status": "CANDIDATE_CAPTURED_MATERIALIZATION_ONLY",
                "candidate_snapshot_digest": snapshot["snapshot_digest"],
                "collector_contract_digest": contract[
                    "collector_contract_digest"
                ],
                "authority_graph_classified": False,
                "aws_mutation_performed": False,
                "lambda_invocation_performed": False,
                "deployment_authorized": False,
                "production_authorized": False,
            },
            sort_keys=True,
        )
    )
    return 0


def _materialize(args: argparse.Namespace) -> int:
    validate_private_output_path(output_dir=args.output_dir, repo_root=REPO_ROOT)
    validate_source_commit_binding(
        source_commit=args.source_commit,
        repo_root=REPO_ROOT,
        include_runtime=True,
    )
    snapshot = _private_input(args.candidate_snapshot)
    contract = _private_input(args.collector_contract)
    binding = _binding(args)
    allowlist, release = materialize_allowlist_release(
        snapshot=snapshot,
        binding=binding,
        collector_contract=contract,
        source_commit=args.source_commit,
        created_at=args.created_at,
        expires_at=args.expires_at,
        repo_root=REPO_ROOT,
    )
    write_private_bundle(
        output_dir=args.output_dir,
        repo_root=REPO_ROOT,
        artifacts={
            "collector-inline-policy.json": render_collector_inline_policy(
                binding=binding, repo_root=REPO_ROOT
            ),
            "collector-contract.json": contract,
            "allowlist.json": allowlist,
            "release-manifest.json": release,
        },
    )
    print(
        json.dumps(
            {
                "status": "MATERIALIZED_REVIEW_REQUIRED",
                "collector_contract_digest": contract["collector_contract_digest"],
                "allowlist_digest": allowlist["allowlist_digest"],
                "release_digest": release["release_digest"],
                "aws_calls_performed": False,
                "aws_mutation_performed": False,
                "deployment_authorized": False,
                "production_authorized": False,
            },
            sort_keys=True,
        )
    )
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Capture and materialize private report-only GUG-219 evidence"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    candidate = commands.add_parser(
        "candidate-aws-readonly",
        help="Collect candidate A with the exact dedicated read-only role",
    )
    candidate.add_argument(
        "--collector-binding",
        type=Path,
        required=True,
        help="Private owner-only JSON containing exact Identity Center IAM and STS role ARNs",
    )
    candidate.add_argument("--created-at", required=True)
    candidate.add_argument("--profile", required=True)
    candidate.add_argument("--ttl-minutes", type=int, choices=range(1, 6), default=5)
    candidate.add_argument("--scan-id", default=None)
    candidate.set_defaults(handler=_candidate_aws_readonly)

    materialize = commands.add_parser(
        "materialize", help="Render the allowlist and release offline from candidate A"
    )
    materialize.add_argument("--candidate-snapshot", type=Path, required=True)
    materialize.add_argument("--collector-contract", type=Path, required=True)
    materialize.add_argument("--source-commit", required=True)
    materialize.add_argument("--created-at", required=True)
    materialize.add_argument("--expires-at", required=True)
    materialize.set_defaults(handler=_materialize)

    for command in (candidate, materialize):
        command.add_argument("--output-dir", type=Path, required=True)
        command.add_argument("--authority-account-id", required=True)
        command.add_argument("--region", required=True)
        command.add_argument("--function-name", required=True)
        command.add_argument(
            "--partition", choices=("aws", "aws-us-gov", "aws-cn"), default="aws"
        )
    return parser


def main() -> int:
    try:
        args = _parser().parse_args()
        if getattr(args, "scan_id", None) is None and args.command == "candidate-aws-readonly":
            args.scan_id = "gug219-a-" + uuid.uuid4().hex
        return args.handler(args)
    except LambdaAuthorityMaterializationError as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 1
    except AuthorityInventoryError as exc:
        print(f"BLOCKED: {exc.code}", file=sys.stderr)
        return 1
    except Exception:
        print("BLOCKED: LAMBDA_AUTHORITY_MATERIALIZATION_FAILED", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
