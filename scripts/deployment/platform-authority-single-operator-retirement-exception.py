#!/usr/bin/env python3
"""Build or verify the private-input, digest-only GUG-215 exception artifact.

This command is offline by construction. Raw account and Identity Store values
are accepted only through an owner-only JSON file outside the repository. The
output contains digests, never those raw values, and is created once with mode
0600. It does not authorize deployment or invoke AWS.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tooling.platform_authority_single_operator_retirement_exception import (  # noqa: E402
    DIGEST,
    SingleOperatorExceptionError,
    build_single_operator_retirement_exception,
    validate_single_operator_retirement_exception,
)
from tooling.platform_authority_change_set_retirement_broker import (  # noqa: E402
    BROKER_VERSION_BINDING_FIELDS,
    BrokerError,
    broker_version_binding_digest,
)


INPUT_FIELDS = frozenset(
    {
        "authority_account_id",
        "region",
        "retirement_id",
        "change_set_name_digest",
        "template_sha256",
        "resource_inventory_sha256",
        "identity_binding_digest",
        "broker_runtime_version_arn",
        "broker_version_binding_sha256",
        "operator_identity_store_user_id",
        "owner_authorization_sha256",
        "created_at",
        "not_before",
        "expires_at",
    }
)
SAFE_ERROR = re.compile(r"^[A-Z][A-Z0-9_]{2,79}$")


class ArtifactCliError(RuntimeError):
    """Sanitized CLI failure."""

    def __init__(self, code: str) -> None:
        self.code = code if SAFE_ERROR.fullmatch(code) else "ARTIFACT_OPERATION_FAILED"
        super().__init__(self.code)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ArtifactCliError("INPUT_JSON_DUPLICATE_KEY")
        value[key] = item
    return value


def _private_json(path: Path) -> dict[str, Any]:
    candidate = Path(path)
    if candidate.is_symlink():
        raise ArtifactCliError("PRIVATE_INPUT_SYMLINK_FORBIDDEN")
    resolved = candidate.resolve(strict=False)
    repository = REPO_ROOT.resolve()
    if resolved == repository or repository in resolved.parents:
        raise ArtifactCliError("PRIVATE_INPUT_INSIDE_REPOSITORY")
    descriptor = -1
    try:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(resolved, flags)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise ArtifactCliError("PRIVATE_INPUT_MODE_INVALID")
        with os.fdopen(descriptor, "r", encoding="utf-8", closefd=True) as stream:
            descriptor = -1
            value = json.load(stream, object_pairs_hook=_reject_duplicate_keys)
    except ArtifactCliError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ArtifactCliError("PRIVATE_INPUT_INVALID") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not isinstance(value, dict):
        raise ArtifactCliError("INPUT_JSON_INVALID")
    return value


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ArtifactCliError("EXCEPTION_TIME_INVALID")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ArtifactCliError("EXCEPTION_TIME_INVALID") from exc
    if parsed.tzinfo is None or parsed.microsecond != 0:
        raise ArtifactCliError("EXCEPTION_TIME_INVALID")
    return parsed


def _private_output(path: Path, artifact: Mapping[str, object]) -> None:
    candidate = Path(path)
    if candidate.is_symlink() or candidate.exists():
        raise ArtifactCliError("PRIVATE_OUTPUT_ALREADY_EXISTS")
    resolved = candidate.resolve(strict=False)
    repository = REPO_ROOT.resolve()
    if resolved == repository or repository in resolved.parents:
        raise ArtifactCliError("PRIVATE_OUTPUT_INSIDE_REPOSITORY")
    parent = resolved.parent
    try:
        parent_metadata = parent.stat()
    except OSError as exc:
        raise ArtifactCliError("PRIVATE_OUTPUT_PARENT_INVALID") from exc
    if (
        not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != os.geteuid()
        or parent_metadata.st_mode & 0o077
    ):
        raise ArtifactCliError("PRIVATE_OUTPUT_PARENT_MODE_INVALID")
    descriptor = -1
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(resolved, flags, 0o600)
        payload = (
            json.dumps(
                artifact,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            )
            + "\n"
        ).encode("utf-8")
        os.write(descriptor, payload)
        os.fsync(descriptor)
    except OSError as exc:
        raise ArtifactCliError("PRIVATE_OUTPUT_WRITE_FAILED") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _build(args: argparse.Namespace) -> int:
    source = _private_json(args.input)
    if set(source) != set(INPUT_FIELDS):
        raise ArtifactCliError("INPUT_FIELDS_INVALID")
    artifact = build_single_operator_retirement_exception(
        authority_account_id=source["authority_account_id"],
        region=source["region"],
        retirement_id=source["retirement_id"],
        change_set_name_digest=source["change_set_name_digest"],
        template_sha256=source["template_sha256"],
        resource_inventory_sha256=source["resource_inventory_sha256"],
        identity_binding_digest=source["identity_binding_digest"],
        broker_runtime_version_arn=source["broker_runtime_version_arn"],
        broker_version_binding_sha256=source["broker_version_binding_sha256"],
        operator_identity_store_user_id=source["operator_identity_store_user_id"],
        owner_authorization_sha256=source["owner_authorization_sha256"],
        created_at=_timestamp(source["created_at"]),
        not_before=_timestamp(source["not_before"]),
        expires_at=_timestamp(source["expires_at"]),
    )
    _private_output(args.output, artifact)
    print(
        json.dumps(
            {
                "status": "EXCEPTION_ARTIFACT_BUILT_REVIEW_REQUIRED",
                "authorization_digest": artifact["authorization_digest"],
                "authorization_mode": artifact["authorization_mode"],
                "two_human_status": artifact["two_human_status"],
                "independent_approval_present": False,
                "deployment_authorized": False,
                "aws_calls_performed": False,
                "aws_mutations": "NONE",
            },
            sort_keys=True,
        )
    )
    return 0


def _verify(args: argparse.Namespace) -> int:
    artifact = _private_json(args.artifact)
    validate_single_operator_retirement_exception(artifact)
    expected = args.expected_authorization_digest
    if DIGEST.fullmatch(expected) is None:
        raise ArtifactCliError("EXPECTED_AUTHORIZATION_DIGEST_INVALID")
    if artifact.get("authorization_digest") != expected:
        raise ArtifactCliError("EXPECTED_AUTHORIZATION_DIGEST_MISMATCH")
    print(
        json.dumps(
            {
                "status": "EXCEPTION_ARTIFACT_VERIFIED_REVIEW_REQUIRED",
                "authorization_digest": expected,
                "authorization_mode": artifact["authorization_mode"],
                "two_human_status": artifact["two_human_status"],
                "independent_approval_present": False,
                "deployment_authorized": False,
                "aws_calls_performed": False,
                "aws_mutations": "NONE",
            },
            sort_keys=True,
        )
    )
    return 0


def _broker_version_binding(args: argparse.Namespace) -> int:
    source = _private_json(args.input)
    if set(source) != set(BROKER_VERSION_BINDING_FIELDS):
        raise ArtifactCliError("BROKER_VERSION_BINDING_INPUT_FIELDS_INVALID")
    if any(
        not isinstance(source[field], str) or not source[field]
        for field in BROKER_VERSION_BINDING_FIELDS
    ):
        raise ArtifactCliError("BROKER_VERSION_BINDING_INPUT_VALUES_INVALID")
    digest = broker_version_binding_digest(source)
    print(
        json.dumps(
            {
                "status": "BROKER_VERSION_BINDING_CALCULATED_REVIEW_REQUIRED",
                "BrokerVersionBindingSha256": digest,
                "deployment_authorized": False,
                "aws_calls_performed": False,
                "aws_mutations": "NONE",
            },
            sort_keys=True,
        )
    )
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Build or verify the offline GUG-215 single-operator artifact, or "
            "calculate its broker version binding"
        )
    )
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser(
        "build", help="create one private digest-only exception artifact"
    )
    build.add_argument("--input", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    build.set_defaults(handler=_build)
    verify = commands.add_parser(
        "verify", help="verify a private artifact against its reviewed digest"
    )
    verify.add_argument("--artifact", type=Path, required=True)
    verify.add_argument("--expected-authorization-digest", required=True)
    verify.set_defaults(handler=_verify)
    binding = commands.add_parser(
        "broker-version-binding",
        help=(
            "calculate BrokerVersionBindingSha256 from an exact private 0600 JSON"
        ),
        description=(
            "Calculate BrokerVersionBindingSha256 offline from a private 0600 "
            "JSON. Required keys (exact set): "
            + ", ".join(BROKER_VERSION_BINDING_FIELDS)
        ),
    )
    binding.add_argument(
        "--input",
        type=Path,
        required=True,
        help="owner-only JSON outside the repository with exact mode 0600",
    )
    binding.set_defaults(handler=_broker_version_binding)
    return parser


def main() -> int:
    try:
        args = _parser().parse_args()
        return args.handler(args)
    except SingleOperatorExceptionError as exc:
        print(f"BLOCKED: {exc.code}", file=sys.stderr)
        return 1
    except BrokerError as exc:
        print(f"BLOCKED: {exc.code}", file=sys.stderr)
        return 1
    except ArtifactCliError as exc:
        print(f"BLOCKED: {exc.code}", file=sys.stderr)
        return 1
    except Exception:
        print("BLOCKED: ARTIFACT_OPERATION_FAILED", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
