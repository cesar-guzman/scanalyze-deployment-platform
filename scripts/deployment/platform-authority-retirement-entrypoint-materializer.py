#!/usr/bin/env python3
"""Plan, apply, or reconcile the exact GUG-363 retirement entrypoint.

``plan`` is completely offline.  ``apply`` requires a fresh GUG-357 execution
authorization and exposes only one possible AWS write: one direct
``CreateStack`` request.  ``reconcile`` is read-only and can never retry the
write.  All operational artifacts are owner-only files outside the repository.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import pwd
import re
import stat
import sys
from typing import Any, Mapping, Sequence


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tooling.platform_authority_retirement_entrypoint_materializer import (  # noqa: E402
    AUTHORITY_ACCOUNT_ID,
    PRODUCTION_STATUS,
    REGION,
    RetirementEntrypointMaterializationError,
    apply_materialization,
    build_materialization_plan,
    reconcile_materialization,
    validate_execution_authorization,
    validate_execution_ledger,
    validate_materialization_plan,
)


MAX_PRIVATE_JSON_BYTES = 2 * 1024 * 1024
MAX_PRIVATE_ARCHIVE_BYTES = 64 * 1024 * 1024
LEDGER_DIRECTORY_NAME = "gug-363-live-v1"
LEDGER_FILE_NAME = "gug363-retirement-entrypoint.execution-ledger.v1.json"
PROFILE_RE = re.compile(r"^[A-Za-z0-9+=,.@_-]{1,128}$")
FORBIDDEN_CREDENTIAL_ENV = frozenset(
    {
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_ROLE_ARN",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        "AWS_CONTAINER_AUTHORIZATION_TOKEN",
        "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
        "AWS_SHARED_CREDENTIALS_FILE",
        "AWS_CONFIG_FILE",
        "BOTO_CONFIG",
    }
)
FORBIDDEN_TRANSPORT_ENV = frozenset(
    {
        "AWS_ENDPOINT_URL",
        "AWS_ENDPOINT_URL_STS",
        "AWS_ENDPOINT_URL_S3",
        "AWS_ENDPOINT_URL_SIGNER",
        "AWS_ENDPOINT_URL_LAMBDA",
        "AWS_ENDPOINT_URL_CLOUDFORMATION",
        "AWS_CA_BUNDLE",
        "REQUESTS_CA_BUNDLE",
        "SSL_CERT_FILE",
    }
)


def _now() -> datetime:
    return datetime.now(tz=UTC).replace(microsecond=0)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise RetirementEntrypointMaterializationError(
                "PRIVATE_JSON_DUPLICATE_KEY"
            )
        value[key] = item
    return value


def _reject_nonfinite(_value: str) -> None:
    raise RetirementEntrypointMaterializationError("PRIVATE_JSON_NONFINITE_NUMBER")


def _outside_repository(path: Path, code: str) -> Path:
    resolved = Path(os.path.abspath(os.path.expanduser(os.fspath(path))))
    try:
        resolved.relative_to(REPO_ROOT.resolve())
    except ValueError:
        return resolved
    raise RetirementEntrypointMaterializationError(code)


def _private_directory(path: Path) -> Path:
    candidate = _outside_repository(path, "PRIVATE_DIRECTORY_INSIDE_REPOSITORY")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory_flag is None:
        raise RetirementEntrypointMaterializationError(
            "PRIVATE_DIRECTORY_NOFOLLOW_UNAVAILABLE"
        )
    try:
        descriptor = os.open(candidate, os.O_RDONLY | nofollow | directory_flag)
    except OSError as exc:
        raise RetirementEntrypointMaterializationError(
            "PRIVATE_DIRECTORY_INVALID"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise RetirementEntrypointMaterializationError(
                "PRIVATE_DIRECTORY_MODE_INVALID"
            )
        try:
            resolved = candidate.resolve(strict=True)
            current = resolved.stat()
        except OSError as exc:
            raise RetirementEntrypointMaterializationError(
                "PRIVATE_DIRECTORY_INVALID"
            ) from exc
        _outside_repository(resolved, "PRIVATE_DIRECTORY_INSIDE_REPOSITORY")
        if (
            current.st_dev != metadata.st_dev
            or current.st_ino != metadata.st_ino
            or current.st_uid != metadata.st_uid
        ):
            raise RetirementEntrypointMaterializationError(
                "PRIVATE_DIRECTORY_CHANGED"
            )
        return resolved
    finally:
        os.close(descriptor)


def _read_private_bytes(path: Path, *, maximum_bytes: int) -> bytes:
    candidate = _outside_repository(path, "PRIVATE_INPUT_INSIDE_REPOSITORY")
    directory = _private_directory(candidate.parent)
    candidate = directory / candidate.name
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise RetirementEntrypointMaterializationError(
            "PRIVATE_INPUT_NOFOLLOW_UNAVAILABLE"
        )
    try:
        descriptor = os.open(candidate, os.O_RDONLY | nofollow)
    except OSError as exc:
        raise RetirementEntrypointMaterializationError("PRIVATE_INPUT_INVALID") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise RetirementEntrypointMaterializationError("PRIVATE_INPUT_INVALID")
        try:
            resolved = candidate.resolve(strict=True)
            current = resolved.stat()
        except OSError as exc:
            raise RetirementEntrypointMaterializationError("PRIVATE_INPUT_INVALID") from exc
        _outside_repository(resolved, "PRIVATE_INPUT_INSIDE_REPOSITORY")
        if (
            current.st_dev != metadata.st_dev
            or current.st_ino != metadata.st_ino
            or current.st_uid != metadata.st_uid
        ):
            raise RetirementEntrypointMaterializationError("PRIVATE_INPUT_CHANGED")
        remaining = maximum_bytes + 1
        chunks: list[bytes] = []
        while remaining > 0:
            chunk = os.read(descriptor, min(remaining, 65_536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > maximum_bytes:
            raise RetirementEntrypointMaterializationError("PRIVATE_INPUT_TOO_LARGE")
        return payload
    finally:
        os.close(descriptor)


def _read_private_json(path: Path) -> dict[str, Any]:
    payload = _read_private_bytes(path, maximum_bytes=MAX_PRIVATE_JSON_BYTES)
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RetirementEntrypointMaterializationError("PRIVATE_JSON_INVALID") from exc
    if not isinstance(value, dict):
        raise RetirementEntrypointMaterializationError("PRIVATE_JSON_INVALID")
    return value


def _reserve_private_output(path: Path, *, exists_code: str) -> tuple[Path, int]:
    candidate = _outside_repository(path, "PRIVATE_OUTPUT_INSIDE_REPOSITORY")
    directory = _private_directory(candidate.parent)
    target = directory / candidate.name
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise RetirementEntrypointMaterializationError(
            "PRIVATE_OUTPUT_NOFOLLOW_UNAVAILABLE"
        )
    flags |= nofollow
    try:
        descriptor = os.open(target, flags, 0o600)
    except FileExistsError as exc:
        raise RetirementEntrypointMaterializationError(exists_code) from exc
    except OSError as exc:
        raise RetirementEntrypointMaterializationError("PRIVATE_OUTPUT_INVALID") from exc
    try:
        os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise OSError
    except OSError as exc:
        os.close(descriptor)
        raise RetirementEntrypointMaterializationError(
            "PRIVATE_OUTPUT_INVALID"
        ) from exc
    return target, descriptor


def _write_reserved_json(descriptor: int, value: Mapping[str, Any]) -> None:
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    try:
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError
            remaining = remaining[written:]
        os.fsync(descriptor)
    except OSError as exc:
        raise RetirementEntrypointMaterializationError(
            "PRIVATE_OUTPUT_WRITE_FAILED"
        ) from exc


def _fsync_private_directory(path: Path) -> None:
    """Durably persist a create-only directory entry or fail closed."""

    directory = _private_directory(path)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory_flag is None:
        raise RetirementEntrypointMaterializationError(
            "PRIVATE_DIRECTORY_FSYNC_UNAVAILABLE"
        )
    try:
        descriptor = os.open(directory, os.O_RDONLY | nofollow | directory_flag)
    except OSError as exc:
        raise RetirementEntrypointMaterializationError(
            "PRIVATE_DIRECTORY_FSYNC_FAILED"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        current = directory.stat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or current.st_dev != metadata.st_dev
            or current.st_ino != metadata.st_ino
            or current.st_uid != metadata.st_uid
        ):
            raise OSError
        os.fsync(descriptor)
    except OSError as exc:
        raise RetirementEntrypointMaterializationError(
            "PRIVATE_DIRECTORY_FSYNC_FAILED"
        ) from exc
    finally:
        os.close(descriptor)


def _replace_reserved_json(descriptor: int, value: Mapping[str, Any]) -> None:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        os.ftruncate(descriptor, 0)
    except OSError as exc:
        raise RetirementEntrypointMaterializationError(
            "PRIVATE_OUTPUT_WRITE_FAILED"
        ) from exc
    _write_reserved_json(descriptor, value)


def _write_private_json(path: Path, value: Mapping[str, Any], *, exists_code: str) -> None:
    target, descriptor = _reserve_private_output(path, exists_code=exists_code)
    write_complete = False
    try:
        _write_reserved_json(descriptor, value)
        write_complete = True
    finally:
        os.close(descriptor)
    if write_complete:
        _fsync_private_directory(target.parent)


def _canonical_ledger_path() -> Path:
    try:
        home = Path(pwd.getpwuid(os.geteuid()).pw_dir)
    except (KeyError, OSError):
        raise RetirementEntrypointMaterializationError("LEDGER_HOME_INVALID") from None
    directory = _private_directory(
        home / ".scanalyze-private-evidence" / LEDGER_DIRECTORY_NAME
    )
    return directory / LEDGER_FILE_NAME


def _require_environment(*, profile: str, region: str) -> None:
    if PROFILE_RE.fullmatch(profile) is None or region != REGION:
        raise RetirementEntrypointMaterializationError("AWS_CONTEXT_INVALID")
    if any(os.environ.get(name) for name in FORBIDDEN_CREDENTIAL_ENV):
        raise RetirementEntrypointMaterializationError(
            "STATIC_AWS_CREDENTIAL_ENV_FORBIDDEN"
        )
    if any(os.environ.get(name) for name in FORBIDDEN_TRANSPORT_ENV):
        raise RetirementEntrypointMaterializationError(
            "AWS_TRANSPORT_OVERRIDE_FORBIDDEN"
        )
    ambient_profile = os.environ.get("AWS_PROFILE") or os.environ.get(
        "AWS_DEFAULT_PROFILE"
    )
    ambient_region = os.environ.get("AWS_REGION") or os.environ.get(
        "AWS_DEFAULT_REGION"
    )
    if ambient_profile not in {None, "", profile} or ambient_region not in {
        None,
        "",
        region,
    }:
        raise RetirementEntrypointMaterializationError("AWS_CONTEXT_AMBIGUOUS")


class BotoClientFactory:
    """Create no-retry clients only after the module chooses their phase."""

    def __init__(self, *, profile: str, region: str) -> None:
        _require_environment(profile=profile, region=region)
        try:
            import boto3
            from botocore.config import Config
        except ImportError as exc:
            raise RetirementEntrypointMaterializationError(
                "AWS_SDK_UNAVAILABLE"
            ) from exc
        self._session = boto3.Session(profile_name=profile, region_name=region)
        self._config = Config(
            retries={"total_max_attempts": 1, "mode": "standard"},
            connect_timeout=5,
            read_timeout=20,
            ignore_configured_endpoint_urls=True,
        )
        self._region = region

    def sts(self) -> Any:
        return self._session.client("sts", region_name=self._region, config=self._config)

    def cloudformation(self) -> Any:
        return self._session.client(
            "cloudformation", region_name=self._region, config=self._config
        )

    def s3(self) -> Any:
        return self._session.client("s3", region_name=self._region, config=self._config)

    def signer(self) -> Any:
        return self._session.client(
            "signer", region_name=self._region, config=self._config
        )

    def lambda_client(self) -> Any:
        return self._session.client(
            "lambda", region_name=self._region, config=self._config
        )


def _public_status(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "status": record.get("status", "PLAN_REVIEW_REQUIRED"),
        "plan_digest": record.get("plan_digest"),
        "receipt_digest": record.get("receipt_digest"),
        "aws_mutation_attempted": bool(record.get("aws_mutation_attempted", False)),
        "retry_permitted": False,
        "materializer_readback_scope": record.get(
            "materializer_readback_scope", "NONE_PLAN_ONLY"
        ),
        "provider_certification_complete": False,
        "gug357_certification_required": True,
        "production_status": PRODUCTION_STATUS,
    }


def _load_plan(args: argparse.Namespace) -> dict[str, Any]:
    plan = _read_private_json(args.plan)
    validate_materialization_plan(plan, repo_root=REPO_ROOT)
    if plan.get("plan_digest") != args.expected_plan_digest:
        raise RetirementEntrypointMaterializationError("EXPECTED_PLAN_DIGEST_MISMATCH")
    if (
        plan.get("artifact_signing_contract_digest")
        != args.expected_artifact_signing_contract_digest
    ):
        raise RetirementEntrypointMaterializationError(
            "EXPECTED_ARTIFACT_SIGNING_CONTRACT_DIGEST_MISMATCH"
        )
    return plan


def _load_authorization(
    args: argparse.Namespace, *, plan: Mapping[str, Any], require_active: bool
) -> dict[str, Any]:
    authorization = _read_private_json(args.authorization)
    validate_execution_authorization(
        authorization,
        plan=plan,
        now=_now(),
        require_active=require_active,
    )
    if authorization.get("authorization_digest") != args.expected_authorization_digest:
        raise RetirementEntrypointMaterializationError(
            "EXPECTED_AUTHORIZATION_DIGEST_MISMATCH"
        )
    if (
        authorization.get("artifact_signing_contract_digest")
        != args.expected_artifact_signing_contract_digest
    ):
        raise RetirementEntrypointMaterializationError(
            "EXPECTED_ARTIFACT_SIGNING_CONTRACT_DIGEST_MISMATCH"
        )
    return authorization


def _cmd_plan(args: argparse.Namespace) -> int:
    intent = _read_private_json(args.intent)
    manifest = _read_private_json(args.unsigned_package_manifest)
    archive = _read_private_bytes(
        args.unsigned_package_archive, maximum_bytes=MAX_PRIVATE_ARCHIVE_BYTES
    )
    plan = build_materialization_plan(
        intent=intent,
        package_manifest=manifest,
        package_archive=archive,
        repo_root=REPO_ROOT,
    )
    _write_private_json(
        args.plan_out, plan, exists_code="MATERIALIZATION_PLAN_ALREADY_EXISTS"
    )
    print(json.dumps(_public_status(plan), sort_keys=True))
    return 0


def _cmd_apply(args: argparse.Namespace) -> int:
    if not args.allow_create_stack:
        raise RetirementEntrypointMaterializationError("CREATE_STACK_NOT_AUTHORIZED")
    plan = _load_plan(args)
    authorization = _load_authorization(args, plan=plan, require_active=True)
    ledger_path = _canonical_ledger_path()
    if ledger_path.exists() or ledger_path.is_symlink():
        raise RetirementEntrypointMaterializationError(
            "EXECUTION_LEDGER_ALREADY_CONSUMED"
        )
    receipt_path, receipt_descriptor = _reserve_private_output(
        args.receipt_out, exists_code="MATERIALIZATION_RECEIPT_ALREADY_EXISTS"
    )
    try:
        _fsync_private_directory(receipt_path.parent)
    except RetirementEntrypointMaterializationError:
        os.close(receipt_descriptor)
        raise

    def claim(ledger: Mapping[str, Any]) -> None:
        _write_private_json(
            ledger_path,
            ledger,
            exists_code="EXECUTION_LEDGER_ALREADY_CONSUMED",
        )

    try:
        factory = BotoClientFactory(profile=args.profile, region=args.region)
        receipt, _ = apply_materialization(
            plan=plan,
            authorization=authorization,
            repo_root=REPO_ROOT,
            client_factory=factory,
            claim_attempt=claim,
            clock=_now,
        )
        _write_reserved_json(receipt_descriptor, receipt)
    except RetirementEntrypointMaterializationError as exc:
        ledger_present = ledger_path.exists() or ledger_path.is_symlink()
        failure = {
            "record_type": (
                "scanalyze.platform_authority."
                "retirement_entrypoint_apply_failure.v1"
            ),
            "schema_version": 1,
            "status": (
                "UNCERTAIN_RECONCILE_ONLY" if ledger_present else "BLOCKED"
            ),
            "reason": exc.code,
            "plan_digest": plan["plan_digest"],
            "authorization_digest": authorization["authorization_digest"],
            "execution_ledger_present": ledger_present,
            "aws_mutation_attempted": (
                exc.aws_mutation_attempted or ledger_present
            ),
            "aws_mutation_evidence": (
                "ATTEMPTED"
                if exc.aws_mutation_attempted
                else ("NOT_PROVEN" if ledger_present else "NONE")
            ),
            "retry_permitted": False,
            "production_status": PRODUCTION_STATUS,
            "created_at": _now().isoformat().replace("+00:00", "Z"),
        }
        try:
            _replace_reserved_json(receipt_descriptor, failure)
        except RetirementEntrypointMaterializationError:
            pass
        raise RetirementEntrypointMaterializationError(
            exc.code,
            aws_mutation_attempted=(
                exc.aws_mutation_attempted or ledger_present
            ),
        ) from exc
    except Exception as exc:
        ledger_present = ledger_path.exists() or ledger_path.is_symlink()
        failure = {
            "record_type": (
                "scanalyze.platform_authority."
                "retirement_entrypoint_apply_failure.v1"
            ),
            "schema_version": 1,
            "status": (
                "UNCERTAIN_RECONCILE_ONLY" if ledger_present else "BLOCKED"
            ),
            "reason": "UNEXPECTED_SANITIZED_FAILURE",
            "plan_digest": plan["plan_digest"],
            "authorization_digest": authorization["authorization_digest"],
            "execution_ledger_present": ledger_present,
            "aws_mutation_attempted": ledger_present,
            "aws_mutation_evidence": (
                "NOT_PROVEN" if ledger_present else "NONE"
            ),
            "retry_permitted": False,
            "production_status": PRODUCTION_STATUS,
            "created_at": _now().isoformat().replace("+00:00", "Z"),
        }
        try:
            _replace_reserved_json(receipt_descriptor, failure)
        except RetirementEntrypointMaterializationError:
            pass
        raise RetirementEntrypointMaterializationError(
            "UNEXPECTED_SANITIZED_FAILURE",
            aws_mutation_attempted=ledger_present,
        ) from exc
    finally:
        os.close(receipt_descriptor)
    print(json.dumps(_public_status(receipt), sort_keys=True))
    return 0 if receipt["status"] == "READBACK_VERIFIED" else 2


def _cmd_reconcile(args: argparse.Namespace) -> int:
    plan = _load_plan(args)
    authorization = _load_authorization(args, plan=plan, require_active=False)
    ledger = _read_private_json(_canonical_ledger_path())
    validate_execution_ledger(ledger, plan=plan, authorization=authorization)
    factory = BotoClientFactory(profile=args.profile, region=args.region)
    receipt = reconcile_materialization(
        plan=plan,
        authorization=authorization,
        ledger=ledger,
        repo_root=REPO_ROOT,
        client_factory=factory,
        clock=_now,
    )
    _write_private_json(
        args.receipt_out,
        receipt,
        exists_code="MATERIALIZATION_RECEIPT_ALREADY_EXISTS",
    )
    print(json.dumps(_public_status(receipt), sort_keys=True))
    return 0 if receipt["status"] == "READBACK_VERIFIED" else 2


def _execution_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--authorization", type=Path, required=True)
    parser.add_argument("--expected-plan-digest", required=True)
    parser.add_argument("--expected-authorization-digest", required=True)
    parser.add_argument(
        "--expected-artifact-signing-contract-digest", required=True
    )
    parser.add_argument("--profile", required=True)
    parser.add_argument("--region", required=True, choices=(REGION,))
    parser.add_argument("--receipt-out", type=Path, required=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan = subparsers.add_parser("plan", help="Build the exact private offline plan")
    plan.add_argument("--intent", type=Path, required=True)
    plan.add_argument("--unsigned-package-manifest", type=Path, required=True)
    plan.add_argument("--unsigned-package-archive", type=Path, required=True)
    plan.add_argument("--plan-out", type=Path, required=True)
    plan.set_defaults(handler=_cmd_plan)

    apply = subparsers.add_parser(
        "apply", help="Attempt the one exact direct CreateStack request"
    )
    _execution_common(apply)
    apply.add_argument("--allow-create-stack", action="store_true")
    apply.set_defaults(handler=_cmd_apply)

    reconcile = subparsers.add_parser(
        "reconcile", help="Read-only reconciliation; never retries CreateStack"
    )
    _execution_common(reconcile)
    reconcile.set_defaults(handler=_cmd_reconcile)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return int(args.handler(args))
    except RetirementEntrypointMaterializationError as exc:
        print(
            json.dumps(
                {
                    "status": "BLOCKED",
                    "reason": exc.code,
                    "aws_mutation_attempted": exc.aws_mutation_attempted,
                    "retry_permitted": False,
                    "production_status": PRODUCTION_STATUS,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    except Exception:
        print(
            json.dumps(
                {
                    "status": "BLOCKED",
                    "reason": "UNEXPECTED_SANITIZED_FAILURE",
                    "aws_mutation_attempted": False,
                    "retry_permitted": False,
                    "production_status": PRODUCTION_STATUS,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
