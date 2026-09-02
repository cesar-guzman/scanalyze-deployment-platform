#!/usr/bin/env python3
"""Run one connected GUG-376 seed or broker-protection step."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any, Mapping, Sequence


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tooling import (  # noqa: E402
    platform_authority_plan_permission_repair_deployment_route as route,
)
from tooling import (  # noqa: E402
    platform_authority_plan_permission_repair_deployment_route_aws as connected,
)
from tooling import (  # noqa: E402
    platform_authority_gug376_collision_admission as collision_admission,
)
from tooling import (  # noqa: E402
    platform_authority_gug376_collision_atomic_context as collision_context,
)
MAX_PRIVATE_JSON_BYTES = 16 * 1024 * 1024
PROFILE_BY_OPERATION = {
    ("create-change-set", "route"): "839393571433_AWSAdministratorAccess",
    ("recover-create-change-set", "route"): "839393571433_AWSAdministratorAccess",
    ("attest-change-set", "route"): "839393571433_AWSAdministratorAccess",
    ("execute-change-set", "route"): "839393571433_AWSAdministratorAccess",
    ("recover-execute-change-set", "route"): "839393571433_AWSAdministratorAccess",
    ("terminal-readback", "route"): "839393571433_AWSAdministratorAccess",
    ("create-change-set", "broker"): "042360977644_ScanalyzeGug376BrokerSeedCreator",
    ("recover-create-change-set", "broker"): "042360977644_ScanalyzeGug376BrokerSeedCreator",
    ("attest-change-set", "broker"): "042360977644_ScanalyzeGug376BrokerSeedCreator",
    ("execute-change-set", "broker"): "042360977644_ScanalyzeGug376BrokerSeedExec",
    ("recover-execute-change-set", "broker"): "042360977644_ScanalyzeGug376BrokerSeedExec",
    ("terminal-readback", "broker"): "042360977644_ScanalyzeGug376BrokerSeedExec",
    (
        "create-change-set",
        route.BROKER_PROTECTION_TARGET,
    ): "042360977644_ScanalyzeGug376BrokerSeedCreator",
    (
        "recover-create-change-set",
        route.BROKER_PROTECTION_TARGET,
    ): "042360977644_ScanalyzeGug376BrokerSeedCreator",
    (
        "attest-change-set",
        route.BROKER_PROTECTION_TARGET,
    ): "042360977644_ScanalyzeGug376BrokerSeedCreator",
    (
        "execute-change-set",
        route.BROKER_PROTECTION_TARGET,
    ): "042360977644_ScanalyzeGug376BrokerSeedExec",
    (
        "recover-execute-change-set",
        route.BROKER_PROTECTION_TARGET,
    ): "042360977644_ScanalyzeGug376BrokerSeedExec",
    (
        "terminal-readback",
        route.BROKER_PROTECTION_TARGET,
    ): "042360977644_ScanalyzeGug376BrokerSeedExec",
}


class _Parser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise connected.ConnectedRouteError("CLI_ARGUMENTS_INVALID")


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.path.expanduser(os.fspath(path))))


def _source_root(path: Path) -> Path:
    candidate = _absolute(path)
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise connected.ConnectedRouteError("SOURCE_ROOT_INVALID") from exc
    if (
        resolved != candidate
        or not resolved.is_dir()
        or resolved != REPO_ROOT.resolve(strict=True)
    ):
        raise connected.ConnectedRouteError("SOURCE_ROOT_INVALID")
    return resolved


def _root(path: Path) -> tuple[Path, int]:
    candidate = _absolute(path)
    try:
        candidate.relative_to(REPO_ROOT.resolve(strict=True))
    except ValueError:
        pass
    except OSError as exc:
        raise connected.ConnectedRouteError("REPOSITORY_ROOT_INVALID") from exc
    else:
        raise connected.ConnectedRouteError("PRIVATE_ROOT_INSIDE_REPOSITORY")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory is None:
        raise connected.ConnectedRouteError("NOFOLLOW_UNAVAILABLE")
    try:
        if candidate.resolve(strict=True) != candidate:
            raise connected.ConnectedRouteError("PRIVATE_ROOT_INVALID")
        descriptor = os.open(candidate, os.O_RDONLY | nofollow | directory)
        metadata = os.fstat(descriptor)
    except connected.ConnectedRouteError:
        raise
    except OSError as exc:
        raise connected.ConnectedRouteError("PRIVATE_ROOT_INVALID") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        os.close(descriptor)
        raise connected.ConnectedRouteError("PRIVATE_ROOT_INVALID")
    return candidate, descriptor


def _assert_root_identity(root: Path, root_fd: int) -> tuple[int, int]:
    try:
        opened = os.fstat(root_fd)
        current = root.lstat()
    except OSError as exc:
        raise connected.ConnectedRouteError("PRIVATE_ROOT_CHANGED") from exc
    if (
        not stat.S_ISDIR(opened.st_mode)
        or not stat.S_ISDIR(current.st_mode)
        or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
        or current.st_uid != os.geteuid()
        or stat.S_IMODE(current.st_mode) != 0o700
    ):
        raise connected.ConnectedRouteError("PRIVATE_ROOT_CHANGED")
    return opened.st_dev, opened.st_ino


def _name(root: Path, requested: Path) -> str:
    candidate = requested if requested.is_absolute() else root / requested
    candidate = _absolute(candidate)
    if candidate.parent != root or candidate.name in {"", ".", ".."}:
        raise connected.ConnectedRouteError("PRIVATE_FILE_OUTSIDE_ROOT")
    return candidate.name


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise connected.ConnectedRouteError("PRIVATE_JSON_DUPLICATE_KEY")
        result[key] = value
    return result


def _nonfinite(_value: str) -> None:
    raise connected.ConnectedRouteError("PRIVATE_JSON_NONFINITE")


def _read(root: Path, root_fd: int, requested: Path) -> dict[str, Any]:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise connected.ConnectedRouteError("NOFOLLOW_UNAVAILABLE")
    try:
        descriptor = os.open(
            _name(root, requested), os.O_RDONLY | nofollow, dir_fd=root_fd
        )
    except OSError as exc:
        raise connected.ConnectedRouteError("PRIVATE_INPUT_INVALID") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or not 0 < before.st_size <= MAX_PRIVATE_JSON_BYTES
        ):
            raise connected.ConnectedRouteError("PRIVATE_INPUT_INVALID")
        chunks: list[bytes] = []
        remaining = MAX_PRIVATE_JSON_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(payload) != before.st_size
            or (after.st_dev, after.st_ino, after.st_size)
            != (before.st_dev, before.st_ino, before.st_size)
        ):
            raise connected.ConnectedRouteError("PRIVATE_INPUT_CHANGED")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=_nonfinite,
        )
    except connected.ConnectedRouteError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise connected.ConnectedRouteError("PRIVATE_JSON_INVALID") from exc
    if not isinstance(value, dict):
        raise connected.ConnectedRouteError("PRIVATE_JSON_OBJECT_REQUIRED")
    return value


def _reserve(root: Path, root_fd: int, requested: Path) -> tuple[str, int]:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise connected.ConnectedRouteError("NOFOLLOW_UNAVAILABLE")
    name = _name(root, requested)
    try:
        descriptor = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow,
            0o600,
            dir_fd=root_fd,
        )
    except FileExistsError as exc:
        raise connected.ConnectedRouteError("PRIVATE_OUTPUT_EXISTS") from exc
    except OSError as exc:
        raise connected.ConnectedRouteError("PRIVATE_OUTPUT_INVALID") from exc
    # Persist the reservation before any provider operation can begin.
    os.fsync(root_fd)
    return name, descriptor


def _finish(descriptor: int, value: Mapping[str, Any]) -> None:
    payload = (route.canonical_json(value) + "\n").encode("utf-8")
    os.fchmod(descriptor, 0o600)
    remaining = memoryview(payload)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise connected.ConnectedRouteError("PRIVATE_OUTPUT_WRITE_FAILED")
        remaining = remaining[written:]
    os.fsync(descriptor)
    metadata = os.fstat(descriptor)
    if (
        metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size != len(payload)
    ):
        raise connected.ConnectedRouteError("PRIVATE_OUTPUT_INVALID")


def _environment(profile: str) -> None:
    connected.validate_aws_environment(expected_profile=profile)


def _provider(
    root: Path,
    root_fd: int,
    *,
    profile: str,
) -> connected.ConnectedSeedProvider:
    root_identity = _assert_root_identity(root, root_fd)
    claims = connected.OExclClaimStore(
        root,
        expected_root_identity=root_identity,
    )
    _environment(profile)
    try:
        import boto3  # type: ignore[import-not-found]
        from botocore.config import Config  # type: ignore[import-not-found]
    except ImportError as exc:
        claims.close()
        raise connected.ConnectedRouteError("AWS_SDK_UNAVAILABLE") from exc
    try:
        session = boto3.Session(profile_name=profile, region_name=route.REGION)
        clients = connected.clients_from_session(
            session,
            Config,
            expected_profile=profile,
        )
    except Exception:
        claims.close()
        raise
    return connected.ConnectedSeedProvider(
        clients=clients,
        claims=claims,
        clock=lambda: datetime.now(timezone.utc),
    )


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in (
        "create-change-set",
        "recover-create-change-set",
        "attest-change-set",
        "execute-change-set",
        "recover-execute-change-set",
        "terminal-readback",
    ):
        child = commands.add_parser(command)
        child.add_argument("--profile", required=True)
        child.add_argument("--target", choices=route.TARGETS, required=True)
        child.add_argument("--source-root", type=Path, required=True)
        child.add_argument("--private-root", type=Path, required=True)
        child.add_argument("--receipt-name", type=Path, required=True)
    commands.choices["create-change-set"].add_argument(
        "--intent-name", type=Path, required=True
    )
    commands.choices["create-change-set"].add_argument(
        "--input-name", type=Path, required=True
    )
    commands.choices["create-change-set"].add_argument(
        "--authorization-name", type=Path, required=True
    )
    commands.choices["create-change-set"].add_argument(
        "--collision-admission-root",
        type=Path,
        required=True,
    )
    commands.choices["create-change-set"].add_argument(
        "--gug393-private-root",
        type=Path,
        required=True,
    )
    commands.choices["create-change-set"].add_argument(
        "--gug395-private-root",
        type=Path,
        required=True,
    )
    commands.choices["recover-create-change-set"].add_argument(
        "--intent-name", type=Path, required=True
    )
    attest = commands.choices["attest-change-set"]
    attest.add_argument("--intent-name", type=Path, required=True)
    attest.add_argument("--dispatch-name", type=Path, required=True)
    commands.choices["execute-change-set"].add_argument(
        "--execution-intent-name", type=Path, required=True
    )
    commands.choices["execute-change-set"].add_argument(
        "--intent-name", type=Path, required=True
    )
    commands.choices["execute-change-set"].add_argument(
        "--input-name", type=Path, required=True
    )
    commands.choices["execute-change-set"].add_argument(
        "--create-attestation-name", type=Path, required=True
    )
    commands.choices["execute-change-set"].add_argument(
        "--authorization-name", type=Path, required=True
    )
    commands.choices["execute-change-set"].add_argument(
        "--collision-admission-root",
        type=Path,
        required=True,
    )
    commands.choices["execute-change-set"].add_argument(
        "--gug393-private-root",
        type=Path,
        required=True,
    )
    commands.choices["execute-change-set"].add_argument(
        "--gug395-private-root",
        type=Path,
        required=True,
    )
    commands.choices["recover-execute-change-set"].add_argument(
        "--execution-intent-name", type=Path, required=True
    )
    commands.choices["recover-execute-change-set"].add_argument(
        "--intent-name", type=Path, required=True
    )
    terminal = commands.choices["terminal-readback"]
    terminal.add_argument("--intent-name", type=Path, required=True)
    terminal.add_argument("--execution-intent-name", type=Path, required=True)
    terminal.add_argument("--execution-receipt-name", type=Path, required=True)
    return parser


def _emit(value: Mapping[str, Any]) -> None:
    sys.stdout.write(route.canonical_json(value) + "\n")


def main(argv: Sequence[str] | None = None) -> int:
    root_fd: int | None = None
    output_fd: int | None = None
    output_name: str | None = None
    mutation_operation = False
    try:
        args = _parser().parse_args(argv)
        expected_profile = PROFILE_BY_OPERATION[(args.command, args.target)]
        if args.profile != expected_profile:
            raise connected.ConnectedRouteError("AWS_PROFILE_INVALID")
        root, root_fd = _root(args.private_root)
        git = route.SubprocessGit(_source_root(args.source_root))
        evaluated_at = datetime.now(timezone.utc)

        # Freeze and validate every caller-controlled causal record before
        # boto3 Session construction.  Provider discovery must not run for a
        # forged source input, re-sealed intent, mismatched target, or malformed
        # private receipt.
        seed_intent = _read(root, root_fd, args.intent_name)
        seed_input: dict[str, Any] | None = None
        creation_authorization: dict[str, Any] | None = None
        dispatch_receipt: dict[str, Any] | None = None
        create_attestation: dict[str, Any] | None = None
        execution_authorization: dict[str, Any] | None = None
        execution: dict[str, Any] | None = None
        execution_receipt: dict[str, Any] | None = None
        admission_binding: dict[str, str] | None = None
        if args.command == "create-change-set":
            seed_input = _read(root, root_fd, args.input_name)
            route.validate_seed_intent_against_input(
                seed_intent,
                seed_input=seed_input,
                git=git,
                now=evaluated_at,
            )
            creation_authorization = _read(
                root, root_fd, args.authorization_name
            )
            route.validate_creation_authorization(
                creation_authorization,
                seed_intent=seed_intent,
                target=args.target,
                now=evaluated_at,
            )
            admission_binding = connected.derive_collision_admission_binding(
                action="create",
                target=args.target,
                seed_input=seed_input,
                seed_intent=seed_intent,
            )
        elif args.command == "execute-change-set":
            seed_input = _read(root, root_fd, args.input_name)
            route.validate_seed_intent_against_input(
                seed_intent,
                seed_input=seed_input,
                git=git,
                now=evaluated_at,
            )
            execution = _read(root, root_fd, args.execution_intent_name)
            create_attestation = _read(
                root, root_fd, args.create_attestation_name
            )
            execution_authorization = _read(
                root, root_fd, args.authorization_name
            )
            route.validate_execution_intent_against_causal_records(
                execution,
                seed_intent=seed_intent,
                create_attestation=create_attestation,
                authorization=execution_authorization,
            )
            route.validate_execution_authorization(
                execution_authorization,
                seed_intent=seed_intent,
                create_attestation=create_attestation,
                now=evaluated_at,
            )
            admission_binding = connected.derive_collision_admission_binding(
                action="execute",
                target=args.target,
                seed_input=seed_input,
                seed_intent=seed_intent,
                execution_intent=execution,
            )
        else:
            route.validate_seed_intent_against_git(seed_intent, git=git)
            if args.command == "attest-change-set":
                dispatch_receipt = _read(
                    root, root_fd, args.dispatch_name
                )
                connected.validate_dispatch(
                    dispatch_receipt,
                    seed_intent=seed_intent,
                )
            elif args.command in {
                "recover-execute-change-set",
                "terminal-readback",
            }:
                execution = _read(
                    root, root_fd, args.execution_intent_name
                )
                route.validate_execution_intent(execution)
                if args.command == "terminal-readback":
                    execution_receipt = _read(
                        root, root_fd, args.execution_receipt_name
                    )

        if execution is not None and (
            execution.get("target") != args.target
            or execution.get("source_commit") != seed_intent["source_commit"]
            or execution.get("parent_intent_digest")
            != seed_intent["intent_digest"]
        ):
            raise connected.ConnectedRouteError("TARGET_INVALID")

        output_name, output_fd = _reserve(
            root,
            root_fd,
            args.receipt_name,
        )
        collision_admission_loader = None
        if admission_binding is not None:
            approval = (
                creation_authorization
                if args.command == "create-change-set"
                else execution_authorization
            )
            assert approval is not None
            collision_admission_loader = (
                collision_context.build_atomic_loader_from_private_context(
                    admission_private_root=args.collision_admission_root,
                    effect_private_root=root,
                    gug393_private_root=args.gug393_private_root,
                    gug395_private_root=args.gug395_private_root,
                    expected_approval_reference_digest=approval[
                        "authorization_digest"
                    ],
                    expected_authorized_at=approval["authorized_at"],
                    expected_expires_at=approval["expires_at"],
                    expected_operation=admission_binding[
                        "collision_operation"
                    ],
                    expected_source_commit_sha=seed_intent["source_commit"],
                    environment=os.environ,
                )
            )
        provider = _provider(root, root_fd, profile=args.profile)
        if args.command == "create-change-set":
            assert seed_input is not None
            assert creation_authorization is not None
            assert collision_admission_loader is not None
            mutation_operation = True
            value = provider.create_change_set(
                seed_input=seed_input,
                seed_intent=seed_intent,
                git=git,
                target=args.target,
                creation_authorization=creation_authorization,
                collision_admission_loader=collision_admission_loader,
            )
        elif args.command == "recover-create-change-set":
            value = provider.recover_create_change_set(
                seed_intent=seed_intent,
                target=args.target,
            )
        elif args.command == "attest-change-set":
            assert dispatch_receipt is not None
            value = provider.attest_change_set(
                seed_intent=seed_intent,
                dispatch_receipt=dispatch_receipt,
            )
        elif args.command == "execute-change-set":
            assert seed_input is not None
            assert create_attestation is not None
            assert execution_authorization is not None
            assert execution is not None
            assert collision_admission_loader is not None
            mutation_operation = True
            value = provider.execute_change_set(
                seed_input=seed_input,
                seed_intent=seed_intent,
                git=git,
                create_attestation=create_attestation,
                execution_authorization=execution_authorization,
                execution_intent=execution,
                collision_admission_loader=collision_admission_loader,
            )
        elif args.command == "recover-execute-change-set":
            assert execution is not None
            value = provider.recover_execute_change_set(
                execution_intent=execution
            )
        else:
            assert execution is not None
            assert execution_receipt is not None
            value = provider.terminal_readback(
                seed_intent=seed_intent,
                execution_intent=execution,
                execution_receipt=execution_receipt,
            )
        _assert_root_identity(root, root_fd)
        _finish(output_fd, value)
        os.close(output_fd)
        output_fd = None
        os.fsync(root_fd)
        _emit(
            {
                "status": value.get("status", "RECORDED"),
                "record_type": value["record_type"],
                "target": value["target"],
                "aws_mutations": value["aws_mutations"],
                "production_authorized": False,
                "production_status": route.PRODUCTION_STATUS,
            }
        )
        return 0
    except (
        connected.ConnectedRouteError,
        route.RouteSeedError,
        collision_admission.RouteCollisionAdmissionError,
        collision_context.AtomicCollisionContextError,
    ) as exc:
        code = exc.code
        uncertain = isinstance(exc, connected.ConnectedRouteError) and exc.uncertain
        if output_fd is not None:
            if mutation_operation:
                # Once a mutating operation has been entered, never erase the
                # reserved evidence slot.  A closed failure marker and the
                # durable claim/result journal make recovery explicit.
                try:
                    os.ftruncate(output_fd, 0)
                    os.lseek(output_fd, 0, os.SEEK_SET)
                    _finish(
                        output_fd,
                        {
                            "schema_version": 1,
                            "record_type": (
                                "scanalyze.platform_authority."
                                "plan_permission_repair_mutation_failure.v1"
                            ),
                            "operation": args.command,
                            "target": args.target,
                            "status": "UNCERTAIN" if uncertain else "BLOCKED",
                            "reason_code": code,
                            "mutation_outcome": "UNKNOWN",
                            "retry_permitted": False,
                            "production_authorized": False,
                            "production_status": route.PRODUCTION_STATUS,
                        },
                    )
                    if root_fd is not None:
                        os.fsync(root_fd)
                except (OSError, connected.ConnectedRouteError):
                    pass
            os.close(output_fd)
            output_fd = None
        if (
            not mutation_operation
            and root_fd is not None
            and output_name is not None
        ):
            try:
                os.unlink(output_name, dir_fd=root_fd)
                os.fsync(root_fd)
            except OSError:
                pass
        _emit(
            {
                "status": "UNCERTAIN" if uncertain else "BLOCKED",
                "reason_code": code,
                "retry_permitted": False,
                "production_authorized": False,
                "production_status": route.PRODUCTION_STATUS,
            }
        )
        return 2
    finally:
        if output_fd is not None:
            os.close(output_fd)
        if root_fd is not None:
            os.close(root_fd)


if __name__ == "__main__":
    raise SystemExit(main())
