#!/usr/bin/env python3
"""Run the finite, attested GUG-376 deployment-recovery lanes."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any, Callable, Mapping, Sequence


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tooling import (  # noqa: E402
    platform_authority_plan_permission_repair_deployment_recovery as recovery,
)
from tooling import (  # noqa: E402
    platform_authority_plan_permission_repair_deployment_route as route,
)
from tooling import (  # noqa: E402
    platform_authority_plan_permission_repair_deployment_route_aws as connected,
)


MAX_PRIVATE_JSON_BYTES = 16 * 1024 * 1024
CONNECTED_COMMANDS = frozenset(
    {
        "attest-preexecute-failure",
        "create-reentry",
        "attest-reentry",
        "execute-reentry",
        "attest-protection-rollback",
        "attest-failed-create",
        "delete-failed-stack",
        "attest-cleanup",
    }
)
PROFILE_BY_COMMAND = {
    ("attest-preexecute-failure", "route"): (
        "839393571433_AWSAdministratorAccess"
    ),
    ("create-reentry", "route"): "839393571433_AWSAdministratorAccess",
    ("attest-reentry", "route"): "839393571433_AWSAdministratorAccess",
    ("execute-reentry", "route"): "839393571433_AWSAdministratorAccess",
    ("attest-failed-create", "route"): "839393571433_AWSAdministratorAccess",
    ("attest-preexecute-failure", "broker"): (
        "042360977644_ScanalyzeGug376BrokerSeedCreator"
    ),
    ("create-reentry", "broker"): (
        "042360977644_ScanalyzeGug376BrokerSeedCreator"
    ),
    ("attest-reentry", "broker"): (
        "042360977644_ScanalyzeGug376BrokerSeedCreator"
    ),
    ("execute-reentry", "broker"): (
        "042360977644_ScanalyzeGug376BrokerSeedExec"
    ),
    ("attest-failed-create", "broker"): (
        "042360977644_ScanalyzeGug376BrokerSeedExec"
    ),
    ("create-reentry", route.BROKER_PROTECTION_TARGET): (
        "042360977644_ScanalyzeGug376BrokerSeedCreator"
    ),
    ("attest-reentry", route.BROKER_PROTECTION_TARGET): (
        "042360977644_ScanalyzeGug376BrokerSeedCreator"
    ),
    ("execute-reentry", route.BROKER_PROTECTION_TARGET): (
        "042360977644_ScanalyzeGug376BrokerSeedExec"
    ),
    ("attest-protection-rollback", route.BROKER_PROTECTION_TARGET): (
        "042360977644_ScanalyzeGug376BrokerSeedExec"
    ),
    ("delete-failed-stack", "route"): recovery.CLEANUP_PROFILE_NAMES["route"],
    ("attest-cleanup", "route"): recovery.CLEANUP_PROFILE_NAMES["route"],
    ("delete-failed-stack", "broker"): recovery.CLEANUP_PROFILE_NAMES[
        "broker"
    ],
    ("attest-cleanup", "broker"): recovery.CLEANUP_PROFILE_NAMES["broker"],
}


class _Parser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise recovery.DeploymentRecoveryError("CLI_ARGUMENTS_INVALID")


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.path.expanduser(os.fspath(path))))


def _source_root(path: Path) -> Path:
    candidate = _absolute(path)
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise recovery.DeploymentRecoveryError("SOURCE_ROOT_INVALID") from exc
    if (
        resolved != candidate
        or not resolved.is_dir()
        or resolved != REPO_ROOT.resolve(strict=True)
    ):
        raise recovery.DeploymentRecoveryError("SOURCE_ROOT_INVALID")
    return resolved


def _private_root(path: Path) -> tuple[Path, int]:
    candidate = _absolute(path)
    try:
        candidate.relative_to(REPO_ROOT.resolve(strict=True))
    except ValueError:
        pass
    except OSError as exc:
        raise recovery.DeploymentRecoveryError(
            "REPOSITORY_ROOT_INVALID"
        ) from exc
    else:
        raise recovery.DeploymentRecoveryError("PRIVATE_ROOT_INSIDE_REPOSITORY")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory is None:
        raise recovery.DeploymentRecoveryError("NOFOLLOW_UNAVAILABLE")
    try:
        if candidate.resolve(strict=True) != candidate:
            raise recovery.DeploymentRecoveryError("PRIVATE_ROOT_INVALID")
        descriptor = os.open(candidate, os.O_RDONLY | nofollow | directory)
        metadata = os.fstat(descriptor)
    except recovery.DeploymentRecoveryError:
        raise
    except OSError as exc:
        raise recovery.DeploymentRecoveryError("PRIVATE_ROOT_INVALID") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        os.close(descriptor)
        raise recovery.DeploymentRecoveryError("PRIVATE_ROOT_INVALID")
    return candidate, descriptor


def _assert_root(root: Path, descriptor: int) -> tuple[int, int]:
    try:
        opened = os.fstat(descriptor)
        current = root.lstat()
    except OSError as exc:
        raise recovery.DeploymentRecoveryError("PRIVATE_ROOT_CHANGED") from exc
    if (
        not stat.S_ISDIR(opened.st_mode)
        or not stat.S_ISDIR(current.st_mode)
        or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
        or current.st_uid != os.geteuid()
        or stat.S_IMODE(current.st_mode) != 0o700
    ):
        raise recovery.DeploymentRecoveryError("PRIVATE_ROOT_CHANGED")
    return opened.st_dev, opened.st_ino


def _name(root: Path, requested: Path) -> str:
    candidate = requested if requested.is_absolute() else root / requested
    candidate = _absolute(candidate)
    if candidate.parent != root or candidate.name in {"", ".", ".."}:
        raise recovery.DeploymentRecoveryError("PRIVATE_FILE_OUTSIDE_ROOT")
    return candidate.name


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise recovery.DeploymentRecoveryError("PRIVATE_JSON_DUPLICATE_KEY")
        value[key] = item
    return value


def _nonfinite(_value: str) -> None:
    raise recovery.DeploymentRecoveryError("PRIVATE_JSON_NONFINITE")


def _read(root: Path, root_fd: int, requested: Path) -> dict[str, Any]:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise recovery.DeploymentRecoveryError("NOFOLLOW_UNAVAILABLE")
    try:
        descriptor = os.open(
            _name(root, requested), os.O_RDONLY | nofollow, dir_fd=root_fd
        )
    except OSError as exc:
        raise recovery.DeploymentRecoveryError("PRIVATE_INPUT_INVALID") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or not 0 < before.st_size <= MAX_PRIVATE_JSON_BYTES
        ):
            raise recovery.DeploymentRecoveryError("PRIVATE_INPUT_INVALID")
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
            raise recovery.DeploymentRecoveryError("PRIVATE_INPUT_CHANGED")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=_nonfinite,
        )
    except recovery.DeploymentRecoveryError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise recovery.DeploymentRecoveryError("PRIVATE_JSON_INVALID") from exc
    if not isinstance(value, dict):
        raise recovery.DeploymentRecoveryError("PRIVATE_JSON_OBJECT_REQUIRED")
    return value


def _reserve(root: Path, root_fd: int, requested: Path) -> tuple[str, int]:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise recovery.DeploymentRecoveryError("NOFOLLOW_UNAVAILABLE")
    name = _name(root, requested)
    try:
        descriptor = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow,
            0o600,
            dir_fd=root_fd,
        )
    except FileExistsError as exc:
        raise recovery.DeploymentRecoveryError("PRIVATE_OUTPUT_EXISTS") from exc
    except OSError as exc:
        raise recovery.DeploymentRecoveryError("PRIVATE_OUTPUT_INVALID") from exc
    os.fsync(root_fd)
    return name, descriptor


def _finish(descriptor: int, value: Mapping[str, Any]) -> None:
    payload = (route.canonical_json(value) + "\n").encode("utf-8")
    os.fchmod(descriptor, 0o600)
    remaining = memoryview(payload)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise recovery.DeploymentRecoveryError(
                "PRIVATE_OUTPUT_WRITE_FAILED"
            )
        remaining = remaining[written:]
    os.fsync(descriptor)
    metadata = os.fstat(descriptor)
    if (
        metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size != len(payload)
    ):
        raise recovery.DeploymentRecoveryError("PRIVATE_OUTPUT_INVALID")


def _add_common(child: argparse.ArgumentParser, *, connected_step: bool) -> None:
    child.add_argument("--source-root", type=Path, required=True)
    child.add_argument("--private-root", type=Path, required=True)
    child.add_argument("--seed-input-name", type=Path, required=True)
    child.add_argument("--seed-intent-name", type=Path, required=True)
    child.add_argument("--target", choices=route.TARGETS, required=True)
    child.add_argument("--output-name", type=Path, required=True)
    if connected_step:
        child.add_argument("--profile", required=True)


def _add_authorization(child: argparse.ArgumentParser) -> None:
    child.add_argument("--authorization", required=True)
    child.add_argument("--ttl-seconds", type=int, required=True)


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in (
        "authorize-reentry",
        "materialize-reentry",
        "authorize-reentry-execution",
        "materialize-reentry-execution",
        "authorize-cleanup",
        "materialize-cleanup",
        *sorted(CONNECTED_COMMANDS),
    ):
        _add_common(
            commands.add_parser(command),
            connected_step=command in CONNECTED_COMMANDS,
        )
    for command in (
        "authorize-reentry",
        "materialize-reentry",
        "authorize-cleanup",
        "materialize-cleanup",
    ):
        commands.choices[command].add_argument(
            "--failure-attestation-name", type=Path, required=True
        )
    for command in (
        "authorize-reentry-execution",
        "materialize-reentry-execution",
    ):
        commands.choices[command].add_argument(
            "--reentry-intent-name", type=Path, required=True
        )
        commands.choices[command].add_argument(
            "--reentry-attestation-name", type=Path, required=True
        )
        commands.choices[command].add_argument(
            "--reentry-dispatch-name", type=Path, required=True
        )
        commands.choices[command].add_argument(
            "--failure-attestation-name", type=Path, required=True
        )
        commands.choices[command].add_argument(
            "--reentry-creation-authorization-name", type=Path, required=True
        )
    for command in (
        "authorize-reentry",
        "authorize-reentry-execution",
        "authorize-cleanup",
    ):
        _add_authorization(commands.choices[command])
    for command in (
        "materialize-reentry",
        "materialize-reentry-execution",
        "materialize-cleanup",
    ):
        commands.choices[command].add_argument(
            "--authorization-name", type=Path, required=True
        )
    commands.choices["attest-preexecute-failure"].add_argument(
        "--primary-dispatch-name", type=Path, required=True
    )
    for command in ("create-reentry", "attest-reentry"):
        commands.choices[command].add_argument(
            "--reentry-intent-name", type=Path, required=True
        )
        commands.choices[command].add_argument(
            "--failure-attestation-name", type=Path, required=True
        )
        commands.choices[command].add_argument(
            "--reentry-authorization-name", type=Path, required=True
        )
    commands.choices["attest-reentry"].add_argument(
        "--reentry-dispatch-name", type=Path, required=True
    )
    for command in (
        "execute-reentry",
        "attest-protection-rollback",
        "attest-failed-create",
    ):
        commands.choices[command].add_argument(
            "--execution-intent-name", type=Path, required=True
        )
    commands.choices["execute-reentry"].add_argument(
        "--failure-attestation-name", type=Path, required=True
    )
    commands.choices["execute-reentry"].add_argument(
        "--reentry-creation-authorization-name", type=Path, required=True
    )
    commands.choices["execute-reentry"].add_argument(
        "--reentry-intent-name", type=Path, required=True
    )
    commands.choices["execute-reentry"].add_argument(
        "--reentry-attestation-name", type=Path, required=True
    )
    commands.choices["execute-reentry"].add_argument(
        "--reentry-dispatch-name", type=Path, required=True
    )
    commands.choices["execute-reentry"].add_argument(
        "--execution-authorization-name", type=Path, required=True
    )
    for command in ("attest-protection-rollback", "attest-failed-create"):
        commands.choices[command].add_argument(
            "--execution-receipt-name", type=Path, required=True
        )
    for command in ("delete-failed-stack", "attest-cleanup"):
        commands.choices[command].add_argument(
            "--cleanup-intent-name", type=Path, required=True
        )
        commands.choices[command].add_argument(
            "--failure-attestation-name", type=Path, required=True
        )
        commands.choices[command].add_argument(
            "--cleanup-authorization-name", type=Path, required=True
        )
    commands.choices["attest-cleanup"].add_argument(
        "--cleanup-dispatch-name", type=Path, required=True
    )
    return parser


def _read_seed(
    args: argparse.Namespace, root: Path, root_fd: int
) -> tuple[dict[str, Any], dict[str, Any], route.GitPort]:
    seed_input = _read(root, root_fd, args.seed_input_name)
    seed = _read(root, root_fd, args.seed_intent_name)
    git = route.SubprocessGit(_source_root(args.source_root))
    seed = route.validate_seed_intent_against_input(
        seed,
        seed_input=seed_input,
        git=git,
        now=datetime.now(timezone.utc),
    )
    if args.target not in route.TARGETS:
        raise recovery.DeploymentRecoveryError("TARGET_INVALID")
    return seed, seed_input, git


def _bind_target(value: Mapping[str, Any], target: str) -> None:
    if value.get("target") != target:
        raise recovery.DeploymentRecoveryError("TARGET_INVALID")


def _offline(
    args: argparse.Namespace, root: Path, root_fd: int
) -> dict[str, Any]:
    seed, _seed_input, _git = _read_seed(args, root, root_fd)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    expires = now + timedelta(seconds=args.ttl_seconds) if hasattr(
        args, "ttl_seconds"
    ) else None
    if args.command in {"authorize-reentry", "materialize-reentry"}:
        failure = _read(root, root_fd, args.failure_attestation_name)
        _bind_target(failure, args.target)
        if args.command == "authorize-reentry":
            assert expires is not None
            return recovery.materialize_reentry_authorization(
                seed_intent=seed,
                failure_attestation=failure,
                authorization=args.authorization,
                authorized_at=recovery._stamp(now),
                expires_at=recovery._stamp(expires),
            )
        return recovery.materialize_reentry_intent(
            seed_intent=seed,
            failure_attestation=failure,
            authorization=_read(root, root_fd, args.authorization_name),
        )
    if args.command in {
        "authorize-reentry-execution",
        "materialize-reentry-execution",
    }:
        intent = _read(root, root_fd, args.reentry_intent_name)
        attestation = _read(root, root_fd, args.reentry_attestation_name)
        dispatch = _read(root, root_fd, args.reentry_dispatch_name)
        failure = _read(root, root_fd, args.failure_attestation_name)
        creation_authorization = _read(
            root, root_fd, args.reentry_creation_authorization_name
        )
        _bind_target(intent, args.target)
        _bind_target(attestation, args.target)
        _bind_target(dispatch, args.target)
        _bind_target(failure, args.target)
        if args.command == "authorize-reentry-execution":
            assert expires is not None
            return recovery.materialize_reentry_execution_authorization(
                seed_intent=seed,
                failure_attestation=failure,
                reentry_creation_authorization=creation_authorization,
                reentry_intent=intent,
                reentry_dispatch=dispatch,
                reentry_attestation=attestation,
                authorization=args.authorization,
                authorized_at=recovery._stamp(now),
                expires_at=recovery._stamp(expires),
            )
        return recovery.materialize_reentry_execution_intent(
            seed_intent=seed,
            failure_attestation=failure,
            reentry_creation_authorization=creation_authorization,
            reentry_intent=intent,
            reentry_dispatch=dispatch,
            reentry_attestation=attestation,
            authorization=_read(root, root_fd, args.authorization_name),
        )
    failure = _read(root, root_fd, args.failure_attestation_name)
    _bind_target(failure, args.target)
    if args.command == "authorize-cleanup":
        assert expires is not None
        return recovery.materialize_cleanup_authorization(
            seed_intent=seed,
            failed_stack_attestation=failure,
            authorization=args.authorization,
            authorized_at=recovery._stamp(now),
            expires_at=recovery._stamp(expires),
        )
    return recovery.materialize_cleanup_intent(
        seed_intent=seed,
        failed_stack_attestation=failure,
        authorization=_read(root, root_fd, args.authorization_name),
    )


def _provider(
    root: Path, root_fd: int, *, profile: str
) -> tuple[recovery.ConnectedDeploymentRecoveryProvider, connected.OExclClaimStore]:
    claims = connected.OExclClaimStore(
        root, expected_root_identity=_assert_root(root, root_fd)
    )
    try:
        import boto3  # type: ignore[import-not-found]
        from botocore.config import Config  # type: ignore[import-not-found]
    except ImportError as exc:
        claims.close()
        raise recovery.DeploymentRecoveryError("AWS_SDK_UNAVAILABLE") from exc
    try:
        session = boto3.Session(profile_name=profile, region_name=route.REGION)
        clients = recovery.clients_from_session(
            session, Config, expected_profile=profile
        )
    except (
        recovery.DeploymentRecoveryError,
        connected.ConnectedRouteError,
    ):
        claims.close()
        raise
    except Exception as exc:
        claims.close()
        raise recovery.DeploymentRecoveryError("AWS_SESSION_INVALID") from exc
    return (
        recovery.ConnectedDeploymentRecoveryProvider(
            clients=clients,
            claims=claims,
            clock=lambda: datetime.now(timezone.utc),
        ),
        claims,
    )


def _connected(
    args: argparse.Namespace,
    root: Path,
    root_fd: int,
    seed: Mapping[str, Any],
    seed_input: Mapping[str, Any],
    git: route.GitPort,
    provider: recovery.ConnectedDeploymentRecoveryProvider,
    mark_mutation: Callable[[], None],
) -> dict[str, Any]:
    if args.command == "attest-preexecute-failure":
        return provider.attest_preexecute_failure(
            seed_intent=seed,
            target=args.target,
            primary_dispatch=_read(root, root_fd, args.primary_dispatch_name),
        )
    if args.command == "create-reentry":
        intent = _read(root, root_fd, args.reentry_intent_name)
        failure = _read(root, root_fd, args.failure_attestation_name)
        authorization = _read(root, root_fd, args.reentry_authorization_name)
        _bind_target(intent, args.target)
        _bind_target(failure, args.target)
        mark_mutation()
        return provider.create_reentry_change_set(
            seed_input=seed_input,
            seed_intent=seed,
            git=git,
            failure_attestation=failure,
            authorization=authorization,
            reentry_intent=intent,
        )
    if args.command == "attest-reentry":
        intent = _read(root, root_fd, args.reentry_intent_name)
        failure = _read(root, root_fd, args.failure_attestation_name)
        authorization = _read(root, root_fd, args.reentry_authorization_name)
        _bind_target(intent, args.target)
        _bind_target(failure, args.target)
        return provider.attest_reentry_change_set(
            seed_intent=seed,
            failure_attestation=failure,
            authorization=authorization,
            reentry_intent=intent,
            dispatch=_read(root, root_fd, args.reentry_dispatch_name),
        )
    if args.command == "execute-reentry":
        intent = _read(root, root_fd, args.execution_intent_name)
        failure = _read(root, root_fd, args.failure_attestation_name)
        reentry_intent = _read(root, root_fd, args.reentry_intent_name)
        reentry_attestation = _read(
            root, root_fd, args.reentry_attestation_name
        )
        reentry_dispatch = _read(
            root, root_fd, args.reentry_dispatch_name
        )
        creation_authorization = _read(
            root, root_fd, args.reentry_creation_authorization_name
        )
        execution_authorization = _read(
            root, root_fd, args.execution_authorization_name
        )
        _bind_target(intent, args.target)
        _bind_target(failure, args.target)
        _bind_target(reentry_intent, args.target)
        _bind_target(reentry_attestation, args.target)
        _bind_target(reentry_dispatch, args.target)
        mark_mutation()
        return provider.execute_reentry_change_set(
            seed_input=seed_input,
            seed_intent=seed,
            git=git,
            failure_attestation=failure,
            reentry_creation_authorization=creation_authorization,
            reentry_intent=reentry_intent,
            reentry_dispatch=reentry_dispatch,
            reentry_attestation=reentry_attestation,
            execution_authorization=execution_authorization,
            execution_intent=intent,
        )
    if args.command in {"attest-protection-rollback", "attest-failed-create"}:
        execution = _read(root, root_fd, args.execution_intent_name)
        receipt = _read(root, root_fd, args.execution_receipt_name)
        _bind_target(execution, args.target)
        _bind_target(receipt, args.target)
        if args.command == "attest-protection-rollback":
            return provider.attest_protection_rollback(
                seed_intent=seed,
                execution_intent=execution,
                execution_receipt=receipt,
            )
        return provider.attest_failed_create_stack(
            seed_intent=seed,
            execution_intent=execution,
            execution_receipt=receipt,
        )
    cleanup = _read(root, root_fd, args.cleanup_intent_name)
    failure = _read(root, root_fd, args.failure_attestation_name)
    authorization = _read(root, root_fd, args.cleanup_authorization_name)
    _bind_target(cleanup, args.target)
    _bind_target(failure, args.target)
    if args.command == "delete-failed-stack":
        mark_mutation()
        return provider.delete_failed_stack(
            seed_input=seed_input,
            seed_intent=seed,
            git=git,
            failed_stack_attestation=failure,
            authorization=authorization,
            cleanup_intent=cleanup,
        )
    return provider.attest_cleanup_complete(
        seed_intent=seed,
        failed_stack_attestation=failure,
        authorization=authorization,
        cleanup_intent=cleanup,
        cleanup_dispatch=_read(root, root_fd, args.cleanup_dispatch_name),
    )


def _emit(value: Mapping[str, Any]) -> None:
    sys.stdout.write(route.canonical_json(value) + "\n")


def main(argv: Sequence[str] | None = None) -> int:
    root_fd: int | None = None
    output_fd: int | None = None
    output_name: str | None = None
    claims: connected.OExclClaimStore | None = None
    mutation_entered = False
    args: argparse.Namespace | None = None

    def mark_mutation() -> None:
        nonlocal mutation_entered
        mutation_entered = True

    try:
        args = _parser().parse_args(argv)
        root, root_fd = _private_root(args.private_root)
        if args.command not in CONNECTED_COMMANDS:
            value = _offline(args, root, root_fd)
            output_name, output_fd = _reserve(root, root_fd, args.output_name)
        else:
            expected_profile = PROFILE_BY_COMMAND.get((args.command, args.target))
            if expected_profile is None or args.profile != expected_profile:
                raise recovery.DeploymentRecoveryError("AWS_PROFILE_INVALID")
            seed, seed_input, git = _read_seed(args, root, root_fd)
            output_name, output_fd = _reserve(root, root_fd, args.output_name)
            provider, claims = _provider(
                root, root_fd, profile=expected_profile
            )
            value = _connected(
                args,
                root,
                root_fd,
                seed,
                seed_input,
                git,
                provider,
                mark_mutation,
            )
        _assert_root(root, root_fd)
        _finish(output_fd, value)
        os.close(output_fd)
        output_fd = None
        os.fsync(root_fd)
        _emit(
            {
                "status": value.get("status", "RECORDED"),
                "record_type": value["record_type"],
                "target": value["target"],
                "aws_mutations": value.get("aws_mutations", 0),
                "production_authorized": False,
                "production_status": route.PRODUCTION_STATUS,
            }
        )
        return 0
    except (
        recovery.DeploymentRecoveryError,
        connected.ConnectedRouteError,
        route.RouteSeedError,
    ) as exc:
        code = exc.code
        uncertain = bool(getattr(exc, "uncertain", False))
        if output_fd is not None:
            if mutation_entered and args is not None:
                try:
                    os.ftruncate(output_fd, 0)
                    os.lseek(output_fd, 0, os.SEEK_SET)
                    _finish(
                        output_fd,
                        {
                            "schema_version": 1,
                            "record_type": (
                                "scanalyze.platform_authority."
                                "plan_permission_repair_recovery_mutation_failure.v1"
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
                except (OSError, recovery.DeploymentRecoveryError):
                    pass
            os.close(output_fd)
            output_fd = None
        if (
            not mutation_entered
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
        if claims is not None:
            claims.close()
        if root_fd is not None:
            os.close(root_fd)


if __name__ == "__main__":
    raise SystemExit(main())
