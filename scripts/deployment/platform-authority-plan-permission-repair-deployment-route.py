#!/usr/bin/env python3
"""Materialize the private GUG-376 seed and broker-protection intents."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
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
    platform_authority_plan_permission_repair_broker_config as broker_config,
)
from tooling import (  # noqa: E402
    platform_authority_plan_permission_repair_artifact_bootstrap as artifact_bootstrap,
)


MAX_PRIVATE_JSON_BYTES = 2 * 1024 * 1024


class _Parser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise route.RouteSeedError("CLI_ARGUMENTS_INVALID")


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.path.expanduser(os.fspath(path))))


def _private_root(path: Path) -> tuple[Path, int]:
    candidate = _absolute(path)
    try:
        candidate.relative_to(REPO_ROOT.resolve(strict=True))
    except ValueError:
        pass
    except OSError as exc:
        raise route.RouteSeedError("REPOSITORY_ROOT_INVALID") from exc
    else:
        raise route.RouteSeedError("PRIVATE_ROOT_INSIDE_REPOSITORY")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory is None:
        raise route.RouteSeedError("PRIVATE_ROOT_NOFOLLOW_UNAVAILABLE")
    try:
        if candidate.resolve(strict=True) != candidate:
            raise route.RouteSeedError("PRIVATE_ROOT_INVALID")
        descriptor = os.open(candidate, os.O_RDONLY | nofollow | directory)
        metadata = os.fstat(descriptor)
    except route.RouteSeedError:
        raise
    except OSError as exc:
        raise route.RouteSeedError("PRIVATE_ROOT_INVALID") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        os.close(descriptor)
        raise route.RouteSeedError("PRIVATE_ROOT_MODE_INVALID")
    return candidate, descriptor


def _source_root(path: Path) -> Path:
    candidate = _absolute(path)
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise route.RouteSeedError("SOURCE_ROOT_INVALID") from exc
    if resolved != candidate or not resolved.is_dir():
        raise route.RouteSeedError("SOURCE_ROOT_INVALID")
    return resolved


def _name(root: Path, requested: Path) -> str:
    candidate = requested if requested.is_absolute() else root / requested
    candidate = _absolute(candidate)
    if candidate.parent != root or candidate.name in {"", ".", ".."}:
        raise route.RouteSeedError("PRIVATE_FILE_OUTSIDE_ROOT")
    return candidate.name


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise route.RouteSeedError("PRIVATE_JSON_DUPLICATE_KEY")
        result[key] = value
    return result


def _nonfinite(_value: str) -> None:
    raise route.RouteSeedError("PRIVATE_JSON_NONFINITE")


def _read(root: Path, root_fd: int, requested: Path) -> dict[str, Any]:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise route.RouteSeedError("PRIVATE_NOFOLLOW_UNAVAILABLE")
    try:
        descriptor = os.open(
            _name(root, requested), os.O_RDONLY | nofollow, dir_fd=root_fd
        )
    except OSError as exc:
        raise route.RouteSeedError("PRIVATE_INPUT_INVALID") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or not 0 < before.st_size <= MAX_PRIVATE_JSON_BYTES
        ):
            raise route.RouteSeedError("PRIVATE_INPUT_INVALID")
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
            raise route.RouteSeedError("PRIVATE_INPUT_CHANGED")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=_nonfinite,
        )
    except route.RouteSeedError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise route.RouteSeedError("PRIVATE_JSON_INVALID") from exc
    if not isinstance(value, dict):
        raise route.RouteSeedError("PRIVATE_JSON_OBJECT_REQUIRED")
    return value


def _write(
    root: Path, root_fd: int, requested: Path, value: Mapping[str, Any]
) -> None:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise route.RouteSeedError("PRIVATE_NOFOLLOW_UNAVAILABLE")
    name = _name(root, requested)
    try:
        descriptor = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow,
            0o600,
            dir_fd=root_fd,
        )
    except FileExistsError as exc:
        raise route.RouteSeedError("PRIVATE_OUTPUT_EXISTS") from exc
    except OSError as exc:
        raise route.RouteSeedError("PRIVATE_OUTPUT_INVALID") from exc
    payload = (route.canonical_json(value) + "\n").encode("utf-8")
    try:
        os.fchmod(descriptor, 0o600)
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise route.RouteSeedError("PRIVATE_OUTPUT_WRITE_FAILED")
            remaining = remaining[written:]
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size != len(payload)
        ):
            raise route.RouteSeedError("PRIVATE_OUTPUT_INVALID")
    except Exception:
        try:
            os.unlink(name, dir_fd=root_fd)
        except OSError:
            pass
        raise
    finally:
        os.close(descriptor)
    os.fsync(root_fd)


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    materialize = commands.add_parser("materialize-seeds")
    materialize.add_argument("--source-root", type=Path, required=True)
    materialize.add_argument("--private-root", type=Path, required=True)
    materialize.add_argument("--input-name", type=Path, required=True)
    materialize.add_argument("--output-name", type=Path, required=True)
    validate = commands.add_parser("validate-intent")
    validate.add_argument("--source-root", type=Path, required=True)
    validate.add_argument("--private-root", type=Path, required=True)
    validate.add_argument("--intent-name", type=Path, required=True)
    authorize_create = commands.add_parser("authorize-creation")
    authorize_create.add_argument("--source-root", type=Path, required=True)
    authorize_create.add_argument("--private-root", type=Path, required=True)
    authorize_create.add_argument("--intent-name", type=Path, required=True)
    authorize_create.add_argument(
        "--target", choices=route.TARGETS, required=True
    )
    authorize_create.add_argument("--authorization", required=True)
    authorize_create.add_argument("--ttl-seconds", type=int, required=True)
    authorize_create.add_argument("--output-name", type=Path, required=True)
    authorize = commands.add_parser("authorize-execution")
    authorize.add_argument("--source-root", type=Path, required=True)
    authorize.add_argument("--private-root", type=Path, required=True)
    authorize.add_argument("--intent-name", type=Path, required=True)
    authorize.add_argument("--attestation-name", type=Path, required=True)
    authorize.add_argument("--target", choices=route.TARGETS, required=True)
    authorize.add_argument("--authorization", required=True)
    authorize.add_argument("--ttl-seconds", type=int, required=True)
    authorize.add_argument("--output-name", type=Path, required=True)
    execute = commands.add_parser("materialize-execution-intent")
    execute.add_argument("--source-root", type=Path, required=True)
    execute.add_argument("--private-root", type=Path, required=True)
    execute.add_argument("--intent-name", type=Path, required=True)
    execute.add_argument("--attestation-name", type=Path, required=True)
    execute.add_argument("--authorization-name", type=Path, required=True)
    execute.add_argument("--output-name", type=Path, required=True)
    config = commands.add_parser("materialize-broker-config")
    config.add_argument("--source-root", type=Path, required=True)
    config.add_argument("--private-root", type=Path, required=True)
    config.add_argument("--input-name", type=Path, required=True)
    config.add_argument("--plan-snapshot-name", type=Path, required=True)
    config.add_argument("--artifact-bootstrap-intent-name", type=Path, required=True)
    config.add_argument("--foundation-publish-binding-name", type=Path, required=True)
    config.add_argument("--output-name", type=Path, required=True)
    return parser


def _emit(value: Mapping[str, Any]) -> None:
    sys.stdout.write(route.canonical_json(value) + "\n")


def main(argv: Sequence[str] | None = None) -> int:
    root_fd: int | None = None
    try:
        args = _parser().parse_args(argv)
        root, root_fd = _private_root(args.private_root)
        git = route.SubprocessGit(_source_root(args.source_root))
        if args.command == "materialize-seeds":
            value = route.materialize_seed_intent(
                _read(root, root_fd, args.input_name), git=git
            )
            _write(root, root_fd, args.output_name, value)
            status = "MATERIALIZED"
        elif args.command == "validate-intent":
            value = route.validate_seed_intent_against_git(
                _read(root, root_fd, args.intent_name), git=git
            )
            status = "VALID"
        elif args.command == "authorize-creation":
            if not 60 <= args.ttl_seconds <= 900:
                raise route.RouteSeedError("AUTHORIZATION_TTL_INVALID")
            seed = _read(root, root_fd, args.intent_name)
            route.validate_seed_intent_against_git(seed, git=git)
            now = datetime.now(timezone.utc).replace(microsecond=0)
            value = route.materialize_creation_authorization(
                seed_intent=seed,
                target=args.target,
                authorization=args.authorization,
                authorized_at=now.isoformat().replace("+00:00", "Z"),
                expires_at=(now + timedelta(seconds=args.ttl_seconds))
                .isoformat()
                .replace("+00:00", "Z"),
            )
            _write(root, root_fd, args.output_name, value)
            status = "MATERIALIZED"
        elif args.command == "authorize-execution":
            if not 60 <= args.ttl_seconds <= 900:
                raise route.RouteSeedError("AUTHORIZATION_TTL_INVALID")
            seed = _read(root, root_fd, args.intent_name)
            route.validate_seed_intent_against_git(seed, git=git)
            attestation = _read(root, root_fd, args.attestation_name)
            if attestation.get("target") != args.target:
                raise route.RouteSeedError("TARGET_INVALID")
            now = datetime.now(timezone.utc).replace(microsecond=0)
            value = route.materialize_execution_authorization(
                seed_intent=seed,
                create_attestation=attestation,
                authorization=args.authorization,
                authorized_at=now.isoformat().replace("+00:00", "Z"),
                expires_at=(now + timedelta(seconds=args.ttl_seconds))
                .isoformat()
                .replace("+00:00", "Z"),
            )
            _write(root, root_fd, args.output_name, value)
            status = "MATERIALIZED"
        elif args.command == "materialize-execution-intent":
            seed = _read(root, root_fd, args.intent_name)
            route.validate_seed_intent_against_git(seed, git=git)
            value = route.materialize_execution_intent(
                seed_intent=seed,
                create_attestation=_read(root, root_fd, args.attestation_name),
                authorization=_read(root, root_fd, args.authorization_name),
            )
            _write(root, root_fd, args.output_name, value)
            status = "MATERIALIZED"
        else:
            evaluated = datetime.now(timezone.utc).replace(microsecond=0)
            raw = broker_config.bind_plan_snapshot(
                _read(root, root_fd, args.input_name),
                plan_snapshot=_read(root, root_fd, args.plan_snapshot_name),
                now=evaluated,
            )
            source_commit = raw.get("source_commit")
            source_root = _source_root(args.source_root)
            if (
                not isinstance(source_commit, str)
                or git.root() != source_root
                or git.branch() != "main"
                or git.head() != source_commit
                or git.origin_main() != source_commit
                or git.status() != ""
            ):
                raise route.RouteSeedError("CLEAN_MAIN_REQUIRED")
            bootstrap_intent = artifact_bootstrap.validate_bootstrap_intent(
                _read(root, root_fd, args.artifact_bootstrap_intent_name)
            )
            storage_binding = artifact_bootstrap.validate_foundation_publish_binding(
                _read(root, root_fd, args.foundation_publish_binding_name),
                bootstrap_intent=bootstrap_intent,
            )
            if (
                bootstrap_intent.get("source_commit") != source_commit
                or raw.get("artifact_bootstrap_intent") != bootstrap_intent
                or raw.get("foundation_publish_binding") != storage_binding
            ):
                raise route.RouteSeedError("FOUNDATION_PUBLISH_BINDING_INVALID")
            value = broker_config.materialize_broker_seed_input(
                raw,
                git=git,
                expected_storage_binding=storage_binding,
                now=evaluated,
            )
            _write(root, root_fd, args.output_name, value)
            status = "MATERIALIZED"
        _emit(
            {
                "status": status,
                "record_type": value["record_type"],
                "aws_calls": 0,
                "aws_mutations": 0,
                "production_authorized": False,
                "production_status": route.PRODUCTION_STATUS,
            }
        )
        return 0
    except (
        route.RouteSeedError,
        broker_config.BrokerConfigMaterializationError,
        artifact_bootstrap.ArtifactBootstrapError,
    ) as exc:
        _emit(
            {
                "status": "BLOCKED",
                "reason_code": exc.code,
                "aws_calls": 0,
                "aws_mutations": 0,
                "production_authorized": False,
                "production_status": route.PRODUCTION_STATUS,
            }
        )
        return 2
    finally:
        if root_fd is not None:
            os.close(root_fd)


if __name__ == "__main__":
    raise SystemExit(main())
