#!/usr/bin/env python3
"""Private, write-once CLI for the staged GUG-376 artifact bootstrap."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import subprocess
import sys
from typing import Any, Mapping


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tooling import (  # noqa: E402
    platform_authority_plan_permission_repair_artifact_bootstrap as contract,
)


_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_COMMIT_RE = re.compile(r"^[a-f0-9]{40}$")
_MAX_PRIVATE_BYTES = 16 * 1024 * 1024
_ROUTE_TERMINAL_PROFILE = "839393571433_AWSAdministratorAccess"
_BROKER_TERMINAL_PROFILE = "042360977644_ScanalyzeGug376BrokerSeedExec"
_CLEANUP_TARGETS = ("route", "broker", "broker-protection")


class CliError(RuntimeError):
    pass


def _aws_module() -> Any:
    from tooling import (
        platform_authority_plan_permission_repair_artifact_bootstrap_aws as module,
    )

    return module


def _time(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise CliError("TIME_INVALID")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise CliError("TIME_INVALID") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise CliError("TIME_INVALID")
    return parsed.astimezone(timezone.utc).replace(microsecond=0)


def _open_private_root(path: Path) -> tuple[Path, int]:
    if not path.is_absolute() or path.is_symlink():
        raise CliError("PRIVATE_ROOT_INVALID")
    try:
        root = path.resolve(strict=True)
        metadata = root.lstat()
    except OSError as exc:
        raise CliError("PRIVATE_ROOT_INVALID") from exc
    if (
        root != path
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise CliError("PRIVATE_ROOT_INVALID")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory is None:
        raise CliError("NOFOLLOW_UNAVAILABLE")
    try:
        descriptor = os.open(root, os.O_RDONLY | nofollow | directory)
        opened = os.fstat(descriptor)
    except OSError as exc:
        raise CliError("PRIVATE_ROOT_INVALID") from exc
    if (
        opened.st_dev != metadata.st_dev
        or opened.st_ino != metadata.st_ino
        or stat.S_IMODE(opened.st_mode) != 0o700
    ):
        os.close(descriptor)
        raise CliError("PRIVATE_ROOT_INVALID")
    return root, descriptor


def _name(value: str) -> str:
    if _NAME_RE.fullmatch(value) is None:
        raise CliError("PRIVATE_NAME_INVALID")
    return value


def _read_bytes(root_descriptor: int, name: str) -> bytes:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise CliError("NOFOLLOW_UNAVAILABLE")
    try:
        descriptor = os.open(
            _name(name), os.O_RDONLY | nofollow, dir_fd=root_descriptor
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size > _MAX_PRIVATE_BYTES
        ):
            raise CliError("PRIVATE_INPUT_INVALID")
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining > 0:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                raise CliError("PRIVATE_INPUT_CHANGED")
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if os.read(descriptor, 1) != b"":
            raise CliError("PRIVATE_INPUT_CHANGED")
        observed = os.fstat(descriptor)
        if (
            observed.st_dev != metadata.st_dev
            or observed.st_ino != metadata.st_ino
            or observed.st_size != metadata.st_size
            or observed.st_nlink != 1
            or observed.st_uid != metadata.st_uid
            or stat.S_IMODE(observed.st_mode) != 0o600
        ):
            raise CliError("PRIVATE_INPUT_CHANGED")
        return payload
    except OSError as exc:
        raise CliError("PRIVATE_INPUT_INVALID") from exc
    finally:
        if "descriptor" in locals():
            os.close(descriptor)


def _json(root_descriptor: int, name: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(
            _read_bytes(root_descriptor, name).decode("utf-8"),
            object_pairs_hook=reject_duplicates,
        )
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise CliError("PRIVATE_JSON_INVALID") from exc
    if not isinstance(value, dict):
        raise CliError("PRIVATE_JSON_INVALID")
    return value


def _write_all(descriptor: int, payload: bytes) -> None:
    remaining = memoryview(payload)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError("short write")
        remaining = remaining[written:]


def _reserve_output(
    root_descriptor: int,
    name: str,
    *,
    action: str,
    bundle_name: str,
) -> tuple[int, int, int, dict[str, Any]]:
    """Create and durably seal the output tombstone before any connected action."""

    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise CliError("NOFOLLOW_UNAVAILABLE")
    marker: dict[str, Any] = {
        "schema_version": 1,
        "record_type": "gug376-artifact-bootstrap-output-reservation",
        "action": action,
        "bundle_name": _name(bundle_name),
        "status": "ATTEMPTING",
    }
    marker["reservation_digest"] = contract.digest_value(marker)
    payload = (contract.canonical_json(marker) + "\n").encode("utf-8")
    try:
        descriptor = os.open(
            _name(name),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow,
            0o600,
            dir_fd=root_descriptor,
        )
    except FileExistsError as exc:
        raise CliError("PRIVATE_OUTPUT_EXISTS") from exc
    except OSError as exc:
        raise CliError("PRIVATE_OUTPUT_CREATE_FAILED") from exc
    try:
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        os.fsync(root_descriptor)
    except OSError as exc:
        os.close(descriptor)
        raise CliError("PRIVATE_OUTPUT_WRITE_FAILED") from exc
    return descriptor, metadata.st_dev, metadata.st_ino, marker


def _write_reserved(
    root_descriptor: int,
    name: str,
    reservation: tuple[int, int, int, Mapping[str, Any]],
    value: Mapping[str, Any],
) -> None:
    """Finish a pre-existing reservation through its still-open descriptor."""

    descriptor, device, inode, marker = reservation
    payload = (contract.canonical_json(value) + "\n").encode("utf-8")
    if len(payload) > _MAX_PRIVATE_BYTES:
        raise CliError("PRIVATE_OUTPUT_TOO_LARGE")
    try:
        linked = os.stat(
            _name(name), dir_fd=root_descriptor, follow_symlinks=False
        )
        opened = os.fstat(descriptor)
    except OSError as exc:
        raise CliError("PRIVATE_OUTPUT_RESERVATION_CHANGED") from exc
    if (
        linked.st_dev != device
        or linked.st_ino != inode
        or opened.st_dev != device
        or opened.st_ino != inode
        or not stat.S_ISREG(opened.st_mode)
        or opened.st_uid != os.geteuid()
        or stat.S_IMODE(opened.st_mode) != 0o600
    ):
        raise CliError("PRIVATE_OUTPUT_RESERVATION_CHANGED")
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        os.ftruncate(descriptor, 0)
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        os.fsync(root_descriptor)
    except OSError as exc:
        # Preserve a canonical fail-closed tombstone on the already reserved inode.
        failed = dict(marker)
        failed["status"] = "OUTPUT_WRITE_FAILED"
        failed.pop("reservation_digest", None)
        failed["reservation_digest"] = contract.digest_value(failed)
        tombstone = (contract.canonical_json(failed) + "\n").encode("utf-8")
        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
            os.ftruncate(descriptor, 0)
            _write_all(descriptor, tombstone)
            os.fsync(descriptor)
            os.fsync(root_descriptor)
        except OSError:
            pass
        raise CliError("PRIVATE_OUTPUT_WRITE_FAILED") from exc


def _exact(value: Mapping[str, Any], fields: set[str]) -> dict[str, Any]:
    if set(value) != fields:
        raise CliError("BUNDLE_FIELDS_INVALID")
    return dict(value)


def _git_blob(*, source_root: Path, source_commit: str, path: str) -> bytes:
    _aws_module().read_clean_reviewed_source_bytes(
        source_root=source_root, source_commit=source_commit
    )
    parsed = PurePosixPath(path)
    if parsed.is_absolute() or ".." in parsed.parts or not parsed.parts:
        raise CliError("SOURCE_PATH_INVALID")
    try:
        result = subprocess.run(
            ["git", "-C", str(source_root), "show", f"{source_commit}:{path}"],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CliError("SOURCE_READ_FAILED") from exc
    if result.returncode != 0 or len(result.stdout) > _MAX_PRIVATE_BYTES:
        raise CliError("SOURCE_READ_FAILED")
    return result.stdout


def _body(
    descriptor: Mapping[str, Any],
    *,
    source_root: Path,
    bootstrap_intent: Mapping[str, Any],
) -> bytes:
    bootstrap = contract.validate_bootstrap_intent(bootstrap_intent)
    kind = descriptor.get("kind")
    if kind == "git":
        _exact(descriptor, {"kind", "source_path"})
        return _git_blob(
            source_root=source_root,
            source_commit=bootstrap["source_commit"],
            path=str(descriptor["source_path"]),
        )
    if kind == "broker-package":
        _exact(descriptor, {"kind"})
        from tooling.platform_authority_plan_permission_repair_broker_seed import (
            build_broker_package,
        )

        return build_broker_package(
            source_root=source_root,
            source_commit=bootstrap["source_commit"],
        )
    if kind == "pep-package":
        _exact(
            descriptor,
            {"kind", "expected_boto3_version", "expected_botocore_version"},
        )
        from tooling.platform_authority_plan_permission_repair_package import (
            build_plan_permission_repair_package,
            verify_clean_source_commit,
        )

        committed = verify_clean_source_commit(
            source_root=source_root,
            source_commit=bootstrap["source_commit"],
        )
        return build_plan_permission_repair_package(
            source_root=source_root,
            source_commit=bootstrap["source_commit"],
            expected_boto3_version=str(descriptor["expected_boto3_version"]),
            expected_botocore_version=str(
                descriptor["expected_botocore_version"]
            ),
            committed_sources=committed,
        ).archive
    if kind in {"broker-template", "broker-protection-template"}:
        _exact(descriptor, {"kind", "broker_seed_input"})
        from tooling.platform_authority_plan_permission_repair_broker_seed import (
            render_template,
        )

        return render_template(
            source_root=source_root,
            private_input=descriptor["broker_seed_input"],
            protection_enabled=(kind == "broker-protection-template"),
        )
    raise CliError("BODY_BUILDER_INVALID")


def _offline(
    action: str,
    bundle: Mapping[str, Any],
    *,
    source_root: Path,
) -> dict[str, Any]:
    if action == "materialize-intent":
        data = _exact(bundle, {"input"})
        source_commit = data["input"].get("source_commit")
        if not isinstance(source_commit, str) or _COMMIT_RE.fullmatch(source_commit) is None:
            raise CliError("SOURCE_COMMIT_INVALID")
        sources = _aws_module().read_clean_reviewed_source_bytes(
            source_root=source_root, source_commit=source_commit
        )
        return contract.materialize_bootstrap_intent(
            data["input"],
            bridge_template=sources["bridge"],
            foundation_template=sources["foundation"],
        )
    if action == "authorize-change-set":
        data = _exact(
            bundle,
            {"intent", "operation", "authorization", "authorized_at", "expires_at"},
        )
        return contract.materialize_authorization(
            intent=data["intent"],
            operation=data["operation"],
            authorization=data["authorization"],
            authorized_at=_time(data["authorized_at"]),
            expires_at=_time(data["expires_at"]),
        )
    if action == "authorize-mutation":
        data = _exact(
            bundle,
            {
                "bootstrap_intent",
                "operation",
                "target_digest",
                "authorization",
                "authorized_at",
                "expires_at",
            },
        )
        return contract.materialize_mutation_authorization(
            bootstrap_intent=data["bootstrap_intent"],
            operation=data["operation"],
            target_digest=data["target_digest"],
            authorization=data["authorization"],
            authorized_at=_time(data["authorized_at"]),
            expires_at=_time(data["expires_at"]),
        )
    if action == "materialize-bridge-pin":
        data = _exact(bundle, {"bootstrap_intent", "foundation_readback"})
        sources = _aws_module().read_clean_reviewed_source_bytes(
            source_root=source_root,
            source_commit=data["bootstrap_intent"]["source_commit"],
        )
        return contract.materialize_bridge_pin(
            bootstrap_intent=data["bootstrap_intent"],
            foundation_readback=data["foundation_readback"],
            bridge_template=sources["bridge"],
        )
    if action == "materialize-object-intent":
        data = _exact(
            bundle,
            {"bootstrap_intent", "foundation_readback", "key", "content_type", "body"},
        )
        body = _body(
            data["body"],
            source_root=source_root,
            bootstrap_intent=data["bootstrap_intent"],
        )
        return contract.materialize_object_intent(
            bootstrap_intent=data["bootstrap_intent"],
            foundation_readback=data["foundation_readback"],
            key=data["key"],
            body=body,
            content_type=data["content_type"],
            mutation_nonce=secrets.token_hex(32),
        )
    if action == "materialize-signing-intent":
        data = _exact(
            bundle,
            {
                "bootstrap_intent",
                "foundation_readback",
                "bridge_pin",
                "bridge_pin_readback",
                "unsigned_receipt",
                "destination_prefix",
                "profile_name",
            },
        )
        return contract.materialize_signing_intent(**data)
    if action == "materialize-access-update":
        data = _exact(
            bundle,
            {
                "bootstrap_intent",
                "foundation_readback",
                "route_template_receipt",
                "delegation_template_receipt",
            },
        )
        reviewed = _aws_module().attest_clean_reviewed_sources(
            source_root=source_root,
            bootstrap_intent=data["bootstrap_intent"],
        )
        sources = _aws_module().read_clean_reviewed_source_bytes(
            source_root=source_root,
            source_commit=data["bootstrap_intent"]["source_commit"],
        )
        return contract.materialize_foundation_access_update(
            **data,
            reviewed_sources=reviewed,
            foundation_template=sources["foundation"],
        )
    if action == "materialize-publish-binding":
        data = _exact(
            bundle,
            {
                "bootstrap_intent",
                "foundation_readback",
                "access_update",
                "access_readback",
                "route_template_receipt",
                "delegation_template_receipt",
            },
        )
        reviewed = _aws_module().attest_clean_reviewed_sources(
            source_root=source_root,
            bootstrap_intent=data["bootstrap_intent"],
        )
        return contract.materialize_foundation_publish_binding(
            **data, reviewed_sources=reviewed
        )
    if action == "materialize-route-release":
        fields = {
            "bootstrap_intent", "foundation_readback", "access_update",
            "access_readback", "foundation_publish_binding", "bridge_pin",
            "bridge_pin_readback", "bridge_revoke_readback",
            "route_template_receipt", "delegation_template_receipt",
            "template_readbacks", "pep_signed_artifact_receipt",
            "broker_seed_input", "broker_seed_receipts", "now",
        }
        data = _exact(bundle, fields)
        reviewed = _aws_module().attest_clean_reviewed_sources(
            source_root=source_root,
            bootstrap_intent=data["bootstrap_intent"],
        )
        now = _time(data.pop("now"))
        return contract.materialize_route_release(
            **data, reviewed_sources=reviewed, now=now
        )
    if action == "materialize-cleanup-retire":
        data = _exact(
            bundle,
            {
                "bootstrap_intent",
                "bridge_revoke_readback",
                "mode",
                "evaluated_at",
                "bootstrap_route_release",
                "seed_input",
                "seed_intent",
                "terminal_readbacks",
            },
        )
        evaluated_at = _time(data.pop("evaluated_at"))
        seed_input = data.pop("seed_input")
        if data["mode"] == "SUCCESS":
            if not isinstance(seed_input, Mapping) or not isinstance(
                data["seed_intent"], Mapping
            ):
                raise CliError("CLEANUP_RETIRE_SEED_INPUT_REQUIRED")
            route, _connected_route = _seed_modules()
            data["seed_intent"] = route.validate_seed_intent_against_input(
                data["seed_intent"],
                seed_input=seed_input,
                git=route.SubprocessGit(source_root),
                now=evaluated_at,
            )
        elif data["mode"] == "EXPIRED":
            if seed_input is not None:
                raise CliError("CLEANUP_RETIRE_EXPIRED_SEED_INPUT_FORBIDDEN")
        else:
            raise CliError("CLEANUP_RETIRE_MODE_INVALID")
        sources = _aws_module().read_clean_reviewed_source_bytes(
            source_root=source_root,
            source_commit=data["bootstrap_intent"]["source_commit"],
        )
        return contract.materialize_bridge_cleanup_retire(
            **data,
            bridge_template=sources["bridge"],
            evaluated_at=evaluated_at,
        )
    if action == "authorize-cleanup-retire":
        data = _exact(
            bundle,
            {
                "cleanup_retire",
                "operation",
                "authorization",
                "authorized_at",
                "expires_at",
            },
        )
        return contract.materialize_bridge_cleanup_retire_authorization(
            cleanup_retire=data["cleanup_retire"],
            operation=data["operation"],
            authorization=data["authorization"],
            authorized_at=_time(data["authorized_at"]),
            expires_at=_time(data["expires_at"]),
        )
    raise CliError("ACTION_INVALID")


_CLEANUP_CONNECTED_FIELDS = {
    "bootstrap_intent",
    "cleanup_retire",
    "bridge_revoke_readback",
    "bootstrap_route_release",
    "seed_input",
    "seed_intent",
    "terminal_readbacks",
    "terminal_revalidation",
}


_CONNECTED_FIELDS: dict[str, set[str]] = {
    "dispatch-change-set": {"bootstrap_intent", "operation", "authorization"},
    "recover-change-set": {"bootstrap_intent", "operation"},
    "execute-change-set": {
        "bootstrap_intent", "operation", "dispatch_receipt",
        "change_set_attestation", "authorization",
    },
    "recover-change-set-execution": {
        "bootstrap_intent", "operation", "dispatch_receipt",
        "change_set_attestation",
    },
    "attest-change-set": {
        "bootstrap_intent", "operation", "dispatch_receipt", "access_update",
        "route_template_receipt", "delegation_template_receipt", "bridge_pin",
        "foundation_readback",
    },
    "dispatch-bridge-pin": {
        "bootstrap_intent", "foundation_readback", "bridge_pin", "authorization",
    },
    "execute-bridge-pin": {
        "bootstrap_intent", "foundation_readback", "bridge_pin",
        "dispatch_receipt", "change_set_attestation", "authorization",
    },
    "recover-bridge-pin": {
        "bootstrap_intent", "foundation_readback", "bridge_pin",
    },
    "recover-bridge-pin-execution": {
        "bootstrap_intent", "foundation_readback", "bridge_pin",
        "dispatch_receipt", "change_set_attestation",
    },
    "dispatch-access-update": {
        "bootstrap_intent", "foundation_readback", "access_update",
        "route_template_receipt", "delegation_template_receipt", "authorization",
    },
    "execute-access-update": {
        "bootstrap_intent", "foundation_readback", "access_update",
        "route_template_receipt", "delegation_template_receipt",
        "dispatch_receipt", "change_set_attestation", "authorization",
    },
    "recover-access-update": {
        "bootstrap_intent", "foundation_readback", "access_update",
        "route_template_receipt", "delegation_template_receipt",
    },
    "recover-access-update-execution": {
        "bootstrap_intent", "foundation_readback", "access_update",
        "route_template_receipt", "delegation_template_receipt",
        "dispatch_receipt", "change_set_attestation",
    },
    "readback-access-update": {
        "bootstrap_intent", "foundation_readback", "access_update",
        "route_template_receipt", "delegation_template_receipt",
    },
    "readback-stack": {
        "bootstrap_intent", "operation", "bridge_pin", "foundation_readback",
    },
    "readback-foundation": {"bootstrap_intent"},
    "publish-object": {
        "bootstrap_intent", "foundation_readback", "object_intent", "body",
        "authorization",
    },
    "readback-object": {
        "bootstrap_intent", "foundation_readback", "object_intent",
        "dispatch_receipt",
    },
    "recover-object": {"bootstrap_intent", "foundation_readback", "object_intent"},
    "start-signing-job": {
        "bootstrap_intent", "foundation_readback", "bridge_pin",
        "bridge_pin_readback", "unsigned_receipt", "signing_intent",
        "authorization",
    },
    "readback-signing-job": {
        "bootstrap_intent", "foundation_readback", "bridge_pin",
        "bridge_pin_readback", "unsigned_receipt", "signing_intent",
        "dispatch_receipt",
    },
    "recover-signing-job": {
        "bootstrap_intent", "foundation_readback", "bridge_pin",
        "bridge_pin_readback", "unsigned_receipt", "signing_intent",
    },
    "dispatch-cleanup-retire": _CLEANUP_CONNECTED_FIELDS | {"authorization"},
    "attest-cleanup-retire": _CLEANUP_CONNECTED_FIELDS | {"dispatch_receipt"},
    "execute-cleanup-retire": _CLEANUP_CONNECTED_FIELDS
    | {"dispatch_receipt", "change_set_attestation", "authorization"},
    "recover-cleanup-retire": set(_CLEANUP_CONNECTED_FIELDS),
    "recover-cleanup-retire-execution": _CLEANUP_CONNECTED_FIELDS
    | {"dispatch_receipt", "change_set_attestation"},
    "readback-cleanup-retire": set(_CLEANUP_CONNECTED_FIELDS),
}


_CONNECTED_METHODS = {
    "dispatch-change-set": "dispatch_change_set_once",
    "recover-change-set": "recover_change_set",
    "execute-change-set": "execute_change_set_once",
    "recover-change-set-execution": "recover_change_set_execution",
    "attest-change-set": "attest_change_set",
    "dispatch-bridge-pin": "dispatch_bridge_pin_once",
    "execute-bridge-pin": "execute_bridge_pin_once",
    "recover-bridge-pin": "recover_bridge_pin",
    "recover-bridge-pin-execution": "recover_bridge_pin_execution",
    "dispatch-access-update": "dispatch_foundation_access_update_once",
    "execute-access-update": "execute_foundation_access_update_once",
    "recover-access-update": "recover_foundation_access_update",
    "recover-access-update-execution": (
        "recover_foundation_access_update_execution"
    ),
    "readback-access-update": "readback_foundation_access_update",
    "readback-stack": "readback_stack",
    "readback-foundation": "readback_foundation",
    "publish-object": "publish_object_once",
    "readback-object": "readback_object",
    "recover-object": "recover_object_publish",
    "start-signing-job": "start_signing_job_once",
    "readback-signing-job": "readback_signing_job",
    "recover-signing-job": "recover_signing_job",
    "dispatch-cleanup-retire": "dispatch_change_set_once",
    "attest-cleanup-retire": "attest_change_set",
    "execute-cleanup-retire": "execute_change_set_once",
    "recover-cleanup-retire": "recover_change_set",
    "recover-cleanup-retire-execution": "recover_change_set_execution",
    "readback-cleanup-retire": "readback_stack",
}


_CLEANUP_CONNECTED_ACTIONS = frozenset(
    {
        "dispatch-cleanup-retire",
        "attest-cleanup-retire",
        "execute-cleanup-retire",
        "recover-cleanup-retire",
        "recover-cleanup-retire-execution",
        "readback-cleanup-retire",
    }
)


def _seed_modules() -> tuple[Any, Any]:
    from tooling import (
        platform_authority_plan_permission_repair_deployment_route as route,
    )
    from tooling import (
        platform_authority_plan_permission_repair_deployment_route_aws
        as connected,
    )

    return route, connected


def _seed_provider(
    *,
    profile: str,
    claim_root: Path,
    session_factory: Any,
    config_type: Any,
) -> tuple[Any, Any]:
    """Build one exact-profile terminal provider over the shared claim root."""

    _route, connected = _seed_modules()
    session = session_factory(profile_name=profile, region_name=contract.REGION)
    explicit_environment = dict(os.environ)
    explicit_environment["AWS_PROFILE"] = profile
    explicit_environment["AWS_DEFAULT_PROFILE"] = profile
    clients = connected.clients_from_session(
        session,
        config_type,
        expected_profile=profile,
        environment=explicit_environment,
    )
    claims = connected.OExclClaimStore(claim_root)
    try:
        provider = connected.ConnectedSeedProvider(
            clients=clients,
            claims=claims,
            clock=lambda: datetime.now(timezone.utc),
        )
    except Exception:
        claims.close()
        raise
    return provider, claims


def _cleanup_success_revalidator(
    *,
    source_root: Path,
    claim_root: Path,
    seed_intent: Mapping[str, Any],
    seed_input: Mapping[str, Any],
    terminal_readbacks: Mapping[str, Any],
    terminal_revalidation: Mapping[str, Any],
    session_factory: Any,
    config_type: Any,
) -> Any:
    """Build the non-injectable JIT rereader used by SUCCESS cleanup."""

    if (
        not isinstance(terminal_readbacks, Mapping)
        or set(terminal_readbacks) != set(_CLEANUP_TARGETS)
        or not isinstance(terminal_revalidation, Mapping)
        or set(terminal_revalidation) != set(_CLEANUP_TARGETS)
    ):
        raise CliError("CLEANUP_RETIRE_TERMINAL_REVALIDATION_INVALID")
    for target in _CLEANUP_TARGETS:
        item = terminal_revalidation[target]
        if not isinstance(item, Mapping):
            raise CliError("CLEANUP_RETIRE_TERMINAL_REVALIDATION_INVALID")
        normalized = _exact(item, {"execution_intent", "execution_receipt"})
        if (
            not isinstance(normalized["execution_intent"], Mapping)
            or not isinstance(normalized["execution_receipt"], Mapping)
            or normalized["execution_intent"].get("target") != target
            or normalized["execution_receipt"].get("target") != target
            or not isinstance(terminal_readbacks[target], Mapping)
            or terminal_readbacks[target].get("target") != target
        ):
            raise CliError("CLEANUP_RETIRE_TERMINAL_REVALIDATION_INVALID")

    route, _connected_route = _seed_modules()
    git = route.SubprocessGit(source_root)
    validated_seed = route.validate_seed_intent_against_input(
        seed_intent,
        seed_input=seed_input,
        git=git,
        now=datetime.now(timezone.utc),
    )
    expected_seed = contract.canonical_json(validated_seed)
    expected_terminals = contract.canonical_json(dict(terminal_readbacks))

    def revalidate(
        *,
        seed_intent: Mapping[str, Any],
        terminal_readbacks: Mapping[str, Any],
    ) -> dict[str, Any]:
        if (
            contract.canonical_json(dict(seed_intent)) != expected_seed
            or contract.canonical_json(dict(terminal_readbacks))
            != expected_terminals
        ):
            raise CliError("CLEANUP_RETIRE_LIVE_REVALIDATION_INPUT_INVALID")

        live: dict[str, Any] = {}
        route_provider = None
        route_claims = None
        broker_provider = None
        broker_claims = None
        try:
            route_provider, route_claims = _seed_provider(
                profile=_ROUTE_TERMINAL_PROFILE,
                claim_root=claim_root,
                session_factory=session_factory,
                config_type=config_type,
            )
            route_item = terminal_revalidation["route"]
            live["route"] = route_provider.terminal_readback(
                seed_intent=validated_seed,
                execution_intent=route_item["execution_intent"],
                execution_receipt=route_item["execution_receipt"],
            )

            broker_provider, broker_claims = _seed_provider(
                profile=_BROKER_TERMINAL_PROFILE,
                claim_root=claim_root,
                session_factory=session_factory,
                config_type=config_type,
            )
            for target in ("broker", "broker-protection"):
                item = terminal_revalidation[target]
                live[target] = broker_provider.terminal_readback(
                    seed_intent=validated_seed,
                    execution_intent=item["execution_intent"],
                    execution_receipt=item["execution_receipt"],
                )
            return live
        finally:
            if broker_claims is not None:
                broker_claims.close()
            if route_claims is not None:
                route_claims.close()

    return revalidate


def _connected(
    action: str,
    bundle: Mapping[str, Any],
    *,
    source_root: Path,
    profile: str,
    claim_root: Path,
) -> dict[str, Any]:
    data = _exact(bundle, _CONNECTED_FIELDS[action])
    if not claim_root.is_absolute() or claim_root.is_symlink():
        raise CliError("CLAIM_ROOT_INVALID")
    if action == "publish-object":
        data["body"] = _body(
            data["body"],
            source_root=source_root,
            bootstrap_intent=data["bootstrap_intent"],
        )
    try:
        import boto3
        from botocore.config import Config
    except ImportError as exc:
        raise CliError("AWS_SDK_UNAVAILABLE") from exc

    cleanup_revalidator = None
    if action in _CLEANUP_CONNECTED_ACTIONS:
        terminal_revalidation = data.pop("terminal_revalidation")
        seed_input = data.pop("seed_input")
        cleanup_retire = contract.validate_bridge_cleanup_retire(
            data["cleanup_retire"],
            bootstrap_intent=data["bootstrap_intent"],
            bridge_revoke_readback=data["bridge_revoke_readback"],
            bootstrap_route_release=data["bootstrap_route_release"],
            seed_intent=data["seed_intent"],
            terminal_readbacks=data["terminal_readbacks"],
        )
        data["cleanup_retire"] = cleanup_retire
        mode = cleanup_retire["mode"]
        if mode == "SUCCESS":
            if (
                not isinstance(seed_input, Mapping)
                or not isinstance(data["seed_intent"], Mapping)
                or not isinstance(data["terminal_readbacks"], Mapping)
                or not isinstance(terminal_revalidation, Mapping)
            ):
                raise CliError("CLEANUP_RETIRE_TERMINAL_REVALIDATION_REQUIRED")
            cleanup_revalidator = _cleanup_success_revalidator(
                source_root=source_root,
                claim_root=claim_root,
                seed_intent=data["seed_intent"],
                seed_input=seed_input,
                terminal_readbacks=data["terminal_readbacks"],
                terminal_revalidation=terminal_revalidation,
                session_factory=boto3.Session,
                config_type=Config,
            )
        elif mode == "EXPIRED":
            if terminal_revalidation is not None or seed_input is not None:
                raise CliError("CLEANUP_RETIRE_EXPIRED_REVALIDATION_FORBIDDEN")
        else:
            raise CliError("CLEANUP_RETIRE_MODE_INVALID")
        data["operation"] = "bridge-cleanup-retire"

    session = boto3.Session(profile_name=profile, region_name=contract.REGION)
    aws_boundary = _aws_module()
    clients = aws_boundary.clients_from_session(
        session,
        aws_boundary.sdk_client_config(Config),
    )
    claims = aws_boundary.OExclClaimStore(claim_root)
    try:
        provider = aws_boundary.ConnectedArtifactBootstrapProvider(
            clients=clients,
            claims=claims,
            profile=profile,
            clock=lambda: datetime.now(timezone.utc),
            cleanup_success_revalidator=cleanup_revalidator,
        )
        method = getattr(provider, _CONNECTED_METHODS[action])
        return method(**data, source_root=source_root)
    finally:
        claims.close()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Materialize, authorize, execute, recover, and read back the exact "
            "temporary GUG-376 artifact foundation through private write-once files"
        )
    )
    parser.add_argument("--private-root", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    actions = parser.add_subparsers(dest="action", required=True)
    offline = {
        "materialize-intent", "authorize-change-set", "authorize-mutation",
        "materialize-bridge-pin", "materialize-object-intent",
        "materialize-signing-intent", "materialize-access-update",
        "materialize-publish-binding", "materialize-route-release",
        "materialize-cleanup-retire", "authorize-cleanup-retire",
    }
    for action in sorted(offline | set(_CONNECTED_FIELDS)):
        command = actions.add_parser(action)
        command.add_argument("--bundle-name", required=True)
        command.add_argument("--output-name", required=True)
        if action in _CONNECTED_FIELDS:
            allowed_profiles = (
                [contract.MANAGEMENT_PROFILE]
                if action in _CLEANUP_CONNECTED_ACTIONS
                else [contract.MANAGEMENT_PROFILE, contract.AUTHORITY_PROFILE]
            )
            command.add_argument(
                "--profile",
                choices=allowed_profiles,
                required=True,
            )
            command.add_argument("--claim-root", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    root_descriptor = -1
    reservation: tuple[int, int, int, Mapping[str, Any]] | None = None
    try:
        _root, root_descriptor = _open_private_root(args.private_root)
        bundle = _json(root_descriptor, args.bundle_name)
        reservation = _reserve_output(
            root_descriptor,
            args.output_name,
            action=args.action,
            bundle_name=args.bundle_name,
        )
        if args.action in _CONNECTED_FIELDS:
            result = _connected(
                args.action,
                bundle,
                source_root=args.source_root,
                profile=args.profile,
                claim_root=args.claim_root,
            )
        else:
            result = _offline(
                args.action,
                bundle,
                source_root=args.source_root,
            )
        _write_reserved(
            root_descriptor,
            args.output_name,
            reservation,
            result,
        )
        return 0
    except (
        CliError,
        contract.ArtifactBootstrapError,
        RuntimeError,
    ) as exc:
        code = getattr(exc, "code", str(exc))
        print(f"GUG376_ARTIFACT_BOOTSTRAP_CLI_BLOCKED:{code}", file=sys.stderr)
        return 2
    finally:
        if reservation is not None:
            os.close(reservation[0])
        if root_descriptor >= 0:
            os.close(root_descriptor)


if __name__ == "__main__":
    raise SystemExit(main())
