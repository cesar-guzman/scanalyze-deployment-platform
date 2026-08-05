#!/usr/bin/env python3
"""Execute one owner-authorized branch-protection PUT, fail closed.

The executable authorization is a private, canonical JSON envelope whose
SHA-256 is supplied from the owner-approved checkpoint.  The envelope binds
the exact repository, endpoint, bundle, recovery artifact, fresh structured
prewrite result, probe identity, operator, expiry, and zero-retry policy.

Before the request, an authorization-ID marker is durably and exclusively
created in a stable local consumption ledger.  A crash after that point leaves
the authorization consumed, so the operator must reconcile read-only and
obtain a new authorization instead of retrying an ambiguous write.
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import stat
import subprocess
import sys
from typing import Callable


REPO_ROOT = Path(__file__).resolve().parents[2]
EXPECTED_REPOSITORY = "cesar-guzman/scanalyze-deployment-platform"
EXPECTED_ENDPOINT = f"PUT /repos/{EXPECTED_REPOSITORY}/branches/main/protection"
EXPECTED_API_PATH = f"repos/{EXPECTED_REPOSITORY}/branches/main/protection"
EXPECTED_AUTHORIZER_LOGIN = "cesar-guzman"
EXPECTED_GITHUB_HOSTNAME = "github.com"
GITHUB_API_VERSION = "2026-03-10"

# The reviewed freshness requirement is 60 seconds at the write boundary.  A
# separate launch reserve prevents accepting 60.000001 seconds immediately
# before starting the external gh process.
MINIMUM_REMAINING_SECONDS = 60
TRANSPORT_STARTUP_RESERVE_SECONDS = 30
TRANSPORT_TIMEOUT_SECONDS = 10
IDENTITY_TIMEOUT_SECONDS = 10
MINIMUM_LAUNCH_REMAINING_SECONDS = (
    MINIMUM_REMAINING_SECONDS + TRANSPORT_STARTUP_RESERVE_SECONDS
)
MAXIMUM_PREWRITE_AGE_SECONDS = 60

RECOVERY_MODES = frozenset({"EXACT_BEFORE", "FORWARD_ONLY_TARGET"})
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
GIT_SHA_PATTERN = re.compile(r"[0-9a-f]{40}\Z")
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
LOGIN_PATTERN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\Z")
RFC3339_UTC_PATTERN = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:[.][0-9]{1,6})?Z\Z"
)

AUTHORIZATION_FIELDS = frozenset(
    {
        "schema_version",
        "artifact_type",
        "authorization_id",
        "authorizer_login",
        "operator_login",
        "github_hostname",
        "gh_executable_sha256",
        "repository",
        "endpoint",
        "target_payload_sha256",
        "completion_manifest_sha256",
        "recovery_payload_sha256",
        "recovery_mode",
        "prewrite_result_sha256",
        "prewrite_collector_sha256",
        "prewrite_evidence_manifest_sha256",
        "remote_before_sha256",
        "probe_pr_number",
        "probe_head_sha",
        "expires_at",
        "retry_count",
    }
)
PREWRITE_FIELDS = frozenset(
    {
        "schema_version",
        "artifact_type",
        "authorization_id",
        "operator_login",
        "github_hostname",
        "gh_executable_sha256",
        "repository",
        "endpoint",
        "target_payload_sha256",
        "completion_manifest_sha256",
        "recovery_payload_sha256",
        "recovery_mode",
        "prewrite_collector_sha256",
        "prewrite_evidence_manifest_sha256",
        "remote_before_sha256",
        "probe_pr_number",
        "probe_head_sha",
        "observed_at",
        "classification",
        "network_write_attempted",
        "checks",
    }
)
PREWRITE_EVIDENCE_FIELDS = frozenset(
    {"schema_version", "artifact_type", "authorization_id", "artifacts"}
)
REQUIRED_PREWRITE_CHECKS = frozenset(
    {
        "repository_identity",
        "operator_identity",
        "remote_before_digest",
        "branch_protection",
        "rulesets",
        "effective_rules",
        "collaborator_permission",
        "probe_identity",
        "probe_negative_state",
        "required_check_runs",
        "private_vulnerability_reporting",
        "environments",
        "auto_merge",
    }
)


class AuthorizedWriteError(RuntimeError):
    """Raised when the write boundary cannot be proven safe."""


@dataclass(frozen=True)
class WriteAttemptResult:
    """Lossless transport evidence returned by the one-shot callback."""

    return_code: int
    artifact_kind: str
    artifact_content: bytes


@dataclass(frozen=True)
class AuthorizationBoundaryResult:
    """Sanitized deterministic evidence for the authorization boundary."""

    classification: str
    receipt: dict[str, object]


Clock = Callable[[], datetime]
NetworkWrite = Callable[[bytes], WriteAttemptResult]
OperatorIdentityCheck = Callable[[], str]


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise AuthorizedWriteError(f"duplicate JSON key: {key!r}")
        document[key] = value
    return document


def _reject_nonfinite(value: str) -> None:
    raise AuthorizedWriteError(f"non-finite JSON value is prohibited: {value}")


def _canonical_bytes(document: dict[str, object]) -> bytes:
    return (
        json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _parse_canonical_object(content: bytes, *, role: str) -> dict[str, object]:
    try:
        document = json.loads(
            content,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_nonfinite,
        )
    except AuthorizedWriteError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise AuthorizedWriteError(f"{role} is invalid JSON: {exc}") from None
    if not isinstance(document, dict):
        raise AuthorizedWriteError(f"{role} must be a JSON object")
    if _canonical_bytes(document) != content:
        raise AuthorizedWriteError(f"{role} must use canonical JSON encoding")
    return document


def _absolute_without_resolving(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _reject_symlink_components(path: Path) -> None:
    absolute = _absolute_without_resolving(path)
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(metadata.st_mode):
            raise AuthorizedWriteError(f"symlinked operational path is prohibited: {path}")


def _ensure_outside_repository(path: Path) -> None:
    absolute = _absolute_without_resolving(path)
    repository = REPO_ROOT.resolve()
    for candidate in (absolute, *absolute.parents):
        try:
            if candidate.samefile(repository):
                raise AuthorizedWriteError(
                    f"operational evidence must stay outside the repository: {path}"
                )
        except OSError:
            continue
    try:
        absolute.resolve(strict=False).relative_to(repository)
    except ValueError:
        return
    raise AuthorizedWriteError(
        f"operational evidence must stay outside the repository: {path}"
    )


def _validate_private_directory(path: Path, *, role: str) -> None:
    _reject_symlink_components(path)
    _ensure_outside_repository(path)
    try:
        metadata = path.stat()
    except OSError as exc:
        raise AuthorizedWriteError(f"unable to inspect {role} {path}: {exc}") from None
    if not stat.S_ISDIR(metadata.st_mode):
        raise AuthorizedWriteError(f"{role} is not a directory: {path}")
    if metadata.st_uid != os.getuid():
        raise AuthorizedWriteError(f"{role} must be owned by the current user: {path}")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise AuthorizedWriteError(f"{role} must use mode 0700: {path}")


def _validate_private_input(path: Path, *, role: str) -> bytes:
    _reject_symlink_components(path)
    _ensure_outside_repository(path)
    _validate_private_directory(path.parent, role="run directory")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise AuthorizedWriteError(f"unable to inspect {role} {path}: {exc}") from None
    if not stat.S_ISREG(metadata.st_mode):
        raise AuthorizedWriteError(f"{role} must be a regular file: {path}")
    if metadata.st_uid != os.getuid():
        raise AuthorizedWriteError(f"{role} must be owned by the current user: {path}")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise AuthorizedWriteError(f"{role} must use mode 0600: {path}")
    if metadata.st_nlink != 1:
        raise AuthorizedWriteError(f"hard-linked {role} is prohibited: {path}")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        opened_metadata = os.fstat(descriptor)
        if (opened_metadata.st_dev, opened_metadata.st_ino) != (
            metadata.st_dev,
            metadata.st_ino,
        ):
            raise AuthorizedWriteError(f"{role} changed while opening: {path}")
        if not stat.S_ISREG(opened_metadata.st_mode) or opened_metadata.st_nlink != 1:
            raise AuthorizedWriteError(f"{role} identity is unsafe: {path}")
        with os.fdopen(descriptor, "rb") as source:
            descriptor = -1
            content = source.read()
    except AuthorizedWriteError:
        raise
    except OSError as exc:
        raise AuthorizedWriteError(f"unable to read {role} {path}: {exc}") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not content:
        raise AuthorizedWriteError(f"{role} must not be empty: {path}")
    if len(content) != opened_metadata.st_size:
        raise AuthorizedWriteError(f"{role} changed while reading: {path}")
    return content


def _snapshot_trusted_executable(path: Path, *, role: str) -> tuple[Path, str]:
    """Resolve and hash an executable without trusting PATH after this point."""

    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise AuthorizedWriteError(f"unable to resolve {role} {path}: {exc}") from None
    _reject_symlink_components(resolved)
    try:
        metadata = resolved.lstat()
    except OSError as exc:
        raise AuthorizedWriteError(f"unable to inspect {role} {resolved}: {exc}") from None
    if not stat.S_ISREG(metadata.st_mode):
        raise AuthorizedWriteError(f"{role} must resolve to a regular file: {resolved}")
    if metadata.st_uid not in {0, os.getuid()}:
        raise AuthorizedWriteError(f"{role} must be owned by root or the current user")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise AuthorizedWriteError(f"{role} must not be group- or world-writable")
    if not metadata.st_mode & 0o111:
        raise AuthorizedWriteError(f"{role} must be executable")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(resolved, flags)
        opened_metadata = os.fstat(descriptor)
        if (opened_metadata.st_dev, opened_metadata.st_ino) != (
            metadata.st_dev,
            metadata.st_ino,
        ):
            raise AuthorizedWriteError(f"{role} changed while opening")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
    except AuthorizedWriteError:
        raise
    except OSError as exc:
        raise AuthorizedWriteError(f"unable to hash {role} {resolved}: {exc}") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return resolved, digest.hexdigest()


def _validate_new_private_output(path: Path, *, parent: Path, role: str) -> None:
    _reject_symlink_components(path)
    _ensure_outside_repository(path)
    _validate_private_directory(path.parent, role="output directory")
    try:
        same_parent = path.parent.samefile(parent)
    except OSError as exc:
        raise AuthorizedWriteError(f"unable to compare output directories: {exc}") from None
    if not same_parent:
        raise AuthorizedWriteError(f"{role} must share the private run directory")
    if path.exists() or path.is_symlink():
        raise AuthorizedWriteError(f"refusing to overwrite {role}: {path}")


def _fsync_directory(path: Path) -> None:
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        os.fsync(descriptor)
    except OSError as exc:
        raise AuthorizedWriteError(f"unable to sync private directory {path}: {exc}") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _write_private_output(path: Path, content: bytes) -> None:
    """Sync bytes and publish without overwriting or following links."""

    temporary_path: Path | None = None
    descriptor = -1
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        for _ in range(64):
            temporary_path = path.parent / (
                f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
            )
            try:
                descriptor = os.open(temporary_path, flags, 0o600)
                break
            except FileExistsError:
                temporary_path = None
        if descriptor < 0 or temporary_path is None:
            raise AuthorizedWriteError(f"unable to reserve temporary output for {path}")
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.link(temporary_path, path, follow_symlinks=False)
        _fsync_directory(path.parent)
    except AuthorizedWriteError:
        raise
    except OSError as exc:
        raise AuthorizedWriteError(f"unable to publish private output {path}: {exc}") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except OSError:
                pass


def _parse_utc(value: object, *, field: str) -> datetime:
    if not isinstance(value, str) or not RFC3339_UTC_PATTERN.fullmatch(value):
        raise AuthorizedWriteError(
            f"{field} must be canonical RFC3339 UTC: YYYY-MM-DDTHH:MM:SS[.fraction]Z"
        )
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise AuthorizedWriteError(f"{field} must be a valid RFC3339 timestamp") from None
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise AuthorizedWriteError(f"{field} must carry the UTC offset")
    return parsed.astimezone(UTC)


def _format_utc(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _require_sha(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not SHA256_PATTERN.fullmatch(value):
        raise AuthorizedWriteError(f"{field} must be lowercase SHA-256 hexadecimal")
    return value


def _validate_completion_manifest(
    *,
    completion_content: bytes,
    target_sha256: str,
    recovery_sha256: str,
    recovery_mode: str,
) -> None:
    manifest = _parse_canonical_object(completion_content, role="completion manifest")
    expected_fields = {
        "schema_version",
        "artifact_type",
        "raw_input_sha256",
        "sanitized_input_sha256",
        "policy_sha256",
        "target_payload_sha256",
        "recovery_payload_sha256",
        "recovery_mode",
        "remote_mutation",
    }
    if set(manifest) != expected_fields:
        raise AuthorizedWriteError("completion manifest fields are incomplete or unexpected")
    if manifest["schema_version"] != "1" or manifest["artifact_type"] != (
        "github_branch_protection_projection_bundle"
    ):
        raise AuthorizedWriteError("completion manifest type is unsupported")
    for field in (
        "raw_input_sha256",
        "sanitized_input_sha256",
        "policy_sha256",
        "target_payload_sha256",
        "recovery_payload_sha256",
    ):
        _require_sha(manifest[field], field=f"completion manifest {field}")
    if manifest["target_payload_sha256"] != target_sha256:
        raise AuthorizedWriteError("completion manifest target digest does not match target")
    if manifest["recovery_payload_sha256"] != recovery_sha256:
        raise AuthorizedWriteError("completion manifest recovery digest does not match recovery")
    if manifest["recovery_mode"] != recovery_mode:
        raise AuthorizedWriteError("completion manifest recovery mode is not authorized")
    if manifest["remote_mutation"] != "NONE":
        raise AuthorizedWriteError("completion manifest must be an offline bundle")
    if recovery_mode == "FORWARD_ONLY_TARGET" and recovery_sha256 != target_sha256:
        raise AuthorizedWriteError("FORWARD_ONLY_TARGET recovery must equal the target digest")


def _validate_authorization(
    *,
    content: bytes,
    approved_sha256: str,
) -> tuple[dict[str, object], datetime]:
    _require_sha(approved_sha256, field="owner-approved authorization SHA-256")
    actual_sha256 = hashlib.sha256(content).hexdigest()
    if actual_sha256 != approved_sha256:
        raise AuthorizedWriteError("authorization envelope does not match the owner-approved SHA-256")
    document = _parse_canonical_object(content, role="authorization envelope")
    if set(document) != AUTHORIZATION_FIELDS:
        raise AuthorizedWriteError("authorization envelope fields are incomplete or unexpected")
    if document["schema_version"] != "1" or document["artifact_type"] != (
        "github_branch_protection_write_authorization"
    ):
        raise AuthorizedWriteError("authorization envelope type is unsupported")
    authorization_id = document["authorization_id"]
    if not isinstance(authorization_id, str) or not IDENTIFIER_PATTERN.fullmatch(
        authorization_id
    ):
        raise AuthorizedWriteError("authorization_id is invalid")
    if document["authorizer_login"] != EXPECTED_AUTHORIZER_LOGIN:
        raise AuthorizedWriteError("authorization envelope authorizer is not the repository owner")
    operator_login = document["operator_login"]
    if not isinstance(operator_login, str) or not LOGIN_PATTERN.fullmatch(operator_login):
        raise AuthorizedWriteError("authorization envelope operator_login is invalid")
    if document["github_hostname"] != EXPECTED_GITHUB_HOSTNAME:
        raise AuthorizedWriteError("authorization envelope GitHub hostname is not exact")
    if document["repository"] != EXPECTED_REPOSITORY:
        raise AuthorizedWriteError("authorization envelope repository is not exact")
    if document["endpoint"] != EXPECTED_ENDPOINT:
        raise AuthorizedWriteError("authorization envelope endpoint is not exact")
    for field in (
        "target_payload_sha256",
        "completion_manifest_sha256",
        "recovery_payload_sha256",
        "prewrite_result_sha256",
        "prewrite_collector_sha256",
        "prewrite_evidence_manifest_sha256",
        "remote_before_sha256",
        "gh_executable_sha256",
    ):
        _require_sha(document[field], field=f"authorization envelope {field}")
    if document["recovery_mode"] not in RECOVERY_MODES:
        raise AuthorizedWriteError("authorization envelope recovery mode is unsupported")
    if (
        isinstance(document["probe_pr_number"], bool)
        or not isinstance(document["probe_pr_number"], int)
        or document["probe_pr_number"] <= 0
    ):
        raise AuthorizedWriteError("authorization envelope probe_pr_number is invalid")
    probe_head = document["probe_head_sha"]
    if not isinstance(probe_head, str) or not GIT_SHA_PATTERN.fullmatch(probe_head):
        raise AuthorizedWriteError("authorization envelope probe_head_sha is invalid")
    if document["retry_count"] != 0 or isinstance(document["retry_count"], bool):
        raise AuthorizedWriteError("authorization envelope must authorize exactly zero retries")
    expires_at = _parse_utc(document["expires_at"], field="authorization expires_at")
    return document, expires_at


def _validate_prewrite_result(
    *,
    content: bytes,
    authorization: dict[str, object],
) -> datetime:
    actual_sha256 = hashlib.sha256(content).hexdigest()
    if actual_sha256 != authorization["prewrite_result_sha256"]:
        raise AuthorizedWriteError("prewrite result does not match the authorized SHA-256")
    document = _parse_canonical_object(content, role="prewrite result")
    if set(document) != PREWRITE_FIELDS:
        raise AuthorizedWriteError("prewrite result fields are incomplete or unexpected")
    if document["schema_version"] != "1" or document["artifact_type"] != (
        "github_branch_protection_prewrite_result"
    ):
        raise AuthorizedWriteError("prewrite result type is unsupported")
    bound_fields = (
        "authorization_id",
        "operator_login",
        "github_hostname",
        "gh_executable_sha256",
        "repository",
        "endpoint",
        "target_payload_sha256",
        "completion_manifest_sha256",
        "recovery_payload_sha256",
        "recovery_mode",
        "prewrite_collector_sha256",
        "prewrite_evidence_manifest_sha256",
        "remote_before_sha256",
        "probe_pr_number",
        "probe_head_sha",
    )
    for field in bound_fields:
        if document[field] != authorization[field]:
            raise AuthorizedWriteError(f"prewrite result {field} is not authorization-bound")
    if document["classification"] != "EXACT_AUTHORIZED_REMOTE_BEFORE":
        raise AuthorizedWriteError("prewrite result classification is not safe")
    if document["network_write_attempted"] is not False:
        raise AuthorizedWriteError("prewrite result must prove no network write was attempted")
    checks = document["checks"]
    if not isinstance(checks, dict) or set(checks) != REQUIRED_PREWRITE_CHECKS:
        raise AuthorizedWriteError("prewrite result check set is incomplete or unexpected")
    if any(value != "PASS" for value in checks.values()):
        raise AuthorizedWriteError("every prewrite result check must be PASS")
    return _parse_utc(document["observed_at"], field="prewrite observed_at")


def _validate_prewrite_evidence(
    *,
    content: bytes,
    authorization: dict[str, object],
    run_directory: Path,
    reserved_paths: set[Path],
) -> None:
    actual_sha256 = hashlib.sha256(content).hexdigest()
    if actual_sha256 != authorization["prewrite_evidence_manifest_sha256"]:
        raise AuthorizedWriteError(
            "prewrite evidence manifest does not match the authorized SHA-256"
        )
    document = _parse_canonical_object(content, role="prewrite evidence manifest")
    if set(document) != PREWRITE_EVIDENCE_FIELDS:
        raise AuthorizedWriteError(
            "prewrite evidence manifest fields are incomplete or unexpected"
        )
    if document["schema_version"] != "1" or document["artifact_type"] != (
        "github_branch_protection_prewrite_evidence_manifest"
    ):
        raise AuthorizedWriteError("prewrite evidence manifest type is unsupported")
    if document["authorization_id"] != authorization["authorization_id"]:
        raise AuthorizedWriteError(
            "prewrite evidence manifest authorization_id is not authorization-bound"
        )
    artifacts = document["artifacts"]
    if not isinstance(artifacts, dict) or set(artifacts) != REQUIRED_PREWRITE_CHECKS:
        raise AuthorizedWriteError(
            "prewrite evidence manifest artifact set is incomplete or unexpected"
        )
    observed_filenames: set[str] = set()
    for role in sorted(REQUIRED_PREWRITE_CHECKS):
        entry = artifacts[role]
        if not isinstance(entry, dict) or set(entry) != {
            "filename",
            "sha256",
            "size_bytes",
        }:
            raise AuthorizedWriteError(
                f"prewrite evidence entry {role} is incomplete or unexpected"
            )
        filename = entry["filename"]
        if (
            not isinstance(filename, str)
            or not IDENTIFIER_PATTERN.fullmatch(filename)
            or Path(filename).name != filename
        ):
            raise AuthorizedWriteError(f"prewrite evidence filename for {role} is unsafe")
        if filename in observed_filenames:
            raise AuthorizedWriteError("prewrite evidence filenames must be unique")
        observed_filenames.add(filename)
        expected_sha256 = _require_sha(
            entry["sha256"], field=f"prewrite evidence {role} sha256"
        )
        expected_size = entry["size_bytes"]
        if (
            isinstance(expected_size, bool)
            or not isinstance(expected_size, int)
            or expected_size <= 0
        ):
            raise AuthorizedWriteError(
                f"prewrite evidence {role} size_bytes must be a positive integer"
            )
        artifact_path = run_directory / filename
        if artifact_path in reserved_paths:
            raise AuthorizedWriteError(
                f"prewrite evidence {role} must not alias a boundary input or output"
            )
        artifact_content = _validate_private_input(
            artifact_path, role=f"prewrite evidence {role}"
        )
        if len(artifact_content) != expected_size:
            raise AuthorizedWriteError(f"prewrite evidence {role} size does not match")
        if hashlib.sha256(artifact_content).hexdigest() != expected_sha256:
            raise AuthorizedWriteError(f"prewrite evidence {role} digest does not match")


def _validate_freshness(
    *,
    observed_at: datetime,
    expires_at: datetime,
    now: datetime,
) -> tuple[float, float]:
    prewrite_age = (now - observed_at).total_seconds()
    remaining = (expires_at - now).total_seconds()
    if prewrite_age < 0:
        raise AuthorizedWriteError("prewrite result timestamp is in the future")
    if prewrite_age > MAXIMUM_PREWRITE_AGE_SECONDS:
        raise AuthorizedWriteError("prewrite result is stale")
    return prewrite_age, remaining


def _base_receipt(
    *,
    authorization: dict[str, object],
    authorization_sha256: str,
    prewrite_observed_at: datetime,
    gate_time: datetime,
    remaining_seconds: float,
    prewrite_age_seconds: float,
    authorization_consumed: bool,
    consumption_marker_sha256: str | None,
) -> dict[str, object]:
    return {
        "schema_version": "2",
        "artifact_type": "github_branch_protection_authorization_boundary",
        "authorization_id": authorization["authorization_id"],
        "authorization_envelope_sha256": authorization_sha256,
        "authorizer_login": authorization["authorizer_login"],
        "operator_login": authorization["operator_login"],
        "github_hostname": authorization["github_hostname"],
        "gh_executable_sha256": authorization["gh_executable_sha256"],
        "repository": EXPECTED_REPOSITORY,
        "endpoint": EXPECTED_ENDPOINT,
        "target_payload_sha256": authorization["target_payload_sha256"],
        "completion_manifest_sha256": authorization["completion_manifest_sha256"],
        "recovery_payload_sha256": authorization["recovery_payload_sha256"],
        "recovery_mode": authorization["recovery_mode"],
        "prewrite_result_sha256": authorization["prewrite_result_sha256"],
        "prewrite_collector_sha256": authorization["prewrite_collector_sha256"],
        "prewrite_evidence_manifest_sha256": authorization[
            "prewrite_evidence_manifest_sha256"
        ],
        "prewrite_observed_at": _format_utc(prewrite_observed_at),
        "prewrite_age_seconds": round(prewrite_age_seconds, 6),
        "authorization_expires_at": authorization["expires_at"],
        "final_gate_time": _format_utc(gate_time),
        "remaining_seconds": round(remaining_seconds, 6),
        "minimum_remaining_seconds": MINIMUM_REMAINING_SECONDS,
        "transport_startup_reserve_seconds": TRANSPORT_STARTUP_RESERVE_SECONDS,
        "transport_timeout_seconds": TRANSPORT_TIMEOUT_SECONDS,
        "minimum_launch_remaining_seconds": MINIMUM_LAUNCH_REMAINING_SECONDS,
        "authorization_consumed": authorization_consumed,
        "consumption_marker_sha256": consumption_marker_sha256,
        "retry_count": 0,
        "recovery_attempted": False,
    }


def _consumption_marker_path(directory: Path, authorization_id: str) -> Path:
    identifier_digest = hashlib.sha256(authorization_id.encode("utf-8")).hexdigest()
    return directory / f"{identifier_digest}.consumed.json"


def _consume_authorization(
    *,
    directory: Path,
    run_directory: Path,
    authorization: dict[str, object],
    authorization_sha256: str,
    consumed_at: datetime,
) -> tuple[Path, str]:
    _validate_private_directory(directory, role="authorization consumption ledger")
    try:
        if directory.samefile(run_directory):
            raise AuthorizedWriteError(
                "authorization consumption ledger must be stable and separate from the run directory"
            )
    except OSError as exc:
        raise AuthorizedWriteError(
            f"unable to compare consumption and run directories: {exc}"
        ) from None
    marker_path = _consumption_marker_path(directory, str(authorization["authorization_id"]))
    if marker_path.exists() or marker_path.is_symlink():
        raise AuthorizedWriteError(
            "authorization_id is already consumed; reconcile read-only and obtain a new authorization"
        )
    marker = {
        "schema_version": "1",
        "artifact_type": "github_branch_protection_authorization_consumption",
        "authorization_id": authorization["authorization_id"],
        "authorization_envelope_sha256": authorization_sha256,
        "endpoint": EXPECTED_ENDPOINT,
        "target_payload_sha256": authorization["target_payload_sha256"],
        "consumed_at": _format_utc(consumed_at),
        "state": "CONSUMED_REQUEST_MAY_FOLLOW_OR_HAVE_OCCURRED",
    }
    marker_content = _canonical_bytes(marker)
    _write_private_output(marker_path, marker_content)
    return marker_path, hashlib.sha256(marker_content).hexdigest()


def _transport_capture(*, return_code: int, stdout: bytes, stderr: bytes) -> bytes:
    """Encode both streams losslessly; receipt/finalizer bind these exact bytes."""

    return _canonical_bytes(
        {
            "schema_version": "1",
            "artifact_type": "github_cli_transport_capture",
            "return_code": return_code,
            "stdout_base64": base64.b64encode(stdout).decode("ascii"),
            "stderr_base64": base64.b64encode(stderr).decode("ascii"),
        }
    )


def execute_authorized_write(
    *,
    target_path: Path,
    recovery_path: Path,
    completion_manifest_path: Path,
    authorization_envelope_path: Path,
    owner_approved_authorization_sha256: str,
    prewrite_result_path: Path,
    prewrite_evidence_manifest_path: Path,
    prewrite_collector_path: Path,
    gh_executable_path: Path,
    receipt_output_path: Path,
    response_output_path: Path,
    transport_error_output_path: Path,
    consumption_directory: Path,
    operator_identity_check: OperatorIdentityCheck,
    network_write: NetworkWrite,
    clock: Clock = _utc_now,
) -> AuthorizationBoundaryResult:
    """Attempt one request only for one exact, fresh, unconsumed authorization."""

    if not callable(operator_identity_check):
        raise AuthorizedWriteError("operator identity callback is required")
    if not callable(network_write):
        raise AuthorizedWriteError("network write callback is required")

    input_paths = [
        _absolute_without_resolving(path)
        for path in (
            target_path,
            recovery_path,
            completion_manifest_path,
            authorization_envelope_path,
            prewrite_result_path,
            prewrite_evidence_manifest_path,
        )
    ]
    output_paths = [
        _absolute_without_resolving(path)
        for path in (receipt_output_path, response_output_path, transport_error_output_path)
    ]
    if len(set(input_paths + output_paths)) != len(input_paths + output_paths):
        raise AuthorizedWriteError("authorization-boundary input and output paths must differ")
    run_directory = input_paths[0].parent
    _validate_private_directory(run_directory, role="run directory")
    for path in input_paths[1:]:
        try:
            same_parent = path.parent.samefile(run_directory)
        except OSError as exc:
            raise AuthorizedWriteError(f"unable to compare bundle directories: {exc}") from None
        if not same_parent:
            raise AuthorizedWriteError("all authorization-boundary inputs must share one run directory")
    for path, role in zip(
        output_paths,
        ("receipt output", "response output", "transport-error output"),
        strict=True,
    ):
        _validate_new_private_output(path, parent=run_directory, role=role)

    target_content = _validate_private_input(input_paths[0], role="target payload")
    recovery_content = _validate_private_input(input_paths[1], role="recovery payload")
    completion_content = _validate_private_input(input_paths[2], role="completion manifest")
    authorization_content = _validate_private_input(input_paths[3], role="authorization envelope")
    prewrite_content = _validate_private_input(input_paths[4], role="prewrite result")
    prewrite_evidence_content = _validate_private_input(
        input_paths[5], role="prewrite evidence manifest"
    )

    authorization, expires_at = _validate_authorization(
        content=authorization_content,
        approved_sha256=owner_approved_authorization_sha256,
    )
    _, collector_sha256 = _snapshot_trusted_executable(
        _absolute_without_resolving(prewrite_collector_path),
        role="prewrite collector",
    )
    if collector_sha256 != authorization["prewrite_collector_sha256"]:
        raise AuthorizedWriteError(
            "prewrite collector does not match the authorized SHA-256"
        )
    resolved_gh_path, gh_sha256 = _snapshot_trusted_executable(
        _absolute_without_resolving(gh_executable_path), role="gh executable"
    )
    if gh_sha256 != authorization["gh_executable_sha256"]:
        raise AuthorizedWriteError("gh executable does not match the authorized SHA-256")
    target_sha256 = hashlib.sha256(target_content).hexdigest()
    recovery_sha256 = hashlib.sha256(recovery_content).hexdigest()
    completion_sha256 = hashlib.sha256(completion_content).hexdigest()
    if target_sha256 != authorization["target_payload_sha256"]:
        raise AuthorizedWriteError("target payload does not match the authorized SHA-256")
    if recovery_sha256 != authorization["recovery_payload_sha256"]:
        raise AuthorizedWriteError("recovery payload does not match the authorized SHA-256")
    if completion_sha256 != authorization["completion_manifest_sha256"]:
        raise AuthorizedWriteError("completion manifest does not match the authorized SHA-256")
    _validate_completion_manifest(
        completion_content=completion_content,
        target_sha256=target_sha256,
        recovery_sha256=recovery_sha256,
        recovery_mode=str(authorization["recovery_mode"]),
    )
    prewrite_observed_at = _validate_prewrite_result(
        content=prewrite_content,
        authorization=authorization,
    )
    _validate_prewrite_evidence(
        content=prewrite_evidence_content,
        authorization=authorization,
        run_directory=run_directory,
        reserved_paths=set(input_paths + output_paths),
    )
    if prewrite_observed_at > expires_at:
        raise AuthorizedWriteError("prewrite result was observed after authorization expiry")

    first_gate_time = clock()
    if not isinstance(first_gate_time, datetime) or first_gate_time.tzinfo is None:
        raise AuthorizedWriteError("clock must return a timezone-aware datetime")
    first_gate_time = first_gate_time.astimezone(UTC)
    first_age, first_remaining = _validate_freshness(
        observed_at=prewrite_observed_at,
        expires_at=expires_at,
        now=first_gate_time,
    )
    if first_remaining <= MINIMUM_LAUNCH_REMAINING_SECONDS:
        receipt = _base_receipt(
            authorization=authorization,
            authorization_sha256=owner_approved_authorization_sha256,
            prewrite_observed_at=prewrite_observed_at,
            gate_time=first_gate_time,
            remaining_seconds=first_remaining,
            prewrite_age_seconds=first_age,
            authorization_consumed=False,
            consumption_marker_sha256=None,
        )
        receipt.update(
            {
                "classification": "STALE_AUTHORIZATION_NO_REQUEST",
                "request_launch_gate_time": None,
                "request_send_time": None,
                "operator_identity_verified": False,
                "network_write_attempted": False,
                "request_return_code": None,
                "transport_artifact": None,
                "transport_error_class": None,
            }
        )
        _write_private_output(output_paths[0], _canonical_bytes(receipt))
        return AuthorizationBoundaryResult(receipt["classification"], receipt)

    try:
        observed_operator = operator_identity_check()
    except Exception as exc:
        raise AuthorizedWriteError(
            f"unable to verify effective GitHub operator: {type(exc).__name__}"
        ) from None
    if observed_operator != authorization["operator_login"]:
        raise AuthorizedWriteError("effective GitHub operator is not authorization-bound")

    # Identity verification is read-only but may consume time. Recheck before
    # consuming the authorization so a slow identity request cannot make a
    # stale authorization one-shot.
    identity_gate_time = clock()
    if not isinstance(identity_gate_time, datetime) or identity_gate_time.tzinfo is None:
        raise AuthorizedWriteError("clock must return a timezone-aware datetime")
    identity_gate_time = identity_gate_time.astimezone(UTC)
    identity_age, identity_remaining = _validate_freshness(
        observed_at=prewrite_observed_at,
        expires_at=expires_at,
        now=identity_gate_time,
    )
    if identity_remaining <= MINIMUM_LAUNCH_REMAINING_SECONDS:
        receipt = _base_receipt(
            authorization=authorization,
            authorization_sha256=owner_approved_authorization_sha256,
            prewrite_observed_at=prewrite_observed_at,
            gate_time=identity_gate_time,
            remaining_seconds=identity_remaining,
            prewrite_age_seconds=identity_age,
            authorization_consumed=False,
            consumption_marker_sha256=None,
        )
        receipt.update(
            {
                "classification": "STALE_AFTER_IDENTITY_NO_REQUEST",
                "request_launch_gate_time": None,
                "request_send_time": None,
                "operator_identity_verified": True,
                "network_write_attempted": False,
                "request_return_code": None,
                "transport_artifact": None,
                "transport_error_class": None,
            }
        )
        _write_private_output(output_paths[0], _canonical_bytes(receipt))
        return AuthorizationBoundaryResult(receipt["classification"], receipt)

    # Re-hash the exact resolved binary after the identity request. The CLI
    # invokes this same absolute path for the PUT and pins github.com.
    rechecked_gh_path, rechecked_gh_sha256 = _snapshot_trusted_executable(
        resolved_gh_path, role="gh executable"
    )
    if rechecked_gh_path != resolved_gh_path or rechecked_gh_sha256 != gh_sha256:
        raise AuthorizedWriteError("gh executable changed after identity verification")

    _, marker_sha256 = _consume_authorization(
        directory=_absolute_without_resolving(consumption_directory),
        run_directory=run_directory,
        authorization=authorization,
        authorization_sha256=owner_approved_authorization_sha256,
        consumed_at=identity_gate_time,
    )

    # This final read is immediately before the one callback that may start
    # gh. The bounded transport timeout is shorter than the 30-second reserve,
    # which is itself in addition to the 60-second authorization requirement.
    launch_gate_time = clock()
    if not isinstance(launch_gate_time, datetime) or launch_gate_time.tzinfo is None:
        raise AuthorizedWriteError("clock must return a timezone-aware datetime")
    launch_gate_time = launch_gate_time.astimezone(UTC)
    launch_age, launch_remaining = _validate_freshness(
        observed_at=prewrite_observed_at,
        expires_at=expires_at,
        now=launch_gate_time,
    )
    if launch_remaining <= MINIMUM_LAUNCH_REMAINING_SECONDS:
        receipt = _base_receipt(
            authorization=authorization,
            authorization_sha256=owner_approved_authorization_sha256,
            prewrite_observed_at=prewrite_observed_at,
            gate_time=launch_gate_time,
            remaining_seconds=launch_remaining,
            prewrite_age_seconds=launch_age,
            authorization_consumed=True,
            consumption_marker_sha256=marker_sha256,
        )
        receipt.update(
            {
                "classification": "AUTHORIZATION_CONSUMED_STALE_NO_REQUEST",
                "request_launch_gate_time": None,
                "request_send_time": None,
                "operator_identity_verified": True,
                "network_write_attempted": False,
                "request_return_code": None,
                "transport_artifact": None,
                "transport_error_class": None,
            }
        )
        _write_private_output(output_paths[0], _canonical_bytes(receipt))
        return AuthorizationBoundaryResult(receipt["classification"], receipt)

    try:
        attempt = network_write(target_content)
        if not isinstance(attempt, WriteAttemptResult):
            raise AuthorizedWriteError("network callback returned an invalid result")
        if isinstance(attempt.return_code, bool) or not isinstance(attempt.return_code, int):
            raise AuthorizedWriteError("network callback return code must be an integer")
        if attempt.artifact_kind not in {"response", "transport_error"}:
            raise AuthorizedWriteError("network callback artifact kind is invalid")
        if not isinstance(attempt.artifact_content, bytes) or not attempt.artifact_content:
            raise AuthorizedWriteError("network callback artifact content must be non-empty bytes")
        artifact_kind = attempt.artifact_kind
        artifact_content = attempt.artifact_content
        return_code: int | None = attempt.return_code
        transport_error_class: str | None = None
        classification = "WRITE_ATTEMPTED_RETURNED"
    except Exception as exc:  # Marker already exists: outcome may be unknown; never retry.
        artifact_kind = "transport_error"
        transport_error_class = type(exc).__name__
        artifact_content = _canonical_bytes(
            {
                "schema_version": "1",
                "artifact_type": "github_cli_transport_exception",
                "exception_class": transport_error_class,
            }
        )
        return_code = None
        classification = "WRITE_ATTEMPTED_TRANSPORT_ERROR"

    artifact_path = output_paths[1] if artifact_kind == "response" else output_paths[2]
    _write_private_output(artifact_path, artifact_content)
    artifact_receipt = {
        "kind": artifact_kind,
        "sha256": hashlib.sha256(artifact_content).hexdigest(),
        "size_bytes": len(artifact_content),
    }
    receipt = _base_receipt(
        authorization=authorization,
        authorization_sha256=owner_approved_authorization_sha256,
        prewrite_observed_at=prewrite_observed_at,
        gate_time=launch_gate_time,
        remaining_seconds=launch_remaining,
        prewrite_age_seconds=launch_age,
        authorization_consumed=True,
        consumption_marker_sha256=marker_sha256,
    )
    receipt.update(
        {
            "classification": classification,
            "request_launch_gate_time": _format_utc(launch_gate_time),
            # gh does not expose the exact socket-send instant. Do not relabel
            # the process-launch gate as a directly observed send timestamp.
            "request_send_time": None,
            "operator_identity_verified": True,
            "network_write_attempted": True,
            "request_return_code": return_code,
            "transport_artifact": artifact_receipt,
            "transport_error_class": transport_error_class,
        }
    )
    _write_private_output(output_paths[0], _canonical_bytes(receipt))
    return AuthorizationBoundaryResult(classification, receipt)


def _default_consumption_directory() -> Path:
    # Resolve the account home through the local identity database, not HOME,
    # so changing process environment cannot silently select a fresh ledger.
    account_home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    return account_home / ".local/share/scanalyze-evidence/gug-277/authorization-consumption"


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Execute one exact owner-authorized branch-protection PUT"
    )
    parser.add_argument("--target", required=True, type=Path)
    parser.add_argument("--recovery", required=True, type=Path)
    parser.add_argument("--completion-manifest", required=True, type=Path)
    parser.add_argument("--authorization-envelope", required=True, type=Path)
    parser.add_argument("--owner-approved-authorization-sha256", required=True)
    parser.add_argument("--prewrite-result", required=True, type=Path)
    parser.add_argument("--prewrite-evidence-manifest", required=True, type=Path)
    parser.add_argument("--prewrite-collector", required=True, type=Path)
    parser.add_argument("--receipt-output", required=True, type=Path)
    parser.add_argument("--response-output", required=True, type=Path)
    parser.add_argument("--transport-error-output", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    gh_candidate = shutil.which("gh")
    if gh_candidate is None:
        print("FAIL: authorized branch-protection write stopped\ngh executable not found", file=sys.stderr)
        return 1
    try:
        resolved_gh_path, initial_gh_sha256 = _snapshot_trusted_executable(
            Path(gh_candidate), role="gh executable"
        )
    except AuthorizedWriteError as exc:
        print(f"FAIL: authorized branch-protection write stopped\n{exc}", file=sys.stderr)
        return 1

    def verify_operator_identity() -> str:
        current_path, current_sha256 = _snapshot_trusted_executable(
            resolved_gh_path, role="gh executable"
        )
        if current_path != resolved_gh_path or current_sha256 != initial_gh_sha256:
            raise AuthorizedWriteError("gh executable changed before identity verification")
        completed = subprocess.run(
            [
                str(resolved_gh_path),
                "api",
                "--hostname",
                EXPECTED_GITHUB_HOSTNAME,
                "-H",
                "Accept: application/vnd.github+json",
                "-H",
                f"X-GitHub-Api-Version: {GITHUB_API_VERSION}",
                "user",
                "--jq",
                ".login",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=IDENTITY_TIMEOUT_SECONDS,
        )
        if completed.returncode != 0:
            raise AuthorizedWriteError(
                f"effective GitHub operator lookup failed with exit code {completed.returncode}"
            )
        try:
            login = completed.stdout.decode("utf-8", errors="strict").strip()
        except UnicodeError:
            raise AuthorizedWriteError("effective GitHub operator response is not UTF-8") from None
        if not LOGIN_PATTERN.fullmatch(login):
            raise AuthorizedWriteError("effective GitHub operator response is invalid")
        return login

    def network_write(target_content: bytes) -> WriteAttemptResult:
        try:
            completed = subprocess.run(
                [
                    str(resolved_gh_path),
                    "api",
                    "--hostname",
                    EXPECTED_GITHUB_HOSTNAME,
                    "--method",
                    "PUT",
                    "-H",
                    "Accept: application/vnd.github+json",
                    "-H",
                    f"X-GitHub-Api-Version: {GITHUB_API_VERSION}",
                    "--include",
                    EXPECTED_API_PATH,
                    "--input",
                    "-",
                ],
                input=target_content,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=TRANSPORT_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout if isinstance(exc.stdout, bytes) else b""
            stderr = exc.stderr if isinstance(exc.stderr, bytes) else b""
            return WriteAttemptResult(
                124,
                "transport_error",
                _transport_capture(return_code=124, stdout=stdout, stderr=stderr),
            )
        capture = _transport_capture(
            return_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )
        kind = "response" if completed.stdout else "transport_error"
        return WriteAttemptResult(completed.returncode, kind, capture)

    try:
        result = execute_authorized_write(
            target_path=args.target,
            recovery_path=args.recovery,
            completion_manifest_path=args.completion_manifest,
            authorization_envelope_path=args.authorization_envelope,
            owner_approved_authorization_sha256=args.owner_approved_authorization_sha256,
            prewrite_result_path=args.prewrite_result,
            prewrite_evidence_manifest_path=args.prewrite_evidence_manifest,
            prewrite_collector_path=args.prewrite_collector,
            gh_executable_path=resolved_gh_path,
            receipt_output_path=args.receipt_output,
            response_output_path=args.response_output,
            transport_error_output_path=args.transport_error_output,
            consumption_directory=_default_consumption_directory(),
            operator_identity_check=verify_operator_identity,
            network_write=network_write,
        )
    except AuthorizedWriteError as exc:
        print(f"FAIL: authorized branch-protection write stopped\n{exc}", file=sys.stderr)
        return 1
    print(f"classification={result.classification}")
    print(f"authorization_consumed={str(result.receipt['authorization_consumed']).lower()}")
    print(f"network_write_attempted={str(result.receipt['network_write_attempted']).lower()}")
    print("retry_count=0")
    print("recovery_attempted=false")
    return 0 if (
        result.classification == "WRITE_ATTEMPTED_RETURNED"
        and result.receipt["request_return_code"] == 0
        and isinstance(result.receipt["transport_artifact"], dict)
        and result.receipt["transport_artifact"]["kind"] == "response"
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
