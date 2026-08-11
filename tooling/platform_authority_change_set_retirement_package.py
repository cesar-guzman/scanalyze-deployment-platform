"""Build the deterministic GUG-215 single-operator broker package.

The package is source-only and deliberately relies on an AWS-managed Python
SDK.  That exception is bounded by the separately reviewed, manually pinned
Lambda runtime version.  This module performs no AWS, network, signing,
upload, deployment, or retirement operation.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from hashlib import sha256
from io import BytesIO
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any, Mapping
from zipfile import BadZipFile, ZIP_STORED, ZipFile, ZipInfo


ARTIFACT_TYPE = "scanalyze.platform_authority.change_set_retirement_package.v1"
SCHEMA_VERSION = 1
WORK_PACKAGE = "GUG-215"
AUTHORIZATION_MODE = "SINGLE_OPERATOR_NONPROD_EXCEPTION"
PRODUCTION_STATUS = "NO-GO"
ARCHIVE_NAME = "scanalyze-gug215-change-set-retirement-broker.zip"
MANIFEST_NAME = "scanalyze-gug215-change-set-retirement-broker.manifest.json"
FIXED_ZIP_TIMESTAMP = (2026, 8, 11, 0, 0, 0)
HANDLER = "tooling.platform_authority_identity_context_pep_runtime.handler"
SOURCE_PATHS = tuple(
    sorted(
        (
            Path("policies/iam/aws-managed-identity-context-allowlist-v12.snapshot.json"),
            Path("tooling/__init__.py"),
            Path("tooling/platform_authority_change_set_retirement_broker.py"),
            Path("tooling/platform_authority_identity_context_compatibility.py"),
            Path("tooling/platform_authority_identity_context_pep.py"),
            Path("tooling/platform_authority_identity_context_pep_runtime.py"),
            Path("tooling/platform_authority_single_operator_retirement_exception.py"),
        ),
        key=lambda item: item.as_posix(),
    )
)
PROVENANCE_PATHS = (
    Path("schemas/platform-authority-change-set-retirement-package-manifest.v1.schema.json"),
    Path("scripts/deployment/platform-authority-change-set-retirement-package.py"),
    Path("tooling/platform_authority_change_set_retirement_package.py"),
)

_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_CODE_SHA = re.compile(r"^[A-Za-z0-9+/]{43}=$")
_RUNTIME_ARN = re.compile(
    r"^arn:aws(?:-[a-z]+)*:lambda:[a-z]{2}(?:-[a-z]+)+-[0-9]+::runtime:"
    r"[0-9a-f]{64}$"
)


class RetirementPackageError(ValueError):
    """Stable fail-closed package/provenance contract violation."""


@dataclass(frozen=True)
class BuiltRetirementPackage:
    archive: bytes
    manifest: Mapping[str, Any]


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def canonical_digest(value: Mapping[str, Any]) -> str:
    return "sha256:" + sha256(canonical_json(value).encode("utf-8")).hexdigest()


def runtime_version_arn_digest(runtime_version_arn: str) -> str:
    if _RUNTIME_ARN.fullmatch(runtime_version_arn) is None:
        raise RetirementPackageError("RUNTIME_VERSION_ARN_INVALID")
    return canonical_digest({"broker_runtime_version_arn": runtime_version_arn})


def _read_source(source_root: Path, relative_path: Path) -> bytes:
    root = source_root.resolve(strict=True)
    candidate = root / relative_path
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise RetirementPackageError("PACKAGE_SOURCE_MISSING") from exc
    if candidate.is_symlink() or not resolved.is_file():
        raise RetirementPackageError("PACKAGE_SOURCE_UNSAFE")
    payload = resolved.read_bytes()
    if not payload and relative_path != Path("tooling/__init__.py"):
        raise RetirementPackageError("PACKAGE_SOURCE_EMPTY")
    return payload


def _zip_entry(path: Path, payload: bytes) -> tuple[ZipInfo, bytes]:
    info = ZipInfo(path.as_posix(), FIXED_ZIP_TIMESTAMP)
    info.compress_type = ZIP_STORED
    info.create_system = 3
    info.external_attr = (0o100644 & 0xFFFF) << 16
    info.extra = b""
    info.comment = b""
    return info, payload


def build_retirement_package(
    *,
    source_root: Path,
    source_commit: str,
    broker_runtime_version_arn: str,
    broker_version_binding_sha256: str,
    committed_sources: Mapping[Path, bytes] | None = None,
) -> BuiltRetirementPackage:
    """Return deterministic ZIP bytes plus the strict public manifest."""

    if _COMMIT.fullmatch(source_commit) is None:
        raise RetirementPackageError("SOURCE_COMMIT_INVALID")
    runtime_digest = runtime_version_arn_digest(broker_runtime_version_arn)
    if _DIGEST.fullmatch(broker_version_binding_sha256) is None:
        raise RetirementPackageError("BROKER_VERSION_BINDING_INVALID")
    if committed_sources is None:
        sources = {path: _read_source(source_root, path) for path in SOURCE_PATHS}
    else:
        if set(committed_sources) != set(SOURCE_PATHS):
            raise RetirementPackageError("COMMITTED_SOURCE_SET_INVALID")
        sources = {path: bytes(committed_sources[path]) for path in SOURCE_PATHS}
        if any(
            not payload and path != Path("tooling/__init__.py")
            for path, payload in sources.items()
        ):
            raise RetirementPackageError("PACKAGE_SOURCE_EMPTY")

    buffer = BytesIO()
    with ZipFile(buffer, mode="w", compression=ZIP_STORED, strict_timestamps=True) as archive:
        for path in SOURCE_PATHS:
            info, payload = _zip_entry(path, sources[path])
            archive.writestr(info, payload)
    archive_bytes = buffer.getvalue()
    archive_digest = sha256(archive_bytes).digest()
    manifest: dict[str, Any] = {
        "artifact_type": ARTIFACT_TYPE,
        "schema_version": SCHEMA_VERSION,
        "work_package": WORK_PACKAGE,
        "authorization_mode": AUTHORIZATION_MODE,
        "two_human_status": "NOT_PROVEN",
        "independent_approval_present": False,
        "production": False,
        "source_commit": source_commit,
        "archive_name": ARCHIVE_NAME,
        "archive_format": "ZIP_STORED_FIXED_METADATA",
        "archive_sha256": archive_digest.hex(),
        "lambda_code_sha256": base64.b64encode(archive_digest).decode("ascii"),
        "archive_size_bytes": len(archive_bytes),
        "handler": HANDLER,
        "runtime": "python3.12",
        "architecture": "x86_64",
        "runtime_dependency_mode": "AWS_MANAGED_RUNTIME_PINNED",
        "broker_runtime_version_arn_digest": runtime_digest,
        "broker_version_binding_sha256": broker_version_binding_sha256,
        "entries": [
            {
                "path": path.as_posix(),
                "sha256": sha256(sources[path]).hexdigest(),
                "size_bytes": len(sources[path]),
            }
            for path in SOURCE_PATHS
        ],
        "deployment_authorized": False,
        "production_status": PRODUCTION_STATUS,
    }
    manifest["manifest_digest"] = canonical_digest(manifest)
    validate_retirement_package_manifest(manifest, archive=archive_bytes)
    return BuiltRetirementPackage(archive=archive_bytes, manifest=manifest)


def validate_retirement_package_manifest(
    manifest: Mapping[str, Any], *, archive: bytes | None = None
) -> None:
    """Validate manifest semantics and, when supplied, exact archive bytes."""

    required = {
        "artifact_type",
        "schema_version",
        "work_package",
        "authorization_mode",
        "two_human_status",
        "independent_approval_present",
        "production",
        "source_commit",
        "archive_name",
        "archive_format",
        "archive_sha256",
        "lambda_code_sha256",
        "archive_size_bytes",
        "handler",
        "runtime",
        "architecture",
        "runtime_dependency_mode",
        "broker_runtime_version_arn_digest",
        "broker_version_binding_sha256",
        "entries",
        "deployment_authorized",
        "production_status",
        "manifest_digest",
    }
    if set(manifest) != required:
        raise RetirementPackageError("PACKAGE_MANIFEST_FIELDS_INVALID")
    constants = {
        "artifact_type": ARTIFACT_TYPE,
        "schema_version": SCHEMA_VERSION,
        "work_package": WORK_PACKAGE,
        "authorization_mode": AUTHORIZATION_MODE,
        "two_human_status": "NOT_PROVEN",
        "independent_approval_present": False,
        "production": False,
        "archive_name": ARCHIVE_NAME,
        "archive_format": "ZIP_STORED_FIXED_METADATA",
        "handler": HANDLER,
        "runtime": "python3.12",
        "architecture": "x86_64",
        "runtime_dependency_mode": "AWS_MANAGED_RUNTIME_PINNED",
        "deployment_authorized": False,
        "production_status": PRODUCTION_STATUS,
    }
    if any(manifest.get(key) != value for key, value in constants.items()):
        raise RetirementPackageError("PACKAGE_MANIFEST_SCOPE_INVALID")
    if _COMMIT.fullmatch(str(manifest.get("source_commit"))) is None:
        raise RetirementPackageError("PACKAGE_MANIFEST_SOURCE_INVALID")
    archive_sha = manifest.get("archive_sha256")
    code_sha = manifest.get("lambda_code_sha256")
    if (
        not isinstance(archive_sha, str)
        or _HEX_DIGEST.fullmatch(archive_sha) is None
        or not isinstance(code_sha, str)
        or _CODE_SHA.fullmatch(code_sha) is None
        or base64.b64encode(bytes.fromhex(archive_sha)).decode("ascii") != code_sha
    ):
        raise RetirementPackageError("PACKAGE_MANIFEST_ARCHIVE_DIGEST_INVALID")
    if (
        not isinstance(manifest.get("archive_size_bytes"), int)
        or manifest["archive_size_bytes"] <= 0
        or _DIGEST.fullmatch(str(manifest.get("broker_runtime_version_arn_digest")))
        is None
        or _DIGEST.fullmatch(str(manifest.get("broker_version_binding_sha256")))
        is None
    ):
        raise RetirementPackageError("PACKAGE_MANIFEST_BINDING_INVALID")
    entries = manifest.get("entries")
    if not isinstance(entries, list) or len(entries) != len(SOURCE_PATHS):
        raise RetirementPackageError("PACKAGE_MANIFEST_ENTRIES_INVALID")
    expected_paths = [path.as_posix() for path in SOURCE_PATHS]
    observed_paths: list[str] = []
    for entry in entries:
        if not isinstance(entry, Mapping) or set(entry) != {"path", "sha256", "size_bytes"}:
            raise RetirementPackageError("PACKAGE_MANIFEST_ENTRIES_INVALID")
        path = entry.get("path")
        size = entry.get("size_bytes")
        if (
            not isinstance(path, str)
            or _HEX_DIGEST.fullmatch(str(entry.get("sha256"))) is None
            or not isinstance(size, int)
            or size < 0
            or (size == 0 and path != "tooling/__init__.py")
        ):
            raise RetirementPackageError("PACKAGE_MANIFEST_ENTRIES_INVALID")
        observed_paths.append(path)
    if observed_paths != expected_paths or len(set(observed_paths)) != len(observed_paths):
        raise RetirementPackageError("PACKAGE_MANIFEST_ENTRIES_INVALID")
    manifest_digest = manifest.get("manifest_digest")
    expected_manifest_digest = canonical_digest(
        {key: value for key, value in manifest.items() if key != "manifest_digest"}
    )
    if manifest_digest != expected_manifest_digest:
        raise RetirementPackageError("PACKAGE_MANIFEST_DIGEST_MISMATCH")

    if archive is None:
        return
    archive_digest = sha256(archive).hexdigest()
    if archive_digest != archive_sha or len(archive) != manifest["archive_size_bytes"]:
        raise RetirementPackageError("PACKAGE_ARCHIVE_DIGEST_MISMATCH")
    try:
        with ZipFile(BytesIO(archive)) as package:
            if package.namelist() != expected_paths:
                raise RetirementPackageError("PACKAGE_ARCHIVE_MEMBERS_INVALID")
            for item, entry in zip(package.infolist(), entries, strict=True):
                if (
                    item.date_time != FIXED_ZIP_TIMESTAMP
                    or item.compress_type != ZIP_STORED
                    or item.extra != b""
                    or item.comment != b""
                    or (item.external_attr >> 16) & 0o777 != 0o644
                ):
                    raise RetirementPackageError("PACKAGE_ARCHIVE_METADATA_INVALID")
                payload = package.read(item.filename)
                if (
                    sha256(payload).hexdigest() != entry["sha256"]
                    or len(payload) != entry["size_bytes"]
                ):
                    raise RetirementPackageError("PACKAGE_ARCHIVE_MEMBER_DIGEST_MISMATCH")
    except (BadZipFile, OSError) as exc:
        raise RetirementPackageError("PACKAGE_ARCHIVE_INVALID") from exc


def verify_clean_source_commit(
    *, source_root: Path, source_commit: str
) -> Mapping[Path, bytes]:
    """Return exact Git-object bytes after proving clean HEAD provenance."""

    if _COMMIT.fullmatch(source_commit) is None:
        raise RetirementPackageError("SOURCE_COMMIT_INVALID")
    root = source_root.resolve(strict=True)
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout.strip()
        dirty = subprocess.run(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise RetirementPackageError("SOURCE_PROVENANCE_UNAVAILABLE") from exc
    if head != source_commit:
        raise RetirementPackageError("SOURCE_COMMIT_MISMATCH")
    if dirty:
        raise RetirementPackageError("SOURCE_TREE_DIRTY")

    committed_sources: dict[Path, bytes] = {}
    for relative in (*SOURCE_PATHS, *PROVENANCE_PATHS):
        try:
            committed = subprocess.run(
                ["git", "show", f"{source_commit}:{relative.as_posix()}"],
                cwd=root,
                check=True,
                capture_output=True,
                timeout=30,
            ).stdout
        except (OSError, subprocess.SubprocessError) as exc:
            raise RetirementPackageError("PACKAGE_SOURCE_NOT_IN_COMMIT") from exc
        if committed != _read_source(root, relative):
            raise RetirementPackageError("PACKAGE_SOURCE_COMMIT_DRIFT")
        if relative in SOURCE_PATHS:
            committed_sources[relative] = committed
    return committed_sources


def _write_create_only(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise RetirementPackageError("OUTPUT_WRITE_FAILED")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_retirement_package(
    *,
    source_root: Path,
    source_commit: str,
    broker_runtime_version_arn: str,
    broker_version_binding_sha256: str,
    output_directory: Path,
) -> tuple[Path, Path, Mapping[str, Any]]:
    """Create one owner-only package directory outside the source tree."""

    committed_sources = verify_clean_source_commit(
        source_root=source_root, source_commit=source_commit
    )
    built = build_retirement_package(
        source_root=source_root,
        source_commit=source_commit,
        broker_runtime_version_arn=broker_runtime_version_arn,
        broker_version_binding_sha256=broker_version_binding_sha256,
        committed_sources=committed_sources,
    )
    root = source_root.resolve(strict=True)
    requested = output_directory.resolve(strict=False)
    try:
        requested.relative_to(root)
    except ValueError:
        pass
    else:
        raise RetirementPackageError("OUTPUT_MUST_BE_OUTSIDE_SOURCE_ROOT")
    parent = requested.parent
    try:
        metadata = parent.stat()
    except OSError as exc:
        raise RetirementPackageError("OUTPUT_PARENT_INVALID") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o077
    ):
        raise RetirementPackageError("OUTPUT_PARENT_INVALID")
    try:
        requested.mkdir(mode=0o700, parents=False, exist_ok=False)
        archive_path = requested / ARCHIVE_NAME
        manifest_path = requested / MANIFEST_NAME
        _write_create_only(archive_path, built.archive)
        _write_create_only(
            manifest_path, (canonical_json(built.manifest) + "\n").encode("utf-8")
        )
    except OSError as exc:
        raise RetirementPackageError("OUTPUT_WRITE_FAILED") from exc
    return archive_path, manifest_path, built.manifest
