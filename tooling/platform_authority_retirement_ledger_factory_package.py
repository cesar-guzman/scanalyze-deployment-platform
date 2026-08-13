"""Build the deterministic unsigned GUG-365 ledger-factory source package.

This package is intentionally separate from the GUG-215 retirement broker
package.  It contains only the dedicated ledger factory and package marker,
relies on the AWS-managed Python SDK, and performs no network, AWS, signing,
upload or deployment operation.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
import re
import subprocess
from typing import Any, Mapping
from zipfile import BadZipFile, ZIP_STORED, ZipFile, ZipInfo


ARTIFACT_TYPE = "scanalyze.platform_authority.retirement_ledger_factory_package.v1"
SCHEMA_VERSION = 1
WORK_PACKAGE = "GUG-365"
PRODUCTION_STATUS = "NO-GO"
ARCHIVE_NAME = "scanalyze-gug365-retirement-ledger-factory.zip"
MANIFEST_NAME = "scanalyze-gug365-retirement-ledger-factory.manifest.json"
FIXED_ZIP_TIMESTAMP = (2026, 8, 12, 0, 0, 0)
HANDLER = "tooling.platform_authority_retirement_ledger_factory.handler"
SOURCE_PATHS = (
    Path("tooling/__init__.py"),
    Path("tooling/platform_authority_retirement_ledger_factory.py"),
)
PROVENANCE_PATHS = (
    Path("tooling/platform_authority_retirement_ledger_factory_package.py"),
)

_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_CODE_SHA = re.compile(r"^[A-Za-z0-9+/]{43}=$")
_RUNTIME_ARN = re.compile(
    r"^arn:aws(?:-[a-z]+)*:lambda:[a-z]{2}(?:-[a-z]+)+-[0-9]+::runtime:"
    r"[0-9a-f]{64}$"
)


class LedgerFactoryPackageError(ValueError):
    """Stable fail-closed package/provenance error."""


@dataclass(frozen=True, slots=True)
class BuiltLedgerFactoryPackage:
    archive: bytes
    manifest: Mapping[str, Any]


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def canonical_digest(value: Any) -> str:
    return "sha256:" + sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _read_source(source_root: Path, relative_path: Path) -> bytes:
    root = source_root.resolve(strict=True)
    candidate = root / relative_path
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise LedgerFactoryPackageError("PACKAGE_SOURCE_MISSING") from exc
    if candidate.is_symlink() or not resolved.is_file():
        raise LedgerFactoryPackageError("PACKAGE_SOURCE_UNSAFE")
    payload = resolved.read_bytes()
    if not payload and relative_path != Path("tooling/__init__.py"):
        raise LedgerFactoryPackageError("PACKAGE_SOURCE_EMPTY")
    return payload


def _zip_entry(path: Path, payload: bytes) -> tuple[ZipInfo, bytes]:
    info = ZipInfo(path.as_posix(), FIXED_ZIP_TIMESTAMP)
    info.compress_type = ZIP_STORED
    info.create_system = 3
    info.external_attr = (0o100644 & 0xFFFF) << 16
    info.extra = b""
    info.comment = b""
    return info, payload


def build_ledger_factory_package(
    *,
    source_root: Path,
    source_commit: str,
    runtime_version_arn: str,
    committed_sources: Mapping[Path, bytes] | None = None,
) -> BuiltLedgerFactoryPackage:
    """Return deterministic ZIP bytes and a strict public manifest."""

    if _COMMIT.fullmatch(source_commit) is None:
        raise LedgerFactoryPackageError("SOURCE_COMMIT_INVALID")
    if _RUNTIME_ARN.fullmatch(runtime_version_arn) is None:
        raise LedgerFactoryPackageError("RUNTIME_VERSION_ARN_INVALID")
    if committed_sources is None:
        sources = {path: _read_source(source_root, path) for path in SOURCE_PATHS}
    else:
        if set(committed_sources) != set(SOURCE_PATHS):
            raise LedgerFactoryPackageError("COMMITTED_SOURCE_SET_INVALID")
        sources = {path: bytes(committed_sources[path]) for path in SOURCE_PATHS}
        if any(
            not payload and path != Path("tooling/__init__.py")
            for path, payload in sources.items()
        ):
            raise LedgerFactoryPackageError("PACKAGE_SOURCE_EMPTY")

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
        "runtime_version_arn_sha256": canonical_digest(
            {"runtime_version_arn": runtime_version_arn}
        ),
        "environment": {},
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
    validate_ledger_factory_package_manifest(manifest, archive=archive_bytes)
    return BuiltLedgerFactoryPackage(archive=archive_bytes, manifest=manifest)


def validate_ledger_factory_package_manifest(
    manifest: Mapping[str, Any], *, archive: bytes | None = None
) -> None:
    required = {
        "artifact_type",
        "schema_version",
        "work_package",
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
        "runtime_version_arn_sha256",
        "environment",
        "entries",
        "deployment_authorized",
        "production_status",
        "manifest_digest",
    }
    if set(manifest) != required:
        raise LedgerFactoryPackageError("PACKAGE_MANIFEST_FIELDS_INVALID")
    constants = {
        "artifact_type": ARTIFACT_TYPE,
        "schema_version": SCHEMA_VERSION,
        "work_package": WORK_PACKAGE,
        "production": False,
        "archive_name": ARCHIVE_NAME,
        "archive_format": "ZIP_STORED_FIXED_METADATA",
        "handler": HANDLER,
        "runtime": "python3.12",
        "architecture": "x86_64",
        "runtime_dependency_mode": "AWS_MANAGED_RUNTIME_PINNED",
        "environment": {},
        "deployment_authorized": False,
        "production_status": PRODUCTION_STATUS,
    }
    if any(manifest.get(key) != value for key, value in constants.items()):
        raise LedgerFactoryPackageError("PACKAGE_MANIFEST_SCOPE_INVALID")
    if (
        not isinstance(manifest.get("source_commit"), str)
        or _COMMIT.fullmatch(manifest["source_commit"]) is None
        or not isinstance(manifest.get("archive_sha256"), str)
        or _HEX_DIGEST.fullmatch(manifest["archive_sha256"]) is None
        or not isinstance(manifest.get("lambda_code_sha256"), str)
        or _CODE_SHA.fullmatch(manifest["lambda_code_sha256"]) is None
        or not isinstance(manifest.get("runtime_version_arn_sha256"), str)
        or _DIGEST.fullmatch(manifest["runtime_version_arn_sha256"]) is None
        or type(manifest.get("archive_size_bytes")) is not int
        or manifest["archive_size_bytes"] <= 0
    ):
        raise LedgerFactoryPackageError("PACKAGE_MANIFEST_VALUE_INVALID")
    entries = manifest.get("entries")
    if not isinstance(entries, list) or len(entries) != len(SOURCE_PATHS):
        raise LedgerFactoryPackageError("PACKAGE_MANIFEST_ENTRIES_INVALID")
    expected_paths = [path.as_posix() for path in SOURCE_PATHS]
    if [entry.get("path") if isinstance(entry, Mapping) else None for entry in entries] != expected_paths:
        raise LedgerFactoryPackageError("PACKAGE_MANIFEST_ENTRIES_INVALID")
    for entry in entries:
        if (
            not isinstance(entry, Mapping)
            or set(entry) != {"path", "sha256", "size_bytes"}
            or not isinstance(entry.get("sha256"), str)
            or _HEX_DIGEST.fullmatch(entry["sha256"]) is None
            or type(entry.get("size_bytes")) is not int
            or entry["size_bytes"] < 0
            or (
                entry["path"] != "tooling/__init__.py"
                and entry["size_bytes"] == 0
            )
        ):
            raise LedgerFactoryPackageError("PACKAGE_MANIFEST_ENTRIES_INVALID")
    expected_manifest_digest = canonical_digest(
        {key: value for key, value in manifest.items() if key != "manifest_digest"}
    )
    if manifest.get("manifest_digest") != expected_manifest_digest:
        raise LedgerFactoryPackageError("PACKAGE_MANIFEST_DIGEST_INVALID")
    if archive is None:
        return
    archive_digest = sha256(archive).digest()
    if (
        manifest["archive_sha256"] != archive_digest.hex()
        or manifest["lambda_code_sha256"]
        != base64.b64encode(archive_digest).decode("ascii")
        or manifest["archive_size_bytes"] != len(archive)
    ):
        raise LedgerFactoryPackageError("PACKAGE_ARCHIVE_DIGEST_MISMATCH")
    try:
        with ZipFile(BytesIO(archive)) as value:
            if value.namelist() != expected_paths:
                raise LedgerFactoryPackageError("PACKAGE_ARCHIVE_MEMBERS_INVALID")
            for info, entry in zip(value.infolist(), entries, strict=True):
                if (
                    info.date_time != FIXED_ZIP_TIMESTAMP
                    or info.compress_type != ZIP_STORED
                    or info.create_system != 3
                    or (info.external_attr >> 16) & 0o777 != 0o644
                    or info.extra != b""
                    or info.comment != b""
                ):
                    raise LedgerFactoryPackageError("PACKAGE_ARCHIVE_METADATA_INVALID")
                payload = value.read(info.filename)
                if (
                    entry["sha256"] != sha256(payload).hexdigest()
                    or entry["size_bytes"] != len(payload)
                ):
                    raise LedgerFactoryPackageError(
                        "PACKAGE_ARCHIVE_MEMBER_DIGEST_MISMATCH"
                    )
    except BadZipFile as exc:
        raise LedgerFactoryPackageError("PACKAGE_ARCHIVE_INVALID") from exc


def _git(root: Path, *args: str, text: bool = True) -> str | bytes:
    result = subprocess.run(
        ["git", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=text,
        timeout=30,
    )
    return result.stdout


def verify_clean_source_commit(
    *, source_root: Path, source_commit: str
) -> Mapping[Path, bytes]:
    """Read exact package sources only from a clean checked-out commit."""

    if _COMMIT.fullmatch(source_commit) is None:
        raise LedgerFactoryPackageError("SOURCE_COMMIT_INVALID")
    root = source_root.resolve(strict=True)
    try:
        head = str(_git(root, "rev-parse", "HEAD")).strip()
        dirty = str(
            _git(root, "status", "--porcelain=v1", "--untracked-files=all")
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise LedgerFactoryPackageError("SOURCE_COMMIT_UNAVAILABLE") from exc
    if head != source_commit:
        raise LedgerFactoryPackageError("SOURCE_COMMIT_MISMATCH")
    if dirty:
        raise LedgerFactoryPackageError("SOURCE_TREE_DIRTY")
    committed: dict[Path, bytes] = {}
    for path in SOURCE_PATHS:
        try:
            payload = bytes(
                _git(root, "show", f"{source_commit}:{path.as_posix()}", text=False)
            )
        except subprocess.SubprocessError as exc:
            raise LedgerFactoryPackageError("PACKAGE_SOURCE_NOT_COMMITTED") from exc
        if payload != _read_source(root, path):
            raise LedgerFactoryPackageError("PACKAGE_SOURCE_COMMIT_DRIFT")
        committed[path] = payload
    return committed
