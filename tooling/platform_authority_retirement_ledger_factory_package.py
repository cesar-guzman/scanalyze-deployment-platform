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
WORKFORCE_ARTIFACT_TYPE = "scanalyze.platform_authority.retirement_ledger_factory_package.v2"
WORKFORCE_ARCHIVE_NAME = "scanalyze-gug215-workforce-ledger-factory.zip"
WORKFORCE_MANIFEST_NAME = "scanalyze-gug215-workforce-ledger-factory.manifest.json"
WORKFORCE_HANDLER = "tooling.platform_authority_retirement_ledger_factory.handler_workforce"
WORKFORCE_PROVENANCE_PATHS = PROVENANCE_PATHS + (
    Path("schemas/platform-authority-retirement-ledger-factory-package.v2.schema.json"),
    Path("schemas/platform-authority-retirement-ledger-factory-receipt.v2.schema.json"),
    Path("scripts/deployment/platform-authority-retirement-entrypoint-service-role.py"),
)
_MAX_WORKFORCE_SOURCE_BYTES = 262_144
_MAX_WORKFORCE_ARCHIVE_BYTES = 524_288

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
    *, source_root: Path, source_commit: str, workforce: bool = False
) -> Mapping[Path, bytes]:
    """Read exact package sources only from a clean checked-out commit."""

    if type(workforce) is not bool:
        raise LedgerFactoryPackageError("PACKAGE_MODE_INVALID")
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
    for path in SOURCE_PATHS + (WORKFORCE_PROVENANCE_PATHS if workforce else ()):
        try:
            payload = bytes(
                _git(root, "show", f"{source_commit}:{path.as_posix()}", text=False)
            )
        except subprocess.SubprocessError as exc:
            raise LedgerFactoryPackageError("PACKAGE_SOURCE_NOT_COMMITTED") from exc
        if payload != _read_source(root, path):
            raise LedgerFactoryPackageError("PACKAGE_SOURCE_COMMIT_DRIFT")
        committed[path] = payload
    if workforce:
        try:
            final_head = str(_git(root, "rev-parse", "HEAD")).strip()
            final_dirty = str(_git(root, "status", "--porcelain=v1", "--untracked-files=all"))
        except (OSError, subprocess.SubprocessError):
            raise LedgerFactoryPackageError("SOURCE_COMMIT_UNAVAILABLE") from None
        if final_head != source_commit:
            raise LedgerFactoryPackageError("SOURCE_COMMIT_MISMATCH")
        if final_dirty:
            raise LedgerFactoryPackageError("SOURCE_TREE_DIRTY")
    return committed


def _workforce_runtime() -> Any:
    # Source-only, stdlib-only import. Neither this import nor the runtime's
    # module initialization constructs a provider client.
    from tooling import platform_authority_retirement_ledger_factory

    return platform_authority_retirement_ledger_factory


def _workforce_manifest_constants() -> dict[str, Any]:
    runtime = _workforce_runtime()
    return {
        "artifact_type": WORKFORCE_ARTIFACT_TYPE,
        "schema_version": 2,
        "work_package": "GUG-215",
        "production": True,
        "archive_name": WORKFORCE_ARCHIVE_NAME,
        "handler": WORKFORCE_HANDLER,
        "authorization_mode": runtime.WORKFORCE_AUTHORIZATION_MODE,
        "factory_contract_sha256": runtime.WORKFORCE_CONTRACT_SHA256,
        "artifact_status": "UNSIGNED_SOURCE_NOT_DEPLOYABLE",
        "signature_status": "PENDING_SIGNING_AND_IMMUTABLE_VERSION_READBACK",
        "source_ci_status": "PENDING_CONNECTED_REVALIDATION",
        "source_snapshot_status": "CAPTURED_BYTES_NOT_AUTHENTICATED",
        "function_version_arn": None,
    }


def build_workforce_ledger_factory_package(
    *, source_root: Path, source_commit: str, runtime_version_arn: str,
    committed_sources: Mapping[Path, bytes] | None = None,
) -> BuiltLedgerFactoryPackage:
    """Build unsigned v2 from a complete source/provenance snapshot.

    Without an injected snapshot, the real HEAD/clean-tree/blob gate runs.
    Injected snapshots support pure review/tests, not an authentication claim:
    the manifest never certifies source CI, signing or installation. A future
    caller must protect the pin and revalidate all gates before publication.
    """
    paths = SOURCE_PATHS + WORKFORCE_PROVENANCE_PATHS
    if (type(runtime_version_arn) is not str or re.fullmatch(
            r"arn:aws:lambda:us-east-1::runtime:[0-9a-f]{64}", runtime_version_arn) is None):
        raise LedgerFactoryPackageError("RUNTIME_VERSION_ARN_INVALID")
    captured = (verify_clean_source_commit(source_root=source_root,
                source_commit=source_commit, workforce=True)
                if committed_sources is None else committed_sources)
    if set(captured) != set(paths):
        raise LedgerFactoryPackageError("COMMITTED_SOURCE_SET_INVALID")
    if any(type(captured[path]) is not bytes for path in paths):
        raise LedgerFactoryPackageError("COMMITTED_SOURCE_BYTES_INVALID")
    snapshot = {path: bytes(captured[path]) for path in paths}
    for path, payload in snapshot.items():
        if (len(payload) > _MAX_WORKFORCE_SOURCE_BYTES
                or (not payload and path != Path("tooling/__init__.py"))):
            raise LedgerFactoryPackageError("PACKAGE_SOURCE_SIZE_INVALID")
    # Reuse the exact v1 ZIP writer. The distinct handler and metadata are
    # selected here, never via Lambda event or environment.
    built = build_ledger_factory_package(source_root=source_root,
        source_commit=source_commit, runtime_version_arn=runtime_version_arn,
        committed_sources={path: snapshot[path] for path in SOURCE_PATHS})
    manifest = dict(built.manifest)
    manifest.update(_workforce_manifest_constants())
    manifest["provenance"] = [
        {"path": path.as_posix(), "sha256": sha256(snapshot[path]).hexdigest(),
         "size_bytes": len(snapshot[path])}
        for path in WORKFORCE_PROVENANCE_PATHS
    ]
    manifest["manifest_digest"] = canonical_digest(
        {key: value for key, value in manifest.items() if key != "manifest_digest"})
    validate_workforce_ledger_factory_package_manifest(manifest, archive=built.archive)
    return BuiltLedgerFactoryPackage(built.archive, manifest)


def validate_workforce_ledger_factory_package_manifest(
    manifest: Mapping[str, Any], *, archive: bytes | None = None,
) -> None:
    """Validate v2 integrity and canonical bytes; this grants no authority."""
    if not isinstance(manifest, Mapping):
        raise LedgerFactoryPackageError("PACKAGE_MANIFEST_FIELDS_INVALID")
    constants = _workforce_manifest_constants()
    if any(type(manifest.get(key)) is not type(value) or manifest.get(key) != value
           for key, value in constants.items()):
        raise LedgerFactoryPackageError("PACKAGE_MANIFEST_SCOPE_INVALID")
    if (manifest.get("deployment_authorized") is not False
            or manifest.get("environment") != {}
            or type(manifest.get("environment")) is not dict):
        raise LedgerFactoryPackageError("PACKAGE_MANIFEST_SCOPE_INVALID")
    if manifest.get("manifest_digest") != canonical_digest(
            {key: value for key, value in manifest.items() if key != "manifest_digest"}):
        raise LedgerFactoryPackageError("PACKAGE_MANIFEST_DIGEST_INVALID")
    provenance = manifest.get("provenance")
    if type(provenance) is not list or len(provenance) != len(WORKFORCE_PROVENANCE_PATHS):
        raise LedgerFactoryPackageError("PACKAGE_PROVENANCE_INVALID")
    for entry, path in zip(provenance, WORKFORCE_PROVENANCE_PATHS, strict=True):
        if (not isinstance(entry, Mapping)
                or set(entry) != {"path", "sha256", "size_bytes"}
                or entry.get("path") != path.as_posix()
                or type(entry.get("sha256")) is not str
                or _HEX_DIGEST.fullmatch(entry["sha256"]) is None
                or type(entry.get("size_bytes")) is not int
                or not 1 <= entry["size_bytes"] <= _MAX_WORKFORCE_SOURCE_BYTES):
            raise LedgerFactoryPackageError("PACKAGE_PROVENANCE_INVALID")
    # Adapt only the reviewed v2 differences into the existing pure v1
    # validator. The public v1 validator continues rejecting v2 directly.
    legacy = dict(manifest)
    for key in constants.keys() - {"artifact_type", "schema_version", "work_package",
                                  "production", "archive_name", "handler"}:
        del legacy[key]
    del legacy["provenance"]
    legacy.update(artifact_type=ARTIFACT_TYPE, schema_version=1,
                  work_package=WORK_PACKAGE, production=False,
                  archive_name=ARCHIVE_NAME, handler=HANDLER)
    legacy["manifest_digest"] = canonical_digest(
        {key: value for key, value in legacy.items() if key != "manifest_digest"})
    validate_ledger_factory_package_manifest(legacy)
    if (manifest["archive_size_bytes"] > _MAX_WORKFORCE_ARCHIVE_BYTES
            or any(entry["size_bytes"] > _MAX_WORKFORCE_SOURCE_BYTES
                   for entry in manifest["entries"])):
        raise LedgerFactoryPackageError("PACKAGE_SOURCE_SIZE_INVALID")
    if archive is None:
        return
    if type(archive) is not bytes or len(archive) > _MAX_WORKFORCE_ARCHIVE_BYTES:
        raise LedgerFactoryPackageError("PACKAGE_ARCHIVE_SIZE_INVALID")
    try:
        # Reject oversized declarations before the shared validator reads any
        # member. Only stored, exact-size source bytes are accepted.
        with ZipFile(BytesIO(archive)) as value:
            if value.namelist() != [path.as_posix() for path in SOURCE_PATHS]:
                raise LedgerFactoryPackageError("PACKAGE_ARCHIVE_MEMBERS_INVALID")
            for info, entry in zip(value.infolist(), manifest["entries"], strict=True):
                if (info.file_size != entry["size_bytes"]
                        or info.compress_size != info.file_size
                        or info.compress_type != ZIP_STORED
                        or info.file_size > _MAX_WORKFORCE_SOURCE_BYTES):
                    raise LedgerFactoryPackageError("PACKAGE_ARCHIVE_SIZE_INVALID")
        validate_ledger_factory_package_manifest(legacy, archive=archive)
        buffer = BytesIO()
        with ZipFile(BytesIO(archive)) as source, ZipFile(
                buffer, mode="w", compression=ZIP_STORED, strict_timestamps=True) as rebuilt:
            for path in SOURCE_PATHS:
                info, payload = _zip_entry(path, source.read(path.as_posix()))
                rebuilt.writestr(info, payload)
        if buffer.getvalue() != archive:
            raise LedgerFactoryPackageError("PACKAGE_ARCHIVE_NOT_CANONICAL")
    except BadZipFile:
        raise LedgerFactoryPackageError("PACKAGE_ARCHIVE_INVALID") from None


def validate_workforce_ledger_factory_causal_receipt(
    receipt: Mapping[str, Any], *, expected_receipt_digest: str,
    expected_function_version_arn: str,
) -> None:
    """Validate captured causal metadata with independent pins, not a grant.

    The caller must authenticate custody of both pins and the provider result.
    A valid hash cannot establish provenance or replace revocation/readback.
    """
    runtime = _workforce_runtime()
    version_prefix = (f"arn:aws:lambda:{runtime.REGION}:{runtime.AUTHORITY_ACCOUNT_ID}:"
                      f"function:{runtime.WORKFORCE_FACTORY_FUNCTION_NAME}:")
    if (type(expected_function_version_arn) is not str
            or re.fullmatch(re.escape(version_prefix) + r"[1-9][0-9]{0,7}",
                            expected_function_version_arn) is None
            or type(expected_receipt_digest) is not str
            or _DIGEST.fullmatch(expected_receipt_digest) is None):
        raise LedgerFactoryPackageError("WORKFORCE_RECEIPT_PIN_INVALID")
    constants = {
        "artifact_type": runtime.WORKFORCE_RECEIPT_ARTIFACT_TYPE,
        "schema_version": 2,
        "authorization_mode": runtime.WORKFORCE_AUTHORIZATION_MODE,
        "deployment_authorized": False,
        "production_status": "NO-GO",
        "reason_code": "LEDGER_EXACT_FULL_READBACK",
        "attempt": 1, "create_table_call_count": 1, "update_pitr_call_count": 1,
        "retry_permitted": False, "next_required_action": "REVOKE_FACTORY_AUTHORITY",
        "request_sha256": canonical_digest({}),
        "contract_sha256": runtime.WORKFORCE_CONTRACT_SHA256,
        "qualified_function_sha256": canonical_digest(
            {"qualified_function_arn": expected_function_version_arn}),
        "resource_policy_sha256": canonical_digest(runtime.canonical_workforce_resource_policy()),
    }
    counters = {"active_readback_attempt_count": (2, 60),
                "policy_readback_attempt_count": (2, 12),
                "pitr_readback_attempt_count": (1, 12)}
    digests = {"kms_key_arn_sha256", "kms_key_metadata_sha256",
               "revision_id_sha256", "receipt_sha256"}
    if (not isinstance(receipt, Mapping)
            or set(receipt) != set(constants) | set(counters) | digests | {"status"}
            or receipt.get("status") not in ("CREATED", "CREATED_RECONCILED")
            or any(type(receipt.get(key)) is not type(value) or receipt.get(key) != value
                   for key, value in constants.items())
            or any(type(receipt.get(key)) is not int or not low <= receipt[key] <= high
                   for key, (low, high) in counters.items())
            or any(type(receipt.get(key)) is not str or _DIGEST.fullmatch(receipt[key]) is None
                   for key in digests)):
        raise LedgerFactoryPackageError("WORKFORCE_CAUSAL_RECEIPT_INVALID")
    actual = canonical_digest({key: value for key, value in receipt.items()
                               if key != "receipt_sha256"})
    if receipt["receipt_sha256"] != actual or expected_receipt_digest != actual:
        raise LedgerFactoryPackageError("WORKFORCE_RECEIPT_PIN_MISMATCH")
