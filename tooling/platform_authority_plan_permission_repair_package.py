"""Build the deterministic, source-closed GUG-376 repair Lambda package.

``source_bundle_digest`` is deliberately the SHA-256 digest of a canonical
descriptor for the reviewed source entries only.  The generated runtime lock
is excluded from that descriptor, so the digest can be embedded in the lock
without a circular self-reference.  The public manifest independently binds
the complete ZIP bytes and Lambda ``CodeSha256`` value, including the lock.

The Lambda runtime supplies boto3 and botocore.  Their reviewed versions are
sealed in the generated runtime lock and the handlers fail closed when the
managed SDK versions differ.  This module performs no AWS operation.
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
import subprocess
from typing import Any, Mapping
from zipfile import BadZipFile, ZIP_STORED, ZipFile, ZipInfo


ARTIFACT_TYPE = (
    "scanalyze.platform_authority.plan_permission_repair_package.v1"
)
RUNTIME_LOCK_TYPE = (
    "scanalyze.platform_authority.plan_permission_repair_runtime_lock.v1"
)
SCHEMA_VERSION = 1
WORK_PACKAGE = "GUG-376"
PRODUCTION_STATUS = "NO-GO"
ARCHIVE_NAME = "scanalyze-gug376-plan-permission-repair.zip"
MANIFEST_NAME = "scanalyze-gug376-plan-permission-repair.manifest.json"
FIXED_ZIP_TIMESTAMP = (2026, 8, 30, 0, 0, 0)
SOURCE_BUNDLE_DIGEST_PROFILE = (
    "CANONICAL_SOURCE_ENTRY_SET_V1_EXCLUDES_RUNTIME_LOCK"
)
RUNTIME_LOCK_PATH = Path(
    "gug376_plan_permission_repair_runtime_lock.json"
)
HANDLERS = {
    "plan": "tooling.platform_authority_plan_permission_repair_aws.plan_handler",
    "repair": (
        "tooling.platform_authority_plan_permission_repair_aws.repair_handler"
    ),
    "reconcile": (
        "tooling.platform_authority_plan_permission_repair_aws."
        "reconcile_handler"
    ),
}
FUNCTION_RUNTIME = "python3.12"
FUNCTION_ARCHITECTURE = "x86_64"
SOURCE_PATHS = (
    Path(
        "governance/"
        "platform-authority-bootstrap-plan-repair-effective-iam.json"
    ),
    Path("policies/iam/platform-authority-bootstrap-plan-role.json"),
    Path(
        "policies/iam/"
        "platform-authority-bootstrap-plan-repair-invoker-role.json"
    ),
    Path("tooling/__init__.py"),
    Path("tooling/platform_authority_bootstrap.py"),
    Path(
        "tooling/"
        "platform_authority_lambda_audit_repair_invocation_authority.py"
    ),
    Path("tooling/platform_authority_lambda_invocation_authority.py"),
    Path("tooling/platform_authority_plan_permission_repair.py"),
    Path("tooling/platform_authority_plan_permission_repair_aws.py"),
    Path(
        "tooling/"
        "platform_authority_plan_permission_repair_iam_effective_authority.py"
    ),
)
CLOUDFORMATION_TEMPLATE_PATHS = (
    Path(
        "bootstrap/"
        "cfn-platform-authority-bootstrap-plan-repair-delegation.yaml"
    ),
    Path(
        "bootstrap/"
        "cfn-platform-authority-bootstrap-plan-repair-pep.yaml"
    ),
)
PROVENANCE_TOOL_PATHS = (
    *CLOUDFORMATION_TEMPLATE_PATHS,
    Path(
        "schemas/"
        "platform-authority-plan-permission-repair-package-manifest."
        "v1.schema.json"
    ),
    Path(
        "scripts/deployment/"
        "platform-authority-plan-permission-repair-package.py"
    ),
    Path(
        "scripts/deployment/"
        "platform-authority-plan-permission-repair-signed-artifact.py"
    ),
    Path("tooling/platform_authority_lambda_audit_repair_package.py"),
    Path("tooling/platform_authority_lambda_audit_repair_signed_artifact.py"),
    Path("tooling/platform_authority_plan_permission_repair_package.py"),
    Path(
        "tooling/"
        "platform_authority_plan_permission_repair_signed_artifact.py"
    ),
)
PACKAGE_PATHS = tuple(
    sorted((*SOURCE_PATHS, RUNTIME_LOCK_PATH), key=lambda path: path.as_posix())
)

_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_SDK_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_HEX_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_BUNDLE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CODE_SHA256_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")


class PlanPermissionRepairPackageError(ValueError):
    """Stable fail-closed package/provenance contract violation."""


@dataclass(frozen=True, slots=True)
class BuiltPlanPermissionRepairPackage:
    """One immutable in-memory archive and its public manifest."""

    archive: bytes
    manifest: Mapping[str, Any]


def canonical_json(value: Any) -> str:
    """Serialize one public package record deterministically."""

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _read_reviewed_source(source_root: Path, relative_path: Path) -> bytes:
    try:
        root = source_root.resolve(strict=True)
        candidate = root / relative_path
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise PlanPermissionRepairPackageError(
            "PACKAGE_SOURCE_MISSING"
        ) from exc
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise PlanPermissionRepairPackageError(
            "PACKAGE_SOURCE_ESCAPE"
        ) from exc
    if candidate.is_symlink() or not resolved.is_file():
        raise PlanPermissionRepairPackageError("PACKAGE_SOURCE_UNSAFE")
    data = resolved.read_bytes()
    if not data and relative_path != Path("tooling/__init__.py"):
        raise PlanPermissionRepairPackageError("PACKAGE_SOURCE_EMPTY")
    return data


def _entry_record(path: Path, data: bytes) -> dict[str, Any]:
    return {
        "path": path.as_posix(),
        "sha256": sha256(data).hexdigest(),
        "size_bytes": len(data),
    }


def source_bundle_digest(sources: Mapping[Path, bytes]) -> str:
    """Digest exactly the reviewed source entries, never the generated lock."""

    if set(sources) != set(SOURCE_PATHS):
        raise PlanPermissionRepairPackageError("SOURCE_BUNDLE_SET_INVALID")
    descriptor = {
        "digest_profile": SOURCE_BUNDLE_DIGEST_PROFILE,
        "entries": [
            _entry_record(path, sources[path])
            for path in sorted(SOURCE_PATHS, key=lambda item: item.as_posix())
        ],
    }
    return "sha256:" + sha256(canonical_json(descriptor).encode("utf-8")).hexdigest()


def _runtime_lock(
    *,
    source_commit: str,
    bundle_digest: str,
    expected_boto3_version: str,
    expected_botocore_version: str,
) -> dict[str, Any]:
    return {
        "record_type": RUNTIME_LOCK_TYPE,
        "schema_version": SCHEMA_VERSION,
        "source_commit": source_commit,
        "source_bundle_digest": bundle_digest,
        "expected_boto3_version": expected_boto3_version,
        "expected_botocore_version": expected_botocore_version,
    }


def _zip_entry(path: Path, data: bytes) -> tuple[ZipInfo, bytes]:
    info = ZipInfo(path.as_posix(), FIXED_ZIP_TIMESTAMP)
    info.compress_type = ZIP_STORED
    info.create_system = 3
    info.external_attr = (0o100644 & 0xFFFF) << 16
    info.extra = b""
    info.comment = b""
    return info, data


def _manifest_shape_is_valid(manifest: Mapping[str, Any]) -> bool:
    return (
        set(manifest)
        == {
            "artifact_type",
            "schema_version",
            "work_package",
            "source_commit",
            "source_bundle_digest",
            "source_bundle_digest_profile",
            "archive_name",
            "archive_format",
            "archive_sha256",
            "lambda_code_sha256",
            "archive_size_bytes",
            "handlers",
            "function_runtime",
            "function_architecture",
            "runtime_dependencies",
            "entries",
            "production_status",
        }
        and manifest.get("artifact_type") == ARTIFACT_TYPE
        and manifest.get("schema_version") == SCHEMA_VERSION
        and manifest.get("work_package") == WORK_PACKAGE
        and manifest.get("source_bundle_digest_profile")
        == SOURCE_BUNDLE_DIGEST_PROFILE
        and manifest.get("archive_name") == ARCHIVE_NAME
        and manifest.get("archive_format") == "ZIP_STORED_FIXED_METADATA"
        and manifest.get("handlers") == dict(sorted(HANDLERS.items()))
        and manifest.get("function_runtime") == FUNCTION_RUNTIME
        and manifest.get("function_architecture") == FUNCTION_ARCHITECTURE
        and manifest.get("production_status") == PRODUCTION_STATUS
    )


def validate_plan_permission_repair_package(
    *, archive: bytes, manifest: Mapping[str, Any]
) -> None:
    """Validate the complete archive/manifest boundary from untrusted bytes."""

    if not isinstance(archive, bytes) or not archive:
        raise PlanPermissionRepairPackageError("PACKAGE_ARCHIVE_INVALID")
    if not isinstance(manifest, Mapping) or not _manifest_shape_is_valid(manifest):
        raise PlanPermissionRepairPackageError("PACKAGE_MANIFEST_INVALID")
    source_commit = manifest.get("source_commit")
    bundle_digest = manifest.get("source_bundle_digest")
    archive_sha256 = manifest.get("archive_sha256")
    code_sha256 = manifest.get("lambda_code_sha256")
    runtime_dependencies = manifest.get("runtime_dependencies")
    entries = manifest.get("entries")
    if (
        not isinstance(source_commit, str)
        or _COMMIT_RE.fullmatch(source_commit) is None
        or not isinstance(bundle_digest, str)
        or _SOURCE_BUNDLE_DIGEST_RE.fullmatch(bundle_digest) is None
        or not isinstance(archive_sha256, str)
        or _HEX_DIGEST_RE.fullmatch(archive_sha256) is None
        or not isinstance(code_sha256, str)
        or _CODE_SHA256_RE.fullmatch(code_sha256) is None
        or type(manifest.get("archive_size_bytes")) is not int
        or manifest.get("archive_size_bytes") != len(archive)
        or not isinstance(runtime_dependencies, Mapping)
        or set(runtime_dependencies)
        != {
            "aws_sdk",
            "runtime_lock_path",
            "expected_boto3_version",
            "expected_botocore_version",
        }
        or runtime_dependencies.get("aws_sdk")
        != "AWS_MANAGED_PINNED_BY_RUNTIME_VERSION_GUARD"
        or runtime_dependencies.get("runtime_lock_path")
        != RUNTIME_LOCK_PATH.as_posix()
        or any(
            not isinstance(runtime_dependencies.get(field), str)
            or _SDK_VERSION_RE.fullmatch(str(runtime_dependencies[field])) is None
            for field in (
                "expected_boto3_version",
                "expected_botocore_version",
            )
        )
        or not isinstance(entries, list)
        or len(entries) != len(PACKAGE_PATHS)
    ):
        raise PlanPermissionRepairPackageError("PACKAGE_MANIFEST_INVALID")

    archive_digest = sha256(archive).digest()
    if (
        archive_sha256 != archive_digest.hex()
        or code_sha256 != base64.b64encode(archive_digest).decode("ascii")
    ):
        raise PlanPermissionRepairPackageError("PACKAGE_ARCHIVE_DIGEST_MISMATCH")

    entry_map: dict[str, Mapping[str, Any]] = {}
    for entry in entries:
        if (
            not isinstance(entry, Mapping)
            or set(entry) != {"path", "sha256", "size_bytes"}
            or not isinstance(entry.get("path"), str)
            or entry["path"] in entry_map
            or not isinstance(entry.get("sha256"), str)
            or _HEX_DIGEST_RE.fullmatch(str(entry["sha256"])) is None
            or type(entry.get("size_bytes")) is not int
            or int(entry["size_bytes"]) < 0
        ):
            raise PlanPermissionRepairPackageError("PACKAGE_ENTRY_INVALID")
        entry_map[str(entry["path"])] = entry
    expected_names = [path.as_posix() for path in PACKAGE_PATHS]
    if [str(item["path"]) for item in entries] != expected_names:
        raise PlanPermissionRepairPackageError("PACKAGE_ENTRY_SET_INVALID")

    payloads: dict[Path, bytes] = {}
    try:
        with ZipFile(BytesIO(archive), mode="r") as package:
            if package.comment != b"" or package.namelist() != expected_names:
                raise PlanPermissionRepairPackageError(
                    "PACKAGE_ENTRY_SET_INVALID"
                )
            for info, expected_path in zip(package.infolist(), PACKAGE_PATHS):
                if (
                    info.filename != expected_path.as_posix()
                    or info.is_dir()
                    or info.flag_bits != 0
                    or info.date_time != FIXED_ZIP_TIMESTAMP
                    or info.compress_type != ZIP_STORED
                    or info.create_system != 3
                    or info.external_attr
                    != (0o100644 & 0xFFFF) << 16
                    or info.extra != b""
                    or info.comment != b""
                ):
                    raise PlanPermissionRepairPackageError(
                        "PACKAGE_ENTRY_METADATA_INVALID"
                    )
                payload = package.read(info)
                expected_entry = entry_map[info.filename]
                if (
                    expected_entry["sha256"] != sha256(payload).hexdigest()
                    or expected_entry["size_bytes"] != len(payload)
                    or (
                        not payload
                        and expected_path != Path("tooling/__init__.py")
                    )
                ):
                    raise PlanPermissionRepairPackageError(
                        "PACKAGE_ENTRY_DIGEST_MISMATCH"
                    )
                payloads[expected_path] = payload
    except PlanPermissionRepairPackageError:
        raise
    except (BadZipFile, KeyError, OSError, RuntimeError) as exc:
        raise PlanPermissionRepairPackageError("PACKAGE_ARCHIVE_INVALID") from exc

    reviewed_sources = {path: payloads[path] for path in SOURCE_PATHS}
    if source_bundle_digest(reviewed_sources) != bundle_digest:
        raise PlanPermissionRepairPackageError("SOURCE_BUNDLE_DIGEST_MISMATCH")
    try:
        lock = json.loads(payloads[RUNTIME_LOCK_PATH].decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PlanPermissionRepairPackageError("RUNTIME_LOCK_INVALID") from exc
    expected_lock = _runtime_lock(
        source_commit=source_commit,
        bundle_digest=bundle_digest,
        expected_boto3_version=str(
            runtime_dependencies["expected_boto3_version"]
        ),
        expected_botocore_version=str(
            runtime_dependencies["expected_botocore_version"]
        ),
    )
    if lock != expected_lock:
        raise PlanPermissionRepairPackageError("RUNTIME_LOCK_MISMATCH")


def build_plan_permission_repair_package(
    *,
    source_root: Path,
    source_commit: str,
    expected_boto3_version: str,
    expected_botocore_version: str,
    committed_sources: Mapping[Path, bytes] | None = None,
) -> BuiltPlanPermissionRepairPackage:
    """Return deterministic ZIP bytes and their strict public manifest."""

    if _COMMIT_RE.fullmatch(source_commit) is None:
        raise PlanPermissionRepairPackageError("SOURCE_COMMIT_INVALID")
    if any(
        not isinstance(value, str)
        or _SDK_VERSION_RE.fullmatch(value) is None
        for value in (expected_boto3_version, expected_botocore_version)
    ):
        raise PlanPermissionRepairPackageError("SDK_VERSION_INVALID")
    if committed_sources is None:
        sources = {
            path: _read_reviewed_source(source_root, path)
            for path in SOURCE_PATHS
        }
    else:
        if set(committed_sources) != set(SOURCE_PATHS):
            raise PlanPermissionRepairPackageError(
                "COMMITTED_SOURCE_SET_INVALID"
            )
        sources = {
            path: bytes(committed_sources[path]) for path in SOURCE_PATHS
        }
        if any(
            not payload and path != Path("tooling/__init__.py")
            for path, payload in sources.items()
        ):
            raise PlanPermissionRepairPackageError("PACKAGE_SOURCE_EMPTY")

    bundle_digest = source_bundle_digest(sources)
    lock = _runtime_lock(
        source_commit=source_commit,
        bundle_digest=bundle_digest,
        expected_boto3_version=expected_boto3_version,
        expected_botocore_version=expected_botocore_version,
    )
    package_sources = dict(sources)
    package_sources[RUNTIME_LOCK_PATH] = (
        canonical_json(lock) + "\n"
    ).encode("utf-8")
    package_sources = dict(
        sorted(package_sources.items(), key=lambda item: item[0].as_posix())
    )

    buffer = BytesIO()
    with ZipFile(
        buffer,
        mode="w",
        compression=ZIP_STORED,
        strict_timestamps=True,
    ) as package:
        for path, data in package_sources.items():
            info, payload = _zip_entry(path, data)
            package.writestr(info, payload)
    archive = buffer.getvalue()
    archive_digest = sha256(archive).digest()
    manifest = {
        "artifact_type": ARTIFACT_TYPE,
        "schema_version": SCHEMA_VERSION,
        "work_package": WORK_PACKAGE,
        "source_commit": source_commit,
        "source_bundle_digest": bundle_digest,
        "source_bundle_digest_profile": SOURCE_BUNDLE_DIGEST_PROFILE,
        "archive_name": ARCHIVE_NAME,
        "archive_format": "ZIP_STORED_FIXED_METADATA",
        "archive_sha256": archive_digest.hex(),
        "lambda_code_sha256": base64.b64encode(archive_digest).decode(
            "ascii"
        ),
        "archive_size_bytes": len(archive),
        "handlers": dict(sorted(HANDLERS.items())),
        "function_runtime": FUNCTION_RUNTIME,
        "function_architecture": FUNCTION_ARCHITECTURE,
        "runtime_dependencies": {
            "aws_sdk": "AWS_MANAGED_PINNED_BY_RUNTIME_VERSION_GUARD",
            "runtime_lock_path": RUNTIME_LOCK_PATH.as_posix(),
            "expected_boto3_version": expected_boto3_version,
            "expected_botocore_version": expected_botocore_version,
        },
        "entries": [
            _entry_record(path, data)
            for path, data in package_sources.items()
        ],
        "production_status": PRODUCTION_STATUS,
    }
    validate_plan_permission_repair_package(
        archive=archive, manifest=manifest
    )
    return BuiltPlanPermissionRepairPackage(
        archive=archive,
        manifest=manifest,
    )


def verify_clean_source_commit(
    *, source_root: Path, source_commit: str
) -> Mapping[Path, bytes]:
    """Return exact package bytes from one clean, reviewed Git commit."""

    if _COMMIT_RE.fullmatch(source_commit) is None:
        raise PlanPermissionRepairPackageError("SOURCE_COMMIT_INVALID")
    commands = (
        ("rev-parse", "HEAD"),
        ("status", "--porcelain=v1", "--untracked-files=no"),
    )
    outputs: list[str] = []
    for args in commands:
        try:
            result = subprocess.run(
                ["git", *args],
                cwd=source_root,
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise PlanPermissionRepairPackageError(
                "SOURCE_PROVENANCE_UNAVAILABLE"
            ) from exc
        outputs.append(result.stdout.strip())
    if outputs[0] != source_commit:
        raise PlanPermissionRepairPackageError("SOURCE_COMMIT_MISMATCH")
    if outputs[1]:
        raise PlanPermissionRepairPackageError("SOURCE_TREE_DIRTY")

    committed_sources: dict[Path, bytes] = {}
    for relative_path in (*SOURCE_PATHS, *PROVENANCE_TOOL_PATHS):
        try:
            subprocess.run(
                [
                    "git",
                    "ls-files",
                    "--error-unmatch",
                    "--",
                    relative_path.as_posix(),
                ],
                cwd=source_root,
                check=True,
                capture_output=True,
                timeout=30,
            )
            committed = subprocess.run(
                [
                    "git",
                    "show",
                    f"{source_commit}:{relative_path.as_posix()}",
                ],
                cwd=source_root,
                check=True,
                capture_output=True,
                timeout=30,
            ).stdout
        except (OSError, subprocess.SubprocessError) as exc:
            raise PlanPermissionRepairPackageError(
                "PACKAGE_SOURCE_NOT_IN_COMMIT"
            ) from exc
        if committed != _read_reviewed_source(source_root, relative_path):
            raise PlanPermissionRepairPackageError(
                "PACKAGE_SOURCE_COMMIT_DRIFT"
            )
        if relative_path in SOURCE_PATHS:
            committed_sources[relative_path] = committed
    return committed_sources


def reviewed_cloudformation_template_digests(
    *, source_root: Path, source_commit: str
) -> Mapping[str, str]:
    """Return exact Git-object digests for both reviewed deployment templates."""

    if _COMMIT_RE.fullmatch(source_commit) is None:
        raise PlanPermissionRepairPackageError("SOURCE_COMMIT_INVALID")
    result: dict[str, str] = {}
    for relative_path in CLOUDFORMATION_TEMPLATE_PATHS:
        try:
            committed = subprocess.run(
                [
                    "git",
                    "show",
                    f"{source_commit}:{relative_path.as_posix()}",
                ],
                cwd=source_root,
                check=True,
                capture_output=True,
                timeout=30,
            ).stdout
        except (OSError, subprocess.SubprocessError) as exc:
            raise PlanPermissionRepairPackageError(
                "CLOUDFORMATION_TEMPLATE_NOT_IN_COMMIT"
            ) from exc
        if committed != _read_reviewed_source(source_root, relative_path):
            raise PlanPermissionRepairPackageError(
                "CLOUDFORMATION_TEMPLATE_COMMIT_DRIFT"
            )
        result[relative_path.as_posix()] = sha256(committed).hexdigest()
    return result


def write_plan_permission_repair_package(
    *,
    source_root: Path,
    source_commit: str,
    expected_boto3_version: str,
    expected_botocore_version: str,
    output_directory: Path,
) -> tuple[Path, Path, Mapping[str, Any]]:
    """Write one owner-only artifact directory without overwriting evidence."""

    committed_sources = verify_clean_source_commit(
        source_root=source_root,
        source_commit=source_commit,
    )
    built = build_plan_permission_repair_package(
        source_root=source_root,
        source_commit=source_commit,
        expected_boto3_version=expected_boto3_version,
        expected_botocore_version=expected_botocore_version,
        committed_sources=committed_sources,
    )
    root = source_root.resolve(strict=True)
    requested_output = output_directory.resolve(strict=False)
    try:
        requested_output.relative_to(root)
    except ValueError:
        pass
    else:
        raise PlanPermissionRepairPackageError(
            "OUTPUT_MUST_BE_OUTSIDE_SOURCE_ROOT"
        )
    try:
        output_directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    except OSError as exc:
        raise PlanPermissionRepairPackageError(
            "OUTPUT_DIRECTORY_UNAVAILABLE"
        ) from exc

    archive_path = output_directory / ARCHIVE_NAME
    manifest_path = output_directory / MANIFEST_NAME
    manifest_bytes = (canonical_json(built.manifest) + "\n").encode("utf-8")
    try:
        for path, payload in (
            (archive_path, built.archive),
            (manifest_path, manifest_bytes),
        ):
            descriptor = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
    except OSError as exc:
        raise PlanPermissionRepairPackageError("OUTPUT_WRITE_FAILED") from exc
    return archive_path, manifest_path, built.manifest
