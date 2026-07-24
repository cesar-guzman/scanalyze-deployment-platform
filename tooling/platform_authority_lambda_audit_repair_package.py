"""Build the deterministic, closed GUG-221 Lambda deployment package.

The package contains only the reviewed Python modules and policy templates
required by every private Lambda handler.  ZIP metadata is fixed and entries
are stored rather than deflated so the archive is byte-for-byte reproducible
across zlib implementations.  This module performs no AWS operation.
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
from zipfile import ZIP_STORED, ZipFile, ZipInfo


ARTIFACT_TYPE = "scanalyze.platform_authority.lambda_audit_repair_package.v1"
SCHEMA_VERSION = 1
WORK_PACKAGE = "GUG-221"
PRODUCTION_STATUS = "NO-GO"
ARCHIVE_NAME = "scanalyze-gug221-lambda-audit-repair.zip"
MANIFEST_NAME = "scanalyze-gug221-lambda-audit-repair.manifest.json"
FIXED_ZIP_TIMESTAMP = (2026, 7, 21, 0, 0, 0)
HANDLERS = {
    "phase_b_broker": "tooling.platform_authority_lambda_audit_repair_phase_b_runtime.handler",
    "plan": "tooling.platform_authority_lambda_audit_repair_broker_runtime.plan_handler",
    "repair": "tooling.platform_authority_lambda_audit_repair_broker_runtime.repair_handler",
    "reconcile": "tooling.platform_authority_lambda_audit_repair_broker_runtime.reconcile_handler",
}
SOURCE_PATHS = (
    Path("policies/iam/aws-managed-identity-context-allowlist-v12.snapshot.json"),
    Path("policies/iam/platform-authority-lambda-audit-plan-authority-execution-role.json"),
    Path("policies/iam/platform-authority-lambda-audit-reconcile-authority-execution-role.json"),
    Path("policies/iam/platform-authority-lambda-audit-repair-authority-execution-role.json"),
    Path("policies/iam/platform-authority-lambda-audit-repair-invocation-inspector-role.json"),
    Path("policies/iam/platform-authority-lambda-audit-repair-invoker-role.json"),
    Path("policies/iam/platform-authority-lambda-audit-repair-mutation-service-role.json"),
    Path("policies/iam/platform-authority-lambda-audit-repair-readback-service-role.json"),
    Path(
        "policies/iam/"
        "platform-authority-lambda-audit-repair-phase-b-application-actor-policy.json"
    ),
    Path(
        "policies/iam/"
        "platform-authority-lambda-audit-repair-phase-b-broker-execution-role.json"
    ),
    Path(
        "policies/iam/"
        "platform-authority-lambda-audit-repair-phase-b-invoker-role.json"
    ),
    Path(
        "policies/iam/"
        "platform-authority-lambda-audit-repair-phase-b-proof-role.json"
    ),
    Path("policies/iam/platform-authority-lambda-invocation-inventory-role.json"),
    Path("tooling/__init__.py"),
    Path("tooling/platform_authority_lambda_audit_repair_broker.py"),
    Path("tooling/platform_authority_lambda_audit_repair_broker_runtime.py"),
    Path("tooling/platform_authority_lambda_audit_repair_iam_verifier.py"),
    Path("tooling/platform_authority_lambda_audit_repair_invocation_authority.py"),
    Path("tooling/platform_authority_lambda_audit_repair_phase_b_pep.py"),
    Path("tooling/platform_authority_lambda_audit_repair_phase_b_runtime.py"),
    Path("tooling/platform_authority_lambda_audit_repair_phase_b_topology.py"),
    Path("tooling/platform_authority_identity_context_compatibility.py"),
    Path("tooling/platform_authority_lambda_invocation_authority.py"),
    Path("tooling/platform_authority_lambda_invocation_materializer.py"),
)
PROVENANCE_TOOL_PATHS = (
    Path("scripts/deployment/platform-authority-lambda-audit-repair-package.py"),
    Path("scripts/deployment/platform-authority-lambda-audit-repair-signed-artifact.py"),
    Path("tooling/platform_authority_lambda_audit_repair_package.py"),
    Path("tooling/platform_authority_lambda_audit_repair_signed_artifact.py"),
)
RUNTIME_LOCK_PATH = Path("gug221_runtime_lock.json")
PACKAGE_PATHS = tuple(
    sorted((*SOURCE_PATHS, RUNTIME_LOCK_PATH), key=lambda item: item.as_posix())
)

_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_SDK_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


class RepairPackageError(ValueError):
    """A stable fail-closed package contract violation."""


@dataclass(frozen=True)
class BuiltRepairPackage:
    archive: bytes
    manifest: Mapping[str, Any]


def canonical_json(value: Any) -> str:
    """Serialize a public manifest deterministically."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _read_reviewed_source(source_root: Path, relative_path: Path) -> bytes:
    root = source_root.resolve(strict=True)
    candidate = root / relative_path
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise RepairPackageError("PACKAGE_SOURCE_MISSING") from exc
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise RepairPackageError("PACKAGE_SOURCE_ESCAPE") from exc
    if candidate.is_symlink() or not resolved.is_file():
        raise RepairPackageError("PACKAGE_SOURCE_UNSAFE")
    data = resolved.read_bytes()
    if not data and relative_path != Path("tooling/__init__.py"):
        raise RepairPackageError("PACKAGE_SOURCE_EMPTY")
    return data


def _zip_entry(path: Path, data: bytes) -> tuple[ZipInfo, bytes]:
    info = ZipInfo(path.as_posix(), FIXED_ZIP_TIMESTAMP)
    info.compress_type = ZIP_STORED
    info.create_system = 3
    info.external_attr = (0o100644 & 0xFFFF) << 16
    info.extra = b""
    info.comment = b""
    return info, data


def build_repair_package(
    *,
    source_root: Path,
    source_commit: str,
    expected_boto3_version: str,
    expected_botocore_version: str,
    committed_sources: Mapping[Path, bytes] | None = None,
) -> BuiltRepairPackage:
    """Return deterministic ZIP bytes and their strict public manifest."""

    if _COMMIT_RE.fullmatch(source_commit) is None:
        raise RepairPackageError("SOURCE_COMMIT_INVALID")
    if any(
        _SDK_VERSION_RE.fullmatch(value) is None
        for value in (expected_boto3_version, expected_botocore_version)
    ):
        raise RepairPackageError("SDK_VERSION_INVALID")
    if committed_sources is None:
        sources = {
            path: _read_reviewed_source(source_root, path)
            for path in SOURCE_PATHS
        }
    else:
        if set(committed_sources) != set(SOURCE_PATHS):
            raise RepairPackageError("COMMITTED_SOURCE_SET_INVALID")
        sources = {path: bytes(committed_sources[path]) for path in SOURCE_PATHS}
        if any(
            not payload and path != Path("tooling/__init__.py")
            for path, payload in sources.items()
        ):
            raise RepairPackageError("PACKAGE_SOURCE_EMPTY")
    runtime_lock = {
        "record_type": "scanalyze.platform_authority.lambda_audit_repair_runtime_lock.v1",
        "schema_version": 1,
        "source_commit": source_commit,
        "expected_boto3_version": expected_boto3_version,
        "expected_botocore_version": expected_botocore_version,
    }
    sources[RUNTIME_LOCK_PATH] = (canonical_json(runtime_lock) + "\n").encode("utf-8")
    sources = dict(sorted(sources.items(), key=lambda item: item[0].as_posix()))
    buffer = BytesIO()
    with ZipFile(buffer, mode="w", compression=ZIP_STORED, strict_timestamps=True) as archive:
        for path, data in sources.items():
            info, payload = _zip_entry(path, data)
            archive.writestr(info, payload)
    archive_bytes = buffer.getvalue()
    archive_digest = sha256(archive_bytes).digest()
    manifest = {
        "artifact_type": ARTIFACT_TYPE,
        "schema_version": SCHEMA_VERSION,
        "work_package": WORK_PACKAGE,
        "source_commit": source_commit,
        "archive_name": ARCHIVE_NAME,
        "archive_format": "ZIP_STORED_FIXED_METADATA",
        "archive_sha256": archive_digest.hex(),
        "lambda_code_sha256": base64.b64encode(archive_digest).decode("ascii"),
        "archive_size_bytes": len(archive_bytes),
        "handlers": dict(sorted(HANDLERS.items())),
        "runtime_dependencies": {
            "aws_sdk": "AWS_MANAGED_PINNED_BY_RUNTIME_VERSION_GUARD",
            "runtime_lock_path": RUNTIME_LOCK_PATH.as_posix(),
            "expected_boto3_version": expected_boto3_version,
            "expected_botocore_version": expected_botocore_version,
        },
        "entries": [
            {
                "path": path.as_posix(),
                "sha256": sha256(data).hexdigest(),
                "size_bytes": len(data),
            }
            for path, data in sources.items()
        ],
        "production_status": PRODUCTION_STATUS,
    }
    return BuiltRepairPackage(archive=archive_bytes, manifest=manifest)


def verify_clean_source_commit(
    *, source_root: Path, source_commit: str
) -> Mapping[Path, bytes]:
    """Prove local tools match the commit and return package bytes from Git.

    The returned mapping comes from the Git object database, never from a
    second working-tree read. This removes the package-build TOCTOU window and
    makes ``assume-unchanged`` ineffective as a source-substitution mechanism.
    """

    if _COMMIT_RE.fullmatch(source_commit) is None:
        raise RepairPackageError("SOURCE_COMMIT_INVALID")
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
            raise RepairPackageError("SOURCE_PROVENANCE_UNAVAILABLE") from exc
        outputs.append(result.stdout.strip())
    if outputs[0] != source_commit:
        raise RepairPackageError("SOURCE_COMMIT_MISMATCH")
    if outputs[1]:
        raise RepairPackageError("SOURCE_TREE_DIRTY")
    committed_sources: dict[Path, bytes] = {}
    for relative_path in (*SOURCE_PATHS, *PROVENANCE_TOOL_PATHS):
        try:
            subprocess.run(
                ["git", "ls-files", "--error-unmatch", "--", relative_path.as_posix()],
                cwd=source_root,
                check=True,
                capture_output=True,
                timeout=30,
            )
            committed = subprocess.run(
                ["git", "show", f"{source_commit}:{relative_path.as_posix()}"],
                cwd=source_root,
                check=True,
                capture_output=True,
                timeout=30,
            ).stdout
        except (OSError, subprocess.SubprocessError) as exc:
            raise RepairPackageError("PACKAGE_SOURCE_NOT_IN_COMMIT") from exc
        if committed != _read_reviewed_source(source_root, relative_path):
            raise RepairPackageError("PACKAGE_SOURCE_COMMIT_DRIFT")
        if relative_path in SOURCE_PATHS:
            committed_sources[relative_path] = committed
    return committed_sources


def write_repair_package(
    *,
    source_root: Path,
    source_commit: str,
    expected_boto3_version: str,
    expected_botocore_version: str,
    output_directory: Path,
) -> tuple[Path, Path, Mapping[str, Any]]:
    """Create one owner-only output directory without overwriting evidence."""

    committed_sources = verify_clean_source_commit(
        source_root=source_root, source_commit=source_commit
    )
    built = build_repair_package(
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
        raise RepairPackageError("OUTPUT_MUST_BE_OUTSIDE_SOURCE_ROOT")
    try:
        output_directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    except OSError as exc:
        raise RepairPackageError("OUTPUT_DIRECTORY_UNAVAILABLE") from exc
    archive_path = output_directory / ARCHIVE_NAME
    manifest_path = output_directory / MANIFEST_NAME
    manifest_bytes = (canonical_json(built.manifest) + "\n").encode("utf-8")
    try:
        for path, payload in (
            (archive_path, built.archive),
            (manifest_path, manifest_bytes),
        ):
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
    except OSError as exc:
        raise RepairPackageError("OUTPUT_WRITE_FAILED") from exc
    return archive_path, manifest_path, built.manifest
