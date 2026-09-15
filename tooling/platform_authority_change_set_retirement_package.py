"""Build the deterministic unsigned GUG-215 AWS Signer source package.

The package is source-only and deliberately relies on an AWS-managed Python
SDK.  That exception is bounded by the separately reviewed, manually pinned
Lambda runtime version.

The ZIP and its manifest describe only the exact unsigned input to an external
AWS Signer job.  They are not a Lambda-deployable artifact and their archive
digest and ``lambda_code_sha256`` describe the unsigned source bytes only.  A
separate, externally produced and independently evidenced signed destination
object is the only object eligible for projection into CloudFormation.

This module performs no AWS, network, upload, signing, deployment, or
retirement operation.

Workforce v2 is an explicit pre-sign source contract. Its configuration binding
remains pending: the post-sign consumer must verify the external signature,
exact versioned S3 object and signed bytes, then validate and independently pin
WorkforceRetirementConfig with that signed CodeSha256. Neither an unsigned
digest nor this manifest can substitute for that configuration or evidence of
CI, exclusive assignment, installation, or authorization to execute. Existing
consumers remain on v1 unless they explicitly opt into validating v2 source.
"""

from __future__ import annotations

import base64
import ast
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
WORKFORCE_AUTHORIZATION_MODE = "WORKFORCE_SINGLE_OWNER_RETIREMENT_V1"
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
# Only workforce v2 carries the deployed-stage verifier. Legacy packages keep
# their original seven members and do not import this module at module load.
WORKFORCE_SOURCE_PATHS = tuple(sorted(
    (*SOURCE_PATHS, Path("tooling/platform_authority_workforce_stage_binding.py")),
    key=lambda item: item.as_posix(),
))
PROVENANCE_PATHS = (
    Path("schemas/platform-authority-change-set-retirement-package-manifest.v1.schema.json"),
    Path("scripts/deployment/platform-authority-change-set-retirement-package.py"),
    Path("tooling/platform_authority_change_set_retirement_package.py"),
)
WORKFORCE_PROVENANCE_PATHS = (*PROVENANCE_PATHS,
    Path("schemas/platform-authority-change-set-retirement-package-manifest.v2.schema.json"),
    Path("schemas/platform-authority-change-set-retirement-ledger.v4.schema.json"),
)
WORKFORCE_RUNTIME_CONTRACT = {
    "handler": HANDLER,
    "identity_ingress": "API_GATEWAY_HTTP_API_V2_AWS_IAM",
    "identity_mode": WORKFORCE_AUTHORIZATION_MODE,
    "identity_mode_environment_key": "GUG215_IDENTITY_MODE",
    "configuration_environment_key": "GUG215_WORKFORCE_CONFIG_B64Z",
    "configuration_digest_environment_key": "GUG215_WORKFORCE_CONFIG_DIGEST",
    "configuration_validator": "tooling.platform_authority_change_set_retirement_broker.WorkforceRetirementConfig",
    "configuration_schema_version": "2",
    "function_version_source": "PROVIDER_LAMBDA_CONTEXT_NUMERIC_ARN",
    "deployed_stage_verification": "EDITABLE_AND_STAGE_EXPORT_EXACT_NUMERIC_VERSION",
    "configuration_requires_signed_code_sha256": True,
    "ledger_schema_version": "4",
    "operations": ["classify", "retire", "reconcile"],
    "authority_account_id": "042360977644",
    "region": "us-east-1",
    "intended_destination_account_id": "905418363887",
}
WORKFORCE_MANIFEST_CONSTANTS = {
    "artifact_stage": "UNSIGNED_SOURCE_NOT_DEPLOYABLE",
    "unsigned_digest_semantics": "ARCHIVE_SHA256_AND_LAMBDA_CODE_SHA256_ARE_UNSIGNED_SOURCE_ONLY",
    "configuration_binding_status": "CONFIGURATION_BINDING_PENDING_SIGNED_ARTIFACT",
    "signed_artifact_binding": None,
    "intended_environment": "production",
    "human_authentication_evidence": "NOT_COLLECTED",
    "source_and_ci_evidence": "NOT_ATTESTED_BY_MANIFEST",
    "runtime_configuration_contract": WORKFORCE_RUNTIME_CONTRACT,
}
WORKFORCE_MAX_SOURCE_BYTES = 2 * 1024 * 1024
WORKFORCE_MAX_ARCHIVE_BYTES = 16 * 1024 * 1024

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


def _workforce_mode(authorization_mode: str) -> bool:
    if authorization_mode not in (AUTHORIZATION_MODE, WORKFORCE_AUTHORIZATION_MODE):
        raise RetirementPackageError("PACKAGE_AUTHORIZATION_MODE_INVALID")
    return authorization_mode == WORKFORCE_AUTHORIZATION_MODE


def _require_workforce_source_support(sources: Mapping[Path, bytes]) -> None:
    """Syntactic compatibility only; HEAD/blob custody and review remain required."""
    try:
        broker = ast.parse(sources[Path("tooling/platform_authority_change_set_retirement_broker.py")].decode("utf-8"))
        runtime = ast.parse(sources[Path("tooling/platform_authority_identity_context_pep_runtime.py")].decode("utf-8"))
        stage = ast.parse(sources[Path("tooling/platform_authority_workforce_stage_binding.py")].decode("utf-8"))
        modes = [node.value.value for node in broker.body if isinstance(node, ast.Assign)
                 and any(isinstance(target, ast.Name) and target.id == "WORKFORCE_RETIREMENT_MODE" for target in node.targets)
                 and isinstance(node.value, ast.Constant)]
        classes = {node.name: node for node in broker.body if isinstance(node, ast.ClassDef)}
        functions = {node.name: node for node in runtime.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
        config = classes.get("WorkforceRetirementConfig")
        if (modes != [WORKFORCE_AUTHORIZATION_MODE] or "WorkforceRetirementBroker" not in classes
                or config is None or "handler" not in functions or "_workforce_handler" not in functions
                or "workforce_config_from_environment" not in functions):
            raise ValueError
        environments = [node for node in config.body if isinstance(node, ast.FunctionDef) and node.name == "runtime_environment"]
        binders = [node for node in config.body if isinstance(node, ast.FunctionDef) and node.name == "bind_lambda_context"]
        stage_verifiers = [node for node in stage.body if isinstance(node, ast.FunctionDef) and node.name == "verify_workforce_deployed_stage"]
        if len(environments) != 1 or len(binders) != 1 or len(stage_verifiers) != 1:
            raise ValueError
        keys = {node.value for node in ast.walk(environments[0]) if isinstance(node, ast.Constant)
                and type(node.value) is str and node.value.startswith("GUG215_")}
        if keys != {"GUG215_IDENTITY_MODE", "GUG215_WORKFORCE_CONFIG_B64Z", "GUG215_WORKFORCE_CONFIG_DIGEST"}:
            raise ValueError
    except Exception:
        raise RetirementPackageError("WORKFORCE_RUNTIME_SOURCE_INCOMPATIBLE") from None


def build_retirement_package(
    *,
    source_root: Path,
    source_commit: str,
    broker_runtime_version_arn: str,
    broker_version_binding_sha256: str | None = None,
    committed_sources: Mapping[Path, bytes] | None = None,
    authorization_mode: str = AUTHORIZATION_MODE,
) -> BuiltRetirementPackage:
    """Return deterministic ZIP bytes plus the strict public manifest."""

    workforce = _workforce_mode(authorization_mode)
    source_paths = WORKFORCE_SOURCE_PATHS if workforce else SOURCE_PATHS
    if _COMMIT.fullmatch(source_commit) is None:
        raise RetirementPackageError("SOURCE_COMMIT_INVALID")
    runtime_digest = runtime_version_arn_digest(broker_runtime_version_arn)
    if workforce and broker_version_binding_sha256 is not None:
        raise RetirementPackageError("WORKFORCE_PRE_SIGN_BINDING_FORBIDDEN")
    if workforce and not re.fullmatch(r"arn:aws:lambda:us-east-1::runtime:[a-f0-9]{64}", broker_runtime_version_arn):
        raise RetirementPackageError("WORKFORCE_RUNTIME_REGION_INVALID")
    if not workforce and (not isinstance(broker_version_binding_sha256, str) or _DIGEST.fullmatch(broker_version_binding_sha256) is None):
        raise RetirementPackageError("BROKER_VERSION_BINDING_INVALID")
    if committed_sources is None:
        sources = {path: _read_source(source_root, path) for path in source_paths}
    else:
        if set(committed_sources) != set(source_paths):
            raise RetirementPackageError("COMMITTED_SOURCE_SET_INVALID")
        sources = {path: bytes(committed_sources[path]) for path in source_paths}
        if any(
            not payload and path != Path("tooling/__init__.py")
            for path, payload in sources.items()
        ):
            raise RetirementPackageError("PACKAGE_SOURCE_EMPTY")

    if workforce:
        if any(len(payload) > WORKFORCE_MAX_SOURCE_BYTES for payload in sources.values()):
            raise RetirementPackageError("WORKFORCE_PACKAGE_SIZE_EXCEEDED")
        _require_workforce_source_support(sources)

    buffer = BytesIO()
    with ZipFile(buffer, mode="w", compression=ZIP_STORED, strict_timestamps=True) as archive:
        for path in source_paths:
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
            for path in source_paths
        ],
        "deployment_authorized": False,
        "production_status": PRODUCTION_STATUS,
    }
    manifest["manifest_digest"] = canonical_digest(manifest)
    if workforce:
        manifest.pop("broker_version_binding_sha256")
        manifest.update({
            "artifact_type": "scanalyze.platform_authority.change_set_retirement_package.v2",
            "schema_version": 2, "authorization_mode": WORKFORCE_AUTHORIZATION_MODE,
            "broker_runtime_version_arn": broker_runtime_version_arn,
            **json.loads(canonical_json(WORKFORCE_MANIFEST_CONSTANTS)),
        })
        manifest["manifest_digest"] = canonical_digest({key: value for key, value in manifest.items() if key != "manifest_digest"})
    validate_retirement_package_manifest(manifest, archive=archive_bytes, authorization_mode=authorization_mode)
    return BuiltRetirementPackage(archive=archive_bytes, manifest=manifest)


def validate_retirement_package_manifest(
    manifest: Mapping[str, Any], *, archive: bytes | None = None,
    authorization_mode: str = AUTHORIZATION_MODE,
) -> None:
    """Validate manifest semantics and, when supplied, exact archive bytes."""

    workforce = _workforce_mode(authorization_mode)
    source_paths = WORKFORCE_SOURCE_PATHS if workforce else SOURCE_PATHS
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
    if workforce:
        required.remove("broker_version_binding_sha256")
        required.update({"broker_runtime_version_arn", *WORKFORCE_MANIFEST_CONSTANTS})
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
    if workforce:
        constants.update({"artifact_type": "scanalyze.platform_authority.change_set_retirement_package.v2",
            "schema_version": 2, "authorization_mode": WORKFORCE_AUTHORIZATION_MODE,
            **WORKFORCE_MANIFEST_CONSTANTS})
    if any((canonical_json(manifest.get(key)) != canonical_json(value) if workforce else manifest.get(key) != value)
           for key, value in constants.items()):
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
        or (not workforce and _DIGEST.fullmatch(str(manifest.get("broker_version_binding_sha256"))) is None)
    ):
        raise RetirementPackageError("PACKAGE_MANIFEST_BINDING_INVALID")
    if workforce:
        runtime_arn = manifest.get("broker_runtime_version_arn")
        if (type(manifest.get("source_commit")) is not str or type(runtime_arn) is not str
                or re.fullmatch(r"arn:aws:lambda:us-east-1::runtime:[a-f0-9]{64}", runtime_arn) is None
                or runtime_version_arn_digest(runtime_arn) != manifest["broker_runtime_version_arn_digest"]
                or type(manifest["schema_version"]) is not int or type(manifest["archive_size_bytes"]) is not int
                or any(type(manifest[key]) is not bool for key in ("production", "deployment_authorized", "independent_approval_present"))):
            raise RetirementPackageError("PACKAGE_MANIFEST_BINDING_INVALID")
        if manifest["archive_size_bytes"] > WORKFORCE_MAX_ARCHIVE_BYTES:
            raise RetirementPackageError("WORKFORCE_PACKAGE_SIZE_EXCEEDED")
    entries = manifest.get("entries")
    if not isinstance(entries, list) or len(entries) != len(source_paths):
        raise RetirementPackageError("PACKAGE_MANIFEST_ENTRIES_INVALID")
    expected_paths = [path.as_posix() for path in source_paths]
    observed_paths: list[str] = []
    for entry in entries:
        if not isinstance(entry, Mapping) or set(entry) != {"path", "sha256", "size_bytes"}:
            raise RetirementPackageError("PACKAGE_MANIFEST_ENTRIES_INVALID")
        path = entry.get("path")
        size = entry.get("size_bytes")
        if (
            not isinstance(path, str)
            or _HEX_DIGEST.fullmatch(str(entry.get("sha256"))) is None
            or (workforce and type(entry.get("sha256")) is not str)
            or not isinstance(size, int)
            or (workforce and type(size) is not int)
            or size < 0
            or (size == 0 and path != "tooling/__init__.py")
            or (workforce and size > WORKFORCE_MAX_SOURCE_BYTES)
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
            sources = {}
            for item, entry in zip(package.infolist(), entries, strict=True):
                if (
                    item.date_time != FIXED_ZIP_TIMESTAMP
                    or item.compress_type != ZIP_STORED
                    or item.extra != b""
                    or item.comment != b""
                    or (item.external_attr >> 16) & 0o777 != 0o644
                ):
                    raise RetirementPackageError("PACKAGE_ARCHIVE_METADATA_INVALID")
                if workforce and (item.file_size != entry["size_bytes"]
                                  or item.compress_size != item.file_size or item.file_size > WORKFORCE_MAX_SOURCE_BYTES
                                  or item.flag_bits != 0 or item.create_system != 3
                                  or (item.external_attr >> 16) != 0o100644 or package.comment != b""):
                    raise RetirementPackageError("PACKAGE_ARCHIVE_METADATA_INVALID")
                payload = package.read(item.filename)
                if (
                    sha256(payload).hexdigest() != entry["sha256"]
                    or len(payload) != entry["size_bytes"]
                ):
                    raise RetirementPackageError("PACKAGE_ARCHIVE_MEMBER_DIGEST_MISMATCH")
                sources[Path(item.filename)] = payload
            if workforce:
                _require_workforce_source_support(sources)
                canonical = BytesIO()
                with ZipFile(canonical, mode="w", compression=ZIP_STORED, strict_timestamps=True) as rebuilt:
                    for path in source_paths:
                        info, payload = _zip_entry(path, sources[path])
                        rebuilt.writestr(info, payload)
                # ZipFile accepts prefixes, trailing bytes and adjusted offsets.
                # None belongs to the exact source closure promised by v2.
                if canonical.getvalue() != archive:
                    raise RetirementPackageError("PACKAGE_ARCHIVE_NOT_CANONICAL")
    except (BadZipFile, OSError) as exc:
        raise RetirementPackageError("PACKAGE_ARCHIVE_INVALID") from exc


def verify_clean_source_commit(
    *, source_root: Path, source_commit: str, authorization_mode: str = AUTHORIZATION_MODE,
) -> Mapping[Path, bytes]:
    """Return exact Git-object bytes after proving clean HEAD provenance."""

    workforce = _workforce_mode(authorization_mode)
    source_paths = WORKFORCE_SOURCE_PATHS if workforce else SOURCE_PATHS
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
    provenance = WORKFORCE_PROVENANCE_PATHS if workforce else PROVENANCE_PATHS
    for relative in (*source_paths, *provenance):
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
        if relative in source_paths:
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
    broker_version_binding_sha256: str | None = None,
    output_directory: Path,
    authorization_mode: str = AUTHORIZATION_MODE,
) -> tuple[Path, Path, Mapping[str, Any]]:
    """Create one owner-only package directory outside the source tree."""

    committed_sources = verify_clean_source_commit(
        source_root=source_root, source_commit=source_commit, authorization_mode=authorization_mode,
    )
    built = build_retirement_package(
        source_root=source_root,
        source_commit=source_commit,
        broker_runtime_version_arn=broker_runtime_version_arn,
        broker_version_binding_sha256=broker_version_binding_sha256,
        committed_sources=committed_sources,
        authorization_mode=authorization_mode,
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
