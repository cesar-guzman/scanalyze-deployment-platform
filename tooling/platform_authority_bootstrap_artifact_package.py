"""Build the deterministic, closed GUG-274 Lambda authority package.

The repository artifact is deliberately unsigned.  A separately authorized
AWS Signer lane must sign these exact bytes with the immutable generation-1
profile version, and a later reviewed commit must pin that version, before the
CloudFormation template can accept them.  This module performs no AWS,
network, signing, upload, or deployment operation.
"""

from __future__ import annotations

import base64
import csv
from dataclasses import dataclass
from hashlib import sha256
import importlib
from importlib import metadata
from io import BytesIO
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from types import ModuleType
from typing import Any, Mapping
from zipfile import ZIP_STORED, ZipFile, ZipInfo


ARTIFACT_TYPE = "scanalyze.platform_authority.bootstrap_artifact_authority_package.v1"
SCHEMA_VERSION = 1
WORK_PACKAGE = "GUG-274"
TRUST_ROOT_GENERATION = 1
PRODUCTION_STATUS = "NO-GO"
EXPECTED_BOTO3_VERSION = "1.42.57"
EXPECTED_BOTOCORE_VERSION = "1.42.97"
ARCHIVE_NAME = "scanalyze-gug274-bootstrap-artifact-authority.zip"
MANIFEST_NAME = "scanalyze-gug274-bootstrap-artifact-authority.manifest.json"
FIXED_ZIP_TIMESTAMP = (2026, 8, 2, 0, 0, 0)
SIGNING_PROFILE_NAME = "scanalyze_gug274_bootstrap_artifact_authority"
HANDLERS = {
    "apply": "tooling.platform_authority_bootstrap_artifact_authority.apply_executor_handler",
    "approval": "tooling.platform_authority_bootstrap_artifact_authority.approval_anchor_handler",
    "plan": "tooling.platform_authority_bootstrap_artifact_authority.plan_anchor_handler",
}
SOURCE_PATHS = (
    Path("policies/iam/aws-managed-identity-context-allowlist-v12.snapshot.json"),
    Path("tooling/__init__.py"),
    Path("tooling/platform_authority_bootstrap.py"),
    Path("tooling/platform_authority_bootstrap_artifact_authority.py"),
    Path("tooling/platform_authority_bootstrap_identity_proof.py"),
    Path("tooling/platform_authority_identity_context_compatibility.py"),
    Path("tooling/platform_authority_identity_context_pep.py"),
)
RUNTIME_LOCK_PATH = Path("gug274_runtime_lock.json")
PACKAGE_PATHS = tuple(
    sorted((*SOURCE_PATHS, RUNTIME_LOCK_PATH), key=lambda item: item.as_posix())
)
PROVENANCE_PATHS = (
    Path("bootstrap/platform-authority-bootstrap-artifact-signing-trust-root.json"),
    Path("tooling/platform_authority_source_only_import.py"),
    Path("tooling/platform_authority_bootstrap_artifact_package.py"),
    Path("tooling/platform_authority_bootstrap_signed_artifact.py"),
    Path("tooling/platform_authority_lambda_audit_repair_signed_artifact.py"),
    Path("scripts/deployment/platform-authority-bootstrap.py"),
    Path("scripts/deployment/platform-authority-bootstrap-artifact-package.py"),
    Path("scripts/deployment/platform-authority-bootstrap-signed-artifact.py"),
)

TRUSTED_EXECUTABLE_CANDIDATES: Mapping[str, tuple[Path, ...]] = {
    "aws": (
        Path("/usr/bin/aws"),
        Path("/usr/local/bin/aws"),
        Path("/opt/homebrew/bin/aws"),
    ),
    "gh": (
        Path("/usr/bin/gh"),
        Path("/usr/local/bin/gh"),
        Path("/opt/homebrew/bin/gh"),
    ),
    "git": (
        Path("/usr/bin/git"),
        Path("/bin/git"),
        Path("/usr/local/bin/git"),
        Path("/opt/homebrew/bin/git"),
    ),
}
REVIEWED_NON_ROOT_EXECUTABLE_SHA256: Mapping[str, frozenset[str]] = {
    "aws": frozenset(),
    "gh": frozenset(
        {
            # GitHub CLI v2.89.0, arm64 macOS.
            "abc4a820c3f423c17902feba71f8af9ae73c2b20559d117bac628d4cb53f3416",
        }
    ),
    "git": frozenset(),
}
SDK_DISTRIBUTION_LOCKS: Mapping[str, Mapping[str, Any]] = {
    "boto3": {
        "version": EXPECTED_BOTO3_VERSION,
        "wheel_filename": "boto3-1.42.57-py3-none-any.whl",
        "wheel_sha256": "74f47051e3b741a0c1e64d57b891076c2c68f8d7b98aee36b044fab1849b4823",
        "installed_manifest_sha256": "f0d9b76bbf089116a6f1b405c2b1333588d127c0c1b11faf45d0d1c6362187cc",
        "dist_info_name": "boto3-1.42.57.dist-info",
        "module_name": "boto3",
        "module_path": "boto3/__init__.py",
        "package_paths": ("boto3",),
    },
    "botocore": {
        "version": EXPECTED_BOTOCORE_VERSION,
        "wheel_filename": "botocore-1.42.97-py3-none-any.whl",
        "wheel_sha256": "77d2c8ce1bc592d3fbd7c01c35836f4a5b0cac2ca03ccdf6ffc60faa16b5fadc",
        "installed_manifest_sha256": "e177844a0d475cb94915ed4b09716fe04e839048d6405c735a1d9258719f0466",
        "dist_info_name": "botocore-1.42.97.dist-info",
        "module_name": "botocore",
        "module_path": "botocore/__init__.py",
        "package_paths": ("botocore",),
    },
    "s3transfer": {
        "version": "0.16.1",
        "wheel_filename": "s3transfer-0.16.1-py3-none-any.whl",
        "wheel_sha256": "61bcd00ccb83b21a0fe7e91a553fff9729d46c83b4e0106e7c314a733891f7c2",
        "installed_manifest_sha256": "5dba59df038e6bc746b7045795855b095d69092f8040fd43600e6af556298d33",
        "dist_info_name": "s3transfer-0.16.1.dist-info",
        "module_name": "s3transfer",
        "module_path": "s3transfer/__init__.py",
        "package_paths": ("s3transfer",),
    },
    "jmespath": {
        "version": "1.1.0",
        "wheel_filename": "jmespath-1.1.0-py3-none-any.whl",
        "wheel_sha256": "a5663118de4908c91729bea0acadca56526eb2698e83de10cd116ae0f4e97c64",
        "installed_manifest_sha256": "066b28b473bcd8fc8102ebdda36a3b3302689d8abd2df9f48f0ff6d70675178c",
        "dist_info_name": "jmespath-1.1.0.dist-info",
        "module_name": "jmespath",
        "module_path": "jmespath/__init__.py",
        "package_paths": ("jmespath",),
        "ignored_install_paths": ("../../../bin/jp.py",),
    },
    "python-dateutil": {
        "version": "2.9.0.post0",
        "wheel_filename": "python_dateutil-2.9.0.post0-py2.py3-none-any.whl",
        "wheel_sha256": "a8b2bc7bffae282281c8140a97d3aa9c14da0b136dfe83f850eea9a5f7470427",
        "installed_manifest_sha256": "3c1c51c7f434c3377efcba7522f8d3e8dcbc24245b21d23cf32d6e4014f95a64",
        "dist_info_name": "python_dateutil-2.9.0.post0.dist-info",
        "module_name": "dateutil",
        "module_path": "dateutil/__init__.py",
        "package_paths": ("dateutil",),
    },
    "urllib3": {
        "version": "2.7.0",
        "wheel_filename": "urllib3-2.7.0-py3-none-any.whl",
        "wheel_sha256": "9fb4c81ebbb1ce9531cce37674bbc6f1360472bc18ca9a553ede278ef7276897",
        "installed_manifest_sha256": "c5d9a45cce25d90428a3d17b5db01b583586ee76f024f74ad53d1a56ef97ae7d",
        "dist_info_name": "urllib3-2.7.0.dist-info",
        "module_name": "urllib3",
        "module_path": "urllib3/__init__.py",
        "package_paths": ("urllib3",),
    },
    "six": {
        "version": "1.17.0",
        "wheel_filename": "six-1.17.0-py2.py3-none-any.whl",
        "wheel_sha256": "4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274",
        "installed_manifest_sha256": "3e9786be496e9d8cfc228cc2df025009a38811ac4b8cfe10f2437f28c4f9faf2",
        "dist_info_name": "six-1.17.0.dist-info",
        "module_name": "six",
        "module_path": "six.py",
        "package_paths": ("six.py",),
    },
}
SDK_RUNTIME_ROOT_ENV = "SCANALYZE_GUG274_SDK_RUNTIME_ROOT"
SDK_RUNTIME_SITE_PATH = Path("site-packages")
_INSTALLER_RECORD_NAMES = frozenset({"INSTALLER", "REQUESTED"})

_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_CODE_SHA_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")
_SDK_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


class BootstrapArtifactPackageError(ValueError):
    """Stable fail-closed package/provenance contract violation."""


def sdk_runtime_root_from_environment() -> Path:
    """Read the non-authoritative location of the source-pinned SDK runtime."""

    value = os.environ.get(SDK_RUNTIME_ROOT_ENV)
    if not value or "\x00" in value:
        raise BootstrapArtifactPackageError("SDK_RUNTIME_ROOT_REQUIRED")
    candidate = Path(value)
    if not candidate.is_absolute():
        raise BootstrapArtifactPackageError("SDK_RUNTIME_ROOT_INVALID")
    return candidate


def _trusted_executable_path_metadata(path: Path) -> os.stat_result:
    """Require an executable path closed against other local OS identities."""

    if not hasattr(os, "geteuid"):
        raise BootstrapArtifactPackageError("EXECUTABLE_PLATFORM_NOT_REVIEWED")
    trusted_owners = {0, os.geteuid()}
    try:
        metadata_value = path.lstat()
    except OSError:
        raise BootstrapArtifactPackageError("EXECUTABLE_PATH_UNSAFE") from None
    if (
        metadata_value.st_uid not in trusted_owners
        or not stat.S_ISREG(metadata_value.st_mode)
        or metadata_value.st_mode & 0o022
        or not os.access(path, os.X_OK)
    ):
        raise BootstrapArtifactPackageError("EXECUTABLE_PATH_UNSAFE")
    for parent in path.parents:
        try:
            parent_metadata = parent.lstat()
        except OSError:
            raise BootstrapArtifactPackageError("EXECUTABLE_PATH_UNSAFE") from None
        sticky_root_directory = (
            parent_metadata.st_uid == 0
            and bool(parent_metadata.st_mode & stat.S_ISVTX)
        )
        if (
            parent_metadata.st_uid not in trusted_owners
            or not stat.S_ISDIR(parent_metadata.st_mode)
            or (
                parent_metadata.st_mode & 0o022
                and not sticky_root_directory
            )
        ):
            raise BootstrapArtifactPackageError("EXECUTABLE_PATH_UNSAFE")
    return metadata_value


def resolve_trusted_executable(*, name: str, source_root: Path) -> Path:
    """Resolve an operational tool from a closed OS path, never caller PATH."""

    if os.name != "posix":
        raise BootstrapArtifactPackageError("EXECUTABLE_PLATFORM_NOT_REVIEWED")
    candidates = TRUSTED_EXECUTABLE_CANDIDATES.get(name)
    if candidates is None:
        raise BootstrapArtifactPackageError("EXECUTABLE_NAME_NOT_REVIEWED")
    root = source_root.resolve(strict=True)
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(root)
        except ValueError:
            pass
        except OSError:
            continue
        else:
            continue
        try:
            metadata_value = _trusted_executable_path_metadata(resolved)
        except BootstrapArtifactPackageError:
            continue
        try:
            digest = sha256(resolved.read_bytes()).hexdigest()
            metadata_after_digest = _trusted_executable_path_metadata(resolved)
        except (BootstrapArtifactPackageError, OSError):
            continue
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(
            getattr(metadata_value, field) != getattr(metadata_after_digest, field)
            for field in stable_fields
        ):
            continue
        try:
            system_owned_path = metadata_value.st_uid == 0 and all(
                parent.lstat().st_uid == 0 for parent in resolved.parents
            )
        except OSError:
            continue
        if (
            not system_owned_path
            and digest not in REVIEWED_NON_ROOT_EXECUTABLE_SHA256[name]
        ):
            continue
        return resolved
    raise BootstrapArtifactPackageError(
        f"TRUSTED_{name.upper()}_EXECUTABLE_UNAVAILABLE"
    )


def closed_provenance_environment(
    *, source_root: Path, executables: tuple[Path, ...], include_home: bool
) -> dict[str, str]:
    """Return the minimal environment for reviewed Git/GitHub readbacks."""

    root = source_root.resolve(strict=True)
    path_entries = {"/usr/bin", "/bin"}
    for executable in executables:
        resolved = executable.resolve(strict=True)
        try:
            resolved.relative_to(root)
        except ValueError:
            pass
        else:
            raise BootstrapArtifactPackageError("EXECUTABLE_INSIDE_SOURCE_ROOT")
        path_entries.add(str(resolved.parent))
    environment = {
        "PATH": os.pathsep.join(sorted(path_entries)),
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GH_PROMPT_DISABLED": "1",
        "GH_PAGER": "cat",
        "PAGER": "cat",
        "NO_COLOR": "1",
    }
    if include_home:
        home_text = os.environ.get("HOME")
        if not home_text:
            raise BootstrapArtifactPackageError("OPERATOR_HOME_UNAVAILABLE")
        try:
            home = Path(home_text).resolve(strict=True)
            home.relative_to(root)
        except ValueError:
            pass
        except OSError:
            raise BootstrapArtifactPackageError("OPERATOR_HOME_UNAVAILABLE") from None
        else:
            raise BootstrapArtifactPackageError("OPERATOR_HOME_UNTRUSTED")
        if not home.is_dir():
            raise BootstrapArtifactPackageError("OPERATOR_HOME_UNAVAILABLE")
        environment["HOME"] = str(home)
    return environment


def _canonical_distribution_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).casefold()


@dataclass(frozen=True, slots=True)
class ValidatedSDKRuntime:
    """Pre-import authentication result for the complete SDK closure."""

    module_origins: Mapping[str, Path]
    authenticated_files: frozenset[Path]


def _regular_tree_files(path: Path) -> frozenset[Path]:
    """Return regular files below one path while rejecting every symlink."""

    try:
        root_metadata = path.lstat()
    except OSError:
        raise BootstrapArtifactPackageError(
            "SDK_DISTRIBUTION_FILE_UNAVAILABLE"
        ) from None
    if stat.S_ISLNK(root_metadata.st_mode):
        raise BootstrapArtifactPackageError("SDK_DISTRIBUTION_FILE_UNSAFE")
    if stat.S_ISREG(root_metadata.st_mode):
        return frozenset({path.resolve(strict=True)})
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise BootstrapArtifactPackageError("SDK_DISTRIBUTION_FILE_UNSAFE")
    files: set[Path] = set()
    for candidate in path.rglob("*"):
        try:
            candidate_metadata = candidate.lstat()
        except OSError:
            raise BootstrapArtifactPackageError(
                "SDK_DISTRIBUTION_FILE_UNAVAILABLE"
            ) from None
        if stat.S_ISLNK(candidate_metadata.st_mode):
            raise BootstrapArtifactPackageError("SDK_DISTRIBUTION_FILE_UNSAFE")
        if stat.S_ISDIR(candidate_metadata.st_mode):
            continue
        if not stat.S_ISREG(candidate_metadata.st_mode):
            raise BootstrapArtifactPackageError("SDK_DISTRIBUTION_FILE_UNSAFE")
        files.add(candidate.resolve(strict=True))
    return frozenset(files)


def _require_closed_sdk_runtime_permissions(
    *, runtime_root: Path, runtime_site: Path
) -> None:
    """Reject any runtime path writable by an untrusted local OS identity."""

    if os.name != "posix" or not hasattr(os, "geteuid"):
        raise BootstrapArtifactPackageError("SDK_RUNTIME_PLATFORM_UNREVIEWED")
    trusted_owners = {0, os.geteuid()}
    for ancestor in (runtime_root, *runtime_root.parents):
        try:
            ancestor_metadata = ancestor.lstat()
        except OSError:
            raise BootstrapArtifactPackageError("SDK_RUNTIME_PATH_UNSAFE") from None
        sticky_root_directory = (
            ancestor_metadata.st_uid == 0
            and bool(ancestor_metadata.st_mode & stat.S_ISVTX)
        )
        if (
            ancestor_metadata.st_uid not in trusted_owners
            or not stat.S_ISDIR(ancestor_metadata.st_mode)
            or (
                ancestor_metadata.st_mode & 0o022
                and not sticky_root_directory
            )
        ):
            raise BootstrapArtifactPackageError("SDK_RUNTIME_PATH_UNSAFE")
    for candidate in (runtime_site, *runtime_site.rglob("*")):
        try:
            candidate_metadata = candidate.lstat()
        except OSError:
            raise BootstrapArtifactPackageError("SDK_RUNTIME_PATH_UNSAFE") from None
        if (
            candidate_metadata.st_uid not in trusted_owners
            or candidate_metadata.st_mode & 0o022
            or stat.S_ISLNK(candidate_metadata.st_mode)
            or not (
                stat.S_ISDIR(candidate_metadata.st_mode)
                or stat.S_ISREG(candidate_metadata.st_mode)
            )
        ):
            raise BootstrapArtifactPackageError("SDK_RUNTIME_PATH_UNSAFE")


def _sdk_manifest_digest(entries: list[Mapping[str, Any]]) -> str:
    payload = json.dumps(
        sorted(entries, key=lambda entry: str(entry["path"])),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return sha256(payload).hexdigest()


def _validate_locked_sdk_distributions(
    *, source_root: Path, runtime_site: Path
) -> ValidatedSDKRuntime:
    """Authenticate the exact wheel-derived SDK closure before importing it."""

    root = source_root.resolve(strict=True)
    discovered: dict[str, list[metadata.Distribution]] = {}
    try:
        distributions = tuple(metadata.distributions(path=[str(runtime_site)]))
    except Exception:
        raise BootstrapArtifactPackageError("SDK_DISTRIBUTION_UNAVAILABLE") from None
    for distribution in distributions:
        name = distribution.metadata.get("Name")
        if isinstance(name, str):
            discovered.setdefault(
                _canonical_distribution_name(name), []
            ).append(distribution)
    if set(discovered) != {
        _canonical_distribution_name(name) for name in SDK_DISTRIBUTION_LOCKS
    }:
        raise BootstrapArtifactPackageError("SDK_RUNTIME_DISTRIBUTION_SET_UNREVIEWED")

    expected_top_level = {
        str(contract["dist_info_name"])
        for contract in SDK_DISTRIBUTION_LOCKS.values()
    }
    expected_top_level.update(
        Path(str(package_path)).parts[0]
        for contract in SDK_DISTRIBUTION_LOCKS.values()
        for package_path in contract["package_paths"]
    )
    try:
        actual_top_level = {entry.name for entry in runtime_site.iterdir()}
    except OSError:
        raise BootstrapArtifactPackageError("SDK_RUNTIME_SITE_UNAVAILABLE") from None
    if actual_top_level != expected_top_level:
        raise BootstrapArtifactPackageError("SDK_RUNTIME_SITE_NOT_CLOSED")

    recorded_module_origins: dict[str, Path] = {}
    authenticated_files: set[Path] = set()
    for distribution_name, contract in SDK_DISTRIBUTION_LOCKS.items():
        matches = discovered.get(_canonical_distribution_name(distribution_name), [])
        if len(matches) != 1:
            raise BootstrapArtifactPackageError("SDK_DISTRIBUTION_AMBIGUOUS")
        distribution = matches[0]
        if distribution.version != contract["version"]:
            raise BootstrapArtifactPackageError("SDK_RUNTIME_VERSION_UNREVIEWED")
        distribution_info = getattr(distribution, "_path", None)
        if not isinstance(distribution_info, Path):
            raise BootstrapArtifactPackageError("SDK_DISTRIBUTION_UNAVAILABLE")
        try:
            distribution_root = Path(distribution.locate_file("")).resolve(strict=True)
            distribution_info = distribution_info.resolve(strict=True)
            runtime_site_resolved = runtime_site.resolve(strict=True)
        except OSError:
            raise BootstrapArtifactPackageError("SDK_DISTRIBUTION_UNAVAILABLE") from None
        if distribution_root != runtime_site_resolved:
            raise BootstrapArtifactPackageError("SDK_DISTRIBUTION_ROOT_INVALID")
        if distribution_info != runtime_site_resolved / str(contract["dist_info_name"]):
            raise BootstrapArtifactPackageError("SDK_DISTRIBUTION_INFO_UNREVIEWED")
        try:
            distribution_root.relative_to(root)
        except ValueError:
            pass
        else:
            raise BootstrapArtifactPackageError("SDK_RUNTIME_INSIDE_SOURCE_ROOT")
        record_path = distribution_info / "RECORD"
        try:
            record_bytes = record_path.read_bytes()
        except OSError:
            raise BootstrapArtifactPackageError(
                "SDK_DISTRIBUTION_RECORD_UNAVAILABLE"
            ) from None
        try:
            rows = list(csv.reader(record_bytes.decode("utf-8").splitlines()))
            record_relative = record_path.relative_to(distribution_root)
        except (UnicodeError, csv.Error, ValueError):
            raise BootstrapArtifactPackageError(
                "SDK_DISTRIBUTION_RECORD_UNAVAILABLE"
            ) from None
        seen: set[str] = set()
        recorded_runtime_files: set[Path] = set()
        manifest_entries: list[Mapping[str, Any]] = []
        package_paths = tuple(str(item) for item in contract["package_paths"])
        dist_info_name = str(contract["dist_info_name"])
        ignored_install_paths = frozenset(contract.get("ignored_install_paths", ()))
        for row in rows:
            if len(row) != 3 or not row[0] or row[0] in seen:
                raise BootstrapArtifactPackageError(
                    "SDK_DISTRIBUTION_RECORD_UNAVAILABLE"
                )
            seen.add(row[0])
            if row[0] in ignored_install_paths:
                continue
            in_package = any(
                row[0] == package_path or row[0].startswith(package_path + "/")
                for package_path in package_paths
            )
            in_dist_info = row[0].startswith(dist_info_name + "/")
            if not in_package and not in_dist_info:
                raise BootstrapArtifactPackageError(
                    "SDK_DISTRIBUTION_PATH_UNREVIEWED"
                )
            relative_path = Path(row[0])
            if (
                relative_path.is_absolute()
                or "\x00" in row[0]
                or ".." in relative_path.parts
            ):
                raise BootstrapArtifactPackageError(
                    "SDK_DISTRIBUTION_RECORD_UNAVAILABLE"
                )
            unresolved = distribution_root / relative_path
            try:
                resolved = unresolved.resolve(strict=True)
                resolved.relative_to(distribution_root)
            except OSError:
                raise BootstrapArtifactPackageError(
                    "SDK_DISTRIBUTION_FILE_UNAVAILABLE"
                ) from None
            except ValueError:
                raise BootstrapArtifactPackageError(
                    "SDK_DISTRIBUTION_FILE_UNSAFE"
                ) from None
            if unresolved != resolved:
                raise BootstrapArtifactPackageError("SDK_DISTRIBUTION_FILE_UNSAFE")
            try:
                file_metadata = resolved.lstat()
            except OSError:
                raise BootstrapArtifactPackageError(
                    "SDK_DISTRIBUTION_FILE_UNAVAILABLE"
                ) from None
            if not stat.S_ISREG(file_metadata.st_mode):
                raise BootstrapArtifactPackageError("SDK_DISTRIBUTION_FILE_UNSAFE")
            recorded_runtime_files.add(resolved)
            encoded_digest, encoded_size = row[1], row[2]
            if relative_path == record_relative:
                if encoded_digest or encoded_size:
                    raise BootstrapArtifactPackageError(
                        "SDK_DISTRIBUTION_RECORD_UNAVAILABLE"
                    )
                continue
            if not encoded_digest.startswith("sha256=") or not encoded_size.isdigit():
                raise BootstrapArtifactPackageError(
                    "SDK_DISTRIBUTION_RECORD_UNAVAILABLE"
                )
            payload = resolved.read_bytes()
            actual_digest = (
                base64.urlsafe_b64encode(sha256(payload).digest())
                .decode("ascii")
                .rstrip("=")
            )
            if (
                actual_digest != encoded_digest.removeprefix("sha256=").rstrip("=")
                or len(payload) != int(encoded_size)
            ):
                raise BootstrapArtifactPackageError(
                    "SDK_DISTRIBUTION_FILE_MISMATCH"
                )
            is_installer_metadata = (
                in_dist_info and relative_path.name in _INSTALLER_RECORD_NAMES
            )
            if not is_installer_metadata:
                authenticated_files.add(resolved)
                manifest_entries.append(
                    {
                        "path": row[0],
                        "sha256": encoded_digest.removeprefix("sha256=").rstrip("="),
                        "size_bytes": int(encoded_size),
                    }
                )
        if record_relative.as_posix() not in seen:
            raise BootstrapArtifactPackageError(
                "SDK_DISTRIBUTION_RECORD_UNAVAILABLE"
            )
        if _sdk_manifest_digest(manifest_entries) != contract[
            "installed_manifest_sha256"
        ]:
            raise BootstrapArtifactPackageError("SDK_DISTRIBUTION_RECORD_MISMATCH")
        for package_path in contract["package_paths"]:
            package_root = distribution_root / str(package_path)
            candidates = _regular_tree_files(package_root)
            if not candidates:
                raise BootstrapArtifactPackageError("SDK_DISTRIBUTION_FILE_UNAVAILABLE")
            for candidate in candidates:
                if candidate not in authenticated_files:
                    raise BootstrapArtifactPackageError(
                        "SDK_DISTRIBUTION_EXTRA_FILE"
                    )
        for candidate in _regular_tree_files(distribution_info):
            if candidate not in recorded_runtime_files:
                raise BootstrapArtifactPackageError("SDK_DISTRIBUTION_EXTRA_FILE")
        module_path = distribution_root / str(contract["module_path"])
        recorded_module_origins[str(contract["module_name"])] = module_path.resolve(
            strict=True
        )

    importlib.invalidate_caches()
    for module_name, expected_origin in recorded_module_origins.items():
        try:
            specification = importlib.util.find_spec(module_name)
            actual_origin = Path(str(specification.origin)).resolve(strict=True)
        except (AttributeError, OSError, ValueError):
            raise BootstrapArtifactPackageError("SDK_MODULE_ORIGIN_INVALID") from None
        if actual_origin != expected_origin:
            raise BootstrapArtifactPackageError("SDK_MODULE_ORIGIN_INVALID")
    return ValidatedSDKRuntime(
        module_origins=recorded_module_origins,
        authenticated_files=frozenset(authenticated_files),
    )


def _validate_imported_sdk_modules(
    *, runtime: ValidatedSDKRuntime, boto3: ModuleType, botocore: ModuleType
) -> None:
    """Recheck that every imported SDK module came from authenticated bytes."""

    if (
        getattr(boto3, "__version__", None) != EXPECTED_BOTO3_VERSION
        or getattr(botocore, "__version__", None) != EXPECTED_BOTOCORE_VERSION
    ):
        raise BootstrapArtifactPackageError("SDK_RUNTIME_VERSION_UNREVIEWED")
    module_names = tuple(runtime.module_origins)
    for name, module in tuple(sys.modules.items()):
        if not any(
            name == root_name or name.startswith(root_name + ".")
            for root_name in module_names
        ):
            continue
        module_file = getattr(module, "__file__", None)
        module_spec = getattr(module, "__spec__", None)
        module_loader = getattr(module, "__loader__", None)
        if (
            module_file is None
            and (name == "six.moves" or name.startswith("six.moves."))
            and module_spec is not None
            and type(module_loader).__module__ == "six"
            and type(module_loader).__qualname__ == "_SixMetaPathImporter"
        ):
            continue
        if not isinstance(module_file, str) or module_spec is None:
            raise BootstrapArtifactPackageError("SDK_MODULE_ORIGIN_INVALID")
        try:
            origin = Path(module_file).resolve(strict=True)
            spec_origin = Path(str(module_spec.origin)).resolve(strict=True)
        except (OSError, ValueError):
            raise BootstrapArtifactPackageError("SDK_MODULE_ORIGIN_INVALID") from None
        if origin != spec_origin or origin not in runtime.authenticated_files:
            raise BootstrapArtifactPackageError("SDK_MODULE_ORIGIN_INVALID")


def import_reviewed_aws_sdk(
    *,
    source_root: Path,
    isolated_import_paths: tuple[str, ...],
    sdk_runtime_root: Path,
) -> tuple[ModuleType, ModuleType, type[Any]]:
    """Import exact SDK wheels from one dedicated external runtime."""

    if sys.pycache_prefix is not None:
        raise BootstrapArtifactPackageError("PYTHON_BYTECODE_PREFIX_FORBIDDEN")
    root = source_root.resolve(strict=True)
    if not sdk_runtime_root.is_absolute():
        raise BootstrapArtifactPackageError("SDK_RUNTIME_ROOT_INVALID")
    try:
        runtime_root = sdk_runtime_root.resolve(strict=True)
        runtime_root.relative_to(root)
    except ValueError:
        pass
    except OSError:
        raise BootstrapArtifactPackageError("SDK_RUNTIME_ROOT_INVALID") from None
    else:
        raise BootstrapArtifactPackageError("SDK_RUNTIME_INSIDE_SOURCE_ROOT")
    if sdk_runtime_root != runtime_root or not runtime_root.is_dir():
        raise BootstrapArtifactPackageError("SDK_RUNTIME_ROOT_INVALID")
    runtime_site = runtime_root / SDK_RUNTIME_SITE_PATH
    try:
        resolved_runtime_site = runtime_site.resolve(strict=True)
    except OSError:
        raise BootstrapArtifactPackageError("SDK_RUNTIME_SITE_UNAVAILABLE") from None
    if resolved_runtime_site != runtime_site or not runtime_site.is_dir():
        raise BootstrapArtifactPackageError("SDK_RUNTIME_SITE_UNAVAILABLE")
    _require_closed_sdk_runtime_permissions(
        runtime_root=runtime_root,
        runtime_site=runtime_site,
    )

    safe_paths: list[str] = []
    for entry in isolated_import_paths:
        if not entry:
            continue
        try:
            resolved = Path(entry).resolve(strict=True)
        except OSError:
            continue
        if resolved == root:
            continue
        try:
            relative = resolved.relative_to(root)
        except ValueError:
            pass
        else:
            continue
        if "site-packages" in resolved.parts or "dist-packages" in resolved.parts:
            raise BootstrapArtifactPackageError("PYTHON_SITE_INITIALIZATION_FORBIDDEN")
        safe_paths.append(str(resolved))
    if not safe_paths or str(runtime_site) in safe_paths:
        raise BootstrapArtifactPackageError("ISOLATED_IMPORT_PATH_UNAVAILABLE")
    safe_paths.append(str(runtime_site))
    locked_module_names = tuple(
        str(contract["module_name"])
        for contract in SDK_DISTRIBUTION_LOCKS.values()
    )
    if any(
        name == locked_name or name.startswith(locked_name + ".")
        for name in sys.modules
        for locked_name in locked_module_names
    ):
        raise BootstrapArtifactPackageError("SDK_MODULE_PRELOADED_FORBIDDEN")
    original_paths = list(sys.path)
    original_dont_write_bytecode = sys.dont_write_bytecode
    try:
        sys.path[:] = safe_paths
        sys.dont_write_bytecode = True
        runtime = _validate_locked_sdk_distributions(
            source_root=root, runtime_site=runtime_site
        )
        boto3 = importlib.import_module("boto3")
        botocore = importlib.import_module("botocore")
        botocore_config = importlib.import_module("botocore.config")
        _validate_imported_sdk_modules(
            runtime=runtime,
            boto3=boto3,
            botocore=botocore,
        )
        config_origin = Path(str(botocore_config.__file__)).resolve(strict=True)
        if config_origin not in runtime.authenticated_files:
            raise BootstrapArtifactPackageError("SDK_CONFIG_CLASS_INVALID")
    except BootstrapArtifactPackageError:
        raise
    except Exception:
        raise BootstrapArtifactPackageError("SDK_RUNTIME_UNAVAILABLE") from None
    finally:
        sys.path[:] = original_paths
        if not original_dont_write_bytecode:
            # The caller keeps the repository off sys.path after this boundary;
            # prevent later lazy SDK imports from creating or consuming new cache
            # authority in the reviewed process.
            sys.dont_write_bytecode = True
    config_class = getattr(botocore_config, "Config", None)
    if not isinstance(config_class, type):
        raise BootstrapArtifactPackageError("SDK_CONFIG_CLASS_INVALID")
    return boto3, botocore, config_class


@dataclass(frozen=True, slots=True)
class BuiltBootstrapArtifactPackage:
    """Deterministic unsigned archive and its public review manifest."""

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


def _read_source(source_root: Path, relative_path: Path) -> bytes:
    root = source_root.resolve(strict=True)
    candidate = root / relative_path
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError):
        raise BootstrapArtifactPackageError("PACKAGE_SOURCE_UNAVAILABLE") from None
    if candidate.is_symlink() or not resolved.is_file():
        raise BootstrapArtifactPackageError("PACKAGE_SOURCE_UNSAFE")
    payload = resolved.read_bytes()
    if not payload and relative_path != Path("tooling/__init__.py"):
        raise BootstrapArtifactPackageError("PACKAGE_SOURCE_EMPTY")
    return payload


def _entry(path: Path, payload: bytes) -> tuple[ZipInfo, bytes]:
    info = ZipInfo(path.as_posix(), FIXED_ZIP_TIMESTAMP)
    info.compress_type = ZIP_STORED
    info.create_system = 3
    info.external_attr = (0o100644 & 0xFFFF) << 16
    info.extra = b""
    info.comment = b""
    return info, payload


def _build_bootstrap_artifact_package(
    *,
    source_root: Path,
    source_commit: str,
    expected_boto3_version: str,
    expected_botocore_version: str,
    committed_sources: Mapping[Path, bytes],
) -> BuiltBootstrapArtifactPackage:
    """Pure builder used only after the public Git-provenance check."""

    if _COMMIT_RE.fullmatch(source_commit) is None:
        raise BootstrapArtifactPackageError("SOURCE_COMMIT_INVALID")
    if any(
        _SDK_VERSION_RE.fullmatch(value) is None
        for value in (expected_boto3_version, expected_botocore_version)
    ):
        raise BootstrapArtifactPackageError("SDK_VERSION_INVALID")
    if set(committed_sources) != set(SOURCE_PATHS):
        raise BootstrapArtifactPackageError("COMMITTED_SOURCE_SET_INVALID")
    sources = {path: bytes(committed_sources[path]) for path in SOURCE_PATHS}
    if any(
        not payload and path != Path("tooling/__init__.py")
        for path, payload in sources.items()
    ):
        raise BootstrapArtifactPackageError("PACKAGE_SOURCE_EMPTY")
    runtime_lock = {
        "record_type": (
            "scanalyze.platform_authority.bootstrap_artifact_authority_runtime_lock.v1"
        ),
        "schema_version": 1,
        "work_package": WORK_PACKAGE,
        "trust_root_generation": TRUST_ROOT_GENERATION,
        "source_commit": source_commit,
        "expected_boto3_version": expected_boto3_version,
        "expected_botocore_version": expected_botocore_version,
    }
    sources[RUNTIME_LOCK_PATH] = (canonical_json(runtime_lock) + "\n").encode()
    sources = dict(sorted(sources.items(), key=lambda item: item[0].as_posix()))

    buffer = BytesIO()
    with ZipFile(buffer, "w", compression=ZIP_STORED, strict_timestamps=True) as archive:
        for path, payload in sources.items():
            info, contents = _entry(path, payload)
            archive.writestr(info, contents)
    archive_bytes = buffer.getvalue()
    archive_digest = sha256(archive_bytes).digest()
    manifest: dict[str, Any] = {
        "artifact_type": ARTIFACT_TYPE,
        "schema_version": SCHEMA_VERSION,
        "work_package": WORK_PACKAGE,
        "trust_root_generation": TRUST_ROOT_GENERATION,
        "source_commit": source_commit,
        "archive_name": ARCHIVE_NAME,
        "archive_format": "ZIP_STORED_FIXED_METADATA",
        "archive_sha256": archive_digest.hex(),
        "unsigned_archive_code_sha256": base64.b64encode(archive_digest).decode(
            "ascii"
        ),
        "archive_size_bytes": len(archive_bytes),
        "handlers": dict(sorted(HANDLERS.items())),
        "runtime_dependencies": {
            "runtime_lock_path": RUNTIME_LOCK_PATH.as_posix(),
            "expected_boto3_version": expected_boto3_version,
            "expected_botocore_version": expected_botocore_version,
            "aws_sdk": "AWS_MANAGED_PINNED_BY_RUNTIME_VERSION_GUARD",
        },
        "entries": [
            {
                "path": path.as_posix(),
                "sha256": sha256(payload).hexdigest(),
                "size_bytes": len(payload),
            }
            for path, payload in sources.items()
        ],
        "signing_contract": {
            "profile_name": SIGNING_PROFILE_NAME,
            "trust_root_contract_path": (
                "bootstrap/platform-authority-bootstrap-artifact-signing-trust-root.json"
            ),
            "trust_root_configuration_status": "NOT_CONFIGURED",
            "immutable_profile_version_required": True,
            "untrusted_artifact_on_deployment": "Enforce",
            "signed_s3_object_version_required": True,
            "signed_artifact_receipt_required": True,
            "signed_lambda_code_sha256_from_receipt_required": True,
            "trusted_read_only_refresh_required": True,
            "unsigned_archive_is_not_deployable": True,
        },
        "activation_contract": {
            "all_three_functions_same_signed_code_sha256": True,
            "all_three_published_versions_must_equal": TRUST_ROOT_GENERATION,
            "signed_artifact_evidence_observed": False,
            "deployment_evidence_observed": False,
            "live_identity_proof_observed": False,
        },
        "production_status": PRODUCTION_STATUS,
    }
    validate_bootstrap_artifact_package(
        manifest=manifest,
        archive=archive_bytes,
        expected_source_commit=source_commit,
    )
    return BuiltBootstrapArtifactPackage(archive=archive_bytes, manifest=manifest)


def validate_bootstrap_artifact_package(
    *, manifest: Mapping[str, Any], archive: bytes, expected_source_commit: str
) -> None:
    """Validate bytes and every security-relevant manifest projection."""

    required = {
        "artifact_type",
        "schema_version",
        "work_package",
        "trust_root_generation",
        "source_commit",
        "archive_name",
        "archive_format",
        "archive_sha256",
        "unsigned_archive_code_sha256",
        "archive_size_bytes",
        "handlers",
        "runtime_dependencies",
        "entries",
        "signing_contract",
        "activation_contract",
        "production_status",
    }
    digest = sha256(archive).digest()
    if (
        type(manifest) is not dict
        or set(manifest) != required
        or _COMMIT_RE.fullmatch(expected_source_commit) is None
        or manifest.get("artifact_type") != ARTIFACT_TYPE
        or type(manifest.get("schema_version")) is not int
        or manifest.get("schema_version") != SCHEMA_VERSION
        or manifest.get("work_package") != WORK_PACKAGE
        or type(manifest.get("trust_root_generation")) is not int
        or manifest.get("trust_root_generation") != TRUST_ROOT_GENERATION
        or manifest.get("source_commit") != expected_source_commit
        or manifest.get("archive_name") != ARCHIVE_NAME
        or manifest.get("archive_format") != "ZIP_STORED_FIXED_METADATA"
        or manifest.get("archive_sha256") != digest.hex()
        or manifest.get("unsigned_archive_code_sha256")
        != base64.b64encode(digest).decode("ascii")
        or manifest.get("archive_size_bytes") != len(archive)
        or manifest.get("handlers") != dict(sorted(HANDLERS.items()))
        or manifest.get("production_status") != PRODUCTION_STATUS
    ):
        raise BootstrapArtifactPackageError("PACKAGE_MANIFEST_INVALID")
    if manifest.get("runtime_dependencies") != {
        "runtime_lock_path": RUNTIME_LOCK_PATH.as_posix(),
        "expected_boto3_version": manifest.get("runtime_dependencies", {}).get(
            "expected_boto3_version"
        )
        if isinstance(manifest.get("runtime_dependencies"), Mapping)
        else None,
        "expected_botocore_version": manifest.get("runtime_dependencies", {}).get(
            "expected_botocore_version"
        )
        if isinstance(manifest.get("runtime_dependencies"), Mapping)
        else None,
        "aws_sdk": "AWS_MANAGED_PINNED_BY_RUNTIME_VERSION_GUARD",
    }:
        raise BootstrapArtifactPackageError("PACKAGE_RUNTIME_CONTRACT_INVALID")
    runtime_dependencies = manifest["runtime_dependencies"]
    assert isinstance(runtime_dependencies, Mapping)
    if any(
        _SDK_VERSION_RE.fullmatch(str(runtime_dependencies.get(field, ""))) is None
        for field in ("expected_boto3_version", "expected_botocore_version")
    ):
        raise BootstrapArtifactPackageError("PACKAGE_RUNTIME_CONTRACT_INVALID")
    signing = manifest.get("signing_contract")
    activation = manifest.get("activation_contract")
    if signing != {
        "profile_name": SIGNING_PROFILE_NAME,
        "trust_root_contract_path": (
            "bootstrap/platform-authority-bootstrap-artifact-signing-trust-root.json"
        ),
        "trust_root_configuration_status": "NOT_CONFIGURED",
        "immutable_profile_version_required": True,
        "untrusted_artifact_on_deployment": "Enforce",
        "signed_s3_object_version_required": True,
        "signed_artifact_receipt_required": True,
        "signed_lambda_code_sha256_from_receipt_required": True,
        "trusted_read_only_refresh_required": True,
        "unsigned_archive_is_not_deployable": True,
    } or activation != {
        "all_three_functions_same_signed_code_sha256": True,
        "all_three_published_versions_must_equal": TRUST_ROOT_GENERATION,
        "signed_artifact_evidence_observed": False,
        "deployment_evidence_observed": False,
        "live_identity_proof_observed": False,
    }:
        raise BootstrapArtifactPackageError("PACKAGE_ACTIVATION_CONTRACT_INVALID")

    entries = manifest.get("entries")
    if not isinstance(entries, list) or len(entries) != len(PACKAGE_PATHS):
        raise BootstrapArtifactPackageError("PACKAGE_ENTRY_SET_INVALID")
    expected_paths = [path.as_posix() for path in PACKAGE_PATHS]
    if [entry.get("path") for entry in entries if isinstance(entry, Mapping)] != expected_paths:
        raise BootstrapArtifactPackageError("PACKAGE_ENTRY_SET_INVALID")
    try:
        with ZipFile(BytesIO(archive), "r") as zipped:
            if zipped.namelist() != expected_paths:
                raise BootstrapArtifactPackageError("PACKAGE_ARCHIVE_ENTRY_SET_INVALID")
            for entry in entries:
                if not isinstance(entry, Mapping) or set(entry) != {
                    "path",
                    "sha256",
                    "size_bytes",
                }:
                    raise BootstrapArtifactPackageError("PACKAGE_ENTRY_INVALID")
                path = str(entry["path"])
                contents = zipped.read(path)
                if (
                    _DIGEST_RE.fullmatch(str(entry["sha256"])) is None
                    or entry["sha256"] != sha256(contents).hexdigest()
                    or type(entry["size_bytes"]) is not int
                    or entry["size_bytes"] != len(contents)
                ):
                    raise BootstrapArtifactPackageError("PACKAGE_ENTRY_INVALID")
            try:
                runtime_lock = json.loads(
                    zipped.read(RUNTIME_LOCK_PATH.as_posix()).decode()
                )
            except (KeyError, UnicodeDecodeError, json.JSONDecodeError):
                raise BootstrapArtifactPackageError("PACKAGE_RUNTIME_LOCK_INVALID") from None
            if runtime_lock != {
                "record_type": (
                    "scanalyze.platform_authority."
                    "bootstrap_artifact_authority_runtime_lock.v1"
                ),
                "schema_version": 1,
                "work_package": WORK_PACKAGE,
                "trust_root_generation": TRUST_ROOT_GENERATION,
                "source_commit": expected_source_commit,
                "expected_boto3_version": runtime_dependencies[
                    "expected_boto3_version"
                ],
                "expected_botocore_version": runtime_dependencies[
                    "expected_botocore_version"
                ],
            }:
                raise BootstrapArtifactPackageError("PACKAGE_RUNTIME_LOCK_INVALID")
    except BootstrapArtifactPackageError:
        raise
    except Exception:
        raise BootstrapArtifactPackageError("PACKAGE_ARCHIVE_INVALID") from None
    if (
        _CODE_SHA_RE.fullmatch(str(manifest["unsigned_archive_code_sha256"]))
        is None
    ):
        raise BootstrapArtifactPackageError("PACKAGE_UNSIGNED_CODE_SHA_INVALID")


def verify_clean_source_commit(
    *, source_root: Path, source_commit: str
) -> Mapping[Path, bytes]:
    """Return package sources from one exact clean, reviewed Git commit."""

    if _COMMIT_RE.fullmatch(source_commit) is None:
        raise BootstrapArtifactPackageError("SOURCE_COMMIT_INVALID")
    git_executable = resolve_trusted_executable(
        name="git", source_root=source_root
    )
    git_environment = closed_provenance_environment(
        source_root=source_root,
        executables=(git_executable,),
        include_home=False,
    )
    git_environment.update(
        {
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )

    def git(*arguments: str, text: bool = False) -> bytes | str:
        completed = subprocess.run(
            [
                str(git_executable),
                "--no-replace-objects",
                "-c",
                "core.fsmonitor=false",
                *arguments,
            ],
            cwd=source_root,
            check=True,
            capture_output=True,
            text=text,
            timeout=30,
            env=git_environment,
        )
        return completed.stdout

    try:
        replacement_refs = str(
            git("for-each-ref", "--format=%(refname)", "refs/replace", text=True)
        ).strip()
        head = str(git("rev-parse", "--verify", "HEAD^{commit}", text=True)).strip()
        status = str(
            git("status", "--porcelain=v1", "--untracked-files=all", text=True)
        ).strip()
    except (OSError, subprocess.SubprocessError):
        raise BootstrapArtifactPackageError("SOURCE_PROVENANCE_UNAVAILABLE") from None
    if replacement_refs:
        raise BootstrapArtifactPackageError("SOURCE_REPLACEMENT_FORBIDDEN")
    if head != source_commit:
        raise BootstrapArtifactPackageError("SOURCE_COMMIT_MISMATCH")
    if status:
        raise BootstrapArtifactPackageError("SOURCE_TREE_DIRTY")

    committed: dict[Path, bytes] = {}
    for path in (*SOURCE_PATHS, *PROVENANCE_PATHS):
        try:
            git("ls-files", "--error-unmatch", "--", path.as_posix())
            payload = git("show", f"{source_commit}:{path.as_posix()}")
        except (OSError, subprocess.SubprocessError):
            raise BootstrapArtifactPackageError("PACKAGE_SOURCE_NOT_IN_COMMIT") from None
        assert isinstance(payload, bytes)
        if payload != _read_source(source_root, path):
            raise BootstrapArtifactPackageError("PACKAGE_SOURCE_COMMIT_DRIFT")
        if path in SOURCE_PATHS:
            committed[path] = payload
    return committed


def build_bootstrap_artifact_package(
    *,
    source_root: Path,
    source_commit: str,
    expected_boto3_version: str,
    expected_botocore_version: str,
) -> BuiltBootstrapArtifactPackage:
    """Build only from the exact clean commit proven by Git object bytes."""

    if (
        expected_boto3_version != EXPECTED_BOTO3_VERSION
        or expected_botocore_version != EXPECTED_BOTOCORE_VERSION
    ):
        raise BootstrapArtifactPackageError("SDK_RUNTIME_VERSION_UNREVIEWED")

    committed_sources = verify_clean_source_commit(
        source_root=source_root, source_commit=source_commit
    )
    return _build_bootstrap_artifact_package(
        source_root=source_root,
        source_commit=source_commit,
        expected_boto3_version=expected_boto3_version,
        expected_botocore_version=expected_botocore_version,
        committed_sources=committed_sources,
    )


def write_bootstrap_artifact_package(
    *,
    source_root: Path,
    source_commit: str,
    expected_boto3_version: str,
    expected_botocore_version: str,
    output_directory: Path,
) -> tuple[Path, Path, Mapping[str, Any]]:
    """Write one owner-only evidence directory outside the source tree."""

    built = build_bootstrap_artifact_package(
        source_root=source_root,
        source_commit=source_commit,
        expected_boto3_version=expected_boto3_version,
        expected_botocore_version=expected_botocore_version,
    )
    root = source_root.resolve(strict=True)
    requested_output = output_directory.resolve(strict=False)
    try:
        requested_output.relative_to(root)
    except ValueError:
        pass
    else:
        raise BootstrapArtifactPackageError("OUTPUT_MUST_BE_OUTSIDE_SOURCE_ROOT")
    try:
        output_directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    except OSError:
        raise BootstrapArtifactPackageError("OUTPUT_DIRECTORY_UNAVAILABLE") from None
    archive_path = output_directory / ARCHIVE_NAME
    manifest_path = output_directory / MANIFEST_NAME
    manifest_bytes = (canonical_json(built.manifest) + "\n").encode()
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
    except OSError:
        raise BootstrapArtifactPackageError("OUTPUT_WRITE_FAILED") from None
    return archive_path, manifest_path, built.manifest
