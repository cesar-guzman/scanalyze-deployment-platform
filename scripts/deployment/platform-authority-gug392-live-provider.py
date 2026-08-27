#!/usr/bin/env python3
"""Guarded CLI for the GUG-392 dual-domain live read-only inventory lane."""
from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import importlib
from importlib.machinery import (
    EXTENSION_SUFFIXES,
    SOURCE_SUFFIXES,
    BuiltinImporter,
    ExtensionFileLoader,
    FileFinder,
    FrozenImporter,
    PathFinder,
    SourceFileLoader,
)
from importlib.util import module_from_spec, spec_from_file_location
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import sysconfig
from types import MappingProxyType
from typing import Any, Mapping
from zipimport import zipimporter


REPO_ROOT = Path(__file__).resolve().parents[2]
_TOOLING_ROOT = (REPO_ROOT / "tooling").resolve()
_ENTRYPOINT_RELATIVE_PATH = Path(
    "scripts/deployment/platform-authority-gug392-live-provider.py"
)
_REPOSITORY_MODULE_PATHS = {
    "tooling.platform_authority_gug365_upstream_inventory": (
        _TOOLING_ROOT / "platform_authority_gug365_upstream_inventory.py"
    ),
    "tooling.platform_authority_gug376_authority_inventory_collector": (
        _TOOLING_ROOT
        / "platform_authority_gug376_authority_inventory_collector.py"
    ),
    "tooling.platform_authority_gug376_identity_center_inventory_collector": (
        _TOOLING_ROOT
        / "platform_authority_gug376_identity_center_inventory_collector.py"
    ),
    "tooling.platform_authority_gug376_live_executor": (
        _TOOLING_ROOT / "platform_authority_gug376_live_executor.py"
    ),
    "tooling.platform_authority_gug376_live_provider": (
        _TOOLING_ROOT / "platform_authority_gug376_live_provider.py"
    ),
    "tooling.platform_authority_gug376_live_request_materializer": (
        _TOOLING_ROOT
        / "platform_authority_gug376_live_request_materializer.py"
    ),
    "tooling.platform_authority_gug376_live_readonly_orchestrator": (
        _TOOLING_ROOT
        / "platform_authority_gug376_live_readonly_orchestrator.py"
    ),
}
_MATERIALIZE_MODULES = (
    "tooling.platform_authority_gug365_upstream_inventory",
    "tooling.platform_authority_gug376_authority_inventory_collector",
    "tooling.platform_authority_gug376_identity_center_inventory_collector",
    "tooling.platform_authority_gug376_live_request_materializer",
    "tooling.platform_authority_gug376_live_readonly_orchestrator",
)
_PLAN_MATERIALIZE_MODULES = _MATERIALIZE_MODULES
_LIVE_MODULES = (
    "tooling.platform_authority_gug365_upstream_inventory",
    "tooling.platform_authority_gug376_live_executor",
    "tooling.platform_authority_gug376_live_provider",
    "tooling.platform_authority_gug376_live_request_materializer",
)
_VALIDATE_MODULES = (
    "tooling.platform_authority_gug376_live_executor",
)
_SAFE_META_PATH = (BuiltinImporter, FrozenImporter, PathFinder)
_SAFE_FILE_FINDER_DETAILS = (
    (ExtensionFileLoader, EXTENSION_SUFFIXES),
    (SourceFileLoader, SOURCE_SUFFIXES),
)
_UNSAFE_IMPORT_ENVIRONMENT = frozenset(
    {
        "PYTHONHOME",
        "PYTHONPATH",
        "_PYTHON_PROJECT_BASE",
        "_PYTHON_SYSCONFIGDATA_NAME",
    }
)
_EXPECTED_OPERATIONAL_PYTHON = (3, 11, 14)
_REVIEWED_REPOSITORY_BUNDLE_SENTINEL = object()
DEFAULT_REQUEST = "gug376-live-request.json"
DEFAULT_CHECKPOINT = "gug376-owner-checkpoint.json"
CONSUMPTION_CLAIM = "gug376-live-consumption-claim.json"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SSO_ROLE_NAME = re.compile(r"^[A-Za-z0-9+=,.@_-]{1,64}$")
_FORBIDDEN_AUTHORITY_NAME_FRAGMENTS = (
    "administrator",
    "admin",
    "bootstrap",
    "seed",
    "deploy",
    "destroy",
)


class CliError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class _ReviewedSourceLoader(SourceFileLoader):
    """Compile only the Git-reviewed bytes and never write bytecode caches."""

    def __init__(
        self,
        fullname: str,
        path: str,
        *,
        reviewed_sources: Mapping[Path, bytes],
    ) -> None:
        super().__init__(fullname, path)
        self._reviewed_sources = reviewed_sources

    def get_code(self, fullname: str) -> Any:
        source_path = self.get_filename(fullname)
        try:
            exact_path = Path(source_path).resolve(strict=True)
            source = self._reviewed_sources[exact_path]
            if exact_path.read_bytes() != source:
                raise ImportError("reviewed source changed before import")
        except (KeyError, OSError) as exc:
            raise ImportError("source is outside the reviewed manifest") from exc
        return self.source_to_code(source, source_path)

    def set_data(
        self,
        _path: str,
        _data: bytes,
        *_args: Any,
        **_kwargs: Any,
    ) -> None:
        return None


class _ReviewedRepositoryModules:
    """Opaque result minted only after the reviewed loader validates imports."""

    __slots__ = ("_modules", "_sentinel", "_source_identity")

    def __init__(
        self,
        sentinel: object,
        *,
        source_identity: tuple[str, str],
        modules: Mapping[str, Any],
    ) -> None:
        if sentinel is not _REVIEWED_REPOSITORY_BUNDLE_SENTINEL:
            raise CliError("IMPORT_PROVENANCE_INVALID")
        self._sentinel = sentinel
        self._source_identity = source_identity
        self._modules = MappingProxyType(dict(modules))


def _validated_repository_bundle(
    bundle: Any,
    expected_modules: tuple[str, ...],
) -> tuple[tuple[str, str], Mapping[str, Any]]:
    if (
        type(bundle) is not _ReviewedRepositoryModules
        or bundle._sentinel is not _REVIEWED_REPOSITORY_BUNDLE_SENTINEL
        or set(bundle._modules) != set(expected_modules)
    ):
        raise CliError("IMPORT_PROVENANCE_INVALID")
    source_identity = bundle._source_identity
    if (
        not isinstance(source_identity, tuple)
        or len(source_identity) != 2
        or any(
            not isinstance(value, str)
            or re.fullmatch(r"[0-9a-f]{40,64}", value) is None
            for value in source_identity
        )
    ):
        raise CliError("IMPORT_PROVENANCE_INVALID")
    return source_identity, bundle._modules


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Materialize or execute the attested GUG-392 dual-domain AWS "
            "read-only inventory; no mutation or deployment is authorized."
        )
    )
    sub = parser.add_subparsers(dest="command", required=True)

    plans = sub.add_parser(
        "materialize-plans",
        help="offline derivation of both closed private live plans",
    )
    plans.add_argument("--private-root", required=True, type=Path)
    plans.add_argument("--authority-input-file", required=True)
    plans.add_argument("--identity-center-input-file", required=True)
    plans.add_argument("--authority-plan-file", default="authority-plan.json")
    plans.add_argument(
        "--identity-center-plan-file", default="identity-center-plan.json"
    )

    materialize = sub.add_parser(
        "materialize-request",
        help="offline creation of a private request and owner checkpoint",
    )
    materialize.add_argument("--private-root", required=True, type=Path)
    materialize.add_argument("--authority-plan-file", required=True)
    materialize.add_argument("--identity-center-plan-file", required=True)
    materialize.add_argument("--authority-profile", required=True)
    materialize.add_argument("--identity-center-profile", required=True)
    materialize.add_argument("--authority-sso-role-name", required=True)
    materialize.add_argument("--identity-center-sso-role-name", required=True)
    materialize.add_argument("--run-id", required=True)
    materialize.add_argument("--not-before", required=True)
    materialize.add_argument("--expires-at", required=True)
    materialize.add_argument("--approval-reference-digest", required=True)
    materialize.add_argument(
        "--sdk-runtime-root",
        required=True,
        help="absolute dedicated --target root containing site-packages",
    )
    materialize.add_argument("--request-file", default=DEFAULT_REQUEST)
    materialize.add_argument(
        "--owner-checkpoint-file", default=DEFAULT_CHECKPOINT
    )

    execute = sub.add_parser(
        "live",
        help="consume one fresh private request through the concrete boto3 adapter",
    )
    execute.add_argument("--private-root", required=True, type=Path)
    execute.add_argument("--request-file", default=DEFAULT_REQUEST)
    execute.add_argument("--approval-reference-digest", required=True)
    execute.add_argument("--expected-request-digest", required=True)
    execute.add_argument("--expected-checkpoint-digest", required=True)

    validate_run = sub.add_parser("validate-run-v2")
    validate_run.add_argument("input", type=Path)
    validate_handoff = sub.add_parser("validate-handoff-v2")
    validate_handoff.add_argument("run_input", type=Path)
    validate_handoff.add_argument("handoff_input", type=Path)
    validate_evidence = sub.add_parser(
        "validate-evidence-v2",
        help="recompute the private manifest and exact public run/handoff links",
    )
    validate_evidence.add_argument("--private-root", required=True, type=Path)
    validate_evidence.add_argument(
        "--evidence-file", default="gug376-live-evidence-manifest.json"
    )
    validate_evidence.add_argument("run_input", type=Path)
    validate_evidence.add_argument("handoff_input", type=Path)
    return parser


def _git_binary_and_environment() -> tuple[str, dict[str, str]]:
    git_binary = shutil.which("git", path=os.defpath)
    if git_binary is None or not Path(git_binary).is_absolute():
        raise CliError("SOURCE_CHECKOUT_INVALID")
    return git_binary, {
        "PATH": os.defpath,
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_NO_REPLACE_OBJECTS": "1",
    }


def _git_bytes(*arguments: str) -> bytes:
    git_binary, git_environment = _git_binary_and_environment()
    try:
        result = subprocess.run(
            [git_binary, "-C", str(REPO_ROOT), *arguments],
            check=False,
            capture_output=True,
            timeout=15,
            env=git_environment,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CliError("SOURCE_CHECKOUT_INVALID") from exc
    if result.returncode != 0:
        raise CliError("SOURCE_CHECKOUT_INVALID")
    return result.stdout


def _git(*arguments: str) -> str:
    try:
        return _git_bytes(*arguments).decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise CliError("SOURCE_CHECKOUT_INVALID") from exc


def _source_identity() -> tuple[str, str]:
    try:
        reported_root = Path(_git("rev-parse", "--show-toplevel")).resolve(
            strict=True
        )
        expected_root = REPO_ROOT.resolve(strict=True)
    except OSError as exc:
        raise CliError("SOURCE_CHECKOUT_INVALID") from exc
    if reported_root != expected_root:
        raise CliError("SOURCE_CHECKOUT_INVALID")

    def snapshot() -> tuple[str, str]:
        values = _git("show", "-s", "--format=%H%n%T", "HEAD").splitlines()
        if len(values) != 2 or any(
            re.fullmatch(r"[0-9a-f]{40,64}", value) is None for value in values
        ):
            raise CliError("SOURCE_CHECKOUT_INVALID")
        return values[0], values[1]

    before = snapshot()
    first_status = _git("status", "--porcelain=v1", "--untracked-files=normal")
    after = snapshot()
    second_status = _git("status", "--porcelain=v1", "--untracked-files=normal")
    if before != after:
        raise CliError("SOURCE_CHECKOUT_CHANGED")
    if first_status or second_status:
        raise CliError("SOURCE_CHECKOUT_NOT_CLEAN")
    return after


def _regular_source_bytes(path: Path) -> bytes:
    try:
        before = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
        ):
            raise CliError("SOURCE_FILE_CUSTODY_INVALID")
        payload = path.read_bytes()
        after = path.lstat()
    except CliError:
        raise
    except OSError as exc:
        raise CliError("SOURCE_FILE_CUSTODY_INVALID") from exc
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise CliError("SOURCE_FILE_CHANGED_DURING_READ")
    return payload


def _git_blob_object_id(payload: bytes, object_format: str) -> str:
    if object_format not in {"sha1", "sha256"}:
        raise CliError("SOURCE_GIT_OBJECT_FORMAT_INVALID")
    digest = hashlib.new(object_format)
    digest.update(f"blob {len(payload)}\0".encode("ascii"))
    digest.update(payload)
    return digest.hexdigest()


def _reviewed_repository_source_manifest(commit: str) -> Mapping[Path, bytes]:
    """Return exact reviewed bytes for this entrypoint and every tooling source."""

    if re.fullmatch(r"[0-9a-f]{40,64}", commit) is None:
        raise CliError("SOURCE_COMMIT_INVALID")
    object_format = _git("rev-parse", "--show-object-format")
    raw_tree = _git_bytes(
        "ls-tree",
        "-r",
        "-z",
        "--full-tree",
        commit,
        "--",
        _ENTRYPOINT_RELATIVE_PATH.as_posix(),
        "tooling",
    )
    tracked: dict[str, tuple[str, str, str]] = {}
    try:
        for raw_entry in raw_tree.split(b"\0"):
            if not raw_entry:
                continue
            metadata, raw_path = raw_entry.split(b"\t", 1)
            mode, object_type, object_id = metadata.decode("ascii").split()
            relative = raw_path.decode("utf-8")
            if relative == _ENTRYPOINT_RELATIVE_PATH.as_posix() or (
                relative.startswith("tooling/")
                and relative.endswith(tuple(SOURCE_SUFFIXES))
            ):
                if relative in tracked:
                    raise ValueError("duplicate source path")
                tracked[relative] = (mode, object_type, object_id)
    except (UnicodeDecodeError, ValueError) as exc:
        raise CliError("SOURCE_GIT_TREE_INVALID") from exc

    entrypoint_name = _ENTRYPOINT_RELATIVE_PATH.as_posix()
    tracked_tooling = {
        relative for relative in tracked if relative.startswith("tooling/")
    }
    if entrypoint_name not in tracked or not tracked_tooling:
        raise CliError("SOURCE_GIT_TREE_INVALID")

    working_tooling: set[str] = set()
    try:
        for directory, child_directories, filenames in os.walk(
            _TOOLING_ROOT, followlinks=False
        ):
            base = Path(directory)
            for child in child_directories:
                if (base / child).is_symlink():
                    raise CliError("SOURCE_FILE_CUSTODY_INVALID")
            for filename in filenames:
                if not filename.endswith(tuple(SOURCE_SUFFIXES)):
                    continue
                candidate = base / filename
                relative = candidate.relative_to(REPO_ROOT).as_posix()
                _regular_source_bytes(candidate)
                working_tooling.add(relative)
    except CliError:
        raise
    except (OSError, ValueError) as exc:
        raise CliError("SOURCE_PYTHON_CANDIDATE_INVALID") from exc
    if working_tooling != tracked_tooling:
        raise CliError("SOURCE_PYTHON_CANDIDATE_INVALID")

    reviewed: dict[Path, bytes] = {}
    for relative in sorted({entrypoint_name, *tracked_tooling}):
        mode, object_type, expected_object_id = tracked[relative]
        if mode not in {"100644", "100755"} or object_type != "blob":
            raise CliError("SOURCE_GIT_TREE_INVALID")
        candidate = REPO_ROOT / relative
        payload = _regular_source_bytes(candidate)
        if _git_blob_object_id(payload, object_format) != expected_object_id:
            raise CliError("SOURCE_BLOB_MISMATCH")
        if relative.startswith("tooling/"):
            reviewed[candidate.resolve(strict=True)] = payload
    return MappingProxyType(reviewed)


def _resolved_module_file(module: Any, *, expected: Path | None = None) -> Path:
    raw_file = getattr(module, "__file__", None)
    spec = getattr(module, "__spec__", None)
    raw_origin = getattr(spec, "origin", None)
    if not isinstance(raw_file, str) or not isinstance(raw_origin, str):
        raise CliError("IMPORT_PROVENANCE_INVALID")
    try:
        module_file = Path(raw_file).resolve(strict=True)
        origin = Path(raw_origin).resolve(strict=True)
    except OSError as exc:
        raise CliError("IMPORT_PROVENANCE_INVALID") from exc
    if module_file != origin:
        raise CliError("IMPORT_PROVENANCE_INVALID")
    try:
        module_file.relative_to(_TOOLING_ROOT)
    except ValueError as exc:
        raise CliError("IMPORT_PROVENANCE_INVALID") from exc
    if expected is not None and module_file != expected.resolve(strict=True):
        raise CliError("IMPORT_PROVENANCE_INVALID")
    return module_file


def _tooling_module_name(path: Path) -> str:
    try:
        relative = path.relative_to(REPO_ROOT).with_suffix("")
    except ValueError as exc:
        raise CliError("IMPORT_PROVENANCE_INVALID") from exc
    parts = relative.parts
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    if not parts or parts[0] != "tooling":
        raise CliError("IMPORT_PROVENANCE_INVALID")
    return ".".join(parts)


def _validate_loaded_tooling_modules(
    reviewed_sources: Mapping[Path, bytes],
) -> None:
    for name, module in tuple(sys.modules.items()):
        if name != "tooling" and not name.startswith("tooling."):
            continue
        if module is None:
            raise CliError("IMPORT_PROVENANCE_INVALID")
        expected = _REPOSITORY_MODULE_PATHS.get(name)
        module_file = _resolved_module_file(module, expected=expected)
        spec = getattr(module, "__spec__", None)
        loader = getattr(module, "__loader__", None)
        if (
            name != _tooling_module_name(module_file)
            or reviewed_sources.get(module_file) is None
            or not isinstance(loader, _ReviewedSourceLoader)
            or getattr(spec, "loader", None) is not loader
            or loader._reviewed_sources is not reviewed_sources  # noqa: SLF001
        ):
            raise CliError("IMPORT_PROVENANCE_INVALID")
        if name == "tooling":
            expected_package = (_TOOLING_ROOT / "__init__.py").resolve(
                strict=True
            )
            raw_locations = getattr(spec, "submodule_search_locations", None)
            try:
                locations = tuple(
                    Path(item).resolve(strict=True) for item in raw_locations
                )
            except (OSError, TypeError) as exc:
                raise CliError("IMPORT_PROVENANCE_INVALID") from exc
            if module_file != expected_package or locations != (_TOOLING_ROOT,):
                raise CliError("IMPORT_PROVENANCE_INVALID")


def _reject_preloaded_repository_or_sdk_modules() -> None:
    if any(
        name == "tooling"
        or name.startswith("tooling.")
        or name == "boto"
        or name.startswith("boto.")
        or name == "boto3"
        or name.startswith("boto3.")
        or name == "botocore"
        or name.startswith("botocore.")
        or name == "dateutil"
        or name.startswith("dateutil.")
        or name == "jmespath"
        or name.startswith("jmespath.")
        or name == "s3transfer"
        or name.startswith("s3transfer.")
        or name == "six"
        or name.startswith("six.")
        or name == "urllib3"
        or name.startswith("urllib3.")
        or name == "awscrt"
        or name.startswith("awscrt.")
        or name == "certifi"
        or name.startswith("certifi.")
        for name in sys.modules
    ):
        raise CliError("IMPORT_PRELOADED_UNSAFE")


def _trusted_site_roots() -> tuple[Path, ...]:
    roots: set[Path] = set()
    for name in ("purelib", "platlib"):
        raw_path = sysconfig.get_path(name)
        if not isinstance(raw_path, str) or not raw_path:
            continue
        try:
            roots.add(Path(raw_path).resolve(strict=True))
        except OSError:
            continue
    return tuple(sorted(roots, key=str))


def _is_repository_import_path(item: str) -> bool:
    try:
        candidate = Path.cwd() if item == "" else Path(item)
        resolved = candidate.resolve()
        if resolved in _trusted_site_roots():
            return False
        resolved.relative_to(REPO_ROOT)
    except ValueError:
        return False
    except (OSError, RuntimeError) as exc:
        raise CliError("IMPORT_PATH_INVALID") from exc
    return True


def _validate_discovered_tooling_spec(spec: Any | None) -> None:
    if spec is None:
        return
    raw_origin = getattr(spec, "origin", None)
    loader = getattr(spec, "loader", None)
    raw_locations = getattr(spec, "submodule_search_locations", None)
    if (
        not isinstance(raw_origin, str)
        or not isinstance(loader, SourceFileLoader)
        or raw_locations is None
    ):
        raise CliError("IMPORT_PATH_PREEMPTED")
    try:
        origin = Path(raw_origin).resolve(strict=True)
        locations = tuple(Path(item).resolve(strict=True) for item in raw_locations)
    except (OSError, TypeError) as exc:
        raise CliError("IMPORT_PATH_PREEMPTED") from exc
    if locations != (origin.parent,) or origin.name != "__init__.py":
        raise CliError("IMPORT_PATH_PREEMPTED")
    expected = (_TOOLING_ROOT / "__init__.py").resolve(strict=True)
    if origin == expected:
        return
    if sys.flags.isolated != 1 or origin.parent.name != "tooling":
        raise CliError("IMPORT_PATH_PREEMPTED")
    if any(
        origin == root / "tooling" / "__init__.py"
        for root in _trusted_site_roots()
    ):
        return
    raise CliError("IMPORT_PATH_PREEMPTED")


def _establish_safe_import_runtime() -> None:
    if (
        type(sys.modules) is not dict
        or type(sys.meta_path) is not list
        or type(sys.path_hooks) is not list
        or type(sys.path_importer_cache) is not dict
    ):
        raise CliError("IMPORT_RUNTIME_INVALID")
    sys.meta_path[:] = list(_SAFE_META_PATH)
    sys.path_hooks[:] = [
        zipimporter,
        FileFinder.path_hook(*_SAFE_FILE_FINDER_DETAILS),
    ]
    sys.path_importer_cache.clear()
    if tuple(sys.meta_path) != _SAFE_META_PATH:
        raise CliError("IMPORT_RUNTIME_INVALID")
    importlib.invalidate_caches()


def _operational_python_version() -> tuple[int, int, int]:
    return tuple(sys.version_info[:3])


def _prepare_repository_imports() -> None:
    if sys.flags.isolated != 1:
        raise CliError("PYTHON_ISOLATION_REQUIRED")
    if sys.flags.no_site != 1:
        raise CliError("PYTHON_NO_SITE_REQUIRED")
    if sys.pycache_prefix is not None:
        raise CliError("PYTHON_BYTECODE_PREFIX_FORBIDDEN")
    sys.dont_write_bytecode = True
    if _operational_python_version() != _EXPECTED_OPERATIONAL_PYTHON:
        raise CliError("PYTHON_RUNTIME_UNSUPPORTED")
    if any(name in os.environ for name in _UNSAFE_IMPORT_ENVIRONMENT):
        raise CliError("IMPORT_ENVIRONMENT_UNSAFE")
    if type(sys.path) is not list or any(
        not isinstance(item, str) for item in sys.path
    ):
        raise CliError("IMPORT_PATH_INVALID")
    _reject_preloaded_repository_or_sdk_modules()
    _establish_safe_import_runtime()
    try:
        current_spec = PathFinder.find_spec("tooling", sys.path)
    except (ImportError, AttributeError, TypeError, ValueError) as exc:
        raise CliError("IMPORT_PATH_INVALID") from exc
    _validate_discovered_tooling_spec(current_spec)
    sys.path[:] = [
        item for item in sys.path if not _is_repository_import_path(item)
    ]
    importlib.invalidate_caches()
    try:
        remaining_spec = PathFinder.find_spec("tooling", sys.path)
    except (ImportError, AttributeError, TypeError, ValueError) as exc:
        raise CliError("IMPORT_PATH_INVALID") from exc
    _validate_discovered_tooling_spec(remaining_spec)
    if any(_is_repository_import_path(item) for item in sys.path):
        raise CliError("IMPORT_PATH_INVALID")


def _load_exact_source_module(
    name: str,
    path: Path,
    *,
    reviewed_sources: Mapping[Path, bytes],
    package: bool = False,
) -> Any:
    try:
        exact_path = path.resolve(strict=True)
    except OSError as exc:
        raise CliError("IMPORT_PROVENANCE_INVALID") from exc
    existing = sys.modules.get(name)
    if existing is not None:
        _resolved_module_file(existing, expected=exact_path)
        return existing
    if name in sys.modules or exact_path not in reviewed_sources:
        raise CliError("IMPORT_PROVENANCE_INVALID")
    loader = _ReviewedSourceLoader(
        name,
        str(exact_path),
        reviewed_sources=reviewed_sources,
    )
    locations = [str(_TOOLING_ROOT)] if package else None
    spec = spec_from_file_location(
        name,
        str(exact_path),
        loader=loader,
        submodule_search_locations=locations,
    )
    if spec is None:
        raise CliError("IMPORT_PROVENANCE_INVALID")
    module = module_from_spec(spec)
    sys.modules[name] = module
    try:
        loader.exec_module(module)
    except Exception:
        if sys.modules.get(name) is module:
            del sys.modules[name]
        raise
    return module


def _load_repository_modules(
    reviewed_sources: Mapping[Path, bytes],
    module_names: tuple[str, ...],
    *,
    source_identity: tuple[str, str],
) -> _ReviewedRepositoryModules:
    _prepare_repository_imports()
    if not isinstance(reviewed_sources, Mapping) or not reviewed_sources:
        raise CliError("IMPORT_REVIEWED_SOURCE_MANIFEST_INVALID")
    if not module_names or any(
        name not in _REPOSITORY_MODULE_PATHS for name in module_names
    ):
        raise CliError("IMPORT_REVIEWED_SOURCE_MANIFEST_INVALID")
    normalized: dict[Path, bytes] = {}
    try:
        for raw_path, payload in reviewed_sources.items():
            if not isinstance(raw_path, Path) or not isinstance(payload, bytes):
                raise CliError("IMPORT_REVIEWED_SOURCE_MANIFEST_INVALID")
            path = raw_path.resolve(strict=True)
            path.relative_to(_TOOLING_ROOT)
            if not path.name.endswith(tuple(SOURCE_SUFFIXES)) or path in normalized:
                raise CliError("IMPORT_REVIEWED_SOURCE_MANIFEST_INVALID")
            normalized[path] = payload
    except CliError:
        raise
    except (OSError, ValueError) as exc:
        raise CliError("IMPORT_REVIEWED_SOURCE_MANIFEST_INVALID") from exc
    required = {
        (_TOOLING_ROOT / "__init__.py").resolve(strict=True),
        *(
            _REPOSITORY_MODULE_PATHS[name].resolve(strict=True)
            for name in module_names
        ),
    }
    if not required.issubset(normalized):
        raise CliError("IMPORT_REVIEWED_SOURCE_MANIFEST_INVALID")
    sealed_sources: Mapping[Path, bytes] = MappingProxyType(normalized)

    def reviewed_loader(fullname: str, path: str) -> _ReviewedSourceLoader:
        return _ReviewedSourceLoader(
            fullname,
            path,
            reviewed_sources=sealed_sources,
        )

    try:
        _load_exact_source_module(
            "tooling",
            _TOOLING_ROOT / "__init__.py",
            reviewed_sources=sealed_sources,
            package=True,
        )
        sys.path_importer_cache[str(_TOOLING_ROOT)] = FileFinder(
            str(_TOOLING_ROOT), (reviewed_loader, SOURCE_SUFFIXES)
        )
        modules = {
            name: _load_exact_source_module(
                name,
                _REPOSITORY_MODULE_PATHS[name],
                reviewed_sources=sealed_sources,
            )
            for name in module_names
        }
        _validate_loaded_tooling_modules(sealed_sources)
    except Exception as exc:
        for name in tuple(sys.modules):
            if name == "tooling" or name.startswith("tooling."):
                del sys.modules[name]
        if isinstance(exc, CliError):
            raise
        raise CliError("IMPORT_PROVENANCE_INVALID") from exc
    return _ReviewedRepositoryModules(
        _REVIEWED_REPOSITORY_BUNDLE_SENTINEL,
        source_identity=source_identity,
        modules=modules,
    )


def _host_digest(canonical_digest: Any) -> str:
    hostname = platform.node()
    if not isinstance(hostname, str) or not hostname:
        raise CliError("HOST_BINDING_UNAVAILABLE")
    return canonical_digest({"hostname": hostname, "uid": os.geteuid()})


def _checked_sso_role_name(value: Any) -> str:
    if not isinstance(value, str) or _SSO_ROLE_NAME.fullmatch(value) is None:
        raise CliError("SSO_ROLE_NAME_INVALID")
    normalized = re.sub(r"[^a-z0-9]", "", value.casefold())
    if any(fragment in normalized for fragment in _FORBIDDEN_AUTHORITY_NAME_FRAGMENTS):
        raise CliError("FORBIDDEN_SSO_ROLE_NAME")
    return value


def _checked_digest(value: Any) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise CliError("REVIEWED_PRIVATE_DIGEST_INVALID")
    return value


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise CliError("PUBLIC_INPUT_DUPLICATE_KEY")
        result[key] = value
    return result


def _read_public(path: Path) -> dict[str, Any]:
    try:
        metadata = path.stat()
        if not path.is_file() or not 0 < metadata.st_size <= 1024 * 1024:
            raise CliError("PUBLIC_INPUT_INVALID")
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_pairs)
    except CliError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CliError("PUBLIC_INPUT_INVALID") from exc
    if not isinstance(value, dict):
        raise CliError("PUBLIC_INPUT_INVALID")
    return value


def _emit(value: Any) -> None:
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))


def _materialize_plans(
    args: argparse.Namespace,
    *,
    repository_bundle: _ReviewedRepositoryModules,
) -> dict[str, Any]:
    _, repository_modules = _validated_repository_bundle(
        repository_bundle, _PLAN_MATERIALIZE_MODULES
    )
    upstream = repository_modules[_PLAN_MATERIALIZE_MODULES[0]]
    authority = repository_modules[_PLAN_MATERIALIZE_MODULES[1]]
    materializer = repository_modules[_PLAN_MATERIALIZE_MODULES[3]]
    orchestrator = repository_modules[_PLAN_MATERIALIZE_MODULES[4]]

    canonical_digest = upstream.canonical_digest
    read_private_json = authority.read_private_json
    materialize_live_plans = materializer.materialize_live_plans
    persist_materialized_live_plans = (
        materializer.persist_materialized_live_plans
    )
    artifact_names = set(orchestrator.ARTIFACT_NAMES)
    evidence_manifest_name = orchestrator.EVIDENCE_MANIFEST_NAME
    private_names = (
        args.authority_input_file,
        args.identity_center_input_file,
        args.authority_plan_file,
        args.identity_center_plan_file,
    )
    if (
        len(set(private_names)) != len(private_names)
        or set(private_names)
        & (artifact_names | {CONSUMPTION_CLAIM, evidence_manifest_name})
    ):
        raise CliError("PRIVATE_OUTPUT_COLLISION")

    materialization = materialize_live_plans(
        authority_input=read_private_json(
            args.private_root, args.authority_input_file
        ),
        identity_center_input=read_private_json(
            args.private_root, args.identity_center_input_file
        ),
    )
    persist_materialized_live_plans(
        args.private_root,
        materialization,
        authority_plan_file=args.authority_plan_file,
        identity_center_plan_file=args.identity_center_plan_file,
    )
    return {
        "record_type": (
            "scanalyze.platform_authority.gug392_plan_materialization_result.v1"
        ),
        "status": "PRIVATE_LIVE_PLANS_MATERIALIZED",
        "authority_plan_digest": canonical_digest(
            materialization.authority_plan
        ),
        "identity_center_plan_digest": canonical_digest(
            materialization.identity_center_plan
        ),
        "authority_policy_digest": materialization.authority_plan[
            "expected_policy_digest"
        ],
        "identity_center_discovery_policy_digest": (
            materialization.identity_center_plan[
                "expected_discovery_policy_digest"
            ]
        ),
        "read_only": True,
        "aws_calls": 0,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "production_status": "NO-GO",
    }


def _materialize(
    args: argparse.Namespace,
    *,
    repository_bundle: _ReviewedRepositoryModules,
) -> dict[str, Any]:
    (commit, tree), repository_modules = _validated_repository_bundle(
        repository_bundle, _MATERIALIZE_MODULES
    )
    upstream = repository_modules[_MATERIALIZE_MODULES[0]]
    authority = repository_modules[_MATERIALIZE_MODULES[1]]
    materializer = repository_modules[_MATERIALIZE_MODULES[3]]
    orchestrator = repository_modules[_MATERIALIZE_MODULES[4]]

    canonical_digest = upstream.canonical_digest
    read_private_json = authority.read_private_json
    materialize_live_request = materializer.materialize_live_request
    persist_materialized_live_request = materializer.persist_materialized_live_request
    private_root_binding_digest = materializer.private_root_binding_digest
    ARTIFACT_NAMES = orchestrator.ARTIFACT_NAMES
    EVIDENCE_MANIFEST_NAME = orchestrator.EVIDENCE_MANIFEST_NAME

    private_names = (
        args.authority_plan_file,
        args.identity_center_plan_file,
        args.request_file,
        args.owner_checkpoint_file,
    )
    if (
        len(set(private_names)) != len(private_names)
        or set(private_names)
        & (
            set(ARTIFACT_NAMES)
            | {CONSUMPTION_CLAIM, EVIDENCE_MANIFEST_NAME}
        )
    ):
        raise CliError("PRIVATE_OUTPUT_COLLISION")

    authority_plan = read_private_json(args.private_root, args.authority_plan_file)
    identity_plan = read_private_json(
        args.private_root, args.identity_center_plan_file
    )
    materialization = materialize_live_request(
        authority_plan=authority_plan,
        identity_center_plan=identity_plan,
        profiles={
            "authority": {
                "name": args.authority_profile,
                "source": "DIRECT_SSO",
                "chain_depth": 0,
            },
            "identity_center": {
                "name": args.identity_center_profile,
                "source": "DIRECT_SSO",
                "chain_depth": 0,
            },
        },
        expected_sso_role_name_digests={
            "authority": canonical_digest(
                _checked_sso_role_name(args.authority_sso_role_name)
            ),
            "identity_center": canonical_digest(
                _checked_sso_role_name(args.identity_center_sso_role_name)
            ),
        },
        source_commit_sha=commit,
        source_tree_sha=tree,
        run_id=args.run_id,
        not_before=args.not_before,
        expires_at=args.expires_at,
        host_digest=_host_digest(canonical_digest),
        private_root_digest=private_root_binding_digest(args.private_root),
        sdk_runtime_root=args.sdk_runtime_root,
        request_file=args.request_file,
        owner_checkpoint_file=args.owner_checkpoint_file,
        approval_reference_digest=args.approval_reference_digest,
    )
    persist_materialized_live_request(args.private_root, materialization)
    return {
        "record_type": "scanalyze.platform_authority.gug392_materialization_result.v1",
        "status": "PRIVATE_LIVE_REQUEST_MATERIALIZED",
        "request_digest": materialization.request["request_digest"],
        "checkpoint_digest": materialization.owner_checkpoint["checkpoint_digest"],
        "approval_reference_digest": args.approval_reference_digest,
        "read_only": True,
        "aws_calls": 0,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "production_status": "NO-GO",
    }


def _live(
    args: argparse.Namespace,
    *,
    repository_bundle: _ReviewedRepositoryModules,
) -> dict[str, Any]:
    (commit, tree), repository_modules = _validated_repository_bundle(
        repository_bundle, _LIVE_MODULES
    )
    upstream = repository_modules[_LIVE_MODULES[0]]
    executor = repository_modules[_LIVE_MODULES[1]]
    provider_module = repository_modules[_LIVE_MODULES[2]]
    materializer = repository_modules[_LIVE_MODULES[3]]

    canonical_digest = upstream.canonical_digest
    execute_live = executor.execute_live
    build_live_provider_factory = provider_module.build_live_provider_factory
    claim_materialized_live_request = materializer.claim_materialized_live_request
    read_materialized_live_request = materializer.read_materialized_live_request

    expected_request_digest = _checked_digest(args.expected_request_digest)
    expected_checkpoint_digest = _checked_digest(args.expected_checkpoint_digest)
    host_digest = _host_digest(canonical_digest)
    now = datetime.now(UTC).replace(microsecond=0)
    validated = read_materialized_live_request(
        args.private_root,
        args.request_file,
        now=now,
        expected_source_commit_sha=commit,
        expected_source_tree_sha=tree,
        expected_host_digest=host_digest,
        expected_approval_reference_digest=args.approval_reference_digest,
        expected_request_digest=expected_request_digest,
        expected_checkpoint_digest=expected_checkpoint_digest,
    )
    request = validated.request
    runtime = validated.runtime_config
    request_digest = expected_request_digest
    checkpoint_digest = expected_checkpoint_digest
    execution_capability = claim_materialized_live_request(
        validated,
        private_root=args.private_root,
    )

    profiles = request["profiles"]
    expectations = request["profile_expectations"]
    authority_plan = runtime["authority_plan"]
    identity_plan = runtime["identity_center_plan"]
    provider = build_live_provider_factory(
        sdk_runtime_root=request["sdk_runtime_root"],
        authority_profile=profiles["authority"]["name"],
        identity_center_profile=profiles["identity_center"]["name"],
        authority_expected_account_id=authority_plan["expected_account_id"],
        authority_expected_principal_digest=expectations["authority"][
            "expected_principal_digest"
        ],
        authority_expected_sso_role_name_digest=expectations["authority"][
            "expected_sso_role_name_digest"
        ],
        identity_expected_account_id=identity_plan["expected_account_id"],
        identity_expected_principal_digest=expectations["identity_center"][
            "expected_principal_digest"
        ],
        identity_expected_sso_role_name_digest=expectations["identity_center"][
            "expected_sso_role_name_digest"
        ],
        authority_verification_digest=authority_plan[
            "authority_verification_digest"
        ],
        identity_authority_verification_digest=identity_plan[
            "authority_verification_digest"
        ],
        execution_capability=execution_capability,
    )
    run, handoff = execute_live(
        runtime,
        provider,
        private_root=args.private_root,
        now=now,
        actual_source_commit_sha=commit,
        actual_source_tree_sha=tree,
        request_digest=request_digest,
        checkpoint_digest=checkpoint_digest,
        approval_reference_digest=args.approval_reference_digest,
        execution_capability=execution_capability,
    )
    return {"run_record": run, "public_handoff": handoff}


def _reviewed_command_bundle(
    module_names: tuple[str, ...],
) -> _ReviewedRepositoryModules:
    _prepare_repository_imports()
    source_identity = _source_identity()
    reviewed_sources = _reviewed_repository_source_manifest(
        source_identity[0]
    )
    repository_modules = _load_repository_modules(
        reviewed_sources,
        module_names,
        source_identity=source_identity,
    )
    if _source_identity() != source_identity:
        raise CliError("SOURCE_CHECKOUT_CHANGED")
    return repository_modules


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "materialize-plans":
            result = _materialize_plans(
                args,
                repository_bundle=_reviewed_command_bundle(
                    _PLAN_MATERIALIZE_MODULES
                ),
            )
        elif args.command == "materialize-request":
            result = _materialize(
                args,
                repository_bundle=_reviewed_command_bundle(
                    _MATERIALIZE_MODULES
                ),
            )
        elif args.command == "live":
            result = _live(
                args,
                repository_bundle=_reviewed_command_bundle(_LIVE_MODULES),
            )
        else:
            _, modules = _validated_repository_bundle(
                _reviewed_command_bundle(_VALIDATE_MODULES),
                _VALIDATE_MODULES,
            )
            executor = modules[_VALIDATE_MODULES[0]]

            if args.command == "validate-run-v2":
                result = executor.validate_live_run_record(
                    _read_public(args.input)
                )
            elif args.command == "validate-handoff-v2":
                _, result = executor.validate_live_bundle(
                    _read_public(args.run_input),
                    _read_public(args.handoff_input),
                )
            else:
                result = executor.validate_private_live_evidence_bundle(
                    executor.read_private_json(
                        args.private_root, args.evidence_file
                    ),
                    _read_public(args.run_input),
                    _read_public(args.handoff_input),
                    private_root=args.private_root,
                )
    except Exception as exc:
        code = getattr(exc, "code", "GUG392_LIVE_READ_ONLY_BLOCKED")
        if not isinstance(code, str) or not code.isupper():
            code = "GUG392_LIVE_READ_ONLY_BLOCKED"
        print(
            json.dumps(
                {"error": code, "status": "HUMAN_DECISION_REQUIRED"},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    _emit(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
