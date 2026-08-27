#!/usr/bin/env python3
"""Guarded live entry point for GUG-390.

The parser is intentionally import-inert.  AWS and repository modules are
loaded only after one of the four explicit subcommands is selected.  Every
request is a create-only private JSON document below an owner-only root; stdout
contains only the sanitized public manifest.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import importlib
from importlib.machinery import (
    BYTECODE_SUFFIXES,
    EXTENSION_SUFFIXES,
    SOURCE_SUFFIXES,
    BuiltinImporter,
    ExtensionFileLoader,
    FileFinder,
    FrozenImporter,
    PathFinder,
    SourceFileLoader,
    SourcelessFileLoader,
)
from importlib.util import module_from_spec, spec_from_file_location
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
from types import MappingProxyType
from typing import Any, Mapping
from zipimport import zipimporter


REPO_ROOT = Path(__file__).resolve().parents[2]
_TOOLING_ROOT = (REPO_ROOT / "tooling").resolve()
_ENTRYPOINT_RELATIVE_PATH = Path(
    "scripts/deployment/platform-authority-gug390-live-provider.py"
)
_REPOSITORY_MODULE_PATHS = {
    "tooling.platform_authority_gug365_live_provider": (
        _TOOLING_ROOT / "platform_authority_gug365_live_provider.py"
    ),
    "tooling.platform_authority_gug390_live_executor": (
        _TOOLING_ROOT / "platform_authority_gug390_live_executor.py"
    ),
    "tooling.platform_authority_gug376_authority_inventory_collector": (
        _TOOLING_ROOT
        / "platform_authority_gug376_authority_inventory_collector.py"
    ),
}
_SAFE_META_PATH = (BuiltinImporter, FrozenImporter, PathFinder)
_SAFE_FILE_FINDER_DETAILS = (
    (ExtensionFileLoader, EXTENSION_SUFFIXES),
    (SourceFileLoader, SOURCE_SUFFIXES),
    (SourcelessFileLoader, BYTECODE_SUFFIXES),
)
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,126}\.json$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_PROFILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_TOKEN = re.compile(r"^[A-Z][A-Z0-9_]{2,95}$")
_COMMANDS = ("inventory", "execute-phase", "reconcile", "certify")
_OPT_IN = {
    "inventory": "GUG390_INVENTORY_READ_ONLY",
    "execute-phase": "GUG390_EXECUTE_EXACT_PHASE_ONCE",
    "reconcile": "GUG390_RECONCILE_READ_ONLY_ONLY",
    "certify": "GUG390_CERTIFY_NO_AWS",
}


class _ReviewedSourceLoader(SourceFileLoader):
    """Compile the exact reviewed source and never consult bytecode caches."""

    def __init__(
        self,
        fullname: str,
        path: str,
        *,
        reviewed_sources: Mapping[Path, bytes] | None = None,
    ) -> None:
        super().__init__(fullname, path)
        self._reviewed_sources = reviewed_sources

    def get_code(self, fullname: str) -> Any:
        source_path = self.get_filename(fullname)
        if self._reviewed_sources is None:
            source = self.get_data(source_path)
        else:
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


class CliError(ValueError):
    """Stable CLI failure without echoing a caller-controlled value."""

    def __init__(self, code: str) -> None:
        self.code = code if _TOKEN.fullmatch(code) else "GUG390_CLI_BLOCKED"
        super().__init__(self.code)


class SanitizedParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise CliError("CLI_ARGUMENTS_INVALID")


def _parser() -> argparse.ArgumentParser:
    parser = SanitizedParser(
        description=(
            "Execute one explicitly authorized GUG-390 command from an "
            "owner-only private request. No command is selected by default."
        )
    )
    commands = parser.add_subparsers(dest="command", required=True)
    for command in _COMMANDS:
        child = commands.add_parser(command)
        child.add_argument("--private-root", required=True, type=Path)
        child.add_argument("--request", required=True)
    return parser


def _git(*arguments: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(REPO_ROOT), *arguments],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CliError("SOURCE_GIT_STATE_UNAVAILABLE") from exc
    return result.stdout.strip()


def _git_bytes(*arguments: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", "-C", str(REPO_ROOT), *arguments],
            check=True,
            capture_output=True,
            timeout=10,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CliError("SOURCE_GIT_STATE_UNAVAILABLE") from exc
    return result.stdout


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
    """Bind every tooling source and this entry point to exact Git blobs.

    The filesystem source set is compared independently of index flags, so
    assume-unchanged, skip-worktree and ignored Python candidates cannot hide
    executable drift. Returned bytes are the reviewed bytes the import loader
    will compile, closing the validation-to-import race.
    """

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
        relative
        for relative in tracked
        if relative.startswith("tooling/")
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


def _source_state() -> tuple[str, str]:
    try:
        git_root = Path(_git("rev-parse", "--show-toplevel")).resolve(strict=True)
    except OSError as exc:
        raise CliError("SOURCE_REPOSITORY_ROOT_INVALID") from exc
    if git_root != REPO_ROOT:
        raise CliError("SOURCE_REPOSITORY_ROOT_MISMATCH")
    if _git("status", "--porcelain=v1", "--untracked-files=normal"):
        raise CliError("SOURCE_WORKTREE_NOT_CLEAN")
    commit = _git("rev-parse", "--verify", "HEAD^{commit}")
    tree = _git("rev-parse", "--verify", "HEAD^{tree}")
    remote_main = _git("rev-parse", "--verify", "refs/remotes/origin/main^{commit}")
    if commit != remote_main:
        raise CliError("SOURCE_NOT_EXACT_ORIGIN_MAIN")
    return commit, tree


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
        reviewed_payload = reviewed_sources.get(module_file)
        if (
            name != _tooling_module_name(module_file)
            or not isinstance(reviewed_payload, bytes)
            or not isinstance(loader, _ReviewedSourceLoader)
            or getattr(spec, "loader", None) is not loader
            or loader._reviewed_sources is not reviewed_sources  # noqa: SLF001
        ):
            raise CliError("IMPORT_PROVENANCE_INVALID")
        if name == "tooling":
            if module_file != (_TOOLING_ROOT / "__init__.py").resolve(strict=True):
                raise CliError("IMPORT_PROVENANCE_INVALID")
            raw_locations = getattr(spec, "submodule_search_locations", None)
            if raw_locations is None:
                raise CliError("IMPORT_PROVENANCE_INVALID")
            try:
                locations = tuple(
                    Path(item).resolve(strict=True) for item in raw_locations
                )
            except (OSError, TypeError) as exc:
                raise CliError("IMPORT_PROVENANCE_INVALID") from exc
            if locations != (_TOOLING_ROOT,):
                raise CliError("IMPORT_PROVENANCE_INVALID")


def _reject_preloaded_tooling_modules() -> None:
    if any(
        name == "tooling" or name.startswith("tooling.")
        for name in sys.modules
    ):
        raise CliError("IMPORT_PRELOADED_UNSAFE")


def _reject_preloaded_sdk_modules() -> None:
    if any(
        name == "boto3"
        or name.startswith("boto3.")
        or name == "botocore"
        or name.startswith("botocore.")
        for name in sys.modules
    ):
        raise CliError("IMPORT_PRELOADED_UNSAFE")


def _is_repository_import_path(item: str) -> bool:
    try:
        candidate = Path.cwd() if item == "" else Path(item)
        candidate.resolve().relative_to(REPO_ROOT)
    except ValueError:
        return False
    except (OSError, RuntimeError) as exc:
        raise CliError("IMPORT_PATH_INVALID") from exc
    return True


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


def _prepare_repository_imports() -> None:
    if "PYTHONPATH" in os.environ or "PYTHONHOME" in os.environ:
        raise CliError("IMPORT_ENVIRONMENT_UNSAFE")
    if type(sys.path) is not list or any(
        not isinstance(item, str) for item in sys.path
    ):
        raise CliError("IMPORT_PATH_INVALID")
    _reject_preloaded_tooling_modules()
    _reject_preloaded_sdk_modules()
    _establish_safe_import_runtime()
    try:
        current_spec = PathFinder.find_spec("tooling", sys.path)
    except (ImportError, AttributeError, TypeError, ValueError) as exc:
        raise CliError("IMPORT_PATH_INVALID") from exc
    if current_spec is not None:
        raw_origin = getattr(current_spec, "origin", None)
        if not isinstance(raw_origin, str):
            raise CliError("IMPORT_PATH_PREEMPTED")
        try:
            origin = Path(raw_origin).resolve(strict=True)
        except OSError as exc:
            raise CliError("IMPORT_PATH_PREEMPTED") from exc
        if origin != (_TOOLING_ROOT / "__init__.py").resolve(strict=True):
            raise CliError("IMPORT_PATH_PREEMPTED")

    sys.path[:] = [
        item for item in sys.path if not _is_repository_import_path(item)
    ]
    importlib.invalidate_caches()
    try:
        remaining_spec = PathFinder.find_spec("tooling", sys.path)
    except (ImportError, AttributeError, TypeError, ValueError) as exc:
        raise CliError("IMPORT_PATH_INVALID") from exc
    if remaining_spec is not None:
        raise CliError("IMPORT_PATH_PREEMPTED")
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
    if name in sys.modules:
        raise CliError("IMPORT_PROVENANCE_INVALID")
    if exact_path not in reviewed_sources:
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
) -> tuple[Any, Any, Any]:
    _prepare_repository_imports()
    if not isinstance(reviewed_sources, Mapping) or not reviewed_sources:
        raise CliError("IMPORT_REVIEWED_SOURCE_MANIFEST_INVALID")
    normalized: dict[Path, bytes] = {}
    try:
        for raw_path, payload in reviewed_sources.items():
            if not isinstance(raw_path, Path) or not isinstance(payload, bytes):
                raise CliError("IMPORT_REVIEWED_SOURCE_MANIFEST_INVALID")
            path = raw_path.resolve(strict=True)
            path.relative_to(_TOOLING_ROOT)
            if not path.name.endswith(tuple(SOURCE_SUFFIXES)):
                raise CliError("IMPORT_REVIEWED_SOURCE_MANIFEST_INVALID")
            if path in normalized:
                raise CliError("IMPORT_REVIEWED_SOURCE_MANIFEST_INVALID")
            normalized[path] = payload
    except CliError:
        raise
    except (OSError, ValueError) as exc:
        raise CliError("IMPORT_REVIEWED_SOURCE_MANIFEST_INVALID") from exc
    required = {
        (_TOOLING_ROOT / "__init__.py").resolve(strict=True),
        *(path.resolve(strict=True) for path in _REPOSITORY_MODULE_PATHS.values()),
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
        modules = tuple(
            _load_exact_source_module(
                name, path, reviewed_sources=sealed_sources
            )
            for name, path in _REPOSITORY_MODULE_PATHS.items()
        )
    except Exception as exc:
        for name in tuple(sys.modules):
            if name == "tooling" or name.startswith("tooling."):
                del sys.modules[name]
        raise CliError("IMPORT_PROVENANCE_INVALID") from exc
    _validate_loaded_tooling_modules(sealed_sources)
    for module, expected in zip(
        modules, _REPOSITORY_MODULE_PATHS.values(), strict=True
    ):
        _resolved_module_file(module, expected=expected)
    return modules


def _name(value: Any, code: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise CliError(code)
    return value


def _digest(value: Any, code: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise CliError(code)
    return value


def _stamp(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise CliError(code)
    try:
        result = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise CliError(code) from exc
    if result.tzinfo is None:
        raise CliError(code)
    return result.astimezone(UTC).replace(microsecond=0)


def _host_digest(executor: Any) -> str:
    return executor.canonical_digest(
        {
            "hostname": socket.gethostname(),
            "effective_uid": os.geteuid(),
            "repository_root_digest": executor.canonical_digest(str(REPO_ROOT)),
        }
    )


def _command_fields(command: str) -> set[str]:
    base = {
        "record_type",
        "schema_version",
        "issue",
        "command",
        "opt_in",
        "source_commit_sha",
        "source_tree_sha",
        "plan_file",
        "plan_digest",
        "expected_account_id",
        "region",
        "phase",
        "not_before",
        "expires_at",
        "host_digest",
        "owner_checkpoint",
        "request_digest",
        "output_file",
    }
    profile = {
        "profile",
        "expected_principal_digest",
        "expected_sso_role_name_digest",
    }
    if command == "inventory":
        return base | profile | {
            "snapshot_files",
            "expected_inventory_facts_digest",
            "authorized_before_state_digest",
        }
    if command == "execute-phase":
        return base | profile | {
            "ledger_id",
            "execution_authorization_file",
            "executor_authority_evidence_file",
            "authority_evaluation_at",
            "expected_initial_bundle_absence_digest",
            "predecessor_record_file",
            "predecessor_binding_file",
            "inventory_snapshot_files",
            "expected_inventory_snapshot_digests",
            "expected_inventory_facts_digest",
            "claim_nonce_digest",
            "activator_checkpoint_file",
            "expected_activator_checkpoint_digest",
        }
    if command == "reconcile":
        return base | profile | {
            "ledger_id",
            "expected_ambiguous_ledger_digest",
            "expected_ambiguous_operation_digest",
            "expected_reconciliation_readback_contract_digest",
            "expected_session_identifier_digest",
            "expected_effect_state_digest",
            "expected_no_effect_state_digest",
            "expected_reconciliation_binding_digest",
        }
    if command == "certify":
        return base | {
            "phase_record_files",
            "phase_run_files",
            "expected_phase_run_digests",
            "phase_bindings_file",
            "inventory_snapshot_files",
            "expected_final_snapshot_digests",
            "activator_checkpoint_file",
            "expected_activator_checkpoint_digest",
            "expected_bundle_digest",
            "expected_initial_bundle_absence_digest",
            "expected_final_facts_digest",
        }
    raise CliError("CLI_COMMAND_INVALID")


def _validate_profile(value: Any, executor: Any) -> tuple[dict[str, Any], str]:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"name", "source", "chain_depth"}
        or not isinstance(value.get("name"), str)
        or _PROFILE.fullmatch(value["name"]) is None
        or value["name"].casefold() == "default"
        or value.get("source") != "DIRECT_SSO"
        or value.get("chain_depth") != 0
    ):
        raise CliError("PROFILE_BINDING_INVALID")
    result = json.loads(executor.canonical_json(value))
    return result, executor.canonical_digest(result)


def _validate_checkpoint(
    request: Mapping[str, Any],
    *,
    command: str,
    profile_digest: str,
    host_digest: str,
    executor: Any,
) -> str:
    checkpoint = request.get("owner_checkpoint")
    fields = {
        "record_type",
        "issue",
        "command",
        "phase",
        "source_commit_sha",
        "source_tree_sha",
        "plan_digest",
        "account_digest",
        "region",
        "profile_binding_digest",
        "host_digest",
        "not_before",
        "expires_at",
        "request_binding_digest",
        "mutation_authorized",
        "checkpoint_digest",
    }
    if command != "certify":
        fields |= {
            "expected_principal_digest",
            "expected_sso_role_name_digest",
        }
    if not isinstance(checkpoint, Mapping) or set(checkpoint) != fields:
        raise CliError("OWNER_CHECKPOINT_INVALID")
    binding = {
        key: value
        for key, value in request.items()
        if key not in {"owner_checkpoint", "request_digest"}
    }
    exact = {
        "record_type": "scanalyze.platform_authority.gug390_owner_checkpoint.v1",
        "issue": "GUG-390",
        "command": command,
        "phase": request["phase"],
        "source_commit_sha": request["source_commit_sha"],
        "source_tree_sha": request["source_tree_sha"],
        "plan_digest": request["plan_digest"],
        "account_digest": executor.canonical_digest(request["expected_account_id"]),
        "region": "us-east-1",
        "profile_binding_digest": profile_digest,
        "host_digest": host_digest,
        "not_before": request["not_before"],
        "expires_at": request["expires_at"],
        "request_binding_digest": executor.canonical_digest(binding),
        "mutation_authorized": command == "execute-phase",
    }
    if command != "certify":
        exact.update(
            {
                "expected_principal_digest": request["expected_principal_digest"],
                "expected_sso_role_name_digest": request[
                    "expected_sso_role_name_digest"
                ],
            }
        )
    if any(checkpoint.get(key) != value for key, value in exact.items()):
        raise CliError("OWNER_CHECKPOINT_BINDING_MISMATCH")
    expected = executor.canonical_digest(exact)
    if checkpoint.get("checkpoint_digest") != expected:
        raise CliError("OWNER_CHECKPOINT_DIGEST_MISMATCH")
    return expected


def _validate_request(
    value: Mapping[str, Any],
    *,
    command: str,
    now: datetime,
    source_commit_sha: str,
    source_tree_sha: str,
    executor: Any,
) -> tuple[dict[str, Any], dict[str, Any] | None, str, str]:
    if not isinstance(value, Mapping) or set(value) != _command_fields(command):
        raise CliError("PRIVATE_REQUEST_FIELDS_INVALID")
    request = json.loads(executor.canonical_json(value))
    if (
        request.get("record_type")
        != "scanalyze.platform_authority.gug390_live_request.v1"
        or request.get("schema_version") != 1
        or request.get("issue") != "GUG-390"
        or request.get("command") != command
        or request.get("opt_in") != _OPT_IN[command]
        or request.get("source_commit_sha") != source_commit_sha
        or request.get("source_tree_sha") != source_tree_sha
        or request.get("region") != "us-east-1"
        or request.get("phase")
        not in ((*executor.FORWARD_PHASES, "NONE") if command == "certify" else executor.FORWARD_PHASES)
        or (command == "certify" and request.get("phase") != "NONE")
    ):
        raise CliError("PRIVATE_REQUEST_BINDING_INVALID")
    _name(request.get("plan_file"), "PLAN_FILE_INVALID")
    _name(request.get("output_file"), "OUTPUT_FILE_INVALID")
    _digest(request.get("plan_digest"), "PLAN_DIGEST_INVALID")
    account = request.get("expected_account_id")
    if not isinstance(account, str) or re.fullmatch(r"[0-9]{12}", account) is None:
        raise CliError("ACCOUNT_BINDING_INVALID")
    _assert_request_window(
        request,
        now=now,
        require_active=command not in {"execute-phase", "reconcile"},
    )
    actual_host = _host_digest(executor)
    if request.get("host_digest") != actual_host:
        raise CliError("HOST_BINDING_MISMATCH")
    profile: dict[str, Any] | None = None
    if command != "certify":
        profile, profile_digest = _validate_profile(request.get("profile"), executor)
        _digest(
            request.get("expected_principal_digest"),
            "EXPECTED_PRINCIPAL_DIGEST_INVALID",
        )
        _digest(
            request.get("expected_sso_role_name_digest"),
            "EXPECTED_SSO_ROLE_NAME_DIGEST_INVALID",
        )
    else:
        profile_digest = executor.canonical_digest({"mode": "NO_AWS"})
    owner_checkpoint_digest = _validate_checkpoint(
        request,
        command=command,
        profile_digest=profile_digest,
        host_digest=actual_host,
        executor=executor,
    )
    expected_request_digest = executor.canonical_digest(
        {key: item for key, item in request.items() if key != "request_digest"}
    )
    if request.get("request_digest") != expected_request_digest:
        raise CliError("PRIVATE_REQUEST_DIGEST_MISMATCH")
    return request, profile, owner_checkpoint_digest, expected_request_digest


def _assert_request_window(
    request: Mapping[str, Any],
    *,
    now: datetime | None = None,
    require_active: bool = True,
) -> None:
    start = _stamp(request.get("not_before"), "REQUEST_WINDOW_INVALID")
    end = _stamp(request.get("expires_at"), "REQUEST_WINDOW_INVALID")
    current = (now or datetime.now(UTC)).astimezone(UTC).replace(microsecond=0)
    if (
        not start < end
        or (end - start).total_seconds() > 900
        or (require_active and not start <= current < end)
    ):
        raise CliError("REQUEST_WINDOW_INVALID")


def _guarded_clock(request: Mapping[str, Any]) -> datetime:
    """Return current UTC only while the exact owner request remains active."""

    current = datetime.now(UTC)
    _assert_request_window(request, now=current)
    return current


def _files(value: Any, *, count: int, code: str) -> list[str]:
    if not isinstance(value, list) or len(value) != count or len(set(value)) != count:
        raise CliError(code)
    return [_name(item, code) for item in value]


def _digests(value: Any, *, count: int, code: str) -> list[str]:
    if not isinstance(value, list) or len(value) != count or len(set(value)) != count:
        raise CliError(code)
    return [_digest(item, code) for item in value]


def _read_optional(root: Path, value: Any, collector: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    return collector.read_private_json(root, _name(value, "PRIVATE_FILE_INVALID"))


def _provider(
    profile: Mapping[str, Any],
    account: str,
    provider_module: Any,
    request: Mapping[str, Any],
) -> Any:
    return provider_module.build_live_provider(
        provider_module.ProviderConfig(
            profile_name=str(profile["name"]),
            expected_account_id=account,
            region="us-east-1",
            expected_principal_digest=str(request["expected_principal_digest"]),
            expected_sso_role_name_digest=str(
                request["expected_sso_role_name_digest"]
            ),
            validity_gate=lambda: _assert_request_window(request),
        )
    )


def _inventory(
    request: Mapping[str, Any],
    profile: Mapping[str, Any],
    *,
    root: Path,
    plan: Mapping[str, Any],
    now: datetime,
    executor: Any,
    provider_module: Any,
    collector: Any,
    owner_checkpoint_digest: str,
    live_request_digest: str,
) -> dict[str, Any]:
    names = _files(request.get("snapshot_files"), count=2, code="SNAPSHOT_FILES_INVALID")
    if str(request["output_file"]) in names:
        raise CliError("OUTPUT_FILE_COLLISION")
    for name in names:
        collector.private_target_absent(root, name)
    snapshots: list[dict[str, Any]] = []
    providers: list[Any] = []
    for index, name in enumerate(names, 1):
        _assert_request_window(request)
        provider = _provider(
            profile,
            str(request["expected_account_id"]),
            provider_module,
            request,
        )
        snapshot = executor.capture_inventory_once(
            plan=plan,
            provider=provider,
            expected_plan_digest=str(request["plan_digest"]),
            expected_account_id=str(request["expected_account_id"]),
            expected_region="us-east-1",
            capture_index=index,
            captured_at=datetime.now(UTC),
            owner_checkpoint_digest=owner_checkpoint_digest,
            live_request_digest=live_request_digest,
        )
        provider.finalize()
        collector.write_private_json(root, name, snapshot)
        snapshots.append(snapshot)
        providers.append(provider)
    expected_facts = request.get("expected_inventory_facts_digest")
    if expected_facts is not None:
        _digest(expected_facts, "EXPECTED_INVENTORY_FACTS_DIGEST_INVALID")
    classification = executor.classify_stable_inventory(
        snapshots[0],
        snapshots[1],
        plan=plan,
        expected_plan_digest=str(request["plan_digest"]),
        expected_facts_digest=expected_facts,
        authorized_before_state_digest=_digest(
            request.get("authorized_before_state_digest"),
            "AUTHORIZED_BEFORE_STATE_DIGEST_INVALID",
        ),
    )
    return executor.public_inventory_manifest(
        classification=classification,
        plan=plan,
        first_snapshot=snapshots[0],
        second_snapshot=snapshots[1],
        expected_facts_digest=expected_facts,
        authorized_before_state_digest=_digest(
            request.get("authorized_before_state_digest"),
            "AUTHORIZED_BEFORE_STATE_DIGEST_INVALID",
        ),
        source_commit_sha=str(request["source_commit_sha"]),
        source_tree_sha=str(request["source_tree_sha"]),
        plan_digest=str(request["plan_digest"]),
        phase=str(request["phase"]),
        created_at=datetime.now(UTC),
        owner_checkpoint_digest=owner_checkpoint_digest,
        live_request_digest=live_request_digest,
        live_providers=providers,
    )


def _execute_phase(
    request: Mapping[str, Any],
    profile: Mapping[str, Any],
    *,
    root: Path,
    plan: Mapping[str, Any],
    now: datetime,
    executor: Any,
    provider_module: Any,
    collector: Any,
    owner_checkpoint_digest: str,
    live_request_digest: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    store = executor.phase_ledger.DurablePhaseLedgerStore(root)
    ledger_id = _digest(request.get("ledger_id"), "LEDGER_ID_INVALID")
    current = store.read(ledger_id)
    if current.get("phase") != request.get("phase"):
        raise CliError("PHASE_BINDING_MISMATCH")
    phase = str(request["phase"])
    expected_activator_digest = request.get("expected_activator_checkpoint_digest")
    if phase == "ACTIVATOR":
        _digest(
            expected_activator_digest,
            "EXPECTED_ACTIVATOR_CHECKPOINT_DIGEST_INVALID",
        )
    elif expected_activator_digest is not None or request.get(
        "activator_checkpoint_file"
    ) is not None:
        raise CliError("ACTIVATOR_CHECKPOINT_UNEXPECTED")
    status = current.get("status")
    if status in {"CONSUMED", "AMBIGUOUS", "IN_FLIGHT"}:
        private = executor.execute_one_phase(
            store=store,
            plan=plan,
            expected_plan_digest=str(request["plan_digest"]),
            ledger_id=ledger_id,
            execution_authorization={},
            executor_authority_evidence={},
            authority_evaluation_at=_stamp(
                request.get("authority_evaluation_at"),
                "AUTHORITY_EVALUATION_TIME_INVALID",
            ),
            expected_initial_bundle_absence_digest=(
                request.get("expected_initial_bundle_absence_digest")
            ),
            predecessor_record=None,
            expected_predecessor_binding=None,
            provider=None,
            clock=lambda: datetime.now(UTC),
            inventory_classification={},
            claim_nonce_digest=_digest(
                request.get("claim_nonce_digest"), "CLAIM_NONCE_DIGEST_INVALID"
            ),
            activator_checkpoint=None,
            expected_activator_checkpoint_digest=expected_activator_digest,
            owner_checkpoint_digest=owner_checkpoint_digest,
            live_request_digest=live_request_digest,
        )
        public = executor.public_phase_manifest(
            private_run=private,
            ledger_record=store.read(ledger_id),
            plan=plan,
            expected_plan_digest=str(request["plan_digest"]),
            source_commit_sha=str(request["source_commit_sha"]),
            source_tree_sha=str(request["source_tree_sha"]),
            plan_digest=str(request["plan_digest"]),
            created_at=datetime.now(UTC),
            private_evidence_root=root,
        )
        return private, public
    if status not in {"PREPARED", "CLAIMED"}:
        raise CliError("LEDGER_NOT_EXECUTABLE")
    _assert_request_window(request)
    names = _files(
        request.get("inventory_snapshot_files"),
        count=2,
        code="SNAPSHOT_FILES_INVALID",
    )
    snapshots = [collector.read_private_json(root, name) for name in names]
    expected_facts = _digest(
        request.get("expected_inventory_facts_digest"),
        "EXPECTED_INVENTORY_FACTS_DIGEST_INVALID",
    )
    inventory = executor.classify_stable_inventory(
        snapshots[0],
        snapshots[1],
        plan=plan,
        expected_plan_digest=str(request["plan_digest"]),
        expected_facts_digest=expected_facts,
        authorized_before_state_digest=str(current["before_state_digest"]),
        expected_snapshot_digests=_digests(
            request.get("expected_inventory_snapshot_digests"),
            count=2,
            code="EXPECTED_INVENTORY_SNAPSHOT_DIGESTS_INVALID",
        ),
    )
    execution_authorization = collector.read_private_json(
        root,
        _name(request.get("execution_authorization_file"), "AUTHORIZATION_FILE_INVALID"),
    )
    evidence = collector.read_private_json(
        root,
        _name(request.get("executor_authority_evidence_file"), "EVIDENCE_FILE_INVALID"),
    )
    predecessor = _read_optional(root, request.get("predecessor_record_file"), collector)
    predecessor_binding = _read_optional(
        root, request.get("predecessor_binding_file"), collector
    )
    activator = _read_optional(
        root, request.get("activator_checkpoint_file"), collector
    )
    initial = request.get("expected_initial_bundle_absence_digest")
    if initial is not None:
        _digest(initial, "INITIAL_ABSENCE_DIGEST_INVALID")
    provider = _provider(
        profile,
        str(request["expected_account_id"]),
        provider_module,
        request,
    )
    private = executor.execute_one_phase(
        store=store,
        plan=plan,
        expected_plan_digest=str(request["plan_digest"]),
        ledger_id=ledger_id,
        execution_authorization=execution_authorization,
        executor_authority_evidence=evidence,
        authority_evaluation_at=_stamp(
            request.get("authority_evaluation_at"),
            "AUTHORITY_EVALUATION_TIME_INVALID",
        ),
        expected_initial_bundle_absence_digest=initial,
        predecessor_record=predecessor,
        expected_predecessor_binding=predecessor_binding,
        provider=provider,
        clock=lambda: _guarded_clock(request),
        inventory_classification=inventory,
        claim_nonce_digest=_digest(
            request.get("claim_nonce_digest"), "CLAIM_NONCE_DIGEST_INVALID"
        ),
        activator_checkpoint=activator,
        expected_activator_checkpoint_digest=expected_activator_digest,
        owner_checkpoint_digest=owner_checkpoint_digest,
        live_request_digest=live_request_digest,
    )
    provider.finalize()
    public = executor.public_phase_manifest(
        private_run=private,
        ledger_record=store.read(ledger_id),
        plan=plan,
        expected_plan_digest=str(request["plan_digest"]),
        source_commit_sha=str(request["source_commit_sha"]),
        source_tree_sha=str(request["source_tree_sha"]),
        plan_digest=str(request["plan_digest"]),
        created_at=datetime.now(UTC),
        private_evidence_root=root,
    )
    return private, public


def _reconcile(
    request: Mapping[str, Any],
    profile: Mapping[str, Any],
    *,
    root: Path,
    plan: Mapping[str, Any],
    now: datetime,
    executor: Any,
    provider_module: Any,
    owner_checkpoint_digest: str,
    live_request_digest: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    store = executor.phase_ledger.DurablePhaseLedgerStore(root)
    ledger_id = _digest(request.get("ledger_id"), "LEDGER_ID_INVALID")
    current = store.read(ledger_id)
    expected_plan_digest = _digest(
        request.get("plan_digest"), "PLAN_DIGEST_INVALID"
    )
    expected_ledger_digest = _digest(
        request.get("expected_ambiguous_ledger_digest"),
        "EXPECTED_AMBIGUOUS_LEDGER_DIGEST_INVALID",
    )
    expected_session_digest = _digest(
        request.get("expected_session_identifier_digest"),
        "EXPECTED_SESSION_IDENTIFIER_DIGEST_INVALID",
    )
    if current.get("phase") != request.get("phase"):
        raise CliError("RECONCILIATION_PHASE_BINDING_MISMATCH")
    if (
        current.get("plan_digest") != expected_plan_digest
        or current.get("account_id") != request.get("expected_account_id")
        or current.get("region") != "us-east-1"
    ):
        raise CliError("RECONCILIATION_LOCAL_LEDGER_BINDING_MISMATCH")
    if (
        current.get("authority_session_identifier_digest")
        != expected_session_digest
    ):
        raise CliError("RECONCILIATION_SESSION_BINDING_MISMATCH")
    claim = current.get("claim")
    raw_context = (
        claim.get("execution_context") if isinstance(claim, Mapping) else None
    )
    try:
        stored_context = executor.phase_ledger.validate_execution_context(
            raw_context
        )
    except Exception as exc:
        raise CliError("EXECUTION_CONTEXT_INVALID") from exc
    status = current.get("status")
    if status == "RECONCILED":
        reconciliation = current.get("reconciliation")
        if (
            not isinstance(reconciliation, Mapping)
            or reconciliation.get("ambiguous_ledger_digest")
            != expected_ledger_digest
            or reconciliation.get("owner_checkpoint_digest")
            != owner_checkpoint_digest
            or reconciliation.get("live_request_digest")
            != live_request_digest
        ):
            raise CliError("RECONCILIATION_TERMINAL_BINDING_MISMATCH")
        private = executor.reconcile_ambiguous(
            store=store,
            ledger_id=ledger_id,
            plan=plan,
            expected_plan_digest=expected_plan_digest,
            expected_phase=str(request["phase"]),
            provider=None,
            expected_ambiguous_ledger_digest=expected_ledger_digest,
            expected_ambiguous_operation_digest=_digest(
                request.get("expected_ambiguous_operation_digest"),
                "EXPECTED_AMBIGUOUS_OPERATION_DIGEST_INVALID",
            ),
            expected_reconciliation_readback_contract_digest=_digest(
                request.get("expected_reconciliation_readback_contract_digest"),
                "EXPECTED_RECONCILIATION_READBACK_CONTRACT_DIGEST_INVALID",
            ),
            expected_session_identifier_digest=expected_session_digest,
            expected_effect_state_digest=_digest(
                request.get("expected_effect_state_digest"),
                "EXPECTED_EFFECT_STATE_DIGEST_INVALID",
            ),
            expected_no_effect_state_digest=_digest(
                request.get("expected_no_effect_state_digest"),
                "EXPECTED_NO_EFFECT_STATE_DIGEST_INVALID",
            ),
            expected_reconciliation_binding_digest=_digest(
                request.get("expected_reconciliation_binding_digest"),
                "EXPECTED_RECONCILIATION_BINDING_DIGEST_INVALID",
            ),
            at=now,
            owner_checkpoint_digest=owner_checkpoint_digest,
            live_request_digest=live_request_digest,
        )
        public = executor.public_phase_manifest(
            private_run=private,
            ledger_record=current,
            plan=plan,
            expected_plan_digest=expected_plan_digest,
            source_commit_sha=str(request["source_commit_sha"]),
            source_tree_sha=str(request["source_tree_sha"]),
            plan_digest=str(request["plan_digest"]),
            created_at=datetime.now(UTC),
            private_evidence_root=root,
        )
        return private, public
    if current.get("ledger_digest") != expected_ledger_digest:
        raise CliError("AMBIGUOUS_LEDGER_DIGEST_MISMATCH")
    if status == "IN_FLIGHT":
        executor.phase_ledger.recover_persisted_in_flight(
            store=store,
            ledger_id=ledger_id,
            at=datetime.now(UTC),
        )
        raise CliError(
            "IN_FLIGHT_RECOVERED_NEW_AMBIGUOUS_BINDING_REQUIRED"
        )
    if status != "AMBIGUOUS":
        raise CliError("RECONCILIATION_NOT_PERMITTED")
    _assert_request_window(request, now=now)
    expected_operation_digest = _digest(
        request.get("expected_ambiguous_operation_digest"),
        "EXPECTED_AMBIGUOUS_OPERATION_DIGEST_INVALID",
    )
    expected_contract_digest = _digest(
        request.get("expected_reconciliation_readback_contract_digest"),
        "EXPECTED_RECONCILIATION_READBACK_CONTRACT_DIGEST_INVALID",
    )
    expected_effect_digest = _digest(
        request.get("expected_effect_state_digest"),
        "EXPECTED_EFFECT_STATE_DIGEST_INVALID",
    )
    expected_no_effect_digest = _digest(
        request.get("expected_no_effect_state_digest"),
        "EXPECTED_NO_EFFECT_STATE_DIGEST_INVALID",
    )
    expected_binding_digest = _digest(
        request.get("expected_reconciliation_binding_digest"),
        "EXPECTED_RECONCILIATION_BINDING_DIGEST_INVALID",
    )
    provider = _provider(
        profile,
        str(request["expected_account_id"]),
        provider_module,
        request,
    )
    private = executor.reconcile_ambiguous(
        store=store,
        ledger_id=ledger_id,
        plan=plan,
        expected_plan_digest=expected_plan_digest,
        expected_phase=str(request["phase"]),
        provider=provider,
        expected_ambiguous_ledger_digest=expected_ledger_digest,
        expected_ambiguous_operation_digest=expected_operation_digest,
        expected_reconciliation_readback_contract_digest=(
            expected_contract_digest
        ),
        expected_session_identifier_digest=expected_session_digest,
        expected_effect_state_digest=expected_effect_digest,
        expected_no_effect_state_digest=expected_no_effect_digest,
        expected_reconciliation_binding_digest=expected_binding_digest,
        at=now,
        clock=lambda: _guarded_clock(request),
        owner_checkpoint_digest=owner_checkpoint_digest,
        live_request_digest=live_request_digest,
    )
    provider.finalize()
    public = executor.public_phase_manifest(
        private_run=private,
        ledger_record=store.read(ledger_id),
        plan=plan,
        expected_plan_digest=expected_plan_digest,
        source_commit_sha=str(request["source_commit_sha"]),
        source_tree_sha=str(request["source_tree_sha"]),
        plan_digest=str(request["plan_digest"]),
        created_at=datetime.now(UTC),
        private_evidence_root=root,
    )
    return private, public


def _certify(
    request: Mapping[str, Any],
    *,
    root: Path,
    plan: Mapping[str, Any],
    now: datetime,
    executor: Any,
    collector: Any,
    owner_checkpoint_digest: str,
    live_request_digest: str,
) -> dict[str, Any]:
    record_names = _files(
        request.get("phase_record_files"),
        count=len(executor.FORWARD_PHASES),
        code="PHASE_RECORD_FILES_INVALID",
    )
    records = [collector.read_private_json(root, name) for name in record_names]
    run_names = _files(
        request.get("phase_run_files"),
        count=len(executor.FORWARD_PHASES),
        code="PHASE_RUN_FILES_INVALID",
    )
    runs = [collector.read_private_json(root, name) for name in run_names]
    bindings_envelope = collector.read_private_json(
        root,
        _name(request.get("phase_bindings_file"), "PHASE_BINDINGS_FILE_INVALID"),
    )
    if (
        set(bindings_envelope)
        != {"record_type", "plan_digest", "bindings", "binding_digest"}
        or bindings_envelope.get("record_type")
        != "scanalyze.platform_authority.gug390_phase_bindings.v1"
        or bindings_envelope.get("plan_digest") != request.get("plan_digest")
        or not isinstance(bindings_envelope.get("bindings"), list)
        or bindings_envelope.get("binding_digest")
        != executor.canonical_digest(bindings_envelope["bindings"])
    ):
        raise CliError("PHASE_BINDINGS_INVALID")
    snapshot_names = _files(
        request.get("inventory_snapshot_files"),
        count=2,
        code="SNAPSHOT_FILES_INVALID",
    )
    snapshots = [collector.read_private_json(root, name) for name in snapshot_names]
    activator_checkpoint = collector.read_private_json(
        root,
        _name(
            request.get("activator_checkpoint_file"),
            "ACTIVATOR_CHECKPOINT_FILE_INVALID",
        ),
    )
    expected_activator_digest = _digest(
        request.get("expected_activator_checkpoint_digest"),
        "EXPECTED_ACTIVATOR_CHECKPOINT_DIGEST_INVALID",
    )
    execution_mode = (
        "LIVE"
        if all(item.get("provider_backed") is True for item in snapshots)
        else "SYNTHETIC"
    )
    return executor.certify_bundle(
        plan=plan,
        expected_plan_digest=str(request["plan_digest"]),
        expected_bundle_digest=_digest(
            request.get("expected_bundle_digest"), "BUNDLE_DIGEST_INVALID"
        ),
        phase_records=records,
        phase_runs=runs,
        expected_phase_run_digests=_digests(
            request.get("expected_phase_run_digests"),
            count=len(executor.FORWARD_PHASES),
            code="EXPECTED_PHASE_RUN_DIGESTS_INVALID",
        ),
        expected_phase_bindings=bindings_envelope["bindings"],
        expected_initial_bundle_absence_digest=_digest(
            request.get("expected_initial_bundle_absence_digest"),
            "INITIAL_ABSENCE_DIGEST_INVALID",
        ),
        expected_final_facts_digest=_digest(
            request.get("expected_final_facts_digest"),
            "EXPECTED_FINAL_FACTS_DIGEST_INVALID",
        ),
        expected_final_snapshot_digests=_digests(
            request.get("expected_final_snapshot_digests"),
            count=2,
            code="EXPECTED_FINAL_SNAPSHOT_DIGESTS_INVALID",
        ),
        first_snapshot=snapshots[0],
        second_snapshot=snapshots[1],
        source_commit_sha=str(request["source_commit_sha"]),
        source_tree_sha=str(request["source_tree_sha"]),
        execution_mode=execution_mode,
        activator_checkpoint=activator_checkpoint,
        expected_activator_checkpoint_digest=expected_activator_digest,
        created_at=datetime.now(UTC),
        owner_checkpoint_digest=owner_checkpoint_digest,
        live_request_digest=live_request_digest,
        private_evidence_root=root,
    )


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        _prepare_repository_imports()
        request_name = _name(args.request, "REQUEST_FILE_INVALID")
        now = datetime.now(UTC).replace(microsecond=0)
        source_commit, source_tree = _source_state()
        reviewed_sources = _reviewed_repository_source_manifest(source_commit)
        provider_module, executor, collector = _load_repository_modules(
            reviewed_sources
        )
        raw = collector.read_private_json(args.private_root, request_name)
        request, profile, owner_checkpoint_digest, live_request_digest = (
            _validate_request(
            raw,
            command=args.command,
            now=now,
            source_commit_sha=source_commit,
            source_tree_sha=source_tree,
            executor=executor,
            )
        )
        plan = collector.read_private_json(args.private_root, str(request["plan_file"]))
        plan = executor.validate_plan(
            plan,
            expected_plan_digest=str(request["plan_digest"]),
            expected_account_id=str(request["expected_account_id"]),
            expected_region="us-east-1",
        )
        output_name = str(request["output_file"])
        collector.private_target_absent(args.private_root, output_name)
        if args.command == "inventory":
            assert profile is not None
            public = _inventory(
                request,
                profile,
                root=args.private_root,
                plan=plan,
                now=now,
                executor=executor,
                provider_module=provider_module,
                collector=collector,
                owner_checkpoint_digest=owner_checkpoint_digest,
                live_request_digest=live_request_digest,
            )
            private_output = public
        elif args.command == "execute-phase":
            assert profile is not None
            private_output, public = _execute_phase(
                request,
                profile,
                root=args.private_root,
                plan=plan,
                now=now,
                executor=executor,
                provider_module=provider_module,
                collector=collector,
                owner_checkpoint_digest=owner_checkpoint_digest,
                live_request_digest=live_request_digest,
            )
        elif args.command == "reconcile":
            assert profile is not None
            private_output, public = _reconcile(
                request,
                profile,
                root=args.private_root,
                plan=plan,
                now=now,
                executor=executor,
                provider_module=provider_module,
                owner_checkpoint_digest=owner_checkpoint_digest,
                live_request_digest=live_request_digest,
            )
        else:
            public = _certify(
                request,
                root=args.private_root,
                plan=plan,
                now=now,
                executor=executor,
                collector=collector,
                owner_checkpoint_digest=owner_checkpoint_digest,
                live_request_digest=live_request_digest,
            )
            private_output = public
        collector.write_private_json(args.private_root, output_name, private_output)
        print(json.dumps(public, sort_keys=True, separators=(",", ":")))
        return 0
    except Exception as exc:
        code = getattr(exc, "code", None)
        if not isinstance(code, str) or _TOKEN.fullmatch(code) is None:
            code = "GUG390_COMMAND_FAILED"
        print(
            json.dumps(
                {
                    "error": code,
                    "status": "HUMAN_DECISION_REQUIRED",
                    "production_status": "NO-GO",
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
