"""Pinned, source-only SDK closure shared by the builder and Lambda runtime.

This module has no SDK imports, clients or network effects at import time.
"""
from __future__ import annotations

import base64
from hashlib import sha256
import importlib.abc
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import threading
from types import MappingProxyType, ModuleType
from typing import Any, Mapping

EXPECTED_BOTO3_VERSION = "1.42.57"
EXPECTED_BOTOCORE_VERSION = "1.42.97"
MAX_SDK_BYTES = 24 * 1024 * 1024
MAX_PACKAGE_BYTES = 32 * 1024 * 1024
MAX_ENTRY_BYTES = 2 * 1024 * 1024
MAX_PACKAGE_ENTRIES = 4096
SDK_MODE = "VENDORED_FULL_CLOSURE_SHA256_SOURCE_ONLY"
# Optional imports found in the seven pinned distributions on Python 3.12.
# Absence is deliberate; never execute an optional layer/managed-site package.
FORBIDDEN_OPTIONAL_ROOTS = frozenset({
    "OpenSSL", "StringIO", "awscrt", "backports", "brotli", "brotlicffi",
    "certifi", "compression", "cryptography", "docutils", "h2", "idna",
    "js", "pyodide", "socks", "sphinx", "typing_extensions",
})
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


class VendoredSDKError(ValueError):
    """The signed SDK closure cannot be used."""


def _distribution_for_path(path: str) -> str:
    if (
        not isinstance(path, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", path) is None
        or any(part in {"", ".", "..", "__pycache__"} for part in path.split("/"))
        or path.endswith((".pyc", ".pyo"))
    ):
        raise VendoredSDKError("SDK_PATH_INVALID")
    for name, lock in SDK_DISTRIBUTION_LOCKS.items():
        for prefix in (*lock["package_paths"], lock["dist_info_name"]):
            if path == prefix or path.startswith(prefix + "/"):
                if path.startswith(lock["dist_info_name"] + "/") and path.rsplit("/", 1)[-1] in {"RECORD", "INSTALLER", "REQUESTED"}:
                    raise VendoredSDKError("SDK_INSTALLER_METADATA_FORBIDDEN")
                return name
    raise VendoredSDKError("SDK_PATH_UNREVIEWED")


def validate_sdk_entries(entries: object) -> None:
    """Bind every file to the independently committed distribution hashes."""
    if not isinstance(entries, list) or not 0 < len(entries) < MAX_PACKAGE_ENTRIES:
        raise VendoredSDKError("SDK_MANIFEST_INVALID")
    by_distribution: dict[str, list[dict[str, Any]]] = {name: [] for name in SDK_DISTRIBUTION_LOCKS}
    paths: list[str] = []
    total = 0
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "size_bytes"}:
            raise VendoredSDKError("SDK_MANIFEST_INVALID")
        path = entry["path"]
        name = _distribution_for_path(path)
        digest, size = entry["sha256"], entry["size_bytes"]
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None or type(size) is not int or not 0 <= size <= MAX_ENTRY_BYTES:
            raise VendoredSDKError("SDK_MANIFEST_INVALID")
        total += size
        paths.append(path)
        by_distribution[name].append({
            "path": path,
            "sha256": base64.urlsafe_b64encode(bytes.fromhex(digest)).decode("ascii").rstrip("="),
            "size_bytes": size,
        })
    if paths != sorted(paths) or len({path.casefold() for path in paths}) != len(paths) or total > MAX_SDK_BYTES:
        raise VendoredSDKError("SDK_MANIFEST_INVALID")
    for name, distribution_entries in by_distribution.items():
        payload = json.dumps(distribution_entries, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
        if sha256(payload).hexdigest() != SDK_DISTRIBUTION_LOCKS[name]["installed_manifest_sha256"]:
            raise VendoredSDKError("SDK_MANIFEST_PIN_MISMATCH")


def sdk_entries(sources: Mapping[str, bytes]) -> list[dict[str, Any]]:
    result = [{"path": path, "sha256": sha256(payload).hexdigest(), "size_bytes": len(payload)} for path, payload in sorted(sources.items())]
    validate_sdk_entries(result)
    return result


def _read_snapshot(root: Path, entries: list[dict[str, Any]]) -> Mapping[str, bytes]:
    """Read once, reject extras/symlinks, and authenticate the frozen bytes."""
    validate_sdk_entries(entries)
    if not root.is_absolute() or root.resolve(strict=True) != root:
        raise VendoredSDKError("SDK_ROOT_INVALID")
    expected = {entry["path"]: entry for entry in entries}
    discovered: set[str] = set()
    for lock in SDK_DISTRIBUTION_LOCKS.values():
        for prefix in (*lock["package_paths"], lock["dist_info_name"]):
            base = root / prefix
            candidates = [base, *base.rglob("*")] if base.is_dir() else [base]
            for path in candidates:
                mode = path.lstat().st_mode
                if stat.S_ISLNK(mode) or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                    raise VendoredSDKError("SDK_FILE_UNSAFE")
                if stat.S_ISREG(mode):
                    discovered.add(path.relative_to(root).as_posix())
    if discovered != set(expected):
        raise VendoredSDKError("SDK_FILE_SET_MISMATCH")
    snapshot: dict[str, bytes] = {}
    for path, entry in expected.items():
        candidate = root / path
        if candidate.resolve(strict=True) != candidate or candidate.stat().st_size != entry["size_bytes"]:
            raise VendoredSDKError("SDK_FILE_UNSAFE")
        with candidate.open("rb") as stream:
            payload = stream.read(entry["size_bytes"] + 1)
        if len(payload) != entry["size_bytes"] or sha256(payload).hexdigest() != entry["sha256"]:
            raise VendoredSDKError("SDK_FILE_HASH_MISMATCH")
        snapshot[path] = payload
    return MappingProxyType(snapshot)


class _SourceLoader(importlib.machinery.SourceFileLoader):
    def __init__(self, fullname: str, path: str, payload: bytes, owner: "_SDKFinder") -> None:
        super().__init__(fullname, path)
        self._payload, self._owner = payload, owner

    def get_code(self, fullname: str) -> Any:
        return self.source_to_code(self._payload, self.path)

    def exec_module(self, module: ModuleType) -> None:
        super().exec_module(module)
        self._owner.loaded[module.__name__] = (module, self)


class _SDKFinder(importlib.abc.MetaPathFinder):
    def __init__(self, root: Path, sources: Mapping[str, bytes]) -> None:
        self.root, self.sources = root, sources
        self.loaded: dict[str, tuple[ModuleType, _SourceLoader]] = {}
        self.names = tuple(str(lock["module_name"]) for lock in SDK_DISTRIBUTION_LOCKS.values())

    def owns(self, name: str) -> bool:
        return any(name == prefix or name.startswith(prefix + ".") for prefix in self.names)

    def find_spec(self, fullname: str, path: object = None, target: object = None) -> Any:
        del path, target
        if fullname.split(".", 1)[0] in FORBIDDEN_OPTIONAL_ROOTS:
            raise ModuleNotFoundError("SDK_OPTIONAL_DEPENDENCY_FORBIDDEN", name=fullname)
        if not self.owns(fullname):
            return None
        # six creates these virtual modules with its own reviewed importer.
        if fullname == "six.moves" or fullname.startswith("six.moves."):
            return None
        base = fullname.replace(".", "/")
        if base + "/__init__.py" in self.sources:
            relative, locations = base + "/__init__.py", [str(self.root / base)]
        elif base + ".py" in self.sources:
            relative, locations = base + ".py", None
        else:
            # Preserve optional-import semantics while stopping path fallback.
            raise ModuleNotFoundError("SDK_MODULE_NOT_IN_PACKAGE", name=fullname)
        loader = _SourceLoader(fullname, str(self.root / relative), self.sources[relative], self)
        return importlib.util.spec_from_file_location(fullname, loader.path, loader=loader, submodule_search_locations=locations)

    def check_custody(self) -> None:
        for name, module in tuple(sys.modules.items()):
            if name.split(".", 1)[0] in FORBIDDEN_OPTIONAL_ROOTS:
                raise VendoredSDKError("SDK_OPTIONAL_DEPENDENCY_PRELOADED")
            if not self.owns(name):
                continue
            if name == "six.moves" or name.startswith("six.moves."):
                six_record = self.loaded.get("six")
                importer = getattr(six_record[0], "_importer", None) if six_record else None
                if importer is not None and getattr(module, "__loader__", None) is importer and type(importer).__module__ == "six":
                    continue
            record = self.loaded.get(name)
            if record is None or record[0] is not module or getattr(module, "__loader__", None) is not record[1] or getattr(module, "__file__", None) != record[1].path or getattr(getattr(module, "__spec__", None), "origin", None) != record[1].path:
                raise VendoredSDKError("SDK_MODULE_CUSTODY_INVALID")


_IMPORT_LOCK = threading.RLock()
_OWNED_FINDER: _SDKFinder | None = None
_OWNED_MANIFEST: bytes | None = None


def import_vendored_sdk(*, package_root: Path, entries: list[dict[str, Any]]) -> tuple[ModuleType, ModuleType, type[Any]]:
    """Authenticate the closure before any SDK code, then preserve warm custody."""
    global _OWNED_FINDER, _OWNED_MANIFEST
    manifest = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("ascii")
    with _IMPORT_LOCK:
        if "BOTOCORE_EXPERIMENTAL__PLUGINS" in os.environ:
            raise VendoredSDKError("SDK_PLUGIN_OVERRIDE_FORBIDDEN")
        if _OWNED_FINDER is None:
            finder = _SDKFinder(package_root, {})
            if any(finder.owns(name) or name.split(".", 1)[0] in FORBIDDEN_OPTIONAL_ROOTS for name in sys.modules):
                raise VendoredSDKError("SDK_MODULE_PRELOADED_FORBIDDEN")
            snapshot = _read_snapshot(package_root, entries)
            finder.sources = snapshot
            sys.dont_write_bytecode = True
            sys.meta_path.insert(0, finder)
            _OWNED_FINDER, _OWNED_MANIFEST = finder, manifest
        else:
            finder = _OWNED_FINDER
            if finder.root != package_root or _OWNED_MANIFEST != manifest or not sys.meta_path or sys.meta_path[0] is not finder:
                raise VendoredSDKError("SDK_IMPORT_CUSTODY_INVALID")
        finder.check_custody()
        boto3 = importlib.import_module("boto3")
        botocore = importlib.import_module("botocore")
        config_module = importlib.import_module("botocore.config")
        plugin_module = importlib.import_module("botocore.plugin")
        if plugin_module.get_plugin_context() is not None:
            raise VendoredSDKError("SDK_PLUGIN_CONTEXT_FORBIDDEN")
        finder.check_custody()
        if boto3.__version__ != EXPECTED_BOTO3_VERSION or botocore.__version__ != EXPECTED_BOTOCORE_VERSION:
            raise VendoredSDKError("SDK_VERSION_UNREVIEWED")
        return boto3, botocore, config_module.Config
