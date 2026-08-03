"""Source-only import boundary for the three GUG-274 operator entry points.

This file is loaded explicitly as UTF-8 source by each entry point before the
repository is added to Python's import machinery.  The finder handles only the
``tooling`` package and compiles exact ``.py`` bytes without consulting or
emitting bytecode caches.
"""

from __future__ import annotations

import importlib.abc
import importlib.machinery
import importlib.util
from pathlib import Path
import stat
import sys
from types import CodeType, ModuleType


class RepositorySourceImportError(ValueError):
    """The closed repository source import boundary is unavailable."""


class _RepositorySourceOnlyLoader(importlib.machinery.SourceFileLoader):
    """Compile source directly and never call the bytecode-aware base path."""

    def get_code(self, fullname: str) -> CodeType:
        source_path = self.get_filename(fullname)
        source_bytes = self.get_data(source_path)
        return self.source_to_code(source_bytes, source_path)


class _RepositorySourceOnlyFinder(importlib.abc.MetaPathFinder):
    def __init__(self, source_root: Path) -> None:
        self._source_root = source_root

    def find_spec(
        self,
        fullname: str,
        path: object = None,
        target: ModuleType | None = None,
    ) -> importlib.machinery.ModuleSpec | None:
        del path, target
        if fullname != "tooling" and not fullname.startswith("tooling."):
            return None
        candidate_root = self._source_root.joinpath(*fullname.split("."))
        package_source = candidate_root / "__init__.py"
        module_source = candidate_root.with_suffix(".py")
        if package_source.is_file() and not package_source.is_symlink():
            source_path = package_source
            package_locations = [str(candidate_root)]
        elif module_source.is_file() and not module_source.is_symlink():
            source_path = module_source
            package_locations = None
        else:
            raise RepositorySourceImportError("REPOSITORY_SOURCE_MODULE_UNAVAILABLE")
        try:
            resolved = source_path.resolve(strict=True)
            resolved.relative_to(self._source_root)
            source_metadata = resolved.lstat()
        except (OSError, ValueError):
            raise RepositorySourceImportError(
                "REPOSITORY_SOURCE_MODULE_UNAVAILABLE"
            ) from None
        if source_path != resolved or not stat.S_ISREG(source_metadata.st_mode):
            raise RepositorySourceImportError("REPOSITORY_SOURCE_MODULE_UNSAFE")
        loader = _RepositorySourceOnlyLoader(fullname, str(resolved))
        return importlib.util.spec_from_file_location(
            fullname,
            resolved,
            loader=loader,
            submodule_search_locations=package_locations,
        )


def install_repository_source_only_importer(source_root: Path) -> None:
    """Install the closed finder before importing any repository module."""

    if sys.pycache_prefix is not None:
        raise RepositorySourceImportError("PYTHON_BYTECODE_PREFIX_FORBIDDEN")
    tooling_candidate = source_root / "tooling"
    try:
        root = source_root.resolve(strict=True)
        tooling_root = tooling_candidate.resolve(strict=True)
        tooling_root.relative_to(root)
    except (OSError, ValueError):
        raise RepositorySourceImportError("REPOSITORY_SOURCE_ROOT_INVALID") from None
    if (
        source_root != root
        or tooling_candidate.is_symlink()
        or not tooling_root.is_dir()
    ):
        raise RepositorySourceImportError("REPOSITORY_SOURCE_ROOT_INVALID")
    sys.dont_write_bytecode = True
    sys.meta_path.insert(0, _RepositorySourceOnlyFinder(root))
