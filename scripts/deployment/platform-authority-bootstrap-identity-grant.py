#!/usr/bin/env python3
"""Acquire one PKCE grant in memory and run the exact reviewed normal CLI."""
from __future__ import annotations

import argparse
import importlib
import importlib.abc
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import types


ROOT = Path(__file__).resolve().parents[2]
HELPER = Path("tooling/platform_authority_bootstrap_identity_grant.py")
ENTRYPOINT = Path("scripts/deployment/platform-authority-bootstrap-identity-grant.py")
OIDC_CLIENT = Path("tooling/platform_authority_bootstrap_oidc_client.py")
JWT_GRANT = Path("tooling/platform_authority_bootstrap_jwt_grant.py")


class PublicParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        self.exit(2, "GUG274_PKCE_BLOCKED:ARGUMENTS_INVALID\n")


def _install_source_only_importer() -> None:
    if any(name == "tooling" or name.startswith("tooling.") for name in sys.modules):
        raise ValueError("REPOSITORY_MODULE_PRELOADED")
    boundary = ROOT / "tooling/platform_authority_source_only_import.py"
    if boundary.is_symlink() or not boundary.is_file():
        raise ValueError
    namespace = {"__file__": str(boundary), "__name__": "_gug274_source_only_import_boundary"}
    exec(compile(boundary.read_bytes(), str(boundary), "exec"), namespace)
    namespace["install_repository_source_only_importer"](ROOT)


class _VerifiedSnapshotFinder(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """Resolve only the closed set of authenticated tooling source bytes."""

    def __init__(self, sources: dict[str, bytes]) -> None:
        self.sources = types.MappingProxyType(dict(sources))

    def find_spec(self, fullname, path=None, target=None):
        del path, target
        if fullname != "tooling" and not fullname.startswith("tooling."):
            return None
        relative = fullname.replace(".", "/")
        package, module = relative + "/__init__.py", relative + ".py"
        candidates = [name for name in (package, module) if name in self.sources]
        if len(candidates) != 1:
            raise ImportError("SNAPSHOT_MODULE_UNAVAILABLE")
        spec = importlib.util.spec_from_loader(fullname, self, is_package=candidates[0] == package)
        spec.loader_state = candidates[0]
        return spec

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        relative = module.__spec__.loader_state
        module.__file__ = str(ROOT / relative)
        exec(compile(self.sources[relative], module.__file__, "exec"), module.__dict__)


def _install_verified_snapshot_importer(source_snapshot: dict[str, bytes], expected_paths: set[str]) -> None:
    if (
        type(source_snapshot) is not dict or set(source_snapshot) != expected_paths
        or "tooling/__init__.py" not in source_snapshot
        or any(type(name) is not str or type(value) is not bytes for name, value in source_snapshot.items())
        or sum(map(len, source_snapshot.values())) > 4 * 1024 * 1024
    ):
        raise ValueError("SNAPSHOT_SOURCE_SET_INVALID")
    finder = _VerifiedSnapshotFinder(source_snapshot)
    # Bootstrap provenance imports may already be cached. Discard every tooling
    # module so helper dependencies cannot retain an earlier filesystem import.
    for name in tuple(sys.modules):
        if name == "tooling" or name.startswith("tooling."):
            del sys.modules[name]
    sys.dont_write_bytecode = True
    sys.meta_path.insert(0, finder)


def main() -> int:
    if (
        not sys.flags.isolated or not sys.flags.no_site or sys.pycache_prefix is not None
        or "PYTHONPATH" in os.environ or "PYTHONHOME" in os.environ
    ):
        print("GUG274_PKCE_BLOCKED:ISOLATED_PYTHON_REQUIRED", file=sys.stderr)
        return 2
    parser = PublicParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--binding", type=Path, required=True)
    parser.add_argument("--expected-binding-sha256", required=True)
    parser.add_argument("operation", choices=("plan", "approve", "apply"))
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    try:
        _install_source_only_importer()
        from tooling.platform_authority_bootstrap_artifact_package import (
            PROVENANCE_PATHS, SOURCE_PATHS, closed_provenance_environment,
            resolve_trusted_executable, verify_clean_source_commit,
        )
        if (
            HELPER not in PROVENANCE_PATHS or ENTRYPOINT not in PROVENANCE_PATHS
            or OIDC_CLIENT not in PROVENANCE_PATHS or JWT_GRANT not in SOURCE_PATHS
        ):
            raise ValueError
        def revalidate() -> None:
            verify_clean_source_commit(source_root=ROOT, source_commit=args.source_commit)
        revalidate()
        # Compile authenticated Git object bytes, not a second disk import that
        # could change between provenance verification and helper execution.
        git = resolve_trusted_executable(name="git", source_root=ROOT)
        environment = closed_provenance_environment(source_root=ROOT, executables=(git,), include_home=False)
        environment.update({"GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0", "GIT_PAGER": "cat"})
        source_snapshot = {}
        for path in (*SOURCE_PATHS, *PROVENANCE_PATHS):
            if path.suffix == ".py":
                source_snapshot[path.as_posix()] = subprocess.run(
                    [str(git), "--no-replace-objects", "-c", "core.fsmonitor=false", "show", f"{args.source_commit}:{path.as_posix()}"],
                    cwd=ROOT, env=environment, check=True, capture_output=True, timeout=30,
                ).stdout
        expected_paths = {path.as_posix() for path in (*SOURCE_PATHS, *PROVENANCE_PATHS) if path.suffix == ".py"}
        _install_verified_snapshot_importer(source_snapshot, expected_paths)
        helper = importlib.import_module("tooling.platform_authority_bootstrap_identity_grant")
        binding = helper.read_binding(args.binding, args.expected_binding_sha256)
        result = helper.launch(source_root=ROOT, source_snapshot=source_snapshot,
                               binding=binding, operation=args.operation,
                               arguments=args.arguments, revalidate_source=revalidate)
    except BaseException as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            print("GUG274_PKCE_BLOCKED:OPERATION_INTERRUPTED", file=sys.stderr)
        else:
            # Do not expose arbitrary exception/provider strings or input values.
            print("GUG274_PKCE_BLOCKED:OPERATION_REJECTED_OR_UNCERTAIN", file=sys.stderr)
        return 2
    print("GUG274_PKCE_COMPLETE:NORMAL_CLI_SUCCEEDED")
    return result


if __name__ == "__main__":
    raise SystemExit(main())
