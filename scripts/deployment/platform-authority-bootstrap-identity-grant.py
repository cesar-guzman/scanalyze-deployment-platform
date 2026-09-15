#!/usr/bin/env python3
"""Acquire one PKCE grant in memory and run the exact reviewed normal CLI."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys
import types


ROOT = Path(__file__).resolve().parents[2]
HELPER = Path("tooling/platform_authority_bootstrap_identity_grant.py")
ENTRYPOINT = Path("scripts/deployment/platform-authority-bootstrap-identity-grant.py")


class PublicParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        self.exit(2, "GUG274_PKCE_BLOCKED:ARGUMENTS_INVALID\n")


def _install_source_only_importer() -> None:
    boundary = ROOT / "tooling/platform_authority_source_only_import.py"
    if boundary.is_symlink() or not boundary.is_file():
        raise ValueError
    namespace = {"__file__": str(boundary), "__name__": "_gug274_source_only_import_boundary"}
    exec(compile(boundary.read_bytes(), str(boundary), "exec"), namespace)
    namespace["install_repository_source_only_importer"](ROOT)


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
        if HELPER not in PROVENANCE_PATHS or ENTRYPOINT not in PROVENANCE_PATHS:
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
        helper = types.ModuleType("_gug274_verified_identity_grant")
        helper.__file__ = str(ROOT / HELPER)
        sys.modules[helper.__name__] = helper
        exec(compile(source_snapshot[HELPER.as_posix()], helper.__file__, "exec"), helper.__dict__)
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
