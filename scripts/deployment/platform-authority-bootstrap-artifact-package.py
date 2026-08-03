#!/usr/bin/env python3
"""Build the reviewed GUG-274 unsigned Lambda package outside the repo."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]


def _install_source_only_repository_imports(source_root: Path) -> None:
    boundary = source_root / "tooling/platform_authority_source_only_import.py"
    if boundary.is_symlink() or not boundary.is_file():
        raise ValueError("REPOSITORY_SOURCE_IMPORT_BOUNDARY_INVALID")
    namespace = {
        "__file__": str(boundary),
        "__name__": "_gug274_source_only_import_boundary",
    }
    exec(compile(boundary.read_bytes(), str(boundary), "exec"), namespace)
    installer = namespace.get("install_repository_source_only_importer")
    if not callable(installer):
        raise ValueError("REPOSITORY_SOURCE_IMPORT_BOUNDARY_INVALID")
    installer(source_root)


if (
    not sys.flags.isolated
    or not sys.flags.no_site
    or sys.pycache_prefix is not None
    or "PYTHONPATH" in os.environ
    or "PYTHONHOME" in os.environ
):
    print(
        "GUG274_PACKAGE_BLOCKED:ISOLATED_PYTHON_REQUIRED",
        file=sys.stderr,
    )
    raise SystemExit(2)
try:
    _install_source_only_repository_imports(ROOT)
except Exception:
    print(
        "GUG274_PACKAGE_BLOCKED:REPOSITORY_SOURCE_IMPORT_BOUNDARY_INVALID",
        file=sys.stderr,
    )
    raise SystemExit(2) from None

from tooling.platform_authority_bootstrap_artifact_package import (  # noqa: E402
    BootstrapArtifactPackageError,
    canonical_json,
    write_bootstrap_artifact_package,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build the clean-commit, deterministic GUG-274 unsigned Lambda package"
        )
    )
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--expected-boto3-version", required=True)
    parser.add_argument("--expected-botocore-version", required=True)
    parser.add_argument(
        "--output-directory",
        type=Path,
        required=True,
        help="A new directory outside the repository; existing paths are rejected",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        archive, manifest, evidence = write_bootstrap_artifact_package(
            source_root=ROOT,
            source_commit=args.source_commit,
            expected_boto3_version=args.expected_boto3_version,
            expected_botocore_version=args.expected_botocore_version,
            output_directory=args.output_directory,
        )
    except BootstrapArtifactPackageError as exc:
        print(f"GUG274_PACKAGE_BLOCKED:{exc}", file=sys.stderr)
        return 2
    print(
        canonical_json(
            {
                "archive_name": archive.name,
                "manifest_name": manifest.name,
                "archive_sha256": evidence["archive_sha256"],
                "unsigned_archive_code_sha256": evidence[
                    "unsigned_archive_code_sha256"
                ],
                "deployable": False,
                "source_commit": evidence["source_commit"],
                "production_status": evidence["production_status"],
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
