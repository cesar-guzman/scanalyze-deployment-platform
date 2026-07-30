#!/usr/bin/env python3
"""Build the deterministic GUG-221 Lambda ZIP outside the repository."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tooling.platform_authority_lambda_audit_repair_package import (  # noqa: E402
    RepairPackageError,
    canonical_json,
    write_repair_package,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build the closed, deterministic GUG-221 Lambda package"
    )
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--expected-boto3-version", required=True)
    parser.add_argument("--expected-botocore-version", required=True)
    parser.add_argument(
        "--output-directory",
        required=True,
        type=Path,
        help="A new directory outside the repository; existing paths are rejected",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        archive, manifest, evidence = write_repair_package(
            source_root=ROOT,
            source_commit=args.source_commit,
            expected_boto3_version=args.expected_boto3_version,
            expected_botocore_version=args.expected_botocore_version,
            output_directory=args.output_directory,
        )
    except RepairPackageError as exc:
        print(f"GUG221_PACKAGE_BLOCKED:{exc}", file=sys.stderr)
        return 2
    print(
        canonical_json(
            {
                "archive_name": archive.name,
                "manifest_name": manifest.name,
                "archive_sha256": evidence["archive_sha256"],
                "lambda_code_sha256": evidence["lambda_code_sha256"],
                "production_status": evidence["production_status"],
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
