#!/usr/bin/env python3
"""Build the clean-commit deterministic GUG-215 broker package offline."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tooling.platform_authority_change_set_retirement_package import (  # noqa: E402
    RetirementPackageError,
    canonical_json,
    write_retirement_package,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Build the source-closed deterministic GUG-215 broker package; "
            "no AWS calls or deployment"
        )
    )
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--broker-runtime-version-arn", required=True)
    parser.add_argument("--broker-version-binding-sha256", required=True)
    parser.add_argument(
        "--output-directory",
        type=Path,
        required=True,
        help="New owner-only directory outside the repository",
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        archive, manifest, evidence = write_retirement_package(
            source_root=ROOT,
            source_commit=args.source_commit,
            broker_runtime_version_arn=args.broker_runtime_version_arn,
            broker_version_binding_sha256=args.broker_version_binding_sha256,
            output_directory=args.output_directory,
        )
    except RetirementPackageError as exc:
        print(f"GUG215_PACKAGE_BLOCKED:{exc}", file=sys.stderr)
        return 2
    print(
        canonical_json(
            {
                "status": "PACKAGE_BUILT_REVIEW_REQUIRED",
                "archive_name": archive.name,
                "manifest_name": manifest.name,
                "manifest_digest": evidence["manifest_digest"],
                "lambda_code_sha256": evidence["lambda_code_sha256"],
                "authorization_mode": evidence["authorization_mode"],
                "two_human_status": evidence["two_human_status"],
                "independent_approval_present": False,
                "deployment_authorized": False,
                "aws_calls_performed": False,
                "aws_mutations": "NONE",
                "production_status": evidence["production_status"],
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
