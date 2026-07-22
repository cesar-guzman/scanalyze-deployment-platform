#!/usr/bin/env python3
"""Read back a completed AWS Signer job and emit private GUG-221 bindings."""

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
)
from tooling.platform_authority_lambda_audit_repair_signed_artifact import (  # noqa: E402
    EXPECTED_VERIFIER_PROFILE,
    SignedArtifactError,
    build_signed_artifact_receipt_from_aws,
    write_signed_artifact_receipt,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Rebuild a clean reviewed GUG-221 package, read one Signer job and "
            "its exact S3 versions, then bind the signed ZIP to CFN parameters"
        )
    )
    parser.add_argument("--profile", required=True, choices=(EXPECTED_VERIFIER_PROFILE,))
    parser.add_argument("--region", default="us-east-1", choices=("us-east-1",))
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--expected-boto3-version", required=True)
    parser.add_argument("--expected-botocore-version", required=True)
    parser.add_argument("--job-id", required=True)
    parser.add_argument("--expected-profile-version-arn", required=True)
    parser.add_argument("--output-receipt", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        import boto3
        from botocore.config import Config

        session = boto3.Session(profile_name=args.profile, region_name=args.region)
        config = Config(
            connect_timeout=3,
            read_timeout=8,
            retries={"total_max_attempts": 1, "mode": "standard"},
        )
        receipt = build_signed_artifact_receipt_from_aws(
            source_root=ROOT,
            source_commit=args.source_commit,
            expected_boto3_version=args.expected_boto3_version,
            expected_botocore_version=args.expected_botocore_version,
            profile_name=args.profile,
            job_id=args.job_id,
            sts_client=session.client("sts", config=config),
            signer_client=session.client("signer", config=config),
            s3_client=session.client("s3", config=config),
            expected_profile_version_arn=args.expected_profile_version_arn,
        )
        write_signed_artifact_receipt(
            receipt=receipt,
            output_path=args.output_receipt,
            source_root=ROOT,
        )
    except (ImportError, OSError, RepairPackageError, SignedArtifactError) as exc:
        print(f"GUG221_SIGNED_ARTIFACT_BLOCKED:{exc}", file=sys.stderr)
        return 2
    print(
        canonical_json(
            {
                "evidence_status": receipt["evidence_status"],
                "production_status": receipt["production_status"],
                "receipt_name": args.output_receipt.name,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
