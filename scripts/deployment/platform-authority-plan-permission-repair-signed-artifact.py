#!/usr/bin/env python3
"""Read one completed Signer job and emit private GUG-376 bindings."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tooling.platform_authority_plan_permission_repair_package import (  # noqa: E402
    PlanPermissionRepairPackageError,
    canonical_json,
)
from tooling.platform_authority_plan_permission_repair_signed_artifact import (  # noqa: E402
    EXPECTED_VERIFIER_PROFILE,
    PlanPermissionRepairSignedArtifactError,
    build_signed_artifact_receipt_from_aws,
    write_signed_artifact_receipt,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Rebuild exact protected main, read one completed GUG-376 "
            "Signer job and immutable S3 versions, then emit the reviewed "
            "CloudFormation artifact tuple; this command performs no AWS "
            "mutation"
        )
    )
    parser.add_argument(
        "--profile",
        required=True,
        choices=(EXPECTED_VERIFIER_PROFILE,),
    )
    parser.add_argument(
        "--region",
        default="us-east-1",
        choices=("us-east-1",),
    )
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
    except ImportError:
        print(
            "GUG376_SIGNED_ARTIFACT_BLOCKED:DEPENDENCY_UNAVAILABLE",
            file=sys.stderr,
        )
        return 2
    try:
        session = boto3.Session(
            profile_name=args.profile,
            region_name=args.region,
        )
        config = Config(
            connect_timeout=3,
            read_timeout=8,
            retries={"total_max_attempts": 1, "mode": "standard"},
        )
        clients = {
            "sts_client": session.client("sts", config=config),
            "signer_client": session.client("signer", config=config),
            "signer_data_client": session.client(
                "signer-data", config=config
            ),
            "acm_client": session.client("acm", config=config),
            "s3_client": session.client("s3", config=config),
        }
    except Exception:
        # botocore profile/region/client-construction exceptions may contain
        # workstation paths or configuration values.  Keep the public error
        # stable and sanitized before any provider call is attempted.
        print(
            "GUG376_SIGNED_ARTIFACT_BLOCKED:AWS_CLIENT_SETUP_FAILED",
            file=sys.stderr,
        )
        return 2
    try:
        receipt = build_signed_artifact_receipt_from_aws(
            source_root=ROOT,
            source_commit=args.source_commit,
            expected_boto3_version=args.expected_boto3_version,
            expected_botocore_version=args.expected_botocore_version,
            profile_name=args.profile,
            job_id=args.job_id,
            expected_profile_version_arn=(
                args.expected_profile_version_arn
            ),
            **clients,
        )
        write_signed_artifact_receipt(
            receipt=receipt,
            output_path=args.output_receipt,
            source_root=ROOT,
        )
    except (
        OSError,
        PlanPermissionRepairPackageError,
        PlanPermissionRepairSignedArtifactError,
    ) as exc:
        if isinstance(
            exc,
            (
                PlanPermissionRepairPackageError,
                PlanPermissionRepairSignedArtifactError,
            ),
        ):
            code = str(exc)
        else:
            code = "LOCAL_IO_FAILED"
        print(f"GUG376_SIGNED_ARTIFACT_BLOCKED:{code}", file=sys.stderr)
        return 2
    print(
        canonical_json(
            {
                "source_commit": receipt["source_commit"],
                "source_bundle_digest": receipt[
                    "source_bundle_digest"
                ],
                "evidence_status": receipt["evidence_status"],
                "production_status": receipt["production_status"],
                "receipt_name": args.output_receipt.name,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
