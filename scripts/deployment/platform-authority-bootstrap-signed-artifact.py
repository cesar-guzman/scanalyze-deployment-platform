#!/usr/bin/env python3
"""Read back one AWS Signer job and emit private GUG-274 bindings."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys


ISOLATED_IMPORT_PATHS = tuple(sys.path)
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
        "GUG274_SIGNED_ARTIFACT_BLOCKED:ISOLATED_PYTHON_REQUIRED",
        file=sys.stderr,
    )
    raise SystemExit(2)
try:
    _install_source_only_repository_imports(ROOT)
except Exception:
    print(
        "GUG274_SIGNED_ARTIFACT_BLOCKED:REPOSITORY_SOURCE_IMPORT_BOUNDARY_INVALID",
        file=sys.stderr,
    )
    raise SystemExit(2) from None

from tooling.platform_authority_bootstrap_artifact_package import (  # noqa: E402
    BootstrapArtifactPackageError,
    build_bootstrap_artifact_package,
    canonical_json,
    import_reviewed_aws_sdk,
    sdk_runtime_root_from_environment,
)
from tooling.platform_authority_bootstrap_signed_artifact import (  # noqa: E402
    EXPECTED_VERIFIER_PROFILE,
    REGION,
    BootstrapSignedArtifactError,
    build_signed_artifact_receipt_from_aws,
    load_signing_trust_root_contract,
    verify_reviewed_source_release,
    write_signed_artifact_receipt,
)


UNSAFE_SDK_ENV_NAMES = frozenset(
    {
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_SECURITY_TOKEN",
        "AWS_PROFILE",
        "AWS_DEFAULT_PROFILE",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "AWS_ROLE_ARN",
        "AWS_ROLE_SESSION_NAME",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        "AWS_EC2_METADATA_SERVICE_ENDPOINT",
        "AWS_ENDPOINT_URL",
        "AWS_ENDPOINT_URL_STS",
        "AWS_ENDPOINT_URL_SIGNER",
        "AWS_ENDPOINT_URL_S3",
        "AWS_CA_BUNDLE",
        "AWS_DATA_PATH",
        "AWS_CONFIG_FILE",
        "AWS_SHARED_CREDENTIALS_FILE",
        "BOTO_CONFIG",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "GH_HOST",
        "GH_CONFIG_DIR",
        "GITHUB_API_URL",
    }
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Rebuild the exact GUG-274 package, read one completed Signer job "
            "and immutable S3 versions, then emit the closed CFN handoff"
        )
    )
    parser.add_argument(
        "--profile", required=True, choices=(EXPECTED_VERIFIER_PROFILE,)
    )
    parser.add_argument("--region", default=REGION, choices=(REGION,))
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--expected-boto3-version", required=True)
    parser.add_argument("--expected-botocore-version", required=True)
    parser.add_argument("--job-id", required=True)
    parser.add_argument("--output-receipt", required=True, type=Path)
    return parser.parse_args()


def _require_closed_sdk_environment() -> None:
    if any(name in os.environ for name in UNSAFE_SDK_ENV_NAMES) or any(
        name.startswith("AWS_ENDPOINT_URL_") for name in os.environ
    ):
        raise BootstrapSignedArtifactError("SDK_ENVIRONMENT_OVERRIDE_FORBIDDEN")


def main() -> int:
    args = parse_args()
    try:
        _require_closed_sdk_environment()
        load_signing_trust_root_contract(
            source_root=ROOT, require_configured=True
        )
        build_bootstrap_artifact_package(
            source_root=ROOT,
            source_commit=args.source_commit,
            expected_boto3_version=args.expected_boto3_version,
            expected_botocore_version=args.expected_botocore_version,
        )
        verify_reviewed_source_release(
            source_root=ROOT, source_commit=args.source_commit
        )
        sys.path[:] = list(ISOLATED_IMPORT_PATHS)
        boto3, _, Config = import_reviewed_aws_sdk(
            source_root=ROOT,
            isolated_import_paths=ISOLATED_IMPORT_PATHS,
            sdk_runtime_root=sdk_runtime_root_from_environment(),
        )

        session = boto3.Session(profile_name=args.profile, region_name=args.region)
        config = Config(
            connect_timeout=3,
            read_timeout=8,
            retries={"total_max_attempts": 1, "mode": "standard"},
            ignore_configured_endpoint_urls=True,
        )
        receipt = build_signed_artifact_receipt_from_aws(
            source_root=ROOT,
            source_commit=args.source_commit,
            expected_boto3_version=args.expected_boto3_version,
            expected_botocore_version=args.expected_botocore_version,
            profile_name=args.profile,
            job_id=args.job_id,
            sts_client=session.client("sts", config=config, verify=True),
            signer_client=session.client("signer", config=config, verify=True),
            s3_client=session.client("s3", config=config, verify=True),
        )
        write_signed_artifact_receipt(
            receipt=receipt,
            output_path=args.output_receipt,
            source_root=ROOT,
        )
    except (
        ImportError,
        OSError,
        BootstrapArtifactPackageError,
        BootstrapSignedArtifactError,
    ) as exc:
        print(f"GUG274_SIGNED_ARTIFACT_BLOCKED:{exc}", file=sys.stderr)
        return 2
    print(
        canonical_json(
            {
                "evidence_status": receipt["evidence_status"],
                "production_status": receipt["production_status"],
                "receipt_digest": receipt["receipt_digest"],
                "receipt_name": args.output_receipt.name,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
