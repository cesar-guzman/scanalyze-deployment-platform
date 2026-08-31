#!/usr/bin/env python3
"""Read one completed Signer job and emit private GUG-376 bindings."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import sys
from typing import Any, Mapping
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tooling.platform_authority_plan_permission_repair_package import (  # noqa: E402
    PlanPermissionRepairPackageError,
    canonical_json,
)
from tooling.platform_authority_plan_permission_repair_broker_seed import (  # noqa: E402
    BrokerSeedError,
    load_private_input,
)
from tooling.platform_authority_plan_permission_repair_signed_artifact import (  # noqa: E402
    EXPECTED_VERIFIER_PROFILE,
    PlanPermissionRepairSignedArtifactError,
    build_signed_artifact_receipt_from_aws,
    write_signed_artifact_receipt,
)


_EXPECTED_ACCOUNT_ID = "042360977644"
_EXPECTED_REGION = "us-east-1"
_EXPECTED_SSO_ROLE = "ScanalyzeGug376ArtifactBootstrap"
_PROFILE_ALLOWED = frozenset(
    {
        "cli_pager",
        "output",
        "region",
        "sso_account_id",
        "sso_region",
        "sso_role_name",
        "sso_session",
        "sso_start_url",
    }
)
_SSO_SESSION_ALLOWED = frozenset(
    {"sso_region", "sso_registration_scopes", "sso_start_url"}
)
_AMBIENT_FORBIDDEN = frozenset(
    {
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_SECURITY_TOKEN",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_ROLE_ARN",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        "AWS_SHARED_CREDENTIALS_FILE",
        "AWS_CONFIG_FILE",
        "AWS_CA_BUNDLE",
        "BOTO_CONFIG",
        "REQUESTS_CA_BUNDLE",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    }
)
_ENDPOINT_HOSTS = {
    "sts": "sts.us-east-1.amazonaws.com",
    "signer": "signer.us-east-1.amazonaws.com",
    "signer-data": "data-signer.us-east-1.amazonaws.com",
    "acm": "acm.us-east-1.amazonaws.com",
    "s3": "s3.us-east-1.amazonaws.com",
}


def _fail(code: str) -> None:
    raise PlanPermissionRepairSignedArtifactError(code)


def _validate_environment(environment: Mapping[str, str]) -> None:
    if any(environment.get(name) for name in _AMBIENT_FORBIDDEN) or any(
        name.startswith("AWS_ENDPOINT_URL") and value
        for name, value in environment.items()
    ):
        _fail("AWS_ENVIRONMENT_UNSAFE")
    for name in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE"):
        if environment.get(name) not in (None, "", EXPECTED_VERIFIER_PROFILE):
            _fail("AWS_PROFILE_DRIFT")
    for name in ("AWS_REGION", "AWS_DEFAULT_REGION"):
        if environment.get(name) not in (None, "", _EXPECTED_REGION):
            _fail("AWS_REGION_DRIFT")


def _validate_sso_start_url(value: object) -> None:
    parsed = urlsplit(value) if isinstance(value, str) else None
    if (
        parsed is None
        or parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.query
        or parsed.fragment
        or re.fullmatch(
            r"[a-z0-9-]+\.awsapps\.com(?:\.cn)?",
            str(parsed.hostname or ""),
        )
        is None
    ):
        _fail("AWS_PROFILE_CONFIGURATION_INVALID")


def _validate_session(session: Any, *, profile: str, region: str) -> None:
    if (
        profile == "default"
        or profile != EXPECTED_VERIFIER_PROFILE
        or region != _EXPECTED_REGION
        or getattr(session, "profile_name", None) != profile
        or getattr(session, "region_name", None) != region
    ):
        _fail("AWS_SESSION_DRIFT")
    sdk_session = getattr(session, "_session", None)
    full_config = getattr(sdk_session, "full_config", None)
    profiles = (
        full_config.get("profiles")
        if isinstance(full_config, Mapping)
        else None
    )
    document = profiles.get(profile) if isinstance(profiles, Mapping) else None
    session_name = (
        document.get("sso_session")
        if isinstance(document, Mapping)
        else None
    )
    sessions = (
        full_config.get("sso_sessions")
        if isinstance(full_config, Mapping)
        else None
    )
    selected = (
        sessions.get(session_name)
        if isinstance(session_name, str) and isinstance(sessions, Mapping)
        else None
    )
    if (
        not isinstance(document, Mapping)
        or not set(document).issubset(_PROFILE_ALLOWED)
        or document.get("sso_account_id") != _EXPECTED_ACCOUNT_ID
        or document.get("sso_role_name") != _EXPECTED_SSO_ROLE
        or document.get("region") != region
    ):
        _fail("AWS_PROFILE_CONFIGURATION_INVALID")
    if session_name is None:
        if (
            "sso_session" in document
            or document.get("sso_region") != region
            or "sso_start_url" not in document
        ):
            _fail("AWS_PROFILE_CONFIGURATION_INVALID")
        _validate_sso_start_url(document.get("sso_start_url"))
    elif (
        not isinstance(session_name, str)
        or not session_name
        or "sso_region" in document
        or "sso_start_url" in document
        or not isinstance(selected, Mapping)
        or not set(selected).issubset(_SSO_SESSION_ALLOWED)
        or selected.get("sso_region") != region
    ):
        _fail("AWS_PROFILE_CONFIGURATION_INVALID")
    else:
        _validate_sso_start_url(selected.get("sso_start_url"))
    try:
        credentials = session.get_credentials()
    except Exception as exc:
        raise PlanPermissionRepairSignedArtifactError(
            "AWS_SSO_CREDENTIALS_UNAVAILABLE"
        ) from exc
    if credentials is None or getattr(credentials, "method", None) != "sso":
        _fail("AWS_CREDENTIAL_SOURCE_INVALID")


def _exact_client(session: Any, service: str, region: str, config: Any) -> Any:
    try:
        client = session.client(service, region_name=region, config=config)
        endpoint = urlsplit(str(client.meta.endpoint_url))
    except Exception as exc:
        raise PlanPermissionRepairSignedArtifactError(
            "AWS_CLIENT_INVALID"
        ) from exc
    if (
        service not in _ENDPOINT_HOSTS
        or endpoint.scheme != "https"
        or endpoint.hostname != _ENDPOINT_HOSTS[service]
        or endpoint.username is not None
        or endpoint.password is not None
        or endpoint.port is not None
        or endpoint.path not in ("", "/")
        or endpoint.query
        or endpoint.fragment
    ):
        _fail("AWS_ENDPOINT_INVALID")
    return client


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
    parser.add_argument("--private-root", required=True, type=Path)
    parser.add_argument("--bootstrap-intent-name", required=True)
    parser.add_argument("--foundation-publish-binding-name", required=True)
    parser.add_argument("--output-receipt", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        import boto3
        import botocore
        from botocore.config import Config
    except ImportError:
        print(
            "GUG376_SIGNED_ARTIFACT_BLOCKED:DEPENDENCY_UNAVAILABLE",
            file=sys.stderr,
        )
        return 2
    try:
        if (
            getattr(boto3, "__version__", None)
            != args.expected_boto3_version
            or getattr(botocore, "__version__", None)
            != args.expected_botocore_version
        ):
            _fail("AWS_SDK_VERSION_MISMATCH")
        _validate_environment(os.environ)
        session = boto3.Session(
            profile_name=args.profile,
            region_name=args.region,
        )
        _validate_session(
            session,
            profile=args.profile,
            region=args.region,
        )
        config = Config(
            connect_timeout=3,
            read_timeout=8,
            retries={"total_max_attempts": 1, "mode": "standard"},
            s3={"us_east_1_regional_endpoint": "regional"},
            ignore_configured_endpoint_urls=True,
        )
        clients = {
            "sts_client": _exact_client(
                session, "sts", args.region, config
            ),
            "signer_client": _exact_client(
                session, "signer", args.region, config
            ),
            "signer_data_client": _exact_client(
                session, "signer-data", args.region, config
            ),
            "acm_client": _exact_client(
                session, "acm", args.region, config
            ),
            "s3_client": _exact_client(
                session, "s3", args.region, config
            ),
        }
    except PlanPermissionRepairSignedArtifactError as exc:
        print(f"GUG376_SIGNED_ARTIFACT_BLOCKED:{exc}", file=sys.stderr)
        return 2
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
        private_root = args.private_root.resolve(strict=True)
        try:
            private_root.relative_to(ROOT.resolve(strict=True))
        except ValueError:
            pass
        else:
            raise PlanPermissionRepairSignedArtifactError(
                "PRIVATE_ROOT_INSIDE_SOURCE"
            )
        bootstrap_intent = load_private_input(
            private_root=private_root,
            name=args.bootstrap_intent_name,
        )
        foundation_publish_binding = load_private_input(
            private_root=private_root,
            name=args.foundation_publish_binding_name,
        )
        receipt = build_signed_artifact_receipt_from_aws(
            source_root=ROOT,
            source_commit=args.source_commit,
            expected_boto3_version=args.expected_boto3_version,
            expected_botocore_version=args.expected_botocore_version,
            profile_name=args.profile,
            job_id=args.job_id,
            expected_profile_version_arn=str(
                foundation_publish_binding.get(
                    "signing_profile_version_arn", ""
                )
            ),
            bootstrap_intent=bootstrap_intent,
            foundation_publish_binding=foundation_publish_binding,
            **clients,
        )
        write_signed_artifact_receipt(
            receipt=receipt,
            output_path=args.output_receipt,
            source_root=ROOT,
            private_root=private_root,
            bootstrap_intent=bootstrap_intent,
            foundation_publish_binding=foundation_publish_binding,
        )
    except (
        OSError,
        BrokerSeedError,
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
        elif isinstance(exc, BrokerSeedError):
            code = exc.code
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
