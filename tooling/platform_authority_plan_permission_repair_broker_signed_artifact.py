"""Connected read-only attestation for the GUG-376 route-broker package.

The deterministic unsigned ZIP is rebuilt from an exact clean ``main`` Git
object.  AWS is then used only to read the caller identity, both exact S3
object versions, and the completed Signer job/profile.  The resulting handoff
is consumed by the offline broker-seed materializer; this module never signs,
uploads, deploys, or mutates AWS state.
"""

from __future__ import annotations

import base64
from io import BytesIO
from datetime import datetime, timezone
from hashlib import sha256
import os
from pathlib import Path
import re
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit
from zipfile import BadZipFile, ZipFile

from tooling import platform_authority_plan_permission_repair_broker_seed as seed
from tooling.platform_authority_plan_permission_repair_artifact_bootstrap import (
    ArtifactBootstrapError,
    FOUNDATION_STORAGE_BINDING_TYPE,
    validate_foundation_publish_binding,
)


HANDOFF_TYPE = (
    "scanalyze.platform_authority."
    "plan_permission_repair_broker_signed_artifact_handoff.v1"
)
EXPECTED_PROFILE = "042360977644_ScanalyzeGug376ArtifactBootstrap"
EXPECTED_SSO_ROLE = "ScanalyzeGug376ArtifactBootstrap"
LEGACY_EXPECTED_PROFILE = "042360977644_AWSReadOnlyAccess"
LEGACY_EXPECTED_SSO_ROLE = "AWSReadOnlyAccess"
EXPECTED_ACCOUNT_ID = seed.AUTHORITY_ACCOUNT_ID
EXPECTED_REGION = seed.REGION
SIGNING_PLATFORM_ID = "AWSLambda-SHA384-ECDSA"
MAX_PACKAGE_BYTES = 10 * 1024 * 1024
DEFAULT_OUTPUT_NAME = "broker-signed-artifact-handoff.json"

_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SDK_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9._~+/=-]{1,1024}$")
_JOB_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}$"
)
_CALLER_RE = re.compile(
    r"^arn:aws:sts::042360977644:assumed-role/"
    r"AWSReservedSSO_ScanalyzeGug376ArtifactBootstrap_[0-9A-Fa-f]{16}/"
    r"[A-Za-z0-9+=,.@_-]{1,64}$"
)
_LEGACY_CALLER_RE = re.compile(
    r"^arn:aws:sts::042360977644:assumed-role/"
    r"AWSReservedSSO_AWSReadOnlyAccess_[0-9A-Fa-f]{16}/"
    r"[A-Za-z0-9+=,.@_-]{1,64}$"
)
_PROFILE_ARN_RE = re.compile(
    r"^arn:aws[a-z-]*:signer:us-east-1:042360977644:/signing-profiles/"
    r"(?P<name>[A-Za-z0-9_]{2,64})/(?P<version>[A-Za-z0-9]{10})$"
)
_CERTIFICATE_ARN_RE = re.compile(
    r"^arn:aws:acm:us-east-1:042360977644:certificate/"
    r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$"
)
_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
_UNSIGNED_KEY_RE = re.compile(
    r"^scanalyze/platform-authority/gug-376/plan-policy-repair/broker/unsigned/"
    r"(?P<commit>[0-9a-f]{40})/route-broker-unsigned\.zip$"
)
_SIGNED_KEY_RE = re.compile(
    r"^scanalyze/platform-authority/gug-376/plan-policy-repair/broker/signed/"
    r"(?P<commit>[0-9a-f]{40})/"
    r"(?P<job>[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})\.zip$"
)
_OUTPUT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,126}\.json$")
_ERROR_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,95}$")
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


class BrokerSignedArtifactError(RuntimeError):
    """Stable sanitized failure from the read-only attestation boundary."""

    def __init__(self, code: str) -> None:
        self.code = code if _ERROR_RE.fullmatch(code) else "BROKER_ATTESTATION_BLOCKED"
        super().__init__(self.code)


def _fail(code: str) -> None:
    raise BrokerSignedArtifactError(code)


def _call(method: Any, /, **kwargs: Any) -> Mapping[str, Any]:
    try:
        response = method(**kwargs)
    except Exception as exc:  # botocore is intentionally an optional dependency
        raise BrokerSignedArtifactError("AWS_READBACK_FAILED") from exc
    if not isinstance(response, Mapping):
        _fail("AWS_READBACK_INVALID")
    return response


def _parsed_timestamp(value: object, code: str) -> datetime:
    if isinstance(value, datetime) and value.tzinfo is not None:
        parsed = value.astimezone(timezone.utc)
    elif isinstance(value, str) and value.endswith("Z"):
        try:
            parsed = datetime.fromisoformat(value[:-1] + "+00:00")
        except ValueError:
            _fail(code)
    else:
        _fail(code)
    return parsed.astimezone(timezone.utc)


def _timestamp(value: object, code: str) -> str:
    parsed = _parsed_timestamp(value, code)
    return (
        parsed.replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _code_sha256(payload: bytes) -> str:
    return base64.b64encode(sha256(payload).digest()).decode("ascii")


def _certificate_revocation_hash(
    *, certificate_pem: object, certificate_chain_pem: object
) -> str:
    if not isinstance(certificate_pem, str) or not isinstance(
        certificate_chain_pem, str
    ):
        _fail("SIGNING_CERTIFICATE_INVALID")
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes

        child = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
        blocks = re.findall(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            certificate_chain_pem,
            flags=re.DOTALL,
        )
        chain = [
            x509.load_pem_x509_certificate(block.encode("ascii"))
            for block in blocks
        ]
        if child.issuer == child.subject:
            parent = child
        else:
            parents = [item for item in chain if item.subject == child.issuer]
            if len(parents) != 1:
                raise ValueError("certificate parent is not exact")
            parent = parents[0]
        child_hash = hashes.Hash(hashes.SHA384())
        child_hash.update(child.tbs_certificate_bytes)
        parent_hash = hashes.Hash(hashes.SHA384())
        parent_hash.update(parent.tbs_certificate_bytes)
        value = child_hash.finalize().hex() + parent_hash.finalize().hex()
    except (ImportError, TypeError, UnicodeError, ValueError) as exc:
        raise BrokerSignedArtifactError("SIGNING_CERTIFICATE_INVALID") from exc
    if re.fullmatch(r"[0-9a-f]{192}", value) is None:
        _fail("SIGNING_CERTIFICATE_INVALID")
    return value


def _verify_signed_package_semantics(
    unsigned_payload: bytes, signed_payload: bytes
) -> None:
    """Prove Signer preserved every executable package member byte-for-byte."""

    if signed_payload == unsigned_payload:
        _fail("SIGNED_OUTPUT_NOT_DISTINCT")
    try:
        with ZipFile(BytesIO(unsigned_payload), mode="r") as unsigned_zip, ZipFile(
            BytesIO(signed_payload), mode="r"
        ) as signed_zip:
            unsigned_infos = unsigned_zip.infolist()
            signed_infos = signed_zip.infolist()
            expected_names = [path.as_posix() for path in seed.PACKAGE_SOURCE_PATHS]
            if (
                [item.filename for item in unsigned_infos] != expected_names
                or [item.filename for item in signed_infos] != expected_names
            ):
                _fail("SIGNED_PACKAGE_PATH_SET_INVALID")
            total_uncompressed = 0
            for unsigned_info, signed_info in zip(
                unsigned_infos, signed_infos, strict=True
            ):
                unsigned_mode = unsigned_info.external_attr >> 16
                signed_mode = signed_info.external_attr >> 16
                if (
                    unsigned_info.flag_bits & 0x1
                    or signed_info.flag_bits & 0x1
                    or unsigned_mode & 0o170000 == 0o120000
                    or signed_mode & 0o170000 == 0o120000
                    or unsigned_mode != signed_mode
                ):
                    _fail("SIGNED_PACKAGE_SOURCE_ENTRY_DRIFT")
                if (
                    unsigned_info.file_size != signed_info.file_size
                    or unsigned_info.file_size < 0
                    or unsigned_info.file_size > MAX_PACKAGE_BYTES
                    or unsigned_info.compress_size < 0
                    or unsigned_info.compress_size > MAX_PACKAGE_BYTES
                    or signed_info.compress_size < 0
                    or signed_info.compress_size > MAX_PACKAGE_BYTES
                ):
                    _fail("SIGNED_PACKAGE_ENTRY_SIZE_INVALID")
                total_uncompressed += unsigned_info.file_size
                if total_uncompressed > MAX_PACKAGE_BYTES:
                    _fail("SIGNED_PACKAGE_ENTRY_SIZE_INVALID")
                if unsigned_zip.read(unsigned_info) != signed_zip.read(signed_info):
                    _fail("SIGNED_PACKAGE_SOURCE_ENTRY_DRIFT")
    except BrokerSignedArtifactError:
        raise
    except (BadZipFile, KeyError, OSError, RuntimeError, ValueError) as exc:
        raise BrokerSignedArtifactError("SIGNED_PACKAGE_INVALID") from exc


def _read_exact_object(
    client: Any,
    *,
    bucket: str,
    key: str,
    version: str,
    kms_key_arn: str,
) -> tuple[bytes, int]:
    request = {
        "Bucket": bucket,
        "Key": key,
        "VersionId": version,
        "ExpectedBucketOwner": EXPECTED_ACCOUNT_ID,
        "ChecksumMode": "ENABLED",
    }
    head = _call(client.head_object, **request)
    size = head.get("ContentLength")
    if (
        head.get("VersionId") != version
        or type(size) is not int
        or not 0 < size <= MAX_PACKAGE_BYTES
        or head.get("ServerSideEncryption") != "aws:kms"
        or head.get("SSEKMSKeyId") != kms_key_arn
        or head.get("DeleteMarker") is True
        or head.get("ContentRange") is not None
    ):
        _fail("S3_OBJECT_HEAD_INVALID")
    response = _call(client.get_object, **request)
    body = response.get("Body")
    if body is None or not callable(getattr(body, "read", None)):
        _fail("S3_OBJECT_BODY_INVALID")
    chunks: list[bytes] = []
    total = 0
    try:
        while True:
            remaining = MAX_PACKAGE_BYTES + 1 - total
            if remaining <= 0:
                _fail("S3_OBJECT_BODY_INVALID")
            requested = min(65_536, remaining)
            chunk = body.read(requested)
            if not isinstance(chunk, bytes) or len(chunk) > requested:
                _fail("S3_OBJECT_BODY_INVALID")
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        payload = b"".join(chunks)
    except BrokerSignedArtifactError:
        raise
    except Exception as exc:
        raise BrokerSignedArtifactError("S3_OBJECT_BODY_INVALID") from exc
    finally:
        close = getattr(body, "close", None)
        if callable(close):
            close()
    if (
        not isinstance(payload, bytes)
        or len(payload) != size
        or response.get("VersionId") != version
        or response.get("ContentLength") != size
        or response.get("ServerSideEncryption") != "aws:kms"
        or response.get("SSEKMSKeyId") != kms_key_arn
        or response.get("DeleteMarker") is True
        or response.get("ContentRange") is not None
    ):
        _fail("S3_OBJECT_BODY_INVALID")
    checksum = _code_sha256(payload)
    for metadata in (head, response):
        observed_checksum = metadata.get("ChecksumSHA256")
        checksum_type = metadata.get("ChecksumType")
        if (
            (observed_checksum is None and checksum_type is not None)
            or (
                observed_checksum is not None
                and (
                    not isinstance(observed_checksum, str)
                    or observed_checksum != checksum
                    or checksum_type not in (None, "FULL_OBJECT")
                )
            )
        ):
            _fail("S3_OBJECT_CHECKSUM_MISMATCH")
    return payload, 2


def _validate_location(
    value: object,
    *,
    signed: bool,
    source_commit: str,
    signing_job_id: str | None = None,
) -> tuple[str, str, str | None]:
    allowed = {"bucketName", "key"} if signed else {"bucketName", "key", "version"}
    if not isinstance(value, Mapping) or set(value) != allowed:
        _fail("SIGNING_JOB_LOCATION_INVALID")
    bucket = value.get("bucketName")
    key = value.get("key")
    pattern = _SIGNED_KEY_RE if signed else _UNSIGNED_KEY_RE
    if (
        not isinstance(bucket, str)
        or not _BUCKET_RE.fullmatch(bucket)
        or not isinstance(key, str)
        or (match := pattern.fullmatch(key)) is None
        or match.group("commit") != source_commit
        or (signed and match.group("job") != signing_job_id)
    ):
        _fail("SIGNING_JOB_LOCATION_INVALID")
    if signed:
        return bucket, key, None
    version = value.get("version")
    if (
        not isinstance(version, str)
        or not _VERSION_RE.fullmatch(version)
        or version.casefold() == "null"
    ):
        _fail("SIGNING_JOB_LOCATION_INVALID")
    return bucket, key, version


def _new_session(
    profile: str,
    region: str,
    session_factory: Callable[[str, str], Any] | None,
) -> Any:
    if session_factory is not None:
        return session_factory(profile, region)
    try:
        import boto3  # type: ignore[import-not-found]
    except ImportError as exc:
        raise BrokerSignedArtifactError("AWS_SDK_UNAVAILABLE") from exc
    return boto3.Session(profile_name=profile, region_name=region)


def _validate_sdk_versions(
    expected_boto3_version: str, expected_botocore_version: str
) -> None:
    try:
        import boto3  # type: ignore[import-not-found]
        import botocore  # type: ignore[import-not-found]
    except ImportError as exc:
        raise BrokerSignedArtifactError("AWS_SDK_UNAVAILABLE") from exc
    if (
        getattr(boto3, "__version__", None) != expected_boto3_version
        or getattr(botocore, "__version__", None)
        != expected_botocore_version
    ):
        _fail("AWS_SDK_VERSION_MISMATCH")


def _client_config(factory: Callable[[], Any] | None) -> Any:
    if factory is not None:
        return factory()
    try:
        from botocore.config import Config  # type: ignore[import-not-found]
    except ImportError as exc:
        raise BrokerSignedArtifactError("AWS_SDK_UNAVAILABLE") from exc
    return Config(
        connect_timeout=3,
        read_timeout=5,
        retries={"mode": "standard", "total_max_attempts": 1},
        s3={"us_east_1_regional_endpoint": "regional"},
        ignore_configured_endpoint_urls=True,
    )


def _validate_environment(
    environment: Mapping[str, str],
    *,
    expected_profile: str = EXPECTED_PROFILE,
) -> None:
    if any(environment.get(name) for name in _AMBIENT_FORBIDDEN) or any(
        name.startswith("AWS_ENDPOINT_URL") and value
        for name, value in environment.items()
    ):
        _fail("AWS_ENVIRONMENT_UNSAFE")
    for name in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE"):
        if environment.get(name) not in {None, "", expected_profile}:
            _fail("AWS_PROFILE_DRIFT")
    for name in ("AWS_REGION", "AWS_DEFAULT_REGION"):
        if environment.get(name) not in {None, "", EXPECTED_REGION}:
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


def _validate_session(
    session: Any,
    profile: str,
    region: str,
    *,
    expected_profile: str = EXPECTED_PROFILE,
    expected_sso_role: str = EXPECTED_SSO_ROLE,
) -> None:
    if (
        profile == "default"
        or profile != expected_profile
        or region != EXPECTED_REGION
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
        or document.get("sso_account_id") != EXPECTED_ACCOUNT_ID
        or document.get("sso_role_name") != expected_sso_role
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
        raise BrokerSignedArtifactError(
            "AWS_SSO_CREDENTIALS_UNAVAILABLE"
        ) from exc
    if credentials is None or getattr(credentials, "method", None) != "sso":
        _fail("AWS_CREDENTIAL_SOURCE_INVALID")


def _exact_client(session: Any, service: str, region: str, config: Any) -> Any:
    try:
        client = session.client(service, region_name=region, config=config)
        endpoint = client.meta.endpoint_url
    except Exception as exc:
        raise BrokerSignedArtifactError("AWS_CLIENT_INVALID") from exc
    parsed = urlsplit(str(endpoint))
    expected_hosts = {
        "sts": f"sts.{region}.amazonaws.com",
        "s3": f"s3.{region}.amazonaws.com",
        "signer": f"signer.{region}.amazonaws.com",
        "signer-data": f"data-signer.{region}.amazonaws.com",
        "acm": f"acm.{region}.amazonaws.com",
    }
    if (
        service not in expected_hosts
        or parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or parsed.hostname != expected_hosts[service]
    ):
        _fail("AWS_ENDPOINT_INVALID")
    return client


def _validate_foundation_causality(
    *,
    bootstrap_intent: Mapping[str, Any],
    foundation_publish_binding: Mapping[str, Any],
    source_commit: str,
    observed_at: datetime,
) -> dict[str, Any]:
    try:
        storage = validate_foundation_publish_binding(
            foundation_publish_binding,
            bootstrap_intent=bootstrap_intent,
        )
    except (ArtifactBootstrapError, TypeError, ValueError) as exc:
        raise BrokerSignedArtifactError(
            "FOUNDATION_PUBLISH_BINDING_INVALID"
        ) from exc
    try:
        not_before = _parsed_timestamp(
            bootstrap_intent.get("access_not_before"),
            "FOUNDATION_PUBLISH_WINDOW_INVALID",
        )
        not_after = _parsed_timestamp(
            storage.get("access_not_after"),
            "FOUNDATION_PUBLISH_WINDOW_INVALID",
        )
    except BrokerSignedArtifactError:
        raise
    if (
        storage.get("record_type") != FOUNDATION_STORAGE_BINDING_TYPE
        or storage.get("source_marker")
        != "VALIDATED_GUG376_FOUNDATION_PUBLISH_AUTHORITY"
        or storage.get("source_commit") != source_commit
        or observed_at < not_before
        or observed_at >= not_after
    ):
        _fail("FOUNDATION_PUBLISH_BINDING_INVALID")
    return storage


def _derive_pep_runtime_binding(
    receipt: Mapping[str, Any],
    *,
    source_commit: str,
    observed_at: datetime,
    expected_storage_binding: Mapping[str, Any],
    bootstrap_intent: Mapping[str, Any] | None,
    foundation_publish_binding: Mapping[str, Any] | None,
    allow_legacy_upstream_storage_binding: bool,
    validator: Callable[..., Any] | None,
) -> tuple[str, str, str, str, dict[str, Any]]:
    try:
        if validator is None:
            from tooling import (
                platform_authority_plan_permission_repair_signed_artifact
                as pep_signed_artifact,
            )

            pep_signed_artifact.validate_signed_artifact_receipt(
                receipt,
                now=observed_at,
                bootstrap_intent=bootstrap_intent,
                foundation_publish_binding=foundation_publish_binding,
                allow_legacy_upstream_storage_binding=(
                    allow_legacy_upstream_storage_binding
                ),
            )
        else:
            validator(
                receipt,
                now=observed_at,
                bootstrap_intent=bootstrap_intent,
                foundation_publish_binding=foundation_publish_binding,
                allow_legacy_upstream_storage_binding=(
                    allow_legacy_upstream_storage_binding
                ),
            )
    except Exception as exc:
        raise BrokerSignedArtifactError("PEP_RECEIPT_INVALID") from exc
    sdk = receipt.get("expected_sdk_versions")
    signed_artifact = receipt.get("signed_artifact")
    signing_job = receipt.get("signing_job")
    source = (
        signing_job.get("source")
        if isinstance(signing_job, Mapping)
        else None
    )
    storage = receipt.get("upstream_storage_binding")
    if (
        not isinstance(storage, Mapping)
        or dict(storage) != dict(expected_storage_binding)
    ):
        _fail("PEP_UPSTREAM_STORAGE_BINDING_MISMATCH")
    if (
        receipt.get("source_commit") != source_commit
        or not isinstance(sdk, Mapping)
        or set(sdk) != {"boto3", "botocore"}
        or not _SDK_VERSION_RE.fullmatch(str(sdk.get("boto3")))
        or not _SDK_VERSION_RE.fullmatch(str(sdk.get("botocore")))
        or not isinstance(signed_artifact, Mapping)
        or not isinstance(signing_job, Mapping)
        or not isinstance(source, Mapping)
        or (
            not allow_legacy_upstream_storage_binding
            and signing_job.get("profile_version_arn")
            != expected_storage_binding.get("signing_profile_version_arn")
        )
        or signed_artifact.get("bucket") != storage.get("bucket")
        or signed_artifact.get("sse_algorithm")
        != storage.get("sse_algorithm")
        or signed_artifact.get("sse_kms_key_arn")
        != storage.get("sse_kms_key_arn")
        or source.get("bucket") != storage.get("bucket")
        or source.get("sse_algorithm") != storage.get("sse_algorithm")
        or source.get("sse_kms_key_arn") != storage.get("sse_kms_key_arn")
        or not _DIGEST_RE.fullmatch(str(storage.get("binding_digest")))
        or not _DIGEST_RE.fullmatch(str(receipt.get("receipt_digest")))
        or seed.digest_value(
            {
                key: value
                for key, value in receipt.items()
                if key != "receipt_digest"
            }
        )
        != receipt.get("receipt_digest")
    ):
        _fail("PEP_RUNTIME_BINDING_INVALID")
    receipt_digest = str(receipt["receipt_digest"])
    runtime_evidence = {
        "record_type": (
            "scanalyze.platform_authority."
            "plan_permission_repair_pep_runtime_evidence.v1"
        ),
        "source_commit": source_commit,
        "expected_boto3_version": str(sdk["boto3"]),
        "expected_botocore_version": str(sdk["botocore"]),
        "signed_artifact_code_sha256": signed_artifact.get(
            "lambda_code_sha256"
        ),
        "signing_profile_version_arn": signing_job.get(
            "profile_version_arn"
        ),
        "validated_receipt_digest": receipt_digest,
        "upstream_storage_binding_digest": storage["binding_digest"],
    }
    return (
        str(sdk["boto3"]),
        str(sdk["botocore"]),
        receipt_digest,
        seed.digest_value(runtime_evidence),
        dict(storage),
    )


def attest_broker_signed_artifact(
    *,
    source_root: Path,
    source_commit: str,
    aws_profile: str,
    expected_account_id: str,
    region: str,
    unsigned_bucket: str,
    unsigned_key: str,
    unsigned_version: str,
    signing_job_id: str,
    signed_version: str,
    pep_signed_artifact_receipt: Mapping[str, Any],
    bootstrap_intent: Mapping[str, Any] | None = None,
    foundation_publish_binding: Mapping[str, Any] | None = None,
    gug363_plan: Mapping[str, Any] | None = None,
    gug365_plan: Mapping[str, Any] | None = None,
    upstream_source_root: Path | None = None,
    session_factory: Callable[[str, str], Any] | None = None,
    clock: Callable[[], datetime] | None = None,
    config_factory: Callable[[], Any] | None = None,
    pep_receipt_validator: Callable[..., Any] | None = None,
    gug363_validator: Callable[..., Any] | None = None,
    gug365_validator: Callable[..., Any] | None = None,
    allow_legacy_upstream_plans: bool = False,
    environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Return a closed read-only handoff for offline seed materialization."""

    if (
        not isinstance(source_commit, str)
        or not _COMMIT_RE.fullmatch(source_commit)
        or expected_account_id != EXPECTED_ACCOUNT_ID
        or region != EXPECTED_REGION
        or not isinstance(unsigned_bucket, str)
        or not _BUCKET_RE.fullmatch(unsigned_bucket)
        or not isinstance(unsigned_key, str)
        or (unsigned_match := _UNSIGNED_KEY_RE.fullmatch(unsigned_key)) is None
        or unsigned_match.group("commit") != source_commit
        or not _VERSION_RE.fullmatch(str(unsigned_version))
        or str(unsigned_version).casefold() == "null"
        or not _JOB_RE.fullmatch(str(signing_job_id))
        or not _VERSION_RE.fullmatch(str(signed_version))
        or str(signed_version).casefold() == "null"
        or not isinstance(pep_signed_artifact_receipt, Mapping)
    ):
        _fail("ATTESTATION_INPUT_INVALID")
    foundation_mode = (
        isinstance(bootstrap_intent, Mapping)
        and isinstance(foundation_publish_binding, Mapping)
        and not allow_legacy_upstream_plans
        and gug363_plan is None
        and gug365_plan is None
        and upstream_source_root is None
        and gug363_validator is None
        and gug365_validator is None
    )
    legacy_mode = (
        allow_legacy_upstream_plans
        and bootstrap_intent is None
        and foundation_publish_binding is None
        and isinstance(gug363_plan, Mapping)
        and isinstance(gug365_plan, Mapping)
    )
    if not foundation_mode and not legacy_mode:
        _fail("STORAGE_CAUSALITY_ROUTE_INVALID")
    expected_profile = (
        LEGACY_EXPECTED_PROFILE if legacy_mode else EXPECTED_PROFILE
    )
    expected_sso_role = (
        LEGACY_EXPECTED_SSO_ROLE if legacy_mode else EXPECTED_SSO_ROLE
    )
    expected_caller = _LEGACY_CALLER_RE if legacy_mode else _CALLER_RE
    if aws_profile != expected_profile:
        _fail("ATTESTATION_INPUT_INVALID")
    _validate_environment(
        environment if environment is not None else os.environ,
        expected_profile=expected_profile,
    )
    observed = (clock or (lambda: datetime.now(timezone.utc)))()
    if observed.tzinfo is None or observed.utcoffset() is None:
        _fail("CLOCK_INVALID")
    observed = observed.astimezone(timezone.utc).replace(microsecond=0)
    if foundation_mode:
        storage_binding = _validate_foundation_causality(
            bootstrap_intent=bootstrap_intent,
            foundation_publish_binding=foundation_publish_binding,
            source_commit=source_commit,
            observed_at=observed,
        )
    elif legacy_mode:
        try:
            from tooling import (
                platform_authority_plan_permission_repair_template_readback
                as template_readback,
            )

            storage_binding = template_readback.derive_upstream_storage_binding(
                gug363_plan=gug363_plan,
                gug365_plan=gug365_plan,
                source_root=upstream_source_root or source_root,
                gug363_validator=gug363_validator,
                gug365_validator=gug365_validator,
            )
        except Exception as exc:
            raise BrokerSignedArtifactError(
                "UPSTREAM_STORAGE_BINDING_INVALID"
            ) from exc
    else:
        _fail("STORAGE_CAUSALITY_ROUTE_INVALID")
    (
        expected_boto3_version,
        expected_botocore_version,
        pep_signed_artifact_receipt_digest,
        pep_runtime_readback_digest,
        pep_upstream_storage_binding,
    ) = _derive_pep_runtime_binding(
        pep_signed_artifact_receipt,
        source_commit=source_commit,
        observed_at=observed,
        expected_storage_binding=storage_binding,
        bootstrap_intent=bootstrap_intent,
        foundation_publish_binding=foundation_publish_binding,
        allow_legacy_upstream_storage_binding=legacy_mode,
        validator=pep_receipt_validator,
    )
    if session_factory is None:
        _validate_sdk_versions(
            expected_boto3_version,
            expected_botocore_version,
        )
    unsigned_local = seed.build_broker_package(
        source_root=source_root,
        source_commit=source_commit,
    )
    kms_key_arn = storage_binding.get("sse_kms_key_arn")
    if (
        storage_binding.get("bucket") != unsigned_bucket
        or storage_binding.get("sse_algorithm") != "aws:kms"
        or not isinstance(kms_key_arn, str)
    ):
        _fail("UPSTREAM_STORAGE_BINDING_MISMATCH")
    if pep_upstream_storage_binding != storage_binding:
        _fail("PEP_UPSTREAM_STORAGE_BINDING_MISMATCH")
    session = _new_session(aws_profile, region, session_factory)
    _validate_session(
        session,
        aws_profile,
        region,
        expected_profile=expected_profile,
        expected_sso_role=expected_sso_role,
    )
    client_config = _client_config(config_factory)

    # Identity is the first AWS client and first AWS call.  No S3 or Signer
    # object is touched until the exact read-only caller has been proven.
    sts = _exact_client(session, "sts", region, client_config)
    identity = _call(sts.get_caller_identity)
    caller_arn = identity.get("Arn")
    if (
        identity.get("Account") != expected_account_id
        or not isinstance(caller_arn, str)
        or not expected_caller.fullmatch(caller_arn)
    ):
        _fail("AWS_IDENTITY_INVALID")
    aws_calls = 1

    s3 = _exact_client(session, "s3", region, client_config)
    signer = _exact_client(session, "signer", region, client_config)
    acm = _exact_client(session, "acm", region, client_config)
    signer_data = _exact_client(
        session, "signer-data", region, client_config
    )
    versioning = _call(
        s3.get_bucket_versioning,
        Bucket=unsigned_bucket,
        ExpectedBucketOwner=expected_account_id,
    )
    aws_calls += 1
    if versioning.get("Status") != "Enabled":
        _fail("S3_BUCKET_VERSIONING_INVALID")
    unsigned_remote, calls = _read_exact_object(
        s3,
        bucket=unsigned_bucket,
        key=unsigned_key,
        version=unsigned_version,
        kms_key_arn=kms_key_arn,
    )
    aws_calls += calls
    if unsigned_remote != unsigned_local:
        _fail("UNSIGNED_PACKAGE_SOURCE_MISMATCH")

    job = _call(signer.describe_signing_job, jobId=signing_job_id)
    aws_calls += 1
    source = job.get("source")
    signed_object = job.get("signedObject")
    if (
        not isinstance(source, Mapping)
        or set(source) != {"s3"}
        or not isinstance(signed_object, Mapping)
        or set(signed_object) != {"s3"}
    ):
        _fail("SIGNING_JOB_INVALID")
    job_source = _validate_location(
        source["s3"], signed=False, source_commit=source_commit
    )
    signed_bucket, signed_key, _unused = _validate_location(
        signed_object["s3"],
        signed=True,
        source_commit=source_commit,
        signing_job_id=signing_job_id,
    )
    if (
        job_source != (unsigned_bucket, unsigned_key, unsigned_version)
        or signed_bucket != unsigned_bucket
    ):
        _fail("SIGNING_JOB_SOURCE_MISMATCH")
    profile_name = job.get("profileName")
    profile_version = job.get("profileVersion")
    signing_material = job.get("signingMaterial")
    certificate_arn = (
        signing_material.get("certificateArn")
        if isinstance(signing_material, Mapping)
        else None
    )
    if (
        job.get("jobId") != signing_job_id
        or job.get("status") != "Succeeded"
        or job.get("platformId") != SIGNING_PLATFORM_ID
        or job.get("jobOwner") != expected_account_id
        or job.get("jobInvoker") != expected_account_id
        or not isinstance(profile_name, str)
        or re.fullmatch(r"[A-Za-z0-9_]{2,64}", profile_name) is None
        or not isinstance(profile_version, str)
        or re.fullmatch(r"[A-Za-z0-9]{10}", profile_version) is None
        or job.get("revocationRecord") is not None
        or job.get("overrides") not in (None, {})
        or job.get("signingParameters") not in (None, {})
        or not isinstance(signing_material, Mapping)
        or set(signing_material) != {"certificateArn"}
        or not isinstance(certificate_arn, str)
        or _CERTIFICATE_ARN_RE.fullmatch(certificate_arn) is None
    ):
        _fail("SIGNING_JOB_INVALID")
    created_at = _timestamp(job.get("createdAt"), "SIGNING_JOB_INVALID")
    completed_at = _timestamp(job.get("completedAt"), "SIGNING_JOB_INVALID")
    signature_expires_at = _timestamp(
        job.get("signatureExpiresAt"), "SIGNING_JOB_INVALID"
    )

    profile = _call(
        signer.get_signing_profile,
        profileName=profile_name,
        profileOwner=expected_account_id,
    )
    aws_calls += 1
    profile_arn = profile.get("profileVersionArn")
    if (
        not isinstance(profile_arn, str)
        or (profile_match := _PROFILE_ARN_RE.fullmatch(profile_arn)) is None
        or profile_match.group("name") != profile_name
        or profile_match.group("version") != profile_version
        or profile.get("profileVersion") != profile_version
        or profile.get("status") != "Active"
        or profile.get("platformId") != SIGNING_PLATFORM_ID
        or profile.get("revocationRecord") is not None
        or (
            foundation_mode
            and profile_arn
            != storage_binding.get("signing_profile_version_arn")
        )
    ):
        _fail("SIGNING_PROFILE_INVALID")

    job_arn = (
        f"arn:aws:signer:{region}:{expected_account_id}:"
        f"/signing-jobs/{signing_job_id}"
    )
    certificate = _call(acm.get_certificate, CertificateArn=certificate_arn)
    aws_calls += 1
    certificate_hash = _certificate_revocation_hash(
        certificate_pem=certificate.get("Certificate"),
        certificate_chain_pem=certificate.get("CertificateChain"),
    )
    revocation = _call(
        signer_data.get_revocation_status,
        signatureTimestamp=_parsed_timestamp(
            job.get("completedAt"), "SIGNING_JOB_INVALID"
        ),
        platformId=SIGNING_PLATFORM_ID,
        profileVersionArn=profile_arn,
        jobArn=job_arn,
        certificateHashes=[certificate_hash],
    )
    aws_calls += 1
    revoked_entities = revocation.get("revokedEntities")
    if (
        not isinstance(revoked_entities, list)
        or any(
            not isinstance(item, str) or not item
            for item in revoked_entities
        )
    ):
        _fail("REVOCATION_READBACK_INVALID")
    if revoked_entities:
        _fail("SIGNED_ARTIFACT_REVOKED")

    versions = _call(
        s3.list_object_versions,
        Bucket=signed_bucket,
        Prefix=signed_key,
        ExpectedBucketOwner=expected_account_id,
    )
    aws_calls += 1
    raw_versions = versions.get("Versions", [])
    raw_deletes = versions.get("DeleteMarkers", [])
    if (
        not isinstance(raw_versions, list)
        or not isinstance(raw_deletes, list)
        or any(
            not isinstance(item, Mapping)
            for item in (*raw_versions, *raw_deletes)
        )
    ):
        _fail("SIGNED_OUTPUT_VERSION_NOT_UNIQUE")
    exact_versions = [
        item
        for item in raw_versions
        if item.get("Key") == signed_key
    ]
    exact_deletes = [
        item
        for item in raw_deletes
        if item.get("Key") == signed_key
    ]
    if (
        versions.get("IsTruncated") is not False
        or versions.get("NextKeyMarker") is not None
        or versions.get("NextVersionIdMarker") is not None
        or len(exact_versions) != 1
        or exact_versions[0].get("VersionId") != signed_version
        or exact_versions[0].get("IsLatest") is not True
        or exact_deletes
    ):
        _fail("SIGNED_OUTPUT_VERSION_NOT_UNIQUE")
    signed_payload, calls = _read_exact_object(
        s3,
        bucket=signed_bucket,
        key=signed_key,
        version=signed_version,
        kms_key_arn=kms_key_arn,
    )
    aws_calls += calls
    _verify_signed_package_semantics(unsigned_local, signed_payload)

    observed_at = _timestamp(observed, "CLOCK_INVALID")
    receipt: dict[str, Any] = {
        "schema_version": 1,
        "record_type": seed.BROKER_SIGNING_RECEIPT_TYPE,
        "source_commit": source_commit,
        "verifier": {
            "account_id": expected_account_id,
            "caller_arn": caller_arn,
            "profile": aws_profile,
            "region": region,
        },
        "unsigned_artifact": {
            "bucket": unsigned_bucket,
            "key": unsigned_key,
            "version": unsigned_version,
            "sha256": "sha256:" + sha256(unsigned_local).hexdigest(),
            "code_sha256": _code_sha256(unsigned_local),
            "bytes": len(unsigned_local),
            "sse_algorithm": "aws:kms",
            "sse_kms_key_arn": kms_key_arn,
        },
        "signing_job": {
            "job_id": signing_job_id,
            "job_owner": expected_account_id,
            "job_invoker": expected_account_id,
            "status": "Succeeded",
            "platform_id": SIGNING_PLATFORM_ID,
            "profile_version_arn": profile_arn,
            "certificate_arn": certificate_arn,
            "created_at": created_at,
            "completed_at": completed_at,
            "signature_expires_at": signature_expires_at,
            "profile_status": "Active",
            "job_revocation_record_absent": True,
            "profile_revocation_record_absent": True,
        },
        "signed_artifact": {
            "bucket": signed_bucket,
            "key": signed_key,
            "version": signed_version,
            "sha256": "sha256:" + sha256(signed_payload).hexdigest(),
            "code_sha256": _code_sha256(signed_payload),
            "bytes": len(signed_payload),
            "sse_algorithm": "aws:kms",
            "sse_kms_key_arn": kms_key_arn,
        },
        "upstream_storage_binding": dict(storage_binding),
        "revocation_check": {
            "status": "PROFILE_JOB_AND_CERTIFICATE_NOT_REVOKED",
            "checked_at": observed_at,
            "profile_version_arn_digest": seed.digest_value(profile_arn),
            "job_arn_digest": seed.digest_value(job_arn),
            "certificate_hash_digest": seed.digest_value(certificate_hash),
            "source_marker": (
                "DESCRIBE_SIGNING_JOB_GET_SIGNING_PROFILE_ACM_CERTIFICATE_"
                "AND_SIGNER_DATA_REVOCATION"
            ),
        },
        "observed_at": observed_at,
        "source_marker": (
            "AWS_STS_S3_SIGNER_ACM_REVOCATION_AND_VERSIONED_OBJECT_READBACK"
        ),
        "aws_calls": aws_calls,
        "aws_mutations": 0,
    }
    receipt["receipt_digest"] = seed.digest_value(receipt)
    seed.validate_broker_signing_receipt(
        receipt,
        source_commit=source_commit,
        now=observed,
        bootstrap_intent=bootstrap_intent,
        foundation_publish_binding=foundation_publish_binding,
        allow_legacy_upstream_storage_binding=legacy_mode,
    )

    runtime_binding: dict[str, Any] = {
        "schema_version": 1,
        "record_type": seed.PEP_RUNTIME_BINDING_TYPE,
        "source_commit": source_commit,
        "expected_boto3_version": expected_boto3_version,
        "expected_botocore_version": expected_botocore_version,
        "pep_signed_artifact_receipt_digest": (
            pep_signed_artifact_receipt_digest
        ),
        "pep_runtime_readback_digest": pep_runtime_readback_digest,
        "upstream_storage_binding_digest": storage_binding[
            "binding_digest"
        ],
        "source_marker": (
            "VALIDATED_GUG376_PEP_SIGNED_ARTIFACT_RUNTIME_EVIDENCE"
        ),
    }
    runtime_binding["binding_digest"] = seed.digest_value(runtime_binding)
    seed.validate_pep_runtime_binding(runtime_binding, source_commit=source_commit)

    handoff: dict[str, Any] = {
        "schema_version": 1,
        "record_type": HANDOFF_TYPE,
        "source_commit": source_commit,
        "observed_at": observed_at,
        "broker_code": receipt,
        "pep_runtime_binding": runtime_binding,
        "aws_calls": aws_calls,
        "aws_mutations": 0,
        "deployment_authorized": False,
        "production_status": "NO-GO",
    }
    handoff["handoff_digest"] = seed.digest_value(handoff)
    return handoff


def write_private_handoff(
    *, private_root: Path, output_name: str, handoff: Mapping[str, Any]
) -> Path:
    """Write one attested handoff once with owner-only permissions."""

    if not _OUTPUT_RE.fullmatch(output_name):
        _fail("OUTPUT_NAME_INVALID")
    payload = (seed.canonical_json(dict(handoff)) + "\n").encode("utf-8")
    try:
        return seed._write_private_payload(  # noqa: SLF001
            private_root=private_root,
            name=output_name,
            payload=payload,
        )
    except seed.BrokerSeedError as exc:
        raise BrokerSignedArtifactError(exc.code) from exc


__all__ = [
    "BrokerSignedArtifactError",
    "DEFAULT_OUTPUT_NAME",
    "EXPECTED_ACCOUNT_ID",
    "EXPECTED_PROFILE",
    "EXPECTED_REGION",
    "HANDOFF_TYPE",
    "attest_broker_signed_artifact",
    "write_private_handoff",
]
