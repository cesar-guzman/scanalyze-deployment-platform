"""Authenticate the AWS Signer handoff for the GUG-274 authority package.

The public entry point rebuilds the unsigned ZIP from one exact clean commit
and obtains every provider fact through read-only STS, Signer, and S3 clients.
Operator-supplied provider readbacks or archive bytes never participate in the
decision.  The returned closed receipt is the only supported source for the
CloudFormation artifact parameters.

This module does not start a signing job, upload an object, create a Change
Set, publish a Lambda version, or perform any other provider mutation.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from io import BytesIO
import json
import os
from pathlib import Path
import re
from typing import Any, Mapping
from zipfile import BadZipFile, ZipFile

from tooling.platform_authority_bootstrap_artifact_package import (
    ARCHIVE_NAME,
    EXPECTED_BOTO3_VERSION,
    EXPECTED_BOTOCORE_VERSION,
    PACKAGE_PATHS,
    PRODUCTION_STATUS,
    SIGNING_PROFILE_NAME,
    BootstrapArtifactPackageError,
    BuiltBootstrapArtifactPackage,
    build_bootstrap_artifact_package,
    canonical_json,
    closed_provenance_environment,
    resolve_trusted_executable,
    validate_bootstrap_artifact_package,
)
from tooling.platform_authority_lambda_audit_repair_signed_artifact import (
    SignedArtifactError as SourceReviewError,
    validate_github_source_review,
    verify_github_merged_release,
)


ARTIFACT_TYPE = (
    "scanalyze.platform_authority.bootstrap_signed_artifact_receipt.v1"
)
SCHEMA_VERSION = 1
WORK_PACKAGE = "GUG-274"
TRUST_ROOT_GENERATION = 1
PARTITION = "aws"
AUTHORITY_ACCOUNT_ID = "042360977644"
REGION = "us-east-1"
SIGNING_PLATFORM = "AWSLambda-SHA384-ECDSA"
CODE_SIGNING_POLICY = "Enforce"
EVIDENCE_STATUS = "SIGNED_ARTIFACT_READ_ONLY_VERIFIED_FOR_CHANGE_SET_REVIEW"
EXPECTED_VERIFIER_PROFILE = f"{AUTHORITY_ACCOUNT_ID}_ReadOnlyAccess"
RECEIPT_DOMAIN = (
    b"scanalyze.platform-authority.bootstrap-signed-artifact-receipt.v1"
)
TRUST_ROOT_ARTIFACT_TYPE = (
    "scanalyze.platform_authority.bootstrap_artifact_signing_trust_root.v1"
)
TRUST_ROOT_CONTRACT_PATH = Path(
    "bootstrap/platform-authority-bootstrap-artifact-signing-trust-root.json"
)
TRUST_ROOT_CONTRACT_DOMAIN = (
    b"scanalyze.platform-authority.bootstrap-artifact-signing-trust-root.v1"
)
MAX_ARCHIVE_BYTES = 10 * 1024 * 1024
MAX_S3_VERSION_PAGES = 100
RECEIPT_TTL = timedelta(minutes=15)
MAX_CLOCK_SKEW = timedelta(minutes=2)

_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_DOMAIN_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CODE_SHA_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")
_SDK_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_JOB_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_PROFILE_VERSION_RE = re.compile(r"^[A-Za-z0-9]{10}$")
_PROFILE_ARN_RE = re.compile(
    rf"^arn:{PARTITION}:signer:{REGION}:{AUTHORITY_ACCOUNT_ID}:"
    rf"/signing-profiles/{SIGNING_PROFILE_NAME}/(?P<version>[A-Za-z0-9]{{10}})$"
)
_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
_CALLER_ARN_RE = re.compile(
    rf"^arn:{PARTITION}:sts::{AUTHORITY_ACCOUNT_ID}:assumed-role/"
    r"AWSReservedSSO_AWSReadOnlyAccess_[0-9a-f]{16}/"
    r"[A-Za-z0-9+=,.@_-]{1,64}$"
)
_SOURCE_KEY_RE = re.compile(
    r"^scanalyze/platform-authority/gug-274/unsigned/"
    r"(?P<commit>[0-9a-f]{40})/"
    + re.escape(ARCHIVE_NAME)
    + r"$"
)
_SIGNED_KEY_RE = re.compile(
    r"^scanalyze/platform-authority/gug-274/signed/"
    r"(?P<job>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{12})\.zip$"
)


class BootstrapSignedArtifactError(ValueError):
    """Stable fail-closed signed-artifact contract violation."""


def verify_reviewed_source_release(
    *, source_root: Path, source_commit: str
) -> Mapping[str, Any]:
    """Read GitHub provenance through exact reviewed Git and gh executables."""

    try:
        git_executable = resolve_trusted_executable(
            name="git", source_root=source_root
        )
        gh_executable = resolve_trusted_executable(
            name="gh", source_root=source_root
        )
        environment = closed_provenance_environment(
            source_root=source_root,
            executables=(git_executable, gh_executable),
            include_home=True,
        )
        return verify_github_merged_release(
            source_root=source_root,
            source_commit=source_commit,
            git_executable=str(git_executable),
            gh_executable=str(gh_executable),
            command_environment=environment,
        )
    except (BootstrapArtifactPackageError, SourceReviewError):
        raise BootstrapSignedArtifactError(
            "SOURCE_RELEASE_NOT_VERIFIED"
        ) from None


def _closed_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BootstrapSignedArtifactError("TRUST_ROOT_CONTRACT_INVALID")
        result[key] = value
    return result


def validate_signing_trust_root_contract(
    contract: Mapping[str, Any], *, require_configured: bool
) -> None:
    """Validate the reviewed generation-1 signer version contract."""

    required = {
        "artifact_type",
        "schema_version",
        "work_package",
        "trust_root_generation",
        "partition",
        "authority_account_id",
        "region",
        "profile_name",
        "profile_version_id",
        "profile_version_arn",
        "signing_platform",
        "code_signing_policy",
        "configuration_status",
        "activation_authorized",
        "production_status",
    }
    if (
        not isinstance(contract, Mapping)
        or set(contract) != required
        or contract.get("artifact_type") != TRUST_ROOT_ARTIFACT_TYPE
        or contract.get("schema_version") != SCHEMA_VERSION
        or contract.get("work_package") != WORK_PACKAGE
        or contract.get("trust_root_generation") != TRUST_ROOT_GENERATION
        or contract.get("partition") != PARTITION
        or contract.get("authority_account_id") != AUTHORITY_ACCOUNT_ID
        or contract.get("region") != REGION
        or contract.get("profile_name") != SIGNING_PROFILE_NAME
        or contract.get("signing_platform") != SIGNING_PLATFORM
        or contract.get("code_signing_policy") != CODE_SIGNING_POLICY
        or contract.get("activation_authorized") is not False
        or contract.get("production_status") != PRODUCTION_STATUS
    ):
        raise BootstrapSignedArtifactError("TRUST_ROOT_CONTRACT_INVALID")
    status = contract.get("configuration_status")
    version_id = contract.get("profile_version_id")
    version_arn = contract.get("profile_version_arn")
    if status == "NOT_CONFIGURED":
        if version_id is not None or version_arn is not None:
            raise BootstrapSignedArtifactError("TRUST_ROOT_CONTRACT_INVALID")
        if require_configured:
            raise BootstrapSignedArtifactError("SIGNING_TRUST_ROOT_NOT_CONFIGURED")
        return
    if (
        status != "CONFIGURED_REVIEWED"
        or not isinstance(version_id, str)
        or _PROFILE_VERSION_RE.fullmatch(version_id) is None
        or not isinstance(version_arn, str)
        or _PROFILE_ARN_RE.fullmatch(version_arn) is None
        or not version_arn.endswith("/" + version_id)
    ):
        raise BootstrapSignedArtifactError("TRUST_ROOT_CONTRACT_INVALID")


def signing_trust_root_contract_digest(contract: Mapping[str, Any]) -> str:
    validate_signing_trust_root_contract(contract, require_configured=False)
    preimage = (
        TRUST_ROOT_CONTRACT_DOMAIN
        + b"\x00"
        + canonical_json(contract).encode("utf-8")
    )
    return "sha256:" + sha256(preimage).hexdigest()


def load_signing_trust_root_contract(
    *, source_root: Path, require_configured: bool
) -> Mapping[str, Any]:
    """Load the fixed repository contract; callers cannot choose its path."""

    root = source_root.resolve(strict=True)
    requested = root / TRUST_ROOT_CONTRACT_PATH
    try:
        resolved = requested.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError):
        raise BootstrapSignedArtifactError("TRUST_ROOT_CONTRACT_UNAVAILABLE") from None
    if requested.is_symlink() or not resolved.is_file():
        raise BootstrapSignedArtifactError("TRUST_ROOT_CONTRACT_UNAVAILABLE")
    try:
        loaded = json.loads(
            resolved.read_text(encoding="utf-8"),
            object_pairs_hook=_closed_json_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                BootstrapSignedArtifactError("TRUST_ROOT_CONTRACT_INVALID")
            ),
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise BootstrapSignedArtifactError("TRUST_ROOT_CONTRACT_INVALID") from None
    if not isinstance(loaded, Mapping):
        raise BootstrapSignedArtifactError("TRUST_ROOT_CONTRACT_INVALID")
    validate_signing_trust_root_contract(
        loaded, require_configured=require_configured
    )
    return dict(loaded)


def _strict_version_id(value: Any) -> str:
    if not isinstance(value, str) or not value or value.casefold() == "null":
        raise BootstrapSignedArtifactError("S3_VERSION_INVALID")
    if len(value.encode("utf-8")) > 1024 or any(ord(char) < 32 for char in value):
        raise BootstrapSignedArtifactError("S3_VERSION_INVALID")
    return value


def _timestamp(value: Any, code: str) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise BootstrapSignedArtifactError(code)
        parsed = value.astimezone(UTC)
    elif isinstance(value, str) and value.endswith("Z"):
        try:
            parsed = datetime.fromisoformat(value[:-1] + "+00:00").astimezone(UTC)
        except ValueError as exc:
            raise BootstrapSignedArtifactError(code) from exc
    else:
        raise BootstrapSignedArtifactError(code)
    if parsed.microsecond:
        raise BootstrapSignedArtifactError(code)
    return parsed


def _timestamp_text(value: Any, code: str) -> str:
    return _timestamp(value, code).isoformat().replace("+00:00", "Z")


def _checksum(value: Any, code: str) -> str:
    if not isinstance(value, str):
        raise BootstrapSignedArtifactError(code)
    try:
        decoded = base64.b64decode(value, validate=True)
    except (TypeError, ValueError) as exc:
        raise BootstrapSignedArtifactError(code) from exc
    if len(decoded) != 32:
        raise BootstrapSignedArtifactError(code)
    return value


def _aws_call(call: Any, /, **kwargs: Any) -> Mapping[str, Any]:
    """Call one read-only SDK operation without exposing provider details."""

    try:
        response = call(**kwargs)
    except Exception as exc:  # botocore is an optional operational dependency
        raise BootstrapSignedArtifactError("AWS_READBACK_FAILED") from exc
    if not isinstance(response, Mapping):
        raise BootstrapSignedArtifactError("AWS_READBACK_INVALID")
    return response


def _source_location(value: Any, *, source_commit: str) -> tuple[str, str, str]:
    if not isinstance(value, Mapping) or set(value) != {
        "bucketName",
        "key",
        "version",
    }:
        raise BootstrapSignedArtifactError("SIGNING_JOB_SOURCE_INVALID")
    bucket = value.get("bucketName")
    key = value.get("key")
    match = _SOURCE_KEY_RE.fullmatch(str(key))
    if (
        not isinstance(bucket, str)
        or _BUCKET_RE.fullmatch(bucket) is None
        or match is None
        or match.group("commit") != source_commit
        or any(part in {"", ".", ".."} for part in str(key).split("/"))
    ):
        raise BootstrapSignedArtifactError("SIGNING_JOB_SOURCE_INVALID")
    return bucket, str(key), _strict_version_id(value.get("version"))


def _signed_location(value: Any, *, job_id: str) -> tuple[str, str]:
    if not isinstance(value, Mapping) or set(value) != {"bucketName", "key"}:
        raise BootstrapSignedArtifactError("SIGNING_JOB_DESTINATION_INVALID")
    bucket = value.get("bucketName")
    key = value.get("key")
    match = _SIGNED_KEY_RE.fullmatch(str(key))
    if (
        not isinstance(bucket, str)
        or _BUCKET_RE.fullmatch(bucket) is None
        or match is None
        or match.group("job") != job_id
        or any(part in {"", ".", ".."} for part in str(key).split("/"))
    ):
        raise BootstrapSignedArtifactError("SIGNING_JOB_DESTINATION_INVALID")
    return bucket, str(key)


def _read_exact_object(
    *, s3_client: Any, bucket: str, key: str, version_id: str
) -> tuple[bytes, Mapping[str, Any]]:
    """Head and read one immutable S3 version with a mandatory SHA-256."""

    common = {
        "Bucket": bucket,
        "Key": key,
        "VersionId": version_id,
        "ExpectedBucketOwner": AUTHORITY_ACCOUNT_ID,
        "ChecksumMode": "ENABLED",
    }
    head = _aws_call(s3_client.head_object, **common)
    content_length = head.get("ContentLength")
    if (
        head.get("VersionId") != version_id
        or type(content_length) is not int
        or not 0 < content_length <= MAX_ARCHIVE_BYTES
    ):
        raise BootstrapSignedArtifactError("S3_OBJECT_HEAD_INVALID")
    head_checksum = _checksum(
        head.get("ChecksumSHA256"), "S3_OBJECT_CHECKSUM_MISSING"
    )
    response = _aws_call(s3_client.get_object, **common)
    if (
        response.get("VersionId") != version_id
        or response.get("ContentLength") != content_length
        or _checksum(
            response.get("ChecksumSHA256"), "S3_OBJECT_CHECKSUM_MISSING"
        )
        != head_checksum
    ):
        raise BootstrapSignedArtifactError("S3_OBJECT_READBACK_DRIFT")
    body = response.get("Body")
    if body is None or not callable(getattr(body, "read", None)):
        raise BootstrapSignedArtifactError("S3_OBJECT_BODY_INVALID")
    try:
        payload = body.read(content_length + 1)
    except Exception as exc:
        raise BootstrapSignedArtifactError("S3_OBJECT_BODY_INVALID") from exc
    finally:
        close = getattr(body, "close", None)
        if callable(close):
            close()
    if not isinstance(payload, bytes) or len(payload) != content_length:
        raise BootstrapSignedArtifactError("S3_OBJECT_LENGTH_MISMATCH")
    computed = base64.b64encode(sha256(payload).digest()).decode("ascii")
    if computed != head_checksum:
        raise BootstrapSignedArtifactError("S3_OBJECT_CHECKSUM_MISMATCH")
    return payload, {
        "bucket": bucket,
        "key": key,
        "version_id": version_id,
        "content_length": content_length,
        "checksum_sha256": computed,
    }


def _single_signed_version(*, s3_client: Any, bucket: str, key: str) -> str:
    """Reject an overwritten or delete-marked AWS Signer destination key."""

    kwargs: dict[str, Any] = {
        "Bucket": bucket,
        "Prefix": key,
        "ExpectedBucketOwner": AUTHORITY_ACCOUNT_ID,
    }
    versions: list[Mapping[str, Any]] = []
    delete_markers: list[Mapping[str, Any]] = []
    for _ in range(MAX_S3_VERSION_PAGES):
        response = _aws_call(s3_client.list_object_versions, **kwargs)
        response_versions = response.get("Versions", [])
        response_markers = response.get("DeleteMarkers", [])
        if not isinstance(response_versions, list) or not isinstance(
            response_markers, list
        ):
            raise BootstrapSignedArtifactError("S3_VERSION_INVENTORY_INVALID")
        versions.extend(
            item
            for item in response_versions
            if isinstance(item, Mapping) and item.get("Key") == key
        )
        delete_markers.extend(
            item
            for item in response_markers
            if isinstance(item, Mapping) and item.get("Key") == key
        )
        truncated = response.get("IsTruncated", False)
        if type(truncated) is not bool:
            raise BootstrapSignedArtifactError("S3_VERSION_INVENTORY_INVALID")
        if not truncated:
            break
        next_key = response.get("NextKeyMarker")
        next_version = response.get("NextVersionIdMarker")
        if not isinstance(next_key, str) or not isinstance(next_version, str):
            raise BootstrapSignedArtifactError("S3_VERSION_PAGINATION_INVALID")
        kwargs["KeyMarker"] = next_key
        kwargs["VersionIdMarker"] = next_version
    else:
        raise BootstrapSignedArtifactError("S3_VERSION_PAGINATION_EXHAUSTED")
    if (
        delete_markers
        or len(versions) != 1
        or versions[0].get("IsLatest") is not True
    ):
        raise BootstrapSignedArtifactError("SIGNED_OBJECT_VERSION_AMBIGUOUS")
    return _strict_version_id(versions[0].get("VersionId"))


def _validate_signed_archive(
    *, signed_archive: bytes, unsigned_manifest: Mapping[str, Any]
) -> tuple[str, str]:
    if not signed_archive or len(signed_archive) > MAX_ARCHIVE_BYTES:
        raise BootstrapSignedArtifactError("SIGNED_ARCHIVE_INVALID")
    entries = unsigned_manifest.get("entries")
    if not isinstance(entries, list):
        raise BootstrapSignedArtifactError("UNSIGNED_MANIFEST_INVALID")
    expected: dict[str, Mapping[str, Any]] = {}
    for entry in entries:
        if (
            not isinstance(entry, Mapping)
            or set(entry) != {"path", "sha256", "size_bytes"}
            or not isinstance(entry.get("path"), str)
            or entry["path"] in expected
        ):
            raise BootstrapSignedArtifactError("UNSIGNED_MANIFEST_INVALID")
        expected[entry["path"]] = entry
    expected_paths = [path.as_posix() for path in PACKAGE_PATHS]
    if list(expected) != expected_paths:
        raise BootstrapSignedArtifactError("UNSIGNED_MANIFEST_PATH_SET_INVALID")
    try:
        with ZipFile(BytesIO(signed_archive), mode="r") as archive:
            names = archive.namelist()
            if len(names) != len(set(names)):
                raise BootstrapSignedArtifactError("SIGNED_ARCHIVE_DUPLICATE_PATH")
            if names != expected_paths:
                raise BootstrapSignedArtifactError("SIGNED_ARCHIVE_PATH_SET_INVALID")
            for item in archive.infolist():
                unix_mode = item.external_attr >> 16
                if item.flag_bits & 0x1 or unix_mode & 0o170000 == 0o120000:
                    raise BootstrapSignedArtifactError("SIGNED_ARCHIVE_ENTRY_UNSAFE")
            for path, entry in expected.items():
                payload = archive.read(path)
                if (
                    sha256(payload).hexdigest() != entry.get("sha256")
                    or len(payload) != entry.get("size_bytes")
                ):
                    raise BootstrapSignedArtifactError(
                        "SIGNED_ARCHIVE_SOURCE_ENTRY_DRIFT"
                    )
    except BootstrapSignedArtifactError:
        raise
    except (BadZipFile, KeyError, OSError):
        raise BootstrapSignedArtifactError("SIGNED_ARCHIVE_INVALID") from None
    digest = sha256(signed_archive).digest()
    return digest.hex(), base64.b64encode(digest).decode("ascii")


def _receipt_payload(receipt: Mapping[str, Any]) -> Mapping[str, Any]:
    return {
        key: value
        for key, value in receipt.items()
        if key not in {"receipt_digest", "cloudformation_parameters"}
    }


def _receipt_digest(payload: Mapping[str, Any]) -> str:
    preimage = RECEIPT_DOMAIN + b"\x00" + canonical_json(payload).encode("utf-8")
    return "sha256:" + sha256(preimage).hexdigest()


def _validate_source_review(evidence: Mapping[str, Any], source_commit: str) -> None:
    try:
        validate_github_source_review(evidence)
    except SourceReviewError as exc:
        raise BootstrapSignedArtifactError("SOURCE_REVIEW_INVALID") from exc
    if evidence.get("source_commit") != source_commit:
        raise BootstrapSignedArtifactError("SOURCE_REVIEW_COMMIT_DRIFT")


def _cloudformation_parameters(
    *, payload: Mapping[str, Any], receipt_digest: str
) -> list[Mapping[str, str]]:
    trust_root = payload["trust_root"]
    signed = payload["signed_artifact"]
    sdk = payload["expected_sdk_versions"]
    values = (
        ("AuthorityAccountId", trust_root["authority_account_id"]),
        ("AuthorityArtifactBucket", signed["bucket"]),
        ("AuthorityArtifactKey", signed["key"]),
        ("AuthorityArtifactVersion", signed["version"]),
        ("SignedAuthorityArtifactCodeSha256", signed["lambda_code_sha256"]),
        ("AuthoritySigningReceiptDigest", receipt_digest),
        (
            "AuthoritySigningTrustRootContractDigest",
            trust_root["contract_digest"],
        ),
        ("AuthoritySigningProfileName", trust_root["profile_name"]),
        ("AuthoritySigningProfileVersionId", trust_root["profile_version_id"]),
        ("SourceCommit", payload["source_commit"]),
        ("ExpectedBoto3Version", sdk["boto3"]),
        ("ExpectedBotocoreVersion", sdk["botocore"]),
    )
    return [
        {"ParameterKey": key, "ParameterValue": value} for key, value in values
    ]


def _build_signed_artifact_receipt(
    *,
    unsigned_manifest: Mapping[str, Any],
    downloaded_unsigned_archive: bytes,
    downloaded_signed_archive: bytes,
    signing_job: Mapping[str, Any],
    signed_object_head: Mapping[str, Any],
    signing_trust_root: Mapping[str, Any],
    source_review: Mapping[str, Any],
    verifier_identity: Mapping[str, Any],
    verifier_profile: str,
    now: datetime | None = None,
) -> Mapping[str, Any]:
    """Validate trusted readbacks and build the exact Change Set handoff."""

    source_commit = str(unsigned_manifest.get("source_commit", ""))
    validate_bootstrap_artifact_package(
        manifest=unsigned_manifest,
        archive=downloaded_unsigned_archive,
        expected_source_commit=source_commit,
    )
    if _COMMIT_RE.fullmatch(source_commit) is None:
        raise BootstrapSignedArtifactError("UNSIGNED_MANIFEST_INVALID")
    _validate_source_review(source_review, source_commit)
    evaluated = now or datetime.now(UTC).replace(microsecond=0)
    evaluated_at = _timestamp_text(evaluated, "EVALUATION_TIME_INVALID")
    validate_signing_trust_root_contract(
        signing_trust_root, require_configured=True
    )
    expected_profile_version_arn = str(
        signing_trust_root["profile_version_arn"]
    )
    profile_version_id = str(signing_trust_root["profile_version_id"])
    job_id = signing_job.get("jobId")
    if (
        not isinstance(job_id, str)
        or _JOB_RE.fullmatch(job_id) is None
        or signing_job.get("status") != "Succeeded"
        or signing_job.get("jobOwner") != AUTHORITY_ACCOUNT_ID
        or signing_job.get("jobInvoker") != AUTHORITY_ACCOUNT_ID
        or signing_job.get("platformId") != SIGNING_PLATFORM
        or signing_job.get("profileName") != SIGNING_PROFILE_NAME
        or signing_job.get("profileVersion") != profile_version_id
        or signing_job.get("revocationRecord") not in (None, {})
        or signing_job.get("overrides") not in (None, {})
        or signing_job.get("signingParameters") not in (None, {})
    ):
        raise BootstrapSignedArtifactError("SIGNING_JOB_NOT_EXACT")
    expires = _timestamp(
        signing_job.get("signatureExpiresAt"), "SIGNATURE_EXPIRY_INVALID"
    )
    if expires <= _timestamp(evaluated_at, "EVALUATION_TIME_INVALID"):
        raise BootstrapSignedArtifactError("SIGNATURE_EXPIRED")
    signature_expires_at = expires.isoformat().replace("+00:00", "Z")
    source_wrapper = signing_job.get("source")
    signed_wrapper = signing_job.get("signedObject")
    if not isinstance(source_wrapper, Mapping) or set(source_wrapper) != {"s3"}:
        raise BootstrapSignedArtifactError("SIGNING_JOB_SOURCE_INVALID")
    if not isinstance(signed_wrapper, Mapping) or set(signed_wrapper) != {"s3"}:
        raise BootstrapSignedArtifactError("SIGNING_JOB_DESTINATION_INVALID")
    source_bucket, source_key, source_version = _source_location(
        source_wrapper["s3"], source_commit=source_commit
    )
    signed_bucket, signed_key = _signed_location(
        signed_wrapper["s3"], job_id=job_id
    )
    if source_bucket != signed_bucket:
        raise BootstrapSignedArtifactError("SIGNING_BUCKET_MISMATCH")
    if downloaded_signed_archive == downloaded_unsigned_archive:
        raise BootstrapSignedArtifactError("SIGNED_ARCHIVE_UNVERIFIED")
    signed_archive_sha256, signed_code_sha256 = _validate_signed_archive(
        signed_archive=downloaded_signed_archive,
        unsigned_manifest=unsigned_manifest,
    )
    if (
        not isinstance(signed_object_head, Mapping)
        or set(signed_object_head)
        != {
            "bucket",
            "key",
            "version_id",
            "content_length",
            "checksum_sha256",
        }
        or signed_object_head.get("bucket") != signed_bucket
        or signed_object_head.get("key") != signed_key
        or signed_object_head.get("content_length")
        != len(downloaded_signed_archive)
        or signed_object_head.get("checksum_sha256") != signed_code_sha256
    ):
        raise BootstrapSignedArtifactError("SIGNED_OBJECT_HEAD_MISMATCH")
    signed_version = _strict_version_id(signed_object_head.get("version_id"))
    if (
        verifier_profile != EXPECTED_VERIFIER_PROFILE
        or verifier_identity.get("Account") != AUTHORITY_ACCOUNT_ID
        or _CALLER_ARN_RE.fullmatch(str(verifier_identity.get("Arn"))) is None
    ):
        raise BootstrapSignedArtifactError("VERIFIER_IDENTITY_INVALID")
    runtime = unsigned_manifest.get("runtime_dependencies")
    if not isinstance(runtime, Mapping):
        raise BootstrapSignedArtifactError("UNSIGNED_MANIFEST_INVALID")
    payload: dict[str, Any] = {
        "artifact_type": ARTIFACT_TYPE,
        "schema_version": SCHEMA_VERSION,
        "work_package": WORK_PACKAGE,
        "trust_root_generation": TRUST_ROOT_GENERATION,
        "source_commit": source_commit,
        "unsigned_manifest_sha256": sha256(
            canonical_json(unsigned_manifest).encode("utf-8")
        ).hexdigest(),
        "unsigned_archive_sha256": sha256(
            downloaded_unsigned_archive
        ).hexdigest(),
        "signing_trust_root_contract": dict(signing_trust_root),
        "trust_root": {
            "partition": PARTITION,
            "authority_account_id": AUTHORITY_ACCOUNT_ID,
            "region": REGION,
            "profile_name": SIGNING_PROFILE_NAME,
            "profile_version_id": profile_version_id,
            "profile_version_arn": expected_profile_version_arn,
            "signing_platform": SIGNING_PLATFORM,
            "code_signing_policy": CODE_SIGNING_POLICY,
            "contract_digest": signing_trust_root_contract_digest(
                signing_trust_root
            ),
        },
        "signing_job": {
            "job_id": job_id,
            "status": "Succeeded",
            "job_owner": AUTHORITY_ACCOUNT_ID,
            "job_invoker": AUTHORITY_ACCOUNT_ID,
            "signature_expires_at": signature_expires_at,
            "source": {
                "bucket": source_bucket,
                "key": source_key,
                "version": source_version,
            },
        },
        "signed_artifact": {
            "bucket": signed_bucket,
            "key": signed_key,
            "version": signed_version,
            "archive_sha256": signed_archive_sha256,
            "lambda_code_sha256": signed_code_sha256,
            "size_bytes": len(downloaded_signed_archive),
        },
        "expected_sdk_versions": {
            "boto3": runtime.get("expected_boto3_version"),
            "botocore": runtime.get("expected_botocore_version"),
        },
        "verifier": {
            "profile": verifier_profile,
            "account_id": verifier_identity.get("Account"),
            "caller_arn": verifier_identity.get("Arn"),
        },
        "source_review": dict(source_review),
        "evaluated_at": evaluated_at,
        "expires_at": min(
            expires, _timestamp(evaluated_at, "EVALUATION_TIME_INVALID") + RECEIPT_TTL
        )
        .isoformat()
        .replace("+00:00", "Z"),
        "evidence_status": EVIDENCE_STATUS,
        "production_status": PRODUCTION_STATUS,
    }
    receipt_digest = _receipt_digest(payload)
    receipt = {
        **payload,
        "receipt_digest": receipt_digest,
        "cloudformation_parameters": _cloudformation_parameters(
            payload=payload, receipt_digest=receipt_digest
        ),
    }
    validate_signed_artifact_receipt(
        receipt,
        now=_timestamp(evaluated_at, "EVALUATION_TIME_INVALID"),
    )
    return receipt


def validate_signed_artifact_receipt(
    receipt: Mapping[str, Any], *, now: datetime | None = None
) -> None:
    """Reject any receipt whose domain digest or CFN projection diverges."""

    required = {
        "artifact_type",
        "schema_version",
        "work_package",
        "trust_root_generation",
        "source_commit",
        "unsigned_manifest_sha256",
        "unsigned_archive_sha256",
        "signing_trust_root_contract",
        "trust_root",
        "signing_job",
        "signed_artifact",
        "expected_sdk_versions",
        "verifier",
        "source_review",
        "evaluated_at",
        "expires_at",
        "evidence_status",
        "production_status",
        "receipt_digest",
        "cloudformation_parameters",
    }
    if not isinstance(receipt, Mapping) or set(receipt) != required:
        raise BootstrapSignedArtifactError("SIGNED_RECEIPT_INVALID")
    payload = _receipt_payload(receipt)
    if (
        receipt.get("artifact_type") != ARTIFACT_TYPE
        or receipt.get("schema_version") != SCHEMA_VERSION
        or receipt.get("work_package") != WORK_PACKAGE
        or receipt.get("trust_root_generation") != TRUST_ROOT_GENERATION
        or receipt.get("evidence_status") != EVIDENCE_STATUS
        or receipt.get("production_status") != PRODUCTION_STATUS
        or _COMMIT_RE.fullmatch(str(receipt.get("source_commit"))) is None
        or _DIGEST_RE.fullmatch(str(receipt.get("unsigned_manifest_sha256")))
        is None
        or _DIGEST_RE.fullmatch(str(receipt.get("unsigned_archive_sha256")))
        is None
        or _DOMAIN_DIGEST_RE.fullmatch(str(receipt.get("receipt_digest"))) is None
        or receipt.get("receipt_digest") != _receipt_digest(payload)
    ):
        raise BootstrapSignedArtifactError("SIGNED_RECEIPT_INVALID")
    trust_root = receipt.get("trust_root")
    signing_trust_root = receipt.get("signing_trust_root_contract")
    signing_job = receipt.get("signing_job")
    signed = receipt.get("signed_artifact")
    sdk = receipt.get("expected_sdk_versions")
    verifier = receipt.get("verifier")
    source_review = receipt.get("source_review")
    if not isinstance(signing_trust_root, Mapping):
        raise BootstrapSignedArtifactError("TRUST_ROOT_CONTRACT_INVALID")
    validate_signing_trust_root_contract(
        signing_trust_root, require_configured=True
    )
    if (
        not isinstance(trust_root, Mapping)
        or set(trust_root)
        != {
            "partition",
            "authority_account_id",
            "region",
            "profile_name",
            "profile_version_id",
            "profile_version_arn",
            "signing_platform",
            "code_signing_policy",
            "contract_digest",
        }
        or trust_root.get("partition") != PARTITION
        or trust_root.get("authority_account_id") != AUTHORITY_ACCOUNT_ID
        or trust_root.get("region") != REGION
        or trust_root.get("profile_name") != SIGNING_PROFILE_NAME
        or trust_root.get("signing_platform") != SIGNING_PLATFORM
        or trust_root.get("code_signing_policy") != CODE_SIGNING_POLICY
        or _DOMAIN_DIGEST_RE.fullmatch(str(trust_root.get("contract_digest")))
        is None
        or trust_root.get("contract_digest")
        != signing_trust_root_contract_digest(signing_trust_root)
        or trust_root.get("partition") != signing_trust_root.get("partition")
        or trust_root.get("authority_account_id")
        != signing_trust_root.get("authority_account_id")
        or trust_root.get("region") != signing_trust_root.get("region")
        or trust_root.get("profile_name")
        != signing_trust_root.get("profile_name")
        or trust_root.get("profile_version_id")
        != signing_trust_root.get("profile_version_id")
        or trust_root.get("profile_version_arn")
        != signing_trust_root.get("profile_version_arn")
        or _PROFILE_VERSION_RE.fullmatch(
            str(trust_root.get("profile_version_id"))
        )
        is None
        or _PROFILE_ARN_RE.fullmatch(str(trust_root.get("profile_version_arn")))
        is None
        or not str(trust_root.get("profile_version_arn")).endswith(
            "/" + str(trust_root.get("profile_version_id"))
        )
    ):
        raise BootstrapSignedArtifactError("SIGNED_RECEIPT_TRUST_ROOT_INVALID")
    if not isinstance(signing_job, Mapping) or not isinstance(
        signing_job.get("source"), Mapping
    ):
        raise BootstrapSignedArtifactError("SIGNED_RECEIPT_SIGNING_JOB_INVALID")
    source = signing_job["source"]
    if (
        set(signing_job)
        != {
            "job_id",
            "status",
            "job_owner",
            "job_invoker",
            "signature_expires_at",
            "source",
        }
        or _JOB_RE.fullmatch(str(signing_job.get("job_id"))) is None
        or signing_job.get("status") != "Succeeded"
        or signing_job.get("job_owner") != AUTHORITY_ACCOUNT_ID
        or signing_job.get("job_invoker") != AUTHORITY_ACCOUNT_ID
        or set(source) != {"bucket", "key", "version"}
    ):
        raise BootstrapSignedArtifactError("SIGNED_RECEIPT_SIGNING_JOB_INVALID")
    source_bucket, source_key, source_version = _source_location(
        {
            "bucketName": source.get("bucket"),
            "key": source.get("key"),
            "version": source.get("version"),
        },
        source_commit=str(receipt["source_commit"]),
    )
    evaluated = _timestamp(receipt.get("evaluated_at"), "EVALUATION_TIME_INVALID")
    receipt_expires = _timestamp(
        receipt.get("expires_at"), "RECEIPT_EXPIRY_INVALID"
    )
    expires = _timestamp(
        signing_job.get("signature_expires_at"), "SIGNATURE_EXPIRY_INVALID"
    )
    current = now or datetime.now(UTC).replace(microsecond=0)
    if current.tzinfo is None or current.utcoffset() is None:
        raise BootstrapSignedArtifactError("EVALUATION_TIME_INVALID")
    current = current.astimezone(UTC)
    if current.microsecond:
        raise BootstrapSignedArtifactError("EVALUATION_TIME_INVALID")
    if (
        expires <= evaluated
        or receipt_expires <= evaluated
        or receipt_expires > expires
        or receipt_expires > evaluated + RECEIPT_TTL
        or current < evaluated - MAX_CLOCK_SKEW
        or current >= receipt_expires
    ):
        raise BootstrapSignedArtifactError("SIGNATURE_EXPIRED")
    if (
        not isinstance(signed, Mapping)
        or set(signed)
        != {
            "bucket",
            "key",
            "version",
            "archive_sha256",
            "lambda_code_sha256",
            "size_bytes",
        }
        or signed.get("bucket") != source_bucket
        or _BUCKET_RE.fullmatch(str(signed.get("bucket"))) is None
        or _SIGNED_KEY_RE.fullmatch(str(signed.get("key"))) is None
        or not str(signed.get("key")).endswith(
            f"/{signing_job['job_id']}.zip"
        )
        or type(signed.get("size_bytes")) is not int
        or not 0 < signed["size_bytes"] <= MAX_ARCHIVE_BYTES
        or _DIGEST_RE.fullmatch(str(signed.get("archive_sha256"))) is None
        or _CODE_SHA_RE.fullmatch(str(signed.get("lambda_code_sha256"))) is None
    ):
        raise BootstrapSignedArtifactError("SIGNED_RECEIPT_ARTIFACT_INVALID")
    _strict_version_id(source_version)
    _strict_version_id(signed.get("version"))
    try:
        decoded = base64.b64decode(signed["lambda_code_sha256"], validate=True)
    except (TypeError, ValueError):
        raise BootstrapSignedArtifactError("SIGNED_ARCHIVE_DIGEST_INVALID") from None
    if decoded.hex() != signed.get("archive_sha256"):
        raise BootstrapSignedArtifactError("SIGNED_ARCHIVE_DIGEST_MISMATCH")
    if (
        not isinstance(sdk, Mapping)
        or set(sdk) != {"boto3", "botocore"}
        or any(
            _SDK_VERSION_RE.fullmatch(str(value)) is None for value in sdk.values()
        )
    ):
        raise BootstrapSignedArtifactError("SIGNED_RECEIPT_SDK_INVALID")
    if (
        not isinstance(verifier, Mapping)
        or set(verifier) != {"profile", "account_id", "caller_arn"}
        or verifier.get("profile") != EXPECTED_VERIFIER_PROFILE
        or verifier.get("account_id") != AUTHORITY_ACCOUNT_ID
        or _CALLER_ARN_RE.fullmatch(str(verifier.get("caller_arn"))) is None
    ):
        raise BootstrapSignedArtifactError("SIGNED_RECEIPT_VERIFIER_INVALID")
    if not isinstance(source_review, Mapping):
        raise BootstrapSignedArtifactError("SOURCE_REVIEW_INVALID")
    _validate_source_review(source_review, str(receipt["source_commit"]))
    expected_parameters = _cloudformation_parameters(
        payload=payload, receipt_digest=str(receipt["receipt_digest"])
    )
    if receipt.get("cloudformation_parameters") != expected_parameters:
        raise BootstrapSignedArtifactError("CFN_PARAMETER_BINDING_DRIFT")
    if (
        source_key != source.get("key")
        or signed.get("key")
        != f"scanalyze/platform-authority/gug-274/signed/"
        f"{signing_job['job_id']}.zip"
    ):
        raise BootstrapSignedArtifactError("SIGNED_RECEIPT_LOCATION_INVALID")


def build_signed_artifact_receipt_from_aws(
    *,
    source_root: Path,
    source_commit: str,
    expected_boto3_version: str,
    expected_botocore_version: str,
    profile_name: str,
    job_id: str,
    sts_client: Any,
    signer_client: Any,
    s3_client: Any,
    now: datetime | None = None,
) -> Mapping[str, Any]:
    """Rebuild reviewed source and collect every provider fact read-only."""

    if (
        expected_boto3_version != EXPECTED_BOTO3_VERSION
        or expected_botocore_version != EXPECTED_BOTOCORE_VERSION
    ):
        raise BootstrapSignedArtifactError("SDK_RUNTIME_VERSION_UNREVIEWED")
    if profile_name != EXPECTED_VERIFIER_PROFILE:
        raise BootstrapSignedArtifactError("VERIFIER_PROFILE_INVALID")
    if _JOB_RE.fullmatch(job_id) is None:
        raise BootstrapSignedArtifactError("SIGNING_JOB_ID_INVALID")
    signing_trust_root = load_signing_trust_root_contract(
        source_root=source_root, require_configured=True
    )
    identity = _aws_call(sts_client.get_caller_identity)
    if (
        identity.get("Account") != AUTHORITY_ACCOUNT_ID
        or _CALLER_ARN_RE.fullmatch(str(identity.get("Arn"))) is None
    ):
        raise BootstrapSignedArtifactError("VERIFIER_IDENTITY_INVALID")
    reviewed: BuiltBootstrapArtifactPackage = build_bootstrap_artifact_package(
        source_root=source_root,
        source_commit=source_commit,
        expected_boto3_version=expected_boto3_version,
        expected_botocore_version=expected_botocore_version,
    )
    source_review = verify_reviewed_source_release(
        source_root=source_root, source_commit=source_commit
    )
    signing_job = _aws_call(signer_client.describe_signing_job, jobId=job_id)
    if signing_job.get("jobId") != job_id:
        raise BootstrapSignedArtifactError("SIGNING_JOB_ID_MISMATCH")
    source_wrapper = signing_job.get("source")
    signed_wrapper = signing_job.get("signedObject")
    if not isinstance(source_wrapper, Mapping) or set(source_wrapper) != {"s3"}:
        raise BootstrapSignedArtifactError("SIGNING_JOB_SOURCE_INVALID")
    if not isinstance(signed_wrapper, Mapping) or set(signed_wrapper) != {"s3"}:
        raise BootstrapSignedArtifactError("SIGNING_JOB_DESTINATION_INVALID")
    source_bucket, source_key, source_version = _source_location(
        source_wrapper["s3"], source_commit=source_commit
    )
    signed_bucket, signed_key = _signed_location(
        signed_wrapper["s3"], job_id=job_id
    )
    if source_bucket != signed_bucket:
        raise BootstrapSignedArtifactError("SIGNING_BUCKET_MISMATCH")
    versioning = _aws_call(
        s3_client.get_bucket_versioning,
        Bucket=source_bucket,
        ExpectedBucketOwner=AUTHORITY_ACCOUNT_ID,
    )
    if versioning.get("Status") != "Enabled":
        raise BootstrapSignedArtifactError("SIGNING_BUCKET_VERSIONING_NOT_ENABLED")
    downloaded_unsigned, unsigned_head = _read_exact_object(
        s3_client=s3_client,
        bucket=source_bucket,
        key=source_key,
        version_id=source_version,
    )
    if (
        unsigned_head.get("checksum_sha256")
        != reviewed.manifest.get("unsigned_archive_code_sha256")
        or downloaded_unsigned != reviewed.archive
    ):
        raise BootstrapSignedArtifactError("REVIEWED_SOURCE_ARCHIVE_MISMATCH")
    signed_version = _single_signed_version(
        s3_client=s3_client, bucket=signed_bucket, key=signed_key
    )
    downloaded_signed, signed_head = _read_exact_object(
        s3_client=s3_client,
        bucket=signed_bucket,
        key=signed_key,
        version_id=signed_version,
    )
    return _build_signed_artifact_receipt(
        unsigned_manifest=reviewed.manifest,
        downloaded_unsigned_archive=downloaded_unsigned,
        downloaded_signed_archive=downloaded_signed,
        signing_job=signing_job,
        signed_object_head=signed_head,
        signing_trust_root=signing_trust_root,
        source_review=source_review,
        verifier_identity=identity,
        verifier_profile=profile_name,
        now=now,
    )


def _immutable_receipt_projection(receipt: Mapping[str, Any]) -> Mapping[str, Any]:
    stable = dict(receipt)
    for field in (
        "evaluated_at",
        "expires_at",
        "receipt_digest",
        "cloudformation_parameters",
    ):
        stable.pop(field, None)
    return stable


def refresh_signed_artifact_receipt_read_only(
    *,
    source_root: Path,
    local_receipt: Mapping[str, Any],
    sts_client: Any,
    signer_client: Any,
    s3_client: Any,
    now: datetime | None = None,
) -> Mapping[str, Any]:
    """Refresh GitHub, Signer, and S3 before using any CFN parameter.

    A local receipt and its unkeyed domain digest are evidence containers, not
    authority.  This boundary recreates the receipt from fixed Git trust-root
    configuration and direct read-only provider evidence, then requires every
    immutable field to match before returning freshly derived parameters.
    """

    current = now or datetime.now(UTC).replace(microsecond=0)
    validate_signed_artifact_receipt(local_receipt, now=current)
    signing_job = local_receipt.get("signing_job")
    versions = local_receipt.get("expected_sdk_versions")
    if not isinstance(signing_job, Mapping) or not isinstance(versions, Mapping):
        raise BootstrapSignedArtifactError("SIGNED_RECEIPT_INPUT_INVALID")
    if versions != {
        "boto3": EXPECTED_BOTO3_VERSION,
        "botocore": EXPECTED_BOTOCORE_VERSION,
    }:
        raise BootstrapSignedArtifactError("SDK_RUNTIME_VERSION_UNREVIEWED")
    fresh = build_signed_artifact_receipt_from_aws(
        source_root=source_root,
        source_commit=str(local_receipt.get("source_commit")),
        expected_boto3_version=EXPECTED_BOTO3_VERSION,
        expected_botocore_version=EXPECTED_BOTOCORE_VERSION,
        profile_name=EXPECTED_VERIFIER_PROFILE,
        job_id=str(signing_job.get("job_id")),
        sts_client=sts_client,
        signer_client=signer_client,
        s3_client=s3_client,
        now=current,
    )
    if canonical_json(_immutable_receipt_projection(local_receipt)) != canonical_json(
        _immutable_receipt_projection(fresh)
    ):
        raise BootstrapSignedArtifactError("SIGNED_RECEIPT_PROVIDER_READBACK_DRIFT")
    return fresh


def write_signed_artifact_receipt(
    *, receipt: Mapping[str, Any], output_path: Path, source_root: Path
) -> None:
    """Write private evidence exactly once, outside Git, with mode 0600."""

    root = source_root.resolve(strict=True)
    requested_output = output_path.resolve(strict=False)
    try:
        requested_output.relative_to(root)
    except ValueError:
        pass
    else:
        raise BootstrapSignedArtifactError("OUTPUT_MUST_BE_OUTSIDE_SOURCE_ROOT")
    if output_path.is_symlink() or output_path.exists():
        raise BootstrapSignedArtifactError("SIGNED_RECEIPT_OUTPUT_EXISTS")
    validate_signed_artifact_receipt(receipt)
    payload = (canonical_json(receipt) + "\n").encode("utf-8")
    try:
        descriptor = os.open(
            output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        raise BootstrapSignedArtifactError("SIGNED_RECEIPT_WRITE_FAILED") from exc
