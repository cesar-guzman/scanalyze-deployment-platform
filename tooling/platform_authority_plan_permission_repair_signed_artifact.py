"""Read-only AWS Signer handoff for the GUG-376 repair Lambda package.

The GUG-221 signed-artifact contract cannot be reused directly because its
artifact type, S3 prefixes, runtime-lock shape, handlers, and CloudFormation
parameter names are deliberately closed to GUG-221.  This adapter reuses only
its repository/main/check verification routine; package and signing bindings
remain native, strict GUG-376 contracts.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from io import BytesIO
import os
from pathlib import Path
import re
from typing import Any, Callable, Mapping
from zipfile import BadZipFile, ZipFile

from tooling.platform_authority_lambda_audit_repair_signed_artifact import (
    SignedArtifactError as SourceReviewError,
    validate_github_source_review,
    verify_github_merged_release,
)
from tooling.platform_authority_plan_permission_repair_package import (
    CLOUDFORMATION_TEMPLATE_PATHS,
    PACKAGE_PATHS,
    BuiltPlanPermissionRepairPackage,
    PlanPermissionRepairPackageError,
    build_plan_permission_repair_package,
    canonical_json,
    reviewed_cloudformation_template_digests,
    validate_plan_permission_repair_package,
    verify_clean_source_commit,
)


ARTIFACT_TYPE = (
    "scanalyze.platform_authority."
    "plan_permission_repair_signed_artifact.v1"
)
SCHEMA_VERSION = 1
WORK_PACKAGE = "GUG-376"
AUTHORITY_ACCOUNT_ID = "042360977644"
REGION = "us-east-1"
SIGNING_PLATFORM = "AWSLambda-SHA384-ECDSA"
EVIDENCE_STATUS = "SIGNED_ARTIFACT_BOUND_FOR_CHANGE_SET_REVIEW"
PRODUCTION_STATUS = "NO-GO"
EXPECTED_VERIFIER_PROFILE = "042360977644_AWSReadOnlyAccess"
MAX_ARCHIVE_BYTES = 10 * 1024 * 1024
MAX_S3_VERSION_PAGES = 100
MAX_RECEIPT_AGE = timedelta(minutes=15)
MAX_CLOCK_SKEW = timedelta(minutes=1)

__all__ = (
    "EXPECTED_VERIFIER_PROFILE",
    "PlanPermissionRepairSignedArtifactError",
    "build_signed_artifact_receipt_from_aws",
    "validate_signed_artifact_receipt",
    "write_signed_artifact_receipt",
)

_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_BUNDLE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SDK_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_JOB_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}$"
)
_PROFILE_ARN_RE = re.compile(
    r"^arn:aws[a-z-]*:signer:us-east-1:042360977644:"
    r"/signing-profiles/(?P<name>[A-Za-z0-9_]{2,64})/"
    r"(?P<version>[A-Za-z0-9]{10})$"
)
_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
_SOURCE_KEY_RE = re.compile(
    r"^scanalyze/platform-authority/gug-376/plan-policy-repair/"
    r"unsigned/[A-Za-z0-9._/-]+\.zip$"
)
_SIGNED_KEY_RE = re.compile(
    r"^scanalyze/platform-authority/gug-376/plan-policy-repair/"
    r"signed/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}\.zip$"
)
_CALLER_ARN_RE = re.compile(
    r"^arn:aws:sts::042360977644:assumed-role/"
    r"AWSReservedSSO_AWSReadOnlyAccess_[0-9a-fA-F]{16}/"
    r"[A-Za-z0-9+=,.@_-]{1,64}$"
)
_CERTIFICATE_ARN_RE = re.compile(
    r"^arn:aws:acm:us-east-1:042360977644:certificate/"
    r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$"
)


class PlanPermissionRepairSignedArtifactError(ValueError):
    """Stable fail-closed signed-artifact contract violation."""


def _strict_version_id(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.casefold() == "null"
        or len(value.encode("utf-8")) > 1024
        or any(ord(character) < 32 for character in value)
    ):
        raise PlanPermissionRepairSignedArtifactError("S3_VERSION_INVALID")
    return value


def _timestamp(value: Any, code: str) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise PlanPermissionRepairSignedArtifactError(code)
        parsed = value.astimezone(UTC)
    elif isinstance(value, str) and value.endswith("Z"):
        try:
            parsed = datetime.fromisoformat(
                value[:-1] + "+00:00"
            ).astimezone(UTC)
        except ValueError as exc:
            raise PlanPermissionRepairSignedArtifactError(code) from exc
    else:
        raise PlanPermissionRepairSignedArtifactError(code)
    return parsed


def _timestamp_text(value: Any, code: str) -> str:
    return _timestamp(value, code).isoformat().replace("+00:00", "Z")


def _checksum(value: Any, code: str) -> str:
    if not isinstance(value, str):
        raise PlanPermissionRepairSignedArtifactError(code)
    try:
        decoded = base64.b64decode(value, validate=True)
    except (TypeError, ValueError) as exc:
        raise PlanPermissionRepairSignedArtifactError(code) from exc
    if len(decoded) != 32:
        raise PlanPermissionRepairSignedArtifactError(code)
    return value


def _optional_checksum(value: Any, code: str) -> str | None:
    if value is None:
        return None
    return _checksum(value, code)


def _aws_call(call: Any, /, **kwargs: Any) -> Mapping[str, Any]:
    try:
        response = call(**kwargs)
    except Exception as exc:  # botocore remains an optional CLI dependency
        raise PlanPermissionRepairSignedArtifactError(
            "AWS_READBACK_FAILED"
        ) from exc
    if not isinstance(response, Mapping):
        raise PlanPermissionRepairSignedArtifactError(
            "AWS_READBACK_INVALID"
        )
    return response


def _s3_location(value: Any, *, signed: bool) -> tuple[str, str, str | None]:
    allowed = ({"bucketName", "key"}, {"bucketName", "key", "version"})
    if not isinstance(value, Mapping) or set(value) not in allowed:
        raise PlanPermissionRepairSignedArtifactError(
            "SIGNING_JOB_S3_LOCATION_INVALID"
        )
    bucket = value.get("bucketName")
    key = value.get("key")
    pattern = _SIGNED_KEY_RE if signed else _SOURCE_KEY_RE
    if (
        not isinstance(bucket, str)
        or _BUCKET_RE.fullmatch(bucket) is None
        or not isinstance(key, str)
        or pattern.fullmatch(key) is None
        or any(part in {"", ".", ".."} for part in key.split("/"))
    ):
        raise PlanPermissionRepairSignedArtifactError(
            "SIGNING_JOB_S3_LOCATION_INVALID"
        )
    version = value.get("version")
    if signed:
        if version is not None:
            raise PlanPermissionRepairSignedArtifactError(
                "SIGNING_JOB_S3_LOCATION_INVALID"
            )
        return bucket, key, None
    return bucket, key, _strict_version_id(version)


def _read_exact_object(
    *, s3_client: Any, bucket: str, key: str, version_id: str
) -> tuple[bytes, Mapping[str, Any]]:
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
        raise PlanPermissionRepairSignedArtifactError(
            "S3_OBJECT_HEAD_INVALID"
        )
    head_checksum = _optional_checksum(
        head.get("ChecksumSHA256"),
        "S3_OBJECT_CHECKSUM_INVALID",
    )
    response = _aws_call(s3_client.get_object, **common)
    if (
        response.get("VersionId") != version_id
        or response.get("ContentLength") != content_length
    ):
        raise PlanPermissionRepairSignedArtifactError(
            "S3_OBJECT_READBACK_DRIFT"
        )
    response_checksum = _optional_checksum(
        response.get("ChecksumSHA256"),
        "S3_OBJECT_CHECKSUM_INVALID",
    )
    if (head_checksum is None) != (response_checksum is None) or (
        head_checksum is not None and head_checksum != response_checksum
    ):
        raise PlanPermissionRepairSignedArtifactError(
            "S3_OBJECT_CHECKSUM_DRIFT"
        )
    body = response.get("Body")
    if body is None or not callable(getattr(body, "read", None)):
        raise PlanPermissionRepairSignedArtifactError(
            "S3_OBJECT_BODY_INVALID"
        )
    try:
        payload = body.read(content_length + 1)
    except Exception as exc:
        raise PlanPermissionRepairSignedArtifactError(
            "S3_OBJECT_BODY_INVALID"
        ) from exc
    finally:
        close = getattr(body, "close", None)
        if callable(close):
            close()
    if not isinstance(payload, bytes) or len(payload) != content_length:
        raise PlanPermissionRepairSignedArtifactError(
            "S3_OBJECT_LENGTH_MISMATCH"
        )
    computed = base64.b64encode(sha256(payload).digest()).decode("ascii")
    if head_checksum is not None and computed != head_checksum:
        raise PlanPermissionRepairSignedArtifactError(
            "S3_OBJECT_CHECKSUM_MISMATCH"
        )
    return payload, {
        "bucket": bucket,
        "key": key,
        "version_id": version_id,
        "content_length": content_length,
        "checksum_sha256": computed,
        "checksum_provenance": (
            "S3_SHA256_AND_LOCAL"
            if head_checksum is not None
            else "LOCAL_SHA256_OF_EXACT_S3_VERSION"
        ),
    }


def _single_signed_version(*, s3_client: Any, bucket: str, key: str) -> str:
    kwargs: dict[str, Any] = {
        "Bucket": bucket,
        "Prefix": key,
        "ExpectedBucketOwner": AUTHORITY_ACCOUNT_ID,
    }
    versions: list[Mapping[str, Any]] = []
    delete_markers: list[Mapping[str, Any]] = []
    seen_markers: set[tuple[str, str]] = set()
    for _ in range(MAX_S3_VERSION_PAGES):
        response = _aws_call(s3_client.list_object_versions, **kwargs)
        page_versions = response.get("Versions", [])
        page_delete_markers = response.get("DeleteMarkers", [])
        if not isinstance(page_versions, list) or not isinstance(
            page_delete_markers, list
        ):
            raise PlanPermissionRepairSignedArtifactError(
                "S3_VERSION_INVENTORY_INVALID"
            )
        versions.extend(
            item
            for item in page_versions
            if isinstance(item, Mapping) and item.get("Key") == key
        )
        delete_markers.extend(
            item
            for item in page_delete_markers
            if isinstance(item, Mapping) and item.get("Key") == key
        )
        truncated = response.get("IsTruncated", False)
        if type(truncated) is not bool:
            raise PlanPermissionRepairSignedArtifactError(
                "S3_VERSION_INVENTORY_INVALID"
            )
        if not truncated:
            break
        next_key = response.get("NextKeyMarker")
        next_version = response.get("NextVersionIdMarker")
        marker = (str(next_key), str(next_version))
        if (
            not isinstance(next_key, str)
            or not isinstance(next_version, str)
            or not next_key
            or not next_version
            or marker in seen_markers
        ):
            raise PlanPermissionRepairSignedArtifactError(
                "S3_VERSION_PAGINATION_INVALID"
            )
        seen_markers.add(marker)
        kwargs["KeyMarker"] = next_key
        kwargs["VersionIdMarker"] = next_version
    else:
        raise PlanPermissionRepairSignedArtifactError(
            "S3_VERSION_PAGINATION_EXHAUSTED"
        )
    if (
        delete_markers
        or len(versions) != 1
        or versions[0].get("IsLatest") is not True
    ):
        raise PlanPermissionRepairSignedArtifactError(
            "SIGNED_OBJECT_VERSION_AMBIGUOUS"
        )
    return _strict_version_id(versions[0].get("VersionId"))


def _digest_text(value: str) -> str:
    return "sha256:" + sha256(value.encode("utf-8")).hexdigest()


def _certificate_revocation_hash(
    *, certificate_pem: Any, certificate_chain_pem: Any
) -> str:
    """Return the exact Signer composite SHA-384 certificate identifier."""

    if not isinstance(certificate_pem, str) or not isinstance(
        certificate_chain_pem, str
    ):
        raise PlanPermissionRepairSignedArtifactError(
            "SIGNING_CERTIFICATE_INVALID"
        )
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
        raise PlanPermissionRepairSignedArtifactError(
            "SIGNING_CERTIFICATE_INVALID"
        ) from exc
    if re.fullmatch(r"[0-9a-f]{192}", value) is None:
        raise PlanPermissionRepairSignedArtifactError(
            "SIGNING_CERTIFICATE_INVALID"
        )
    return value


def _verify_revocation_status(
    *,
    signing_job: Mapping[str, Any],
    profile_version_arn: str,
    acm_client: Any,
    signer_data_client: Any,
    checked_at: datetime,
) -> Mapping[str, Any]:
    material = signing_job.get("signingMaterial")
    certificate_arn = (
        material.get("certificateArn")
        if isinstance(material, Mapping)
        else None
    )
    if (
        not isinstance(certificate_arn, str)
        or _CERTIFICATE_ARN_RE.fullmatch(certificate_arn) is None
    ):
        raise PlanPermissionRepairSignedArtifactError(
            "SIGNING_CERTIFICATE_ARN_INVALID"
        )
    signature_timestamp = _timestamp(
        signing_job.get("completedAt"),
        "SIGNATURE_TIMESTAMP_INVALID",
    )
    certificate = _aws_call(
        acm_client.get_certificate,
        CertificateArn=certificate_arn,
    )
    certificate_hash = _certificate_revocation_hash(
        certificate_pem=certificate.get("Certificate"),
        certificate_chain_pem=certificate.get("CertificateChain"),
    )
    job_arn = (
        f"arn:aws:signer:{REGION}:{AUTHORITY_ACCOUNT_ID}:"
        f"/signing-jobs/{signing_job['jobId']}"
    )
    response = _aws_call(
        signer_data_client.get_revocation_status,
        signatureTimestamp=signature_timestamp,
        platformId=SIGNING_PLATFORM,
        profileVersionArn=profile_version_arn,
        jobArn=job_arn,
        certificateHashes=[certificate_hash],
    )
    revoked = response.get("revokedEntities", [])
    if not isinstance(revoked, list) or any(
        not isinstance(item, str) or not item for item in revoked
    ):
        raise PlanPermissionRepairSignedArtifactError(
            "REVOCATION_READBACK_INVALID"
        )
    if revoked:
        raise PlanPermissionRepairSignedArtifactError(
            "SIGNED_ARTIFACT_REVOKED"
        )
    return {
        "status": "PROFILE_JOB_AND_CERTIFICATE_NOT_REVOKED",
        "checked_at": _timestamp_text(
            checked_at, "REVOCATION_CHECK_TIME_INVALID"
        ),
        "profile_version_arn_digest": _digest_text(profile_version_arn),
        "job_arn_digest": _digest_text(job_arn),
        "certificate_hash_digest": _digest_text(certificate_hash),
    }


def _manifest_entries(
    manifest: Mapping[str, Any],
) -> dict[str, Mapping[str, Any]]:
    entries = manifest.get("entries")
    if not isinstance(entries, list):
        raise PlanPermissionRepairSignedArtifactError(
            "UNSIGNED_MANIFEST_INVALID"
        )
    result: dict[str, Mapping[str, Any]] = {}
    for entry in entries:
        if (
            not isinstance(entry, Mapping)
            or set(entry) != {"path", "sha256", "size_bytes"}
            or not isinstance(entry.get("path"), str)
            or str(entry["path"]) in result
        ):
            raise PlanPermissionRepairSignedArtifactError(
                "UNSIGNED_MANIFEST_INVALID"
            )
        result[str(entry["path"])] = entry
    if set(result) != {path.as_posix() for path in PACKAGE_PATHS}:
        raise PlanPermissionRepairSignedArtifactError(
            "UNSIGNED_MANIFEST_PATH_SET_INVALID"
        )
    return result


def _build_signed_artifact_receipt_from_trusted_readbacks(
    *,
    unsigned_manifest: Mapping[str, Any],
    downloaded_unsigned_archive: bytes,
    downloaded_signed_archive: bytes,
    signing_job: Mapping[str, Any],
    signed_object_head: Mapping[str, Any],
    expected_profile_version_arn: str,
    verifier_identity: Mapping[str, Any],
    verifier_profile: str,
    source_review: Mapping[str, Any],
    revocation_check: Mapping[str, Any],
    cloudformation_template_digests: Mapping[str, str],
    now: datetime | None = None,
) -> Mapping[str, Any]:
    """Bind values derived by the AWS/Git adapter to the exact CFN tuple.

    This private constructor is a trusted-readback boundary.  Production
    callers must use :func:`build_signed_artifact_receipt_from_aws`, which
    derives the template digests and certificate revocation binding rather
    than accepting either value from an operator.
    """

    try:
        validate_plan_permission_repair_package(
            archive=downloaded_unsigned_archive,
            manifest=unsigned_manifest,
        )
    except PlanPermissionRepairPackageError as exc:
        raise PlanPermissionRepairSignedArtifactError(
            "UNSIGNED_PACKAGE_INVALID"
        ) from exc
    evaluated = now or datetime.now(UTC)
    if evaluated.tzinfo is None or evaluated.utcoffset() is None:
        raise PlanPermissionRepairSignedArtifactError(
            "EVALUATION_TIME_INVALID"
        )
    evaluated = evaluated.astimezone(UTC)
    evaluated_at = _timestamp_text(evaluated, "EVALUATION_TIME_INVALID")
    profile_match = _PROFILE_ARN_RE.fullmatch(expected_profile_version_arn)
    if profile_match is None:
        raise PlanPermissionRepairSignedArtifactError(
            "SIGNING_PROFILE_INVALID"
        )
    signing_material = signing_job.get("signingMaterial")
    certificate_arn = (
        signing_material.get("certificateArn")
        if isinstance(signing_material, Mapping)
        else None
    )
    if (
        signing_job.get("status") != "Succeeded"
        or signing_job.get("jobOwner") != AUTHORITY_ACCOUNT_ID
        or signing_job.get("jobInvoker") != AUTHORITY_ACCOUNT_ID
        or signing_job.get("platformId") != SIGNING_PLATFORM
        or signing_job.get("profileName") != profile_match.group("name")
        or signing_job.get("profileVersion") != profile_match.group("version")
        or _JOB_RE.fullmatch(str(signing_job.get("jobId"))) is None
        or signing_job.get("revocationRecord") not in (None, {})
        or signing_job.get("overrides") not in (None, {})
        or signing_job.get("signingParameters") not in (None, {})
        or not isinstance(certificate_arn, str)
        or _CERTIFICATE_ARN_RE.fullmatch(certificate_arn) is None
    ):
        raise PlanPermissionRepairSignedArtifactError(
            "SIGNING_JOB_NOT_EXACT"
        )
    expires = _timestamp(
        signing_job.get("signatureExpiresAt"),
        "SIGNATURE_EXPIRY_INVALID",
    )
    if expires <= evaluated:
        raise PlanPermissionRepairSignedArtifactError("SIGNATURE_EXPIRED")
    signature_timestamp = _timestamp(
        signing_job.get("completedAt"),
        "SIGNATURE_TIMESTAMP_INVALID",
    )
    if signature_timestamp > evaluated or signature_timestamp >= expires:
        raise PlanPermissionRepairSignedArtifactError(
            "SIGNATURE_TIMESTAMP_INVALID"
        )
    signature_timestamp_text = _timestamp_text(
        signature_timestamp, "SIGNATURE_TIMESTAMP_INVALID"
    )
    expires_at = _timestamp_text(expires, "SIGNATURE_EXPIRY_INVALID")
    source_wrapper = signing_job.get("source")
    signed_wrapper = signing_job.get("signedObject")
    if not isinstance(source_wrapper, Mapping) or set(source_wrapper) != {"s3"}:
        raise PlanPermissionRepairSignedArtifactError(
            "SIGNING_JOB_SOURCE_INVALID"
        )
    if not isinstance(signed_wrapper, Mapping) or set(signed_wrapper) != {"s3"}:
        raise PlanPermissionRepairSignedArtifactError(
            "SIGNING_JOB_DESTINATION_INVALID"
        )
    source_bucket, source_key, source_version = _s3_location(
        source_wrapper["s3"], signed=False
    )
    signed_bucket, signed_key, _ = _s3_location(
        signed_wrapper["s3"], signed=True
    )
    if (
        source_bucket != signed_bucket
        or signed_key
        != (
            "scanalyze/platform-authority/gug-376/plan-policy-repair/"
            f"signed/{signing_job['jobId']}.zip"
        )
    ):
        raise PlanPermissionRepairSignedArtifactError(
            "SIGNING_BUCKET_MISMATCH"
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
            "checksum_provenance",
        }
        or signed_object_head.get("bucket") != signed_bucket
        or signed_object_head.get("key") != signed_key
        or signed_object_head.get("content_length")
        != len(downloaded_signed_archive)
    ):
        raise PlanPermissionRepairSignedArtifactError(
            "SIGNED_OBJECT_HEAD_MISMATCH"
        )
    signed_version = _strict_version_id(
        signed_object_head.get("version_id")
    )
    checksum_provenance = signed_object_head.get("checksum_provenance")
    if checksum_provenance not in {
        "S3_SHA256_AND_LOCAL",
        "LOCAL_SHA256_OF_EXACT_S3_VERSION",
    }:
        raise PlanPermissionRepairSignedArtifactError(
            "SIGNED_OBJECT_HEAD_MISMATCH"
        )
    if (
        not downloaded_signed_archive
        or downloaded_signed_archive == downloaded_unsigned_archive
    ):
        raise PlanPermissionRepairSignedArtifactError(
            "SIGNED_ARCHIVE_UNVERIFIED"
        )
    expected_entries = _manifest_entries(unsigned_manifest)
    try:
        with ZipFile(BytesIO(downloaded_signed_archive), mode="r") as package:
            names = package.namelist()
            if names != [path.as_posix() for path in PACKAGE_PATHS]:
                raise PlanPermissionRepairSignedArtifactError(
                    "SIGNED_ARCHIVE_PATH_SET_INVALID"
                )
            for info in package.infolist():
                unix_mode = info.external_attr >> 16
                if info.flag_bits & 0x1 or unix_mode & 0o170000 == 0o120000:
                    raise PlanPermissionRepairSignedArtifactError(
                        "SIGNED_ARCHIVE_ENTRY_UNSAFE"
                    )
                payload = package.read(info)
                expected = expected_entries[info.filename]
                if (
                    sha256(payload).hexdigest() != expected["sha256"]
                    or len(payload) != expected["size_bytes"]
                ):
                    raise PlanPermissionRepairSignedArtifactError(
                        "SIGNED_ARCHIVE_SOURCE_ENTRY_DRIFT"
                    )
    except PlanPermissionRepairSignedArtifactError:
        raise
    except (BadZipFile, KeyError, OSError, RuntimeError) as exc:
        raise PlanPermissionRepairSignedArtifactError(
            "SIGNED_ARCHIVE_INVALID"
        ) from exc
    signed_digest = sha256(downloaded_signed_archive).digest()
    signed_code_sha = base64.b64encode(signed_digest).decode("ascii")
    if (
        _checksum(
            signed_object_head.get("checksum_sha256"),
            "SIGNED_OBJECT_CHECKSUM_MISSING",
        )
        != signed_code_sha
    ):
        raise PlanPermissionRepairSignedArtifactError(
            "SIGNED_OBJECT_CHECKSUM_MISMATCH"
        )
    try:
        validate_github_source_review(source_review)
    except SourceReviewError as exc:
        raise PlanPermissionRepairSignedArtifactError(
            "SOURCE_REVIEW_EVIDENCE_INVALID"
        ) from exc
    if source_review.get("source_commit") != unsigned_manifest["source_commit"]:
        raise PlanPermissionRepairSignedArtifactError(
            "SOURCE_REVIEW_EVIDENCE_DRIFT"
        )
    expected_template_paths = {
        path.as_posix() for path in CLOUDFORMATION_TEMPLATE_PATHS
    }
    if (
        not isinstance(cloudformation_template_digests, Mapping)
        or set(cloudformation_template_digests) != expected_template_paths
        or any(
            not isinstance(digest, str)
            or _DIGEST_RE.fullmatch(digest) is None
            for digest in cloudformation_template_digests.values()
        )
    ):
        raise PlanPermissionRepairSignedArtifactError(
            "CLOUDFORMATION_TEMPLATE_BINDING_INVALID"
        )
    job_arn = (
        f"arn:aws:signer:{REGION}:{AUTHORITY_ACCOUNT_ID}:"
        f"/signing-jobs/{signing_job['jobId']}"
    )
    if (
        not isinstance(revocation_check, Mapping)
        or set(revocation_check)
        != {
            "status",
            "checked_at",
            "profile_version_arn_digest",
            "job_arn_digest",
            "certificate_hash_digest",
        }
        or revocation_check.get("status")
        != "PROFILE_JOB_AND_CERTIFICATE_NOT_REVOKED"
        or revocation_check.get("checked_at") != evaluated_at
        or revocation_check.get("profile_version_arn_digest")
        != _digest_text(expected_profile_version_arn)
        or revocation_check.get("job_arn_digest") != _digest_text(job_arn)
        or _SOURCE_BUNDLE_DIGEST_RE.fullmatch(
            str(revocation_check.get("certificate_hash_digest"))
        )
        is None
    ):
        raise PlanPermissionRepairSignedArtifactError(
            "REVOCATION_BINDING_INVALID"
        )
    runtime = unsigned_manifest["runtime_dependencies"]
    parameters = [
        {
            "ParameterKey": "SourceCommit",
            "ParameterValue": unsigned_manifest["source_commit"],
        },
        {
            "ParameterKey": "SourceBundleDigest",
            "ParameterValue": unsigned_manifest["source_bundle_digest"],
        },
        {
            "ParameterKey": "ExpectedBoto3Version",
            "ParameterValue": runtime["expected_boto3_version"],
        },
        {
            "ParameterKey": "ExpectedBotocoreVersion",
            "ParameterValue": runtime["expected_botocore_version"],
        },
        {"ParameterKey": "ArtifactBucket", "ParameterValue": signed_bucket},
        {"ParameterKey": "ArtifactKey", "ParameterValue": signed_key},
        {
            "ParameterKey": "ArtifactVersion",
            "ParameterValue": signed_version,
        },
        {
            "ParameterKey": "ArtifactCodeSha256",
            "ParameterValue": signed_code_sha,
        },
        {
            "ParameterKey": "SigningProfileVersionArn",
            "ParameterValue": expected_profile_version_arn,
        },
    ]
    receipt = {
        "artifact_type": ARTIFACT_TYPE,
        "schema_version": SCHEMA_VERSION,
        "work_package": WORK_PACKAGE,
        "source_commit": unsigned_manifest["source_commit"],
        "source_bundle_digest": unsigned_manifest["source_bundle_digest"],
        "unsigned_manifest_sha256": sha256(
            canonical_json(unsigned_manifest).encode("utf-8")
        ).hexdigest(),
        "unsigned_archive_sha256": sha256(
            downloaded_unsigned_archive
        ).hexdigest(),
        "signing_job": {
            "job_id": signing_job["jobId"],
            "job_owner": AUTHORITY_ACCOUNT_ID,
            "platform_id": SIGNING_PLATFORM,
            "profile_version_arn": expected_profile_version_arn,
            "signature_expires_at": expires_at,
            "signature_timestamp": signature_timestamp_text,
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
            "archive_sha256": signed_digest.hex(),
            "lambda_code_sha256": signed_code_sha,
            "size_bytes": len(downloaded_signed_archive),
            "checksum_provenance": checksum_provenance,
        },
        "expected_sdk_versions": {
            "boto3": runtime["expected_boto3_version"],
            "botocore": runtime["expected_botocore_version"],
        },
        "verifier": {
            "profile": verifier_profile,
            "account_id": verifier_identity.get("Account"),
            "caller_arn": verifier_identity.get("Arn"),
        },
        "source_review": dict(source_review),
        "revocation_check": dict(revocation_check),
        "cloudformation_templates": [
            {
                "path": path.as_posix(),
                "sha256": cloudformation_template_digests[
                    path.as_posix()
                ],
            }
            for path in CLOUDFORMATION_TEMPLATE_PATHS
        ],
        "cloudformation_parameters": parameters,
        "evaluated_at": evaluated_at,
        "evidence_status": EVIDENCE_STATUS,
        "production_status": PRODUCTION_STATUS,
    }
    validate_signed_artifact_receipt(receipt, now=evaluated)
    return receipt


def validate_signed_artifact_receipt(
    receipt: Mapping[str, Any], *, now: datetime | None = None
) -> None:
    """Reject a receipt whose duplicated package/CFN bindings diverge."""

    required = {
        "artifact_type",
        "schema_version",
        "work_package",
        "source_commit",
        "source_bundle_digest",
        "unsigned_manifest_sha256",
        "unsigned_archive_sha256",
        "signing_job",
        "signed_artifact",
        "expected_sdk_versions",
        "verifier",
        "source_review",
        "revocation_check",
        "cloudformation_templates",
        "cloudformation_parameters",
        "evaluated_at",
        "evidence_status",
        "production_status",
    }
    if (
        set(receipt) != required
        or receipt.get("artifact_type") != ARTIFACT_TYPE
        or receipt.get("schema_version") != SCHEMA_VERSION
        or receipt.get("work_package") != WORK_PACKAGE
        or receipt.get("evidence_status") != EVIDENCE_STATUS
        or receipt.get("production_status") != PRODUCTION_STATUS
        or _COMMIT_RE.fullmatch(str(receipt.get("source_commit"))) is None
        or _SOURCE_BUNDLE_DIGEST_RE.fullmatch(
            str(receipt.get("source_bundle_digest"))
        )
        is None
        or _DIGEST_RE.fullmatch(
            str(receipt.get("unsigned_manifest_sha256"))
        )
        is None
        or _DIGEST_RE.fullmatch(
            str(receipt.get("unsigned_archive_sha256"))
        )
        is None
    ):
        raise PlanPermissionRepairSignedArtifactError(
            "SIGNED_RECEIPT_INVALID"
        )
    signing = receipt.get("signing_job")
    signed = receipt.get("signed_artifact")
    sdk = receipt.get("expected_sdk_versions")
    verifier = receipt.get("verifier")
    source_review = receipt.get("source_review")
    revocation = receipt.get("revocation_check")
    templates = receipt.get("cloudformation_templates")
    parameters = receipt.get("cloudformation_parameters")
    if not isinstance(signing, Mapping) or not isinstance(signed, Mapping):
        raise PlanPermissionRepairSignedArtifactError(
            "SIGNED_RECEIPT_INVALID"
        )
    source = signing.get("source")
    if (
        set(signing)
        != {
            "job_id",
            "job_owner",
            "platform_id",
            "profile_version_arn",
            "signature_expires_at",
            "signature_timestamp",
            "source",
        }
        or _JOB_RE.fullmatch(str(signing.get("job_id"))) is None
        or signing.get("job_owner") != AUTHORITY_ACCOUNT_ID
        or signing.get("platform_id") != SIGNING_PLATFORM
        or _PROFILE_ARN_RE.fullmatch(
            str(signing.get("profile_version_arn"))
        )
        is None
        or not isinstance(source, Mapping)
        or set(source) != {"bucket", "key", "version"}
        or _BUCKET_RE.fullmatch(str(source.get("bucket"))) is None
        or _SOURCE_KEY_RE.fullmatch(str(source.get("key"))) is None
    ):
        raise PlanPermissionRepairSignedArtifactError(
            "SIGNED_RECEIPT_SIGNING_JOB_INVALID"
        )
    _strict_version_id(source.get("version"))
    if (
        set(signed)
        != {
            "bucket",
            "key",
            "version",
            "archive_sha256",
            "lambda_code_sha256",
            "size_bytes",
            "checksum_provenance",
        }
        or signed.get("bucket") != source.get("bucket")
        or _SIGNED_KEY_RE.fullmatch(str(signed.get("key"))) is None
        or not str(signed.get("key")).endswith(
            f"/{signing['job_id']}.zip"
        )
        or type(signed.get("size_bytes")) is not int
        or not 0 < int(signed["size_bytes"]) <= MAX_ARCHIVE_BYTES
        or signed.get("checksum_provenance")
        not in {
            "S3_SHA256_AND_LOCAL",
            "LOCAL_SHA256_OF_EXACT_S3_VERSION",
        }
    ):
        raise PlanPermissionRepairSignedArtifactError(
            "SIGNED_RECEIPT_ARTIFACT_INVALID"
        )
    _strict_version_id(signed.get("version"))
    if (
        not isinstance(sdk, Mapping)
        or set(sdk) != {"boto3", "botocore"}
        or any(
            _SDK_VERSION_RE.fullmatch(str(value)) is None
            for value in sdk.values()
        )
    ):
        raise PlanPermissionRepairSignedArtifactError(
            "SIGNED_RECEIPT_INVALID"
        )
    if (
        not isinstance(verifier, Mapping)
        or set(verifier) != {"profile", "account_id", "caller_arn"}
        or verifier.get("profile") != EXPECTED_VERIFIER_PROFILE
        or verifier.get("account_id") != AUTHORITY_ACCOUNT_ID
        or _CALLER_ARN_RE.fullmatch(str(verifier.get("caller_arn"))) is None
    ):
        raise PlanPermissionRepairSignedArtifactError(
            "SIGNED_RECEIPT_VERIFIER_INVALID"
        )
    if not isinstance(source_review, Mapping):
        raise PlanPermissionRepairSignedArtifactError(
            "SIGNED_RECEIPT_SOURCE_REVIEW_INVALID"
        )
    try:
        validate_github_source_review(source_review)
    except SourceReviewError as exc:
        raise PlanPermissionRepairSignedArtifactError(
            "SIGNED_RECEIPT_SOURCE_REVIEW_INVALID"
        ) from exc
    if source_review.get("source_commit") != receipt.get("source_commit"):
        raise PlanPermissionRepairSignedArtifactError(
            "SIGNED_RECEIPT_SOURCE_REVIEW_DRIFT"
        )
    expected_template_paths = [
        path.as_posix() for path in CLOUDFORMATION_TEMPLATE_PATHS
    ]
    if (
        not isinstance(templates, list)
        or len(templates) != len(expected_template_paths)
        or any(
            not isinstance(item, Mapping)
            or set(item) != {"path", "sha256"}
            or item.get("path") != path
            or _DIGEST_RE.fullmatch(str(item.get("sha256"))) is None
            for item, path in zip(
                templates, expected_template_paths, strict=True
            )
        )
    ):
        raise PlanPermissionRepairSignedArtifactError(
            "CLOUDFORMATION_TEMPLATE_BINDING_INVALID"
        )
    job_arn = (
        f"arn:aws:signer:{REGION}:{AUTHORITY_ACCOUNT_ID}:"
        f"/signing-jobs/{signing['job_id']}"
    )
    if (
        not isinstance(revocation, Mapping)
        or set(revocation)
        != {
            "status",
            "checked_at",
            "profile_version_arn_digest",
            "job_arn_digest",
            "certificate_hash_digest",
        }
        or revocation.get("status")
        != "PROFILE_JOB_AND_CERTIFICATE_NOT_REVOKED"
        or revocation.get("profile_version_arn_digest")
        != _digest_text(str(signing["profile_version_arn"]))
        or revocation.get("job_arn_digest") != _digest_text(job_arn)
        or _SOURCE_BUNDLE_DIGEST_RE.fullmatch(
            str(revocation.get("certificate_hash_digest"))
        )
        is None
    ):
        raise PlanPermissionRepairSignedArtifactError(
            "REVOCATION_BINDING_INVALID"
        )
    keys = (
        "SourceCommit",
        "SourceBundleDigest",
        "ExpectedBoto3Version",
        "ExpectedBotocoreVersion",
        "ArtifactBucket",
        "ArtifactKey",
        "ArtifactVersion",
        "ArtifactCodeSha256",
        "SigningProfileVersionArn",
    )
    if not isinstance(parameters, list) or len(parameters) != len(keys):
        raise PlanPermissionRepairSignedArtifactError(
            "CFN_PARAMETER_BINDING_INVALID"
        )
    values: dict[str, str] = {}
    for key, parameter in zip(keys, parameters, strict=True):
        if (
            not isinstance(parameter, Mapping)
            or set(parameter) != {"ParameterKey", "ParameterValue"}
            or parameter.get("ParameterKey") != key
            or not isinstance(parameter.get("ParameterValue"), str)
        ):
            raise PlanPermissionRepairSignedArtifactError(
                "CFN_PARAMETER_BINDING_INVALID"
            )
        values[key] = str(parameter["ParameterValue"])
    expected = {
        "SourceCommit": str(receipt["source_commit"]),
        "SourceBundleDigest": str(receipt["source_bundle_digest"]),
        "ExpectedBoto3Version": str(sdk["boto3"]),
        "ExpectedBotocoreVersion": str(sdk["botocore"]),
        "ArtifactBucket": str(signed["bucket"]),
        "ArtifactKey": str(signed["key"]),
        "ArtifactVersion": str(signed["version"]),
        "ArtifactCodeSha256": str(signed["lambda_code_sha256"]),
        "SigningProfileVersionArn": str(signing["profile_version_arn"]),
    }
    if values != expected:
        raise PlanPermissionRepairSignedArtifactError(
            "CFN_PARAMETER_BINDING_DRIFT"
        )
    archive_digest = signed.get("archive_sha256")
    code_digest = signed.get("lambda_code_sha256")
    if _DIGEST_RE.fullmatch(str(archive_digest)) is None:
        raise PlanPermissionRepairSignedArtifactError(
            "SIGNED_ARCHIVE_DIGEST_INVALID"
        )
    try:
        decoded = base64.b64decode(str(code_digest), validate=True)
    except (TypeError, ValueError) as exc:
        raise PlanPermissionRepairSignedArtifactError(
            "SIGNED_ARCHIVE_DIGEST_INVALID"
        ) from exc
    if decoded.hex() != archive_digest:
        raise PlanPermissionRepairSignedArtifactError(
            "SIGNED_ARCHIVE_DIGEST_MISMATCH"
        )
    evaluated = _timestamp(
        receipt.get("evaluated_at"), "EVALUATION_TIME_INVALID"
    )
    checked = _timestamp(
        revocation.get("checked_at"), "REVOCATION_BINDING_INVALID"
    )
    signature_timestamp = _timestamp(
        signing.get("signature_timestamp"),
        "SIGNATURE_TIMESTAMP_INVALID",
    )
    expires = _timestamp(
        signing.get("signature_expires_at"),
        "SIGNATURE_EXPIRY_INVALID",
    )
    consumed = now or datetime.now(UTC)
    if consumed.tzinfo is None or consumed.utcoffset() is None:
        raise PlanPermissionRepairSignedArtifactError(
            "CONSUMPTION_TIME_INVALID"
        )
    consumed = consumed.astimezone(UTC)
    if (
        checked != evaluated
        or signature_timestamp > evaluated
        or signature_timestamp >= expires
        or evaluated > consumed + MAX_CLOCK_SKEW
        or consumed - evaluated > MAX_RECEIPT_AGE
    ):
        raise PlanPermissionRepairSignedArtifactError(
            "SIGNED_RECEIPT_STALE"
        )
    if expires <= consumed:
        raise PlanPermissionRepairSignedArtifactError("SIGNATURE_EXPIRED")


def build_signed_artifact_receipt_from_aws(
    *,
    source_root: Path,
    source_commit: str,
    expected_boto3_version: str,
    expected_botocore_version: str,
    profile_name: str,
    job_id: str,
    expected_profile_version_arn: str,
    sts_client: Any,
    signer_client: Any,
    signer_data_client: Any,
    acm_client: Any,
    s3_client: Any,
    now: datetime | None = None,
    source_review_verifier: Callable[..., Mapping[str, Any]] = (
        verify_github_merged_release
    ),
) -> Mapping[str, Any]:
    """Rebuild main and read one exact completed Signer job without writes."""

    if profile_name != EXPECTED_VERIFIER_PROFILE:
        raise PlanPermissionRepairSignedArtifactError(
            "VERIFIER_PROFILE_INVALID"
        )
    if _JOB_RE.fullmatch(job_id) is None:
        raise PlanPermissionRepairSignedArtifactError(
            "SIGNING_JOB_ID_INVALID"
        )
    evaluated = now or datetime.now(UTC)
    if evaluated.tzinfo is None or evaluated.utcoffset() is None:
        raise PlanPermissionRepairSignedArtifactError(
            "EVALUATION_TIME_INVALID"
        )
    evaluated = evaluated.astimezone(UTC)
    identity = _aws_call(sts_client.get_caller_identity)
    if (
        identity.get("Account") != AUTHORITY_ACCOUNT_ID
        or _CALLER_ARN_RE.fullmatch(str(identity.get("Arn"))) is None
    ):
        raise PlanPermissionRepairSignedArtifactError(
            "VERIFIER_IDENTITY_INVALID"
        )
    committed_sources = verify_clean_source_commit(
        source_root=source_root,
        source_commit=source_commit,
    )
    template_digests = reviewed_cloudformation_template_digests(
        source_root=source_root,
        source_commit=source_commit,
    )
    try:
        source_review = source_review_verifier(
            source_root=source_root,
            source_commit=source_commit,
        )
    except SourceReviewError as exc:
        raise PlanPermissionRepairSignedArtifactError(
            "SOURCE_REVIEW_FAILED"
        ) from exc
    reviewed: BuiltPlanPermissionRepairPackage = (
        build_plan_permission_repair_package(
            source_root=source_root,
            source_commit=source_commit,
            expected_boto3_version=expected_boto3_version,
            expected_botocore_version=expected_botocore_version,
            committed_sources=committed_sources,
        )
    )
    signing_job = _aws_call(
        signer_client.describe_signing_job,
        jobId=job_id,
    )
    if signing_job.get("jobId") != job_id:
        raise PlanPermissionRepairSignedArtifactError(
            "SIGNING_JOB_ID_MISMATCH"
        )
    source_wrapper = signing_job.get("source")
    signed_wrapper = signing_job.get("signedObject")
    if not isinstance(source_wrapper, Mapping) or set(source_wrapper) != {"s3"}:
        raise PlanPermissionRepairSignedArtifactError(
            "SIGNING_JOB_SOURCE_INVALID"
        )
    if not isinstance(signed_wrapper, Mapping) or set(signed_wrapper) != {"s3"}:
        raise PlanPermissionRepairSignedArtifactError(
            "SIGNING_JOB_DESTINATION_INVALID"
        )
    source_bucket, source_key, source_version = _s3_location(
        source_wrapper["s3"], signed=False
    )
    signed_bucket, signed_key, _ = _s3_location(
        signed_wrapper["s3"], signed=True
    )
    if source_version is None or source_bucket != signed_bucket:
        raise PlanPermissionRepairSignedArtifactError(
            "SIGNING_JOB_LOCATION_NOT_EXACT"
        )
    versioning = _aws_call(
        s3_client.get_bucket_versioning,
        Bucket=source_bucket,
        ExpectedBucketOwner=AUTHORITY_ACCOUNT_ID,
    )
    if versioning.get("Status") != "Enabled":
        raise PlanPermissionRepairSignedArtifactError(
            "SIGNING_BUCKET_VERSIONING_NOT_ENABLED"
        )
    downloaded_unsigned, unsigned_head = _read_exact_object(
        s3_client=s3_client,
        bucket=source_bucket,
        key=source_key,
        version_id=source_version,
    )
    if (
        unsigned_head["checksum_sha256"]
        != reviewed.manifest["lambda_code_sha256"]
        or downloaded_unsigned != reviewed.archive
    ):
        raise PlanPermissionRepairSignedArtifactError(
            "REVIEWED_SOURCE_ARCHIVE_MISMATCH"
        )
    signed_version = _single_signed_version(
        s3_client=s3_client,
        bucket=signed_bucket,
        key=signed_key,
    )
    downloaded_signed, signed_head = _read_exact_object(
        s3_client=s3_client,
        bucket=signed_bucket,
        key=signed_key,
        version_id=signed_version,
    )
    revocation_check = _verify_revocation_status(
        signing_job=signing_job,
        profile_version_arn=expected_profile_version_arn,
        acm_client=acm_client,
        signer_data_client=signer_data_client,
        checked_at=evaluated,
    )
    return _build_signed_artifact_receipt_from_trusted_readbacks(
        unsigned_manifest=reviewed.manifest,
        downloaded_unsigned_archive=downloaded_unsigned,
        downloaded_signed_archive=downloaded_signed,
        signing_job=signing_job,
        signed_object_head=signed_head,
        expected_profile_version_arn=expected_profile_version_arn,
        verifier_identity=identity,
        verifier_profile=profile_name,
        source_review=source_review,
        revocation_check=revocation_check,
        cloudformation_template_digests=template_digests,
        now=evaluated,
    )


def write_signed_artifact_receipt(
    *, receipt: Mapping[str, Any], output_path: Path, source_root: Path
) -> None:
    """Write private evidence once with owner-only permissions."""

    root = source_root.resolve(strict=True)
    requested = output_path.resolve(strict=False)
    try:
        requested.relative_to(root)
    except ValueError:
        pass
    else:
        raise PlanPermissionRepairSignedArtifactError(
            "OUTPUT_MUST_BE_OUTSIDE_SOURCE_ROOT"
        )
    validate_signed_artifact_receipt(receipt)
    payload = (canonical_json(receipt) + "\n").encode("utf-8")
    try:
        descriptor = os.open(
            output_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        raise PlanPermissionRepairSignedArtifactError(
            "SIGNED_RECEIPT_WRITE_FAILED"
        ) from exc
