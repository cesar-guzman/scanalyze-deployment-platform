"""Verify the AWS Signer handoff for the private GUG-221 Lambda package.

The public entry point rebuilds the package from one clean reviewed Git commit
and obtains every Signer/S3 fact through read-only AWS clients.  Operator-
supplied readback JSON and downloaded archives are deliberately not accepted.
The resulting receipt is the only artifact tuple eligible for a reviewed
CloudFormation Change Set.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Mapping
from zipfile import BadZipFile, ZipFile

from tooling.platform_authority_lambda_audit_repair_package import (
    ARTIFACT_TYPE as UNSIGNED_ARTIFACT_TYPE,
    BuiltRepairPackage,
    HANDLERS,
    PACKAGE_PATHS,
    PRODUCTION_STATUS,
    build_repair_package,
    canonical_json,
    verify_clean_source_commit,
)


ARTIFACT_TYPE = "scanalyze.platform_authority.lambda_audit_repair_signed_artifact.v1"
SCHEMA_VERSION = 1
WORK_PACKAGE = "GUG-221"
AUTHORITY_ACCOUNT_ID = "042360977644"
REGION = "us-east-1"
SIGNING_PLATFORM = "AWSLambda-SHA384-ECDSA"
EVIDENCE_STATUS = "SIGNED_ARTIFACT_BOUND_FOR_CHANGE_SET_REVIEW"
EXPECTED_VERIFIER_PROFILE = "042360977644_ReadOnlyAccess"
MAX_ARCHIVE_BYTES = 10 * 1024 * 1024
MAX_S3_VERSION_PAGES = 100
GITHUB_REPOSITORY = "cesar-guzman/scanalyze-deployment-platform"
GITHUB_MAIN_REF = "refs/remotes/origin/main"
GITHUB_RELEASE_STATUS = "MERGED_MAIN_REQUIRED_CHECKS_VERIFIED"
GITHUB_ACTIONS_APP_ID = 15368
REQUIRED_GITHUB_CHECKS = (
    "Microservices validation gate",
    "Lint, security, and schema checks",
    "Python tests",
    "Terraform validate (no AWS)",
    "Validate deployment manifest schema",
    "Verify clean clone reproducibility",
)

_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_SDK_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_JOB_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_PROFILE_ARN_RE = re.compile(
    r"^arn:aws:signer:us-east-1:042360977644:/signing-profiles/"
    r"(?P<name>[A-Za-z0-9_]{2,64})/(?P<version>[A-Za-z0-9]{10})$"
)
_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
_SOURCE_KEY_RE = re.compile(
    r"^scanalyze/platform-authority/gug-221/unsigned/[A-Za-z0-9._/-]+\.zip$"
)
_SIGNED_KEY_RE = re.compile(
    r"^scanalyze/platform-authority/gug-221/signed/[A-Za-z0-9._/-]+\.zip$"
)
_CALLER_ARN_RE = re.compile(
    r"^arn:aws:sts::042360977644:assumed-role/"
    r"AWSReservedSSO_AWSReadOnlyAccess_[0-9a-f]{16}/[A-Za-z0-9+=,.@_-]{1,64}$"
)


class SignedArtifactError(ValueError):
    """A stable fail-closed signed-artifact contract violation."""


def _strict_version_id(value: Any) -> str:
    if not isinstance(value, str) or not value or value.casefold() == "null":
        raise SignedArtifactError("S3_VERSION_INVALID")
    if len(value.encode("utf-8")) > 1024 or any(ord(char) < 32 for char in value):
        raise SignedArtifactError("S3_VERSION_INVALID")
    return value


def _timestamp(value: Any, code: str) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise SignedArtifactError(code)
        return value.astimezone(UTC)
    if isinstance(value, str) and value.endswith("Z"):
        try:
            parsed = datetime.fromisoformat(value[:-1] + "+00:00").astimezone(UTC)
        except ValueError as exc:
            raise SignedArtifactError(code) from exc
        if not parsed.microsecond:
            return parsed
    raise SignedArtifactError(code)


def _manifest_entries(manifest: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    entries = manifest.get("entries")
    if not isinstance(entries, list):
        raise SignedArtifactError("UNSIGNED_MANIFEST_INVALID")
    result: dict[str, Mapping[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, Mapping) or set(entry) != {"path", "sha256", "size_bytes"}:
            raise SignedArtifactError("UNSIGNED_MANIFEST_INVALID")
        path = entry.get("path")
        digest = entry.get("sha256")
        size = entry.get("size_bytes")
        if (
            not isinstance(path, str)
            or path in result
            or _DIGEST_RE.fullmatch(str(digest)) is None
            or type(size) is not int
            or size < 0
        ):
            raise SignedArtifactError("UNSIGNED_MANIFEST_INVALID")
        result[path] = dict(entry)
    expected = {path.as_posix() for path in PACKAGE_PATHS}
    if set(result) != expected:
        raise SignedArtifactError("UNSIGNED_MANIFEST_PATH_SET_INVALID")
    return result


def validate_unsigned_bundle(
    *, manifest: Mapping[str, Any], downloaded_archive: bytes
) -> None:
    """Prove the downloaded source S3 version is the reviewed manifest bundle."""

    required = {
        "artifact_type", "schema_version", "work_package", "source_commit",
        "archive_name", "archive_format", "archive_sha256", "lambda_code_sha256",
        "archive_size_bytes", "handlers", "runtime_dependencies", "entries",
        "production_status",
    }
    if set(manifest) != required:
        raise SignedArtifactError("UNSIGNED_MANIFEST_INVALID")
    if (
        manifest.get("artifact_type") != UNSIGNED_ARTIFACT_TYPE
        or manifest.get("schema_version") != 1
        or manifest.get("work_package") != WORK_PACKAGE
        or _COMMIT_RE.fullmatch(str(manifest.get("source_commit"))) is None
        or manifest.get("archive_name") != "scanalyze-gug221-lambda-audit-repair.zip"
        or manifest.get("archive_format") != "ZIP_STORED_FIXED_METADATA"
        or manifest.get("handlers") != dict(sorted(HANDLERS.items()))
        or manifest.get("production_status") != PRODUCTION_STATUS
    ):
        raise SignedArtifactError("UNSIGNED_MANIFEST_INVALID")
    digest = sha256(downloaded_archive).digest()
    if (
        manifest.get("archive_sha256") != digest.hex()
        or manifest.get("lambda_code_sha256") != base64.b64encode(digest).decode("ascii")
        or manifest.get("archive_size_bytes") != len(downloaded_archive)
    ):
        raise SignedArtifactError("UNSIGNED_ARCHIVE_DIGEST_MISMATCH")
    entries = _manifest_entries(manifest)
    runtime_dependencies = manifest.get("runtime_dependencies")
    if (
        not isinstance(runtime_dependencies, Mapping)
        or set(runtime_dependencies)
        != {
            "aws_sdk",
            "runtime_lock_path",
            "expected_boto3_version",
            "expected_botocore_version",
        }
        or runtime_dependencies.get("aws_sdk")
        != "AWS_MANAGED_PINNED_BY_RUNTIME_VERSION_GUARD"
        or runtime_dependencies.get("runtime_lock_path") != "gug221_runtime_lock.json"
        or _SDK_VERSION_RE.fullmatch(
            str(runtime_dependencies.get("expected_boto3_version"))
        )
        is None
        or _SDK_VERSION_RE.fullmatch(
            str(runtime_dependencies.get("expected_botocore_version"))
        )
        is None
    ):
        raise SignedArtifactError("UNSIGNED_RUNTIME_LOCK_INVALID")
    try:
        from io import BytesIO

        with ZipFile(BytesIO(downloaded_archive), mode="r") as archive:
            if archive.namelist() != sorted(entries):
                raise SignedArtifactError("UNSIGNED_ARCHIVE_PATH_SET_INVALID")
            for path, expected in entries.items():
                payload = archive.read(path)
                if (
                    sha256(payload).hexdigest() != expected["sha256"]
                    or len(payload) != expected["size_bytes"]
                ):
                    raise SignedArtifactError("UNSIGNED_ARCHIVE_ENTRY_MISMATCH")
            try:
                runtime_lock = json.loads(archive.read("gug221_runtime_lock.json"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise SignedArtifactError("UNSIGNED_RUNTIME_LOCK_INVALID") from exc
            if runtime_lock != {
                "record_type": "scanalyze.platform_authority.lambda_audit_repair_runtime_lock.v1",
                "schema_version": 1,
                "source_commit": manifest["source_commit"],
                "expected_boto3_version": runtime_dependencies["expected_boto3_version"],
                "expected_botocore_version": runtime_dependencies["expected_botocore_version"],
            }:
                raise SignedArtifactError("UNSIGNED_RUNTIME_LOCK_INVALID")
    except BadZipFile as exc:
        raise SignedArtifactError("UNSIGNED_ARCHIVE_INVALID") from exc


def _s3_location(value: Any, *, signed: bool) -> tuple[str, str, str | None]:
    if not isinstance(value, Mapping) or set(value) not in ({"bucketName", "key"}, {"bucketName", "key", "version"}):
        raise SignedArtifactError("SIGNING_JOB_S3_LOCATION_INVALID")
    bucket = value.get("bucketName")
    key = value.get("key")
    if not isinstance(bucket, str) or _BUCKET_RE.fullmatch(bucket) is None:
        raise SignedArtifactError("SIGNING_JOB_S3_LOCATION_INVALID")
    pattern = _SIGNED_KEY_RE if signed else _SOURCE_KEY_RE
    if (
        not isinstance(key, str)
        or pattern.fullmatch(key) is None
        or any(part in {"", ".", ".."} for part in key.split("/"))
    ):
        raise SignedArtifactError("SIGNING_JOB_S3_LOCATION_INVALID")
    version = value.get("version")
    if signed:
        if version is not None:
            raise SignedArtifactError("SIGNING_JOB_S3_LOCATION_INVALID")
        return bucket, key, None
    return bucket, key, _strict_version_id(version)


def _aws_call(call: Any, /, **kwargs: Any) -> Mapping[str, Any]:
    """Call one read-only SDK operation without exposing provider details."""

    try:
        response = call(**kwargs)
    except Exception as exc:  # botocore is an optional CLI dependency
        raise SignedArtifactError("AWS_READBACK_FAILED") from exc
    if not isinstance(response, Mapping):
        raise SignedArtifactError("AWS_READBACK_INVALID")
    return response


def _command_text(*, source_root: Path, command: list[str]) -> str:
    try:
        result = subprocess.run(
            command,
            cwd=source_root,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SignedArtifactError("SOURCE_RELEASE_READBACK_FAILED") from exc
    return result.stdout.strip()


def _command_json(*, source_root: Path, command: list[str]) -> Any:
    payload = _command_text(source_root=source_root, command=command)
    try:
        return json.loads(payload)
    except json.JSONDecodeError as exc:
        raise SignedArtifactError("SOURCE_RELEASE_READBACK_INVALID") from exc


def verify_github_merged_release(
    *, source_root: Path, source_commit: str
) -> Mapping[str, Any]:
    """Prove the candidate is merged to origin/main with required PR checks."""

    allowed_remotes = {
        f"https://github.com/{GITHUB_REPOSITORY}.git",
        f"git@github.com:{GITHUB_REPOSITORY}.git",
    }
    remote = _command_text(
        source_root=source_root,
        command=["git", "remote", "get-url", "origin"],
    )
    main_commit = _command_text(
        source_root=source_root,
        command=["git", "rev-parse", "--verify", GITHUB_MAIN_REF],
    )
    if remote not in allowed_remotes or main_commit != source_commit:
        raise SignedArtifactError("SOURCE_NOT_EXACT_ORIGIN_MAIN")

    remote_main = _command_json(
        source_root=source_root,
        command=["gh", "api", f"repos/{GITHUB_REPOSITORY}/branches/main"],
    )
    remote_main_commit = (
        remote_main.get("commit") if isinstance(remote_main, Mapping) else None
    )
    if (
        not isinstance(remote_main_commit, Mapping)
        or remote_main_commit.get("sha") != source_commit
        or remote_main.get("protected") is not True
    ):
        raise SignedArtifactError("SOURCE_NOT_CURRENT_PROTECTED_MAIN")
    protection = _command_json(
        source_root=source_root,
        command=[
            "gh", "api",
            f"repos/{GITHUB_REPOSITORY}/branches/main/protection/required_status_checks",
        ],
    )
    protected_checks = protection.get("checks") if isinstance(protection, Mapping) else None
    if (
        protection.get("strict") is not True
        if isinstance(protection, Mapping)
        else True
    ):
        raise SignedArtifactError("SOURCE_BRANCH_PROTECTION_NOT_STRICT")
    protected_contexts = protection.get("contexts")
    if (
        not isinstance(protected_checks, list)
        or len(protected_checks) != len(REQUIRED_GITHUB_CHECKS)
        or not all(isinstance(item, Mapping) for item in protected_checks)
        or not isinstance(protected_contexts, list)
        or set(protected_contexts) != set(REQUIRED_GITHUB_CHECKS)
        or len(protected_contexts) != len(REQUIRED_GITHUB_CHECKS)
        or {
        (item.get("context"), item.get("app_id"))
        for item in protected_checks
        if isinstance(item, Mapping)
        } != {(name, GITHUB_ACTIONS_APP_ID) for name in REQUIRED_GITHUB_CHECKS}
    ):
        raise SignedArtifactError("SOURCE_REQUIRED_CHECK_POLICY_DRIFT")

    pulls = _command_json(
        source_root=source_root,
        command=[
            "gh", "api",
            f"repos/{GITHUB_REPOSITORY}/commits/{source_commit}/pulls",
            "-H", "Accept: application/vnd.github+json",
        ],
    )
    if not isinstance(pulls, list):
        raise SignedArtifactError("SOURCE_PULL_REQUEST_READBACK_INVALID")
    merged = [
        pull
        for pull in pulls
        if isinstance(pull, Mapping)
        and pull.get("merged_at")
        and pull.get("merge_commit_sha") == source_commit
        and isinstance(pull.get("base"), Mapping)
        and pull["base"].get("ref") == "main"
    ]
    if len(merged) != 1:
        raise SignedArtifactError("SOURCE_MERGED_PULL_REQUEST_NOT_EXACT")
    pull = merged[0]
    head = pull.get("head")
    if (
        type(pull.get("number")) is not int
        or pull["number"] <= 0
        or not isinstance(head, Mapping)
        or _COMMIT_RE.fullmatch(str(head.get("sha"))) is None
    ):
        raise SignedArtifactError("SOURCE_PULL_REQUEST_READBACK_INVALID")
    head_commit = str(head["sha"])
    source_git = _command_json(
        source_root=source_root,
        command=["gh", "api", f"repos/{GITHUB_REPOSITORY}/git/commits/{source_commit}"],
    )
    head_git = _command_json(
        source_root=source_root,
        command=["gh", "api", f"repos/{GITHUB_REPOSITORY}/git/commits/{head_commit}"],
    )
    source_tree = source_git.get("tree") if isinstance(source_git, Mapping) else None
    head_tree = head_git.get("tree") if isinstance(head_git, Mapping) else None
    if (
        not isinstance(source_tree, Mapping)
        or not isinstance(head_tree, Mapping)
        or _COMMIT_RE.fullmatch(str(source_tree.get("sha"))) is None
        or source_tree.get("sha") != head_tree.get("sha")
    ):
        raise SignedArtifactError("SOURCE_PULL_REQUEST_TREE_MISMATCH")

    check_readback = _command_json(
        source_root=source_root,
        command=[
            "gh", "api",
            f"repos/{GITHUB_REPOSITORY}/commits/{head_commit}/check-runs?per_page=100",
            "-H", "Accept: application/vnd.github+json",
        ],
    )
    if not isinstance(check_readback, Mapping):
        raise SignedArtifactError("SOURCE_CHECK_READBACK_INVALID")
    check_runs = check_readback.get("check_runs")
    total_count = check_readback.get("total_count")
    if (
        not isinstance(check_runs, list)
        or type(total_count) is not int
        or total_count != len(check_runs)
        or total_count > 100
    ):
        raise SignedArtifactError("SOURCE_CHECK_READBACK_INCOMPLETE")
    successful: dict[str, Mapping[str, Any]] = {}
    for check in check_runs:
        if not isinstance(check, Mapping) or not isinstance(check.get("name"), str):
            raise SignedArtifactError("SOURCE_CHECK_READBACK_INVALID")
        name = str(check["name"])
        if name in REQUIRED_GITHUB_CHECKS:
            app = check.get("app")
            if (
                check.get("head_sha") != head_commit
                or not isinstance(app, Mapping)
                or app.get("id") != GITHUB_ACTIONS_APP_ID
                or app.get("slug") != "github-actions"
            ):
                raise SignedArtifactError("SOURCE_CHECK_PROVENANCE_INVALID")
            if name in successful:
                raise SignedArtifactError("SOURCE_CHECK_DUPLICATE")
            successful[name] = check
    if set(successful) != set(REQUIRED_GITHUB_CHECKS) or any(
        check.get("status") != "completed" or check.get("conclusion") != "success"
        for check in successful.values()
    ):
        raise SignedArtifactError("SOURCE_REQUIRED_CHECK_NOT_GREEN")
    evidence = {
        "repository": GITHUB_REPOSITORY,
        "branch": "main",
        "source_commit": source_commit,
        "source_tree": source_tree["sha"],
        "pull_request_number": pull["number"],
        "pull_request_head_commit": head_commit,
        "pull_request_head_tree": head_tree["sha"],
        "merged_at": pull["merged_at"],
        "required_checks": [
            {
                "name": name,
                "conclusion": "success",
                "app_id": GITHUB_ACTIONS_APP_ID,
                "app_slug": "github-actions",
            }
            for name in REQUIRED_GITHUB_CHECKS
        ],
        "branch_protection_strict": True,
        "evidence_status": GITHUB_RELEASE_STATUS,
    }
    validate_github_source_review(evidence)
    return evidence


def validate_github_source_review(evidence: Mapping[str, Any]) -> None:
    """Validate the exact auditable source-review projection."""

    required = {
        "repository", "branch", "source_commit", "source_tree",
        "pull_request_number", "pull_request_head_commit",
        "pull_request_head_tree", "merged_at", "required_checks",
        "branch_protection_strict", "evidence_status",
    }
    checks = evidence.get("required_checks")
    if (
        set(evidence) != required
        or evidence.get("repository") != GITHUB_REPOSITORY
        or evidence.get("branch") != "main"
        or evidence.get("evidence_status") != GITHUB_RELEASE_STATUS
        or evidence.get("branch_protection_strict") is not True
        or _COMMIT_RE.fullmatch(str(evidence.get("source_commit"))) is None
        or _COMMIT_RE.fullmatch(str(evidence.get("source_tree"))) is None
        or _COMMIT_RE.fullmatch(str(evidence.get("pull_request_head_commit"))) is None
        or evidence.get("pull_request_head_tree") != evidence.get("source_tree")
        or type(evidence.get("pull_request_number")) is not int
        or evidence["pull_request_number"] <= 0
        or not isinstance(evidence.get("merged_at"), str)
        or not evidence["merged_at"].endswith("Z")
        or not isinstance(checks, list)
        or checks
        != [
            {
                "name": name,
                "conclusion": "success",
                "app_id": GITHUB_ACTIONS_APP_ID,
                "app_slug": "github-actions",
            }
            for name in REQUIRED_GITHUB_CHECKS
        ]
    ):
        raise SignedArtifactError("SOURCE_REVIEW_EVIDENCE_INVALID")
    _timestamp(evidence.get("merged_at"), "SOURCE_REVIEW_EVIDENCE_INVALID")


def _checksum(value: Any, code: str) -> str:
    if not isinstance(value, str):
        raise SignedArtifactError(code)
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise SignedArtifactError(code) from exc
    if len(decoded) != 32:
        raise SignedArtifactError(code)
    return value


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
        raise SignedArtifactError("S3_OBJECT_HEAD_INVALID")
    head_checksum = _checksum(head.get("ChecksumSHA256"), "S3_OBJECT_CHECKSUM_MISSING")
    response = _aws_call(s3_client.get_object, **common)
    if (
        response.get("VersionId") != version_id
        or response.get("ContentLength") != content_length
        or _checksum(response.get("ChecksumSHA256"), "S3_OBJECT_CHECKSUM_MISSING")
        != head_checksum
    ):
        raise SignedArtifactError("S3_OBJECT_READBACK_DRIFT")
    body = response.get("Body")
    if body is None or not callable(getattr(body, "read", None)):
        raise SignedArtifactError("S3_OBJECT_BODY_INVALID")
    try:
        payload = body.read(content_length + 1)
    except Exception as exc:
        raise SignedArtifactError("S3_OBJECT_BODY_INVALID") from exc
    finally:
        close = getattr(body, "close", None)
        if callable(close):
            close()
    if not isinstance(payload, bytes) or len(payload) != content_length:
        raise SignedArtifactError("S3_OBJECT_LENGTH_MISMATCH")
    computed = base64.b64encode(sha256(payload).digest()).decode("ascii")
    if computed != head_checksum:
        raise SignedArtifactError("S3_OBJECT_CHECKSUM_MISMATCH")
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
        if not isinstance(response_versions, list) or not isinstance(response_markers, list):
            raise SignedArtifactError("S3_VERSION_INVENTORY_INVALID")
        versions.extend(
            item for item in response_versions
            if isinstance(item, Mapping) and item.get("Key") == key
        )
        delete_markers.extend(
            item for item in response_markers
            if isinstance(item, Mapping) and item.get("Key") == key
        )
        truncated = response.get("IsTruncated", False)
        if type(truncated) is not bool:
            raise SignedArtifactError("S3_VERSION_INVENTORY_INVALID")
        if not truncated:
            break
        next_key = response.get("NextKeyMarker")
        next_version = response.get("NextVersionIdMarker")
        if not isinstance(next_key, str) or not isinstance(next_version, str):
            raise SignedArtifactError("S3_VERSION_PAGINATION_INVALID")
        kwargs["KeyMarker"] = next_key
        kwargs["VersionIdMarker"] = next_version
    else:
        raise SignedArtifactError("S3_VERSION_PAGINATION_EXHAUSTED")
    if delete_markers or len(versions) != 1 or versions[0].get("IsLatest") is not True:
        raise SignedArtifactError("SIGNED_OBJECT_VERSION_AMBIGUOUS")
    return _strict_version_id(versions[0].get("VersionId"))


def _build_signed_artifact_receipt(
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
    now: datetime | None = None,
) -> Mapping[str, Any]:
    """Validate trusted readbacks and build the exact Change Set handoff."""

    validate_unsigned_bundle(
        manifest=unsigned_manifest,
        downloaded_archive=downloaded_unsigned_archive,
    )
    evaluated = now or datetime.now(UTC)
    if evaluated.tzinfo is None or evaluated.utcoffset() is None:
        raise SignedArtifactError("EVALUATION_TIME_INVALID")
    evaluated = evaluated.astimezone(UTC).replace(microsecond=0)
    evaluated_at = evaluated.isoformat().replace("+00:00", "Z")
    profile_match = _PROFILE_ARN_RE.fullmatch(expected_profile_version_arn)
    if profile_match is None:
        raise SignedArtifactError("SIGNING_PROFILE_INVALID")
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
    ):
        raise SignedArtifactError("SIGNING_JOB_NOT_EXACT")
    expires_at = _timestamp(signing_job.get("signatureExpiresAt"), "SIGNATURE_EXPIRY_INVALID")
    if expires_at <= evaluated:
        raise SignedArtifactError("SIGNATURE_EXPIRED")
    expires_at_text = expires_at.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    source_wrapper = signing_job.get("source")
    signed_wrapper = signing_job.get("signedObject")
    if not isinstance(source_wrapper, Mapping) or set(source_wrapper) != {"s3"}:
        raise SignedArtifactError("SIGNING_JOB_SOURCE_INVALID")
    if not isinstance(signed_wrapper, Mapping) or set(signed_wrapper) != {"s3"}:
        raise SignedArtifactError("SIGNING_JOB_DESTINATION_INVALID")
    source_bucket, source_key, source_version = _s3_location(source_wrapper["s3"], signed=False)
    signed_bucket, signed_key, _ = _s3_location(signed_wrapper["s3"], signed=True)
    expected_signed_suffix = f"/{signing_job['jobId']}.zip"
    if source_bucket != signed_bucket or not signed_key.endswith(expected_signed_suffix):
        raise SignedArtifactError("SIGNING_BUCKET_MISMATCH")
    if (
        not isinstance(signed_object_head, Mapping)
        or set(signed_object_head)
        != {"bucket", "key", "version_id", "content_length", "checksum_sha256"}
        or signed_object_head.get("bucket") != signed_bucket
        or signed_object_head.get("key") != signed_key
        or type(signed_object_head.get("content_length")) is not int
        or signed_object_head.get("content_length") != len(downloaded_signed_archive)
    ):
        raise SignedArtifactError("SIGNED_OBJECT_HEAD_MISMATCH")
    signed_version = _strict_version_id(signed_object_head.get("version_id"))
    if not downloaded_signed_archive or downloaded_signed_archive == downloaded_unsigned_archive:
        raise SignedArtifactError("SIGNED_ARCHIVE_UNVERIFIED")
    try:
        from io import BytesIO

        with ZipFile(BytesIO(downloaded_signed_archive), mode="r") as archive:
            names = archive.namelist()
            if len(names) != len(set(names)):
                raise SignedArtifactError("SIGNED_ARCHIVE_DUPLICATE_PATH")
            expected_entries = _manifest_entries(unsigned_manifest)
            if names != sorted(expected_entries):
                raise SignedArtifactError("SIGNED_ARCHIVE_PATH_SET_INVALID")
            for item in archive.infolist():
                unix_mode = item.external_attr >> 16
                if item.flag_bits & 0x1 or unix_mode & 0o170000 == 0o120000:
                    raise SignedArtifactError("SIGNED_ARCHIVE_ENTRY_UNSAFE")
            for path, expected in expected_entries.items():
                payload = archive.read(path)
                if (
                    sha256(payload).hexdigest() != expected["sha256"]
                    or len(payload) != expected["size_bytes"]
                ):
                    raise SignedArtifactError("SIGNED_ARCHIVE_SOURCE_ENTRY_DRIFT")
    except BadZipFile as exc:
        raise SignedArtifactError("SIGNED_ARCHIVE_INVALID") from exc
    signed_digest = sha256(downloaded_signed_archive).digest()
    signed_code_sha = base64.b64encode(signed_digest).decode("ascii")
    head_checksum = _checksum(
        signed_object_head.get("checksum_sha256"),
        "SIGNED_OBJECT_CHECKSUM_MISSING",
    )
    if head_checksum != signed_code_sha:
        raise SignedArtifactError("SIGNED_OBJECT_CHECKSUM_MISMATCH")
    source_commit = str(unsigned_manifest["source_commit"])
    runtime_dependencies = unsigned_manifest["runtime_dependencies"]
    expected_boto3_version = runtime_dependencies["expected_boto3_version"]
    expected_botocore_version = runtime_dependencies["expected_botocore_version"]
    parameters = [
        {"ParameterKey": "SourceCommit", "ParameterValue": source_commit},
        {"ParameterKey": "ExpectedBoto3Version", "ParameterValue": expected_boto3_version},
        {"ParameterKey": "ExpectedBotocoreVersion", "ParameterValue": expected_botocore_version},
        {"ParameterKey": "RepairArtifactBucket", "ParameterValue": signed_bucket},
        {"ParameterKey": "RepairArtifactKey", "ParameterValue": signed_key},
        {"ParameterKey": "RepairArtifactVersion", "ParameterValue": signed_version},
        {"ParameterKey": "RepairArtifactCodeSha256", "ParameterValue": signed_code_sha},
        {"ParameterKey": "ReconcileArtifactBucket", "ParameterValue": signed_bucket},
        {"ParameterKey": "ReconcileArtifactKey", "ParameterValue": signed_key},
        {"ParameterKey": "ReconcileArtifactVersion", "ParameterValue": signed_version},
        {"ParameterKey": "ReconcileArtifactCodeSha256", "ParameterValue": signed_code_sha},
        {"ParameterKey": "SigningProfileVersionArn", "ParameterValue": expected_profile_version_arn},
    ]
    receipt = {
        "artifact_type": ARTIFACT_TYPE,
        "schema_version": SCHEMA_VERSION,
        "work_package": WORK_PACKAGE,
        "source_commit": source_commit,
        "unsigned_manifest_sha256": sha256(canonical_json(unsigned_manifest).encode("utf-8")).hexdigest(),
        "unsigned_archive_sha256": sha256(downloaded_unsigned_archive).hexdigest(),
        "signing_job": {
            "job_id": signing_job["jobId"],
            "job_owner": AUTHORITY_ACCOUNT_ID,
            "platform_id": SIGNING_PLATFORM,
            "profile_version_arn": expected_profile_version_arn,
            "signature_expires_at": expires_at_text,
            "source": {"bucket": source_bucket, "key": source_key, "version": source_version},
        },
        "signed_artifact": {
            "bucket": signed_bucket,
            "key": signed_key,
            "version": signed_version,
            "archive_sha256": signed_digest.hex(),
            "lambda_code_sha256": signed_code_sha,
            "size_bytes": len(downloaded_signed_archive),
        },
        "expected_sdk_versions": {
            "boto3": expected_boto3_version,
            "botocore": expected_botocore_version,
        },
        "verifier": {
            "profile": verifier_profile,
            "account_id": verifier_identity.get("Account"),
            "caller_arn": verifier_identity.get("Arn"),
        },
        "source_review": dict(source_review),
        "cloudformation_parameters": parameters,
        "evaluated_at": evaluated_at,
        "evidence_status": EVIDENCE_STATUS,
        "production_status": PRODUCTION_STATUS,
    }
    validate_signed_artifact_receipt(receipt)
    return receipt


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
    s3_client: Any,
    now: datetime | None = None,
) -> Mapping[str, Any]:
    """Rebuild reviewed source and collect every AWS fact read-only.

    The profile, caller, source commit, package bytes, Signer job, S3 versions,
    and S3 checksums are independent inputs that must converge exactly.  No
    operator-provided AWS readback document participates in the decision.
    """

    if profile_name != EXPECTED_VERIFIER_PROFILE:
        raise SignedArtifactError("VERIFIER_PROFILE_INVALID")
    if _JOB_RE.fullmatch(job_id) is None:
        raise SignedArtifactError("SIGNING_JOB_ID_INVALID")
    identity = _aws_call(sts_client.get_caller_identity)
    if (
        identity.get("Account") != AUTHORITY_ACCOUNT_ID
        or _CALLER_ARN_RE.fullmatch(str(identity.get("Arn"))) is None
    ):
        raise SignedArtifactError("VERIFIER_IDENTITY_INVALID")

    committed_sources = verify_clean_source_commit(
        source_root=source_root, source_commit=source_commit
    )
    source_review = verify_github_merged_release(
        source_root=source_root,
        source_commit=source_commit,
    )
    reviewed: BuiltRepairPackage = build_repair_package(
        source_root=source_root,
        source_commit=source_commit,
        expected_boto3_version=expected_boto3_version,
        expected_botocore_version=expected_botocore_version,
        committed_sources=committed_sources,
    )
    signing_job = _aws_call(signer_client.describe_signing_job, jobId=job_id)
    if signing_job.get("jobId") != job_id:
        raise SignedArtifactError("SIGNING_JOB_ID_MISMATCH")
    source_wrapper = signing_job.get("source")
    signed_wrapper = signing_job.get("signedObject")
    if not isinstance(source_wrapper, Mapping) or set(source_wrapper) != {"s3"}:
        raise SignedArtifactError("SIGNING_JOB_SOURCE_INVALID")
    if not isinstance(signed_wrapper, Mapping) or set(signed_wrapper) != {"s3"}:
        raise SignedArtifactError("SIGNING_JOB_DESTINATION_INVALID")
    source_bucket, source_key, source_version = _s3_location(
        source_wrapper["s3"], signed=False
    )
    signed_bucket, signed_key, _ = _s3_location(signed_wrapper["s3"], signed=True)
    if (
        source_version is None
        or source_bucket != signed_bucket
        or not signed_key.endswith(f"/{job_id}.zip")
    ):
        raise SignedArtifactError("SIGNING_JOB_LOCATION_NOT_EXACT")
    versioning = _aws_call(
        s3_client.get_bucket_versioning,
        Bucket=source_bucket,
        ExpectedBucketOwner=AUTHORITY_ACCOUNT_ID,
    )
    if versioning.get("Status") != "Enabled":
        raise SignedArtifactError("SIGNING_BUCKET_VERSIONING_NOT_ENABLED")

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
        raise SignedArtifactError("REVIEWED_SOURCE_ARCHIVE_MISMATCH")
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
    return _build_signed_artifact_receipt(
        unsigned_manifest=reviewed.manifest,
        downloaded_unsigned_archive=downloaded_unsigned,
        downloaded_signed_archive=downloaded_signed,
        signing_job=signing_job,
        signed_object_head=signed_head,
        expected_profile_version_arn=expected_profile_version_arn,
        verifier_identity=identity,
        verifier_profile=profile_name,
        source_review=source_review,
        now=now,
    )


def validate_signed_artifact_receipt(receipt: Mapping[str, Any]) -> None:
    """Reject any signed receipt whose duplicated CFN bindings diverge."""

    required = {
        "artifact_type", "schema_version", "work_package", "source_commit",
        "unsigned_manifest_sha256", "unsigned_archive_sha256", "signing_job",
        "signed_artifact", "expected_sdk_versions", "verifier",
        "source_review",
        "cloudformation_parameters", "evaluated_at", "evidence_status",
        "production_status",
    }
    if (
        set(receipt) != required
        or _DIGEST_RE.fullmatch(str(receipt.get("unsigned_manifest_sha256"))) is None
        or _DIGEST_RE.fullmatch(str(receipt.get("unsigned_archive_sha256"))) is None
    ):
        raise SignedArtifactError("SIGNED_RECEIPT_INVALID")
    if (
        receipt.get("artifact_type") != ARTIFACT_TYPE
        or receipt.get("schema_version") != SCHEMA_VERSION
        or receipt.get("work_package") != WORK_PACKAGE
        or receipt.get("evidence_status") != EVIDENCE_STATUS
        or receipt.get("production_status") != PRODUCTION_STATUS
        or _COMMIT_RE.fullmatch(str(receipt.get("source_commit"))) is None
    ):
        raise SignedArtifactError("SIGNED_RECEIPT_INVALID")
    signing_job = receipt.get("signing_job")
    signed = receipt.get("signed_artifact")
    sdk = receipt.get("expected_sdk_versions")
    verifier = receipt.get("verifier")
    source_review = receipt.get("source_review")
    parameters = receipt.get("cloudformation_parameters")
    if not isinstance(signing_job, Mapping) or not isinstance(signed, Mapping):
        raise SignedArtifactError("SIGNED_RECEIPT_INVALID")
    source = signing_job.get("source")
    if (
        set(signing_job)
        != {
            "job_id", "job_owner", "platform_id", "profile_version_arn",
            "signature_expires_at", "source",
        }
        or _JOB_RE.fullmatch(str(signing_job.get("job_id"))) is None
        or signing_job.get("job_owner") != AUTHORITY_ACCOUNT_ID
        or signing_job.get("platform_id") != SIGNING_PLATFORM
        or _PROFILE_ARN_RE.fullmatch(str(signing_job.get("profile_version_arn"))) is None
        or not isinstance(source, Mapping)
        or set(source) != {"bucket", "key", "version"}
        or _BUCKET_RE.fullmatch(str(source.get("bucket"))) is None
        or _SOURCE_KEY_RE.fullmatch(str(source.get("key"))) is None
        or any(part in {"", ".", ".."} for part in str(source.get("key")).split("/"))
    ):
        raise SignedArtifactError("SIGNED_RECEIPT_SIGNING_JOB_INVALID")
    _strict_version_id(source.get("version"))
    if (
        set(signed)
        != {
            "bucket", "key", "version", "archive_sha256",
            "lambda_code_sha256", "size_bytes",
        }
        or signed.get("bucket") != source.get("bucket")
        or _BUCKET_RE.fullmatch(str(signed.get("bucket"))) is None
        or _SIGNED_KEY_RE.fullmatch(str(signed.get("key"))) is None
        or any(part in {"", ".", ".."} for part in str(signed.get("key")).split("/"))
        or not str(signed.get("key")).endswith(f"/{signing_job['job_id']}.zip")
        or receipt.get("unsigned_archive_sha256") == signed.get("archive_sha256")
        or type(signed.get("size_bytes")) is not int
        or not 0 < signed["size_bytes"] <= MAX_ARCHIVE_BYTES
    ):
        raise SignedArtifactError("SIGNED_RECEIPT_ARTIFACT_INVALID")
    _strict_version_id(signed.get("version"))
    if (
        not isinstance(sdk, Mapping)
        or set(sdk) != {"boto3", "botocore"}
        or any(_SDK_VERSION_RE.fullmatch(str(value)) is None for value in sdk.values())
    ):
        raise SignedArtifactError("SIGNED_RECEIPT_INVALID")
    if (
        not isinstance(verifier, Mapping)
        or set(verifier) != {"profile", "account_id", "caller_arn"}
        or verifier.get("profile") != EXPECTED_VERIFIER_PROFILE
        or verifier.get("account_id") != AUTHORITY_ACCOUNT_ID
        or _CALLER_ARN_RE.fullmatch(str(verifier.get("caller_arn"))) is None
    ):
        raise SignedArtifactError("SIGNED_RECEIPT_VERIFIER_INVALID")
    if not isinstance(source_review, Mapping):
        raise SignedArtifactError("SIGNED_RECEIPT_SOURCE_REVIEW_INVALID")
    validate_github_source_review(source_review)
    if source_review.get("source_commit") != receipt.get("source_commit"):
        raise SignedArtifactError("SIGNED_RECEIPT_SOURCE_REVIEW_DRIFT")
    if not isinstance(parameters, list):
        raise SignedArtifactError("SIGNED_RECEIPT_INVALID")
    keys = (
        "SourceCommit",
        "ExpectedBoto3Version",
        "ExpectedBotocoreVersion",
        "RepairArtifactBucket",
        "RepairArtifactKey",
        "RepairArtifactVersion",
        "RepairArtifactCodeSha256",
        "ReconcileArtifactBucket",
        "ReconcileArtifactKey",
        "ReconcileArtifactVersion",
        "ReconcileArtifactCodeSha256",
        "SigningProfileVersionArn",
    )
    if len(parameters) != len(keys):
        raise SignedArtifactError("CFN_PARAMETER_BINDING_INVALID")
    values: dict[str, Any] = {}
    for expected_key, parameter in zip(keys, parameters, strict=True):
        if (
            not isinstance(parameter, Mapping)
            or set(parameter) != {"ParameterKey", "ParameterValue"}
            or parameter.get("ParameterKey") != expected_key
            or not isinstance(parameter.get("ParameterValue"), str)
        ):
            raise SignedArtifactError("CFN_PARAMETER_BINDING_INVALID")
        values[expected_key] = parameter["ParameterValue"]
    expected = {
        "SourceCommit": receipt["source_commit"],
        "ExpectedBoto3Version": sdk.get("boto3"),
        "ExpectedBotocoreVersion": sdk.get("botocore"),
        "RepairArtifactBucket": signed.get("bucket"),
        "RepairArtifactKey": signed.get("key"),
        "RepairArtifactVersion": signed.get("version"),
        "RepairArtifactCodeSha256": signed.get("lambda_code_sha256"),
        "ReconcileArtifactBucket": signed.get("bucket"),
        "ReconcileArtifactKey": signed.get("key"),
        "ReconcileArtifactVersion": signed.get("version"),
        "ReconcileArtifactCodeSha256": signed.get("lambda_code_sha256"),
        "SigningProfileVersionArn": signing_job.get("profile_version_arn"),
    }
    if values != expected:
        raise SignedArtifactError("CFN_PARAMETER_BINDING_DRIFT")
    archive_digest = signed.get("archive_sha256")
    code_digest = signed.get("lambda_code_sha256")
    if _DIGEST_RE.fullmatch(str(archive_digest)) is None or not isinstance(code_digest, str):
        raise SignedArtifactError("SIGNED_ARCHIVE_DIGEST_INVALID")
    try:
        decoded = base64.b64decode(code_digest, validate=True)
    except (ValueError, TypeError) as exc:
        raise SignedArtifactError("SIGNED_ARCHIVE_DIGEST_INVALID") from exc
    if decoded.hex() != archive_digest:
        raise SignedArtifactError("SIGNED_ARCHIVE_DIGEST_MISMATCH")
    evaluated = _timestamp(receipt.get("evaluated_at"), "EVALUATION_TIME_INVALID")
    expires = _timestamp(signing_job.get("signature_expires_at"), "SIGNATURE_EXPIRY_INVALID")
    if expires <= evaluated:
        raise SignedArtifactError("SIGNATURE_EXPIRED")


def write_signed_artifact_receipt(
    *, receipt: Mapping[str, Any], output_path: Path, source_root: Path
) -> None:
    """Write private evidence once with owner-only permissions."""

    root = source_root.resolve(strict=True)
    requested_output = output_path.resolve(strict=False)
    try:
        requested_output.relative_to(root)
    except ValueError:
        pass
    else:
        raise SignedArtifactError("OUTPUT_MUST_BE_OUTSIDE_SOURCE_ROOT")
    validate_signed_artifact_receipt(receipt)
    payload = (canonical_json(receipt) + "\n").encode("utf-8")
    try:
        descriptor = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        raise SignedArtifactError("SIGNED_RECEIPT_WRITE_FAILED") from exc
