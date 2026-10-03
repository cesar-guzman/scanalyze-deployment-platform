"""Pure integrity checks for exact-version S3 Batch SHA-256 readbacks.

This module performs no I/O. Its binding MUST come from an independently trusted
policy, and its inputs MUST come from authenticated, exact-version readbacks.
Passing these checks does not authenticate a report's producer, prove historical
IAM/bucket custody, verify a code signature, or authorize a signed-artifact
receipt. A caller must establish those facts independently. In particular, a
self-consistent CSV and its hashes are not provider evidence by themselves.
"""

from __future__ import annotations

import base64
import binascii
import csv
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import io
import json
import re
from typing import Any, Mapping
from urllib.parse import quote, unquote_to_bytes


ACCOUNT_ID = "042360977644"
REGION = "us-east-1"
MAX_MANIFEST_BYTES = 8 * 1024
MAX_REPORT_MANIFEST_BYTES = 64 * 1024
MAX_REPORT_CSV_BYTES = 16 * 1024
MAX_SIGNED_OBJECT_BYTES = 32 * 1024 * 1024
ERROR_THEN_HTTP_SCHEMA = (
    "Bucket, Key, VersionId, TaskStatus, ErrorCode, HTTPStatusCode, ResultMessage"
)
HTTP_THEN_ERROR_SCHEMA = (
    "Bucket, Key, VersionId, TaskStatus, HTTPStatusCode, ErrorCode, ResultMessage"
)
REPORT_SCHEMAS = frozenset({ERROR_THEN_HTTP_SCHEMA, HTTP_THEN_ERROR_SCHEMA})

_JOB = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
_BUCKET = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\Z")
_VERSION = re.compile(r"[A-Za-z0-9._~+/=-]{1,1024}\Z")
_ROLE = re.compile(
    rf"arn:aws:iam::{ACCOUNT_ID}:role/[A-Za-z0-9+=,.@_/-]{{1,512}}\Z"
)
_HEX256 = re.compile(r"[0-9a-fA-F]{64}\Z")
_HEX128 = re.compile(r"[0-9a-fA-F]{32}\Z")


class BatchChecksumError(ValueError):
    """A closed, non-sensitive error; never include provider contents."""


@dataclass(frozen=True)
class ObjectVersion:
    bucket: str
    key: str
    version_id: str


@dataclass(frozen=True)
class BatchChecksumBinding:
    job_id: str
    role_arn: str
    signed_object: ObjectVersion
    # Exact authenticated HEAD ETag, including its single ASCII quote wrapper.
    # An ETag is an opaque identifier, never an assumed MD5 or content digest.
    signed_etag: str
    manifest: ObjectVersion
    manifest_etag: str
    report_bucket: str
    report_prefix: str
    report_manifest: ObjectVersion
    report_csv: ObjectVersion
    # Required: the caller selects a reviewed dialect; never infer CSV column
    # order from HTTP-looking values or from AWS's inconsistent example rows.
    report_schema: str


def _fail(code: str) -> None:
    raise BatchChecksumError(code) from None


def _closed(value: Any, required: set[str], optional: set[str] | None = None) -> Mapping[str, Any]:
    if (
        not isinstance(value, Mapping)
        or not required <= set(value)
        or not set(value) <= required | (optional or set())
    ):
        _fail("BATCH_CHECKSUM_SHAPE_INVALID")
    return value


def _text(value: Any, *, maximum: int = 1024) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8", errors="replace")) > maximum
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
        or any(0xD800 <= ord(char) <= 0xDFFF for char in value)
    ):
        _fail("BATCH_CHECKSUM_TEXT_INVALID")
    return value


def _key(value: Any) -> str:
    key = _text(value)
    if any(part in {"", ".", ".."} for part in key.split("/")):
        _fail("BATCH_CHECKSUM_LOCATION_INVALID")
    return key


def _bucket(value: Any) -> str:
    bucket = _text(value, maximum=63)
    if not _BUCKET.fullmatch(bucket) or any(item in bucket for item in ("..", ".-", "-.")):
        _fail("BATCH_CHECKSUM_LOCATION_INVALID")
    return bucket


def _location(value: Any) -> dict[str, str]:
    if not isinstance(value, ObjectVersion):
        _fail("BATCH_CHECKSUM_BINDING_INVALID")
    version = _text(value.version_id)
    if not _VERSION.fullmatch(version) or version.casefold() in {"null", "latest"}:
        _fail("BATCH_CHECKSUM_VERSION_INVALID")
    return {"bucket": _bucket(value.bucket), "key": _key(value.key), "version_id": version}


def _bounded_bytes(value: Any, maximum: int) -> bytes:
    if not isinstance(value, bytes) or not 0 < len(value) <= maximum:
        _fail("BATCH_CHECKSUM_BYTES_INVALID")
    return value


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("BATCH_CHECKSUM_DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    _fail("BATCH_CHECKSUM_JSON_INVALID")


def _json(raw: bytes, maximum: int) -> Mapping[str, Any]:
    _bounded_bytes(raw, maximum)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_reject_constant)
    except BatchChecksumError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        _fail("BATCH_CHECKSUM_JSON_INVALID")
    if not isinstance(value, dict):
        _fail("BATCH_CHECKSUM_JSON_INVALID")
    return value


def _csv_row(raw: bytes, maximum: int, columns: int) -> list[str]:
    _bounded_bytes(raw, maximum)
    try:
        text = raw.decode("utf-8")
        if "\x00" in text or "\ufeff" in text:
            _fail("BATCH_CHECKSUM_CSV_INVALID")
        rows = list(csv.reader(io.StringIO(text, newline=""), strict=True))
    except (UnicodeError, csv.Error):
        _fail("BATCH_CHECKSUM_CSV_INVALID")
    if len(rows) != 1 or len(rows[0]) != columns:
        _fail("BATCH_CHECKSUM_CSV_INVALID")
    return rows[0]


def _csv_key(value: str) -> str:
    # Only canonical URL-encoded keys are accepted; no '+'-as-space conversion,
    # double decoding, malformed percent escapes, or path normalization.
    try:
        decoded = unquote_to_bytes(value).decode("utf-8")
    except UnicodeError:
        _fail("BATCH_CHECKSUM_LOCATION_INVALID")
    if quote(decoded, safe="/") != value:
        _fail("BATCH_CHECKSUM_LOCATION_INVALID")
    return _key(decoded)


def _timestamp(value: Any) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00")) if isinstance(value, str) else value
    except ValueError:
        _fail("BATCH_CHECKSUM_TIME_INVALID")
    if not isinstance(parsed, datetime) or parsed.tzinfo is None or parsed.utcoffset() is None:
        _fail("BATCH_CHECKSUM_TIME_INVALID")
    return parsed.astimezone(UTC)


def _timestamp_text(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _md5_for_report_transport(value: bytes) -> str:
    # AWS report manifests use MD5 to describe their CSV. This is only a file
    # consistency check; SHA-256 and independently established custody remain
    # required and MD5 never authenticates the artifact or the report producer.
    return hashlib.md5(value, usedforsecurity=False).hexdigest()


def validate_batch_checksum_readbacks(
    *,
    job: Mapping[str, Any],
    binding: BatchChecksumBinding,
    manifest_bytes: bytes,
    report_manifest_bytes: bytes,
    report_csv_bytes: bytes,
    signed_object_bytes: bytes,
) -> dict[str, Any]:
    """Validate consistency against a trusted binding, not its authority.

    ``job`` is the inner ``DescribeJob['Job']`` mapping. S3 HEAD/GET identities,
    encryption, object history, freshness and historical report-write custody
    must be independently checked by the collector before using this result.
    No supplied digest, location, role, or job ID is independently authorized by
    this pure function. The returned projection is not a signed-artifact receipt.
    """

    if not isinstance(binding, BatchChecksumBinding):
        _fail("BATCH_CHECKSUM_BINDING_INVALID")
    if not _JOB.fullmatch(_text(binding.job_id, maximum=36)):
        _fail("BATCH_CHECKSUM_JOB_INVALID")
    if not _ROLE.fullmatch(_text(binding.role_arn, maximum=600)):
        _fail("BATCH_CHECKSUM_ROLE_INVALID")
    signed = _location(binding.signed_object)
    manifest = _location(binding.manifest)
    report_manifest_location = _location(binding.report_manifest)
    report_csv_location = _location(binding.report_csv)
    report_bucket = _bucket(binding.report_bucket)
    report_prefix = _key(binding.report_prefix)
    manifest_etag = _text(binding.manifest_etag, maximum=128)
    signed_etag = _text(binding.signed_etag, maximum=128)
    if (
        len(signed_etag) < 3
        or signed_etag[0] != '"'
        or signed_etag[-1] != '"'
        or '"' in signed_etag[1:-1]
    ):
        _fail("BATCH_CHECKSUM_ETAG_INVALID")
    # HEAD and the Batch result use different documented wrappers. Remove only
    # HEAD's required wrapper; do not normalize or reinterpret either token.
    signed_etag_token = signed_etag[1:-1]
    if not isinstance(binding.report_schema, str) or binding.report_schema not in REPORT_SCHEMAS:
        _fail("BATCH_CHECKSUM_REPORT_SCHEMA_INVALID")
    job_prefix = f"{report_prefix}/job-{binding.job_id}/"
    result_prefix = job_prefix + "results/"
    if (
        report_manifest_location["bucket"] != report_bucket
        or report_csv_location["bucket"] != report_bucket
        or report_manifest_location["key"] != job_prefix + "manifest.json"
        or not report_csv_location["key"].startswith(result_prefix)
        or not report_csv_location["key"].endswith(".csv")
        or "/" in report_csv_location["key"][len(result_prefix):]
        or report_csv_location["key"] == result_prefix + ".csv"
        or len({(entry["bucket"], entry["key"]) for entry in (
            signed, manifest, report_manifest_location, report_csv_location
        )}) != 4
    ):
        _fail("BATCH_CHECKSUM_LOCATION_INVALID")

    required_job = {
        "JobId", "JobArn", "RoleArn", "Manifest", "Operation", "Report",
        "ProgressSummary", "Status", "CreationTime", "TerminationDate",
    }
    optional_job = {"ConfirmationRequired", "Priority", "Description", "FailureReasons", "StatusUpdateReason"}
    _closed(job, required_job, optional_job)
    expected_job_arn = f"arn:aws:s3:{REGION}:{ACCOUNT_ID}:job/{binding.job_id}"
    if (
        job["JobId"] != binding.job_id
        or job["JobArn"] != expected_job_arn
        or job["RoleArn"] != binding.role_arn
        or job["Status"] != "Complete"
        or job.get("FailureReasons", []) != []
    ):
        _fail("BATCH_CHECKSUM_JOB_INVALID")
    if "ConfirmationRequired" in job and type(job["ConfirmationRequired"]) is not bool:
        _fail("BATCH_CHECKSUM_JOB_INVALID")
    if "Priority" in job and (type(job["Priority"]) is not int or not 0 <= job["Priority"] <= 2_147_483_647):
        _fail("BATCH_CHECKSUM_JOB_INVALID")
    for field in ("Description", "StatusUpdateReason"):
        if field in job:
            _text(job[field], maximum=1024)
    created = _timestamp(job["CreationTime"])
    terminated = _timestamp(job["TerminationDate"])
    if terminated < created:
        _fail("BATCH_CHECKSUM_TIME_INVALID")
    if job["Operation"] != {"S3ComputeObjectChecksum": {"ChecksumAlgorithm": "SHA256", "ChecksumType": "FULL_OBJECT"}}:
        _fail("BATCH_CHECKSUM_OPERATION_INVALID")
    expected_manifest = {
        "Location": {
            "ObjectArn": f"arn:aws:s3:::{manifest['bucket']}/{manifest['key']}",
            "ObjectVersionId": manifest["version_id"],
            "ETag": manifest_etag,
        },
        "Spec": {"Format": "S3BatchOperations_CSV_20180820", "Fields": ["Bucket", "Key", "VersionId"]},
    }
    if job["Manifest"] != expected_manifest:
        _fail("BATCH_CHECKSUM_MANIFEST_INVALID")
    expected_report = {
        "Bucket": f"arn:aws:s3:::{report_bucket}", "Enabled": True,
        "ExpectedBucketOwner": ACCOUNT_ID, "Format": "Report_CSV_20180820",
        "Prefix": report_prefix, "ReportScope": "AllTasks",
    }
    report = job["Report"]
    if (
        not isinstance(report, Mapping)
        or type(report.get("Enabled")) is not bool
        or report != expected_report
    ):
        _fail("BATCH_CHECKSUM_REPORT_INVALID")
    progress = _closed(job["ProgressSummary"], {"TotalNumberOfTasks", "NumberOfTasksSucceeded", "NumberOfTasksFailed"}, {"Timers"})
    for field, expected in (("TotalNumberOfTasks", 1), ("NumberOfTasksSucceeded", 1), ("NumberOfTasksFailed", 0)):
        if type(progress[field]) is not int or progress[field] != expected:
            _fail("BATCH_CHECKSUM_TASK_COUNTS_INVALID")
    if "Timers" in progress:
        timers = _closed(progress["Timers"], {"ElapsedTimeInActiveSeconds"})
        if type(timers["ElapsedTimeInActiveSeconds"]) is not int or timers["ElapsedTimeInActiveSeconds"] < 0:
            _fail("BATCH_CHECKSUM_JOB_INVALID")

    row = _csv_row(manifest_bytes, MAX_MANIFEST_BYTES, 3)
    if row[0] != signed["bucket"] or _csv_key(row[1]) != signed["key"] or row[2] != signed["version_id"]:
        _fail("BATCH_CHECKSUM_MANIFEST_INVALID")
    report_manifest = _closed(_json(report_manifest_bytes, MAX_REPORT_MANIFEST_BYTES), {"Format", "ReportCreationDate", "Results", "ReportSchema"})
    report_created = _timestamp(report_manifest["ReportCreationDate"])
    if (
        report_manifest["Format"] != "Report_CSV_20180820"
        or report_manifest["ReportSchema"] != binding.report_schema
        or report_created < created
    ):
        _fail("BATCH_CHECKSUM_REPORT_INVALID")
    results = report_manifest["Results"]
    if not isinstance(results, list) or len(results) != 1:
        _fail("BATCH_CHECKSUM_REPORT_INVALID")
    result = _closed(results[0], {"TaskExecutionStatus", "Bucket", "Key", "MD5Checksum"})
    _bounded_bytes(report_csv_bytes, MAX_REPORT_CSV_BYTES)
    md5 = _text(result["MD5Checksum"], maximum=32)
    if (
        result["TaskExecutionStatus"] != "succeeded"
        or result["Bucket"] != report_bucket
        or result["Key"] != report_csv_location["key"]
        or not _HEX128.fullmatch(md5)
        or md5.lower() != _md5_for_report_transport(report_csv_bytes)
    ):
        _fail("BATCH_CHECKSUM_REPORT_INVALID")
    report_row = dict(zip(binding.report_schema.split(", "), _csv_row(report_csv_bytes, MAX_REPORT_CSV_BYTES, 7), strict=True))
    if (
        report_row["Bucket"] != signed["bucket"]
        or _csv_key(report_row["Key"]) != signed["key"]
        or report_row["VersionId"] != signed["version_id"]
        or report_row["TaskStatus"] != "succeeded"
        or report_row["HTTPStatusCode"] != "200"
        or report_row["ErrorCode"] != ""
    ):
        _fail("BATCH_CHECKSUM_TASK_INVALID")
    checksum = _closed(_json(report_row["ResultMessage"].encode("utf-8"), MAX_REPORT_CSV_BYTES), {"checksum_base64", "checksum_hex", "checksumAlgorithm", "checksumType", "etag"})
    result_etag = _text(checksum["etag"], maximum=128)
    if '"' in result_etag or result_etag != signed_etag_token:
        _fail("BATCH_CHECKSUM_ETAG_MISMATCH")
    if checksum["checksumAlgorithm"] != "SHA256" or checksum["checksumType"] != "FULL_OBJECT":
        _fail("BATCH_CHECKSUM_ALGORITHM_INVALID")
    digest64 = _text(checksum["checksum_base64"], maximum=44)
    digest_hex = _text(checksum["checksum_hex"], maximum=64)
    try:
        digest = base64.b64decode(digest64, validate=True)
    except (ValueError, binascii.Error):
        _fail("BATCH_CHECKSUM_DIGEST_INVALID")
    if (
        len(digest) != 32
        or base64.b64encode(digest).decode("ascii") != digest64
        or not _HEX256.fullmatch(digest_hex)
        or digest.hex() != digest_hex.lower()
    ):
        _fail("BATCH_CHECKSUM_DIGEST_INVALID")
    _bounded_bytes(signed_object_bytes, MAX_SIGNED_OBJECT_BYTES)
    if hashlib.sha256(signed_object_bytes).digest() != digest:
        _fail("BATCH_CHECKSUM_OBJECT_MISMATCH")

    return {
        "input_format": "s3_batch_operations_completion_report",
        "validation_scope": "syntax_and_content_consistency_only",
        "account_id": ACCOUNT_ID, "region": REGION,
        "job": {"job_id": binding.job_id, "job_arn": expected_job_arn, "role_arn": binding.role_arn,
                "status": "Complete", "created_at": _timestamp_text(created), "terminated_at": _timestamp_text(terminated),
                "total_tasks": 1, "succeeded_tasks": 1, "failed_tasks": 0},
        "signed_object": {**signed, "etag": signed_etag, "size_bytes": len(signed_object_bytes)},
        "checksum": {"algorithm": "SHA256", "type": "FULL_OBJECT", "base64": digest64, "hex": digest.hex()},
        "manifest": {**manifest, "etag": manifest_etag, "sha256": _sha256(manifest_bytes)},
        "report": {"bucket": report_bucket, "prefix": report_prefix, "schema": binding.report_schema,
                   "result_etag": result_etag,
                   "created_at": _timestamp_text(report_created),
                   "manifest": {**report_manifest_location, "sha256": _sha256(report_manifest_bytes)},
                   "csv": {**report_csv_location, "sha256": _sha256(report_csv_bytes), "md5": md5.lower()}},
    }
