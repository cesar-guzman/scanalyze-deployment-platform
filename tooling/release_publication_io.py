"""Single-attempt S3 archive transport, not a publication executor or authority.

The embedding executor must first admit the complete signed release with
``prepare_publication``, authenticate its independent pins and source VersionId,
and consume a durable claim. Both required callbacks must recheck that actual
runtime identity/permissions and durable custody still cover the exact binding.
A Python callback, local token or this module's result does not establish any of
those external facts. Clients must be dedicated to this operation and supplied
by that trusted runtime; this module creates no clients or credentials.

Only bounded archive bytes are copied. There is no claim acquisition, takeover,
retry, existing-object reuse, ECR writer, frontend expansion or release receipt.
After any uncertain write, the executor must retain the consumed attempt and
reconcile independently; calling this function again is not recovery.

AWS request semantics: https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html
and https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html.
"""
from __future__ import annotations

import base64
from copy import deepcopy
from dataclasses import dataclass, field
import hashlib
import re
from typing import Any, Callable, Literal, Protocol
from uuid import uuid4

from tooling.release_publication import FRONTEND, RUNTIME_ARTIFACT_IDS, _content_key


MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
READ_CHUNK_BYTES = 64 * 1024
Phase = Literal["before_read", "before_write", "before_readback", "after_readback"]
ACCOUNT = re.compile(r"(?!000000000000)[0-9]{12}\Z")
REGION = re.compile(r"(?!cn-|us-gov-)[a-z]{2}-[a-z]+-[0-9]+\Z")
DEPLOYMENT = re.compile(r"dep_[0-9A-HJKMNP-TV-Z]{26}\Z")
DIGEST = re.compile(r"sha256:[a-f0-9]{64}\Z")
BUCKET = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\Z")


class ArchiveCopyRejected(ValueError):
    """No destination write was attempted, or AWS definitively rejected it."""


class ArchiveCopyConflict(ArchiveCopyRejected):
    """One conditional write failed; no existing object is reused or retried."""


class ArchiveCopyUncertain(RuntimeError):
    """UNCERTAIN: a write may exist; no verified observation is returned."""


class S3Client(Protocol):
    meta: Any

    def get_object(self, **kwargs: Any) -> dict[str, Any]: ...

    def put_object(self, **kwargs: Any) -> dict[str, Any]: ...


@dataclass(frozen=True)
class SourceReadScope:
    bucket: str
    key: str
    version_id: str
    owner_account_id: str
    region: str


@dataclass(frozen=True)
class ArchiveRuntimeScope:
    account_id: str
    region: str
    deployment_id: str
    promotion_role_arn: str
    destination_bucket: str
    sse_algorithm: str
    kms_key_arn: str | None


@dataclass(frozen=True)
class ArchiveCopyBinding:
    """Detached scope to check against external admission and durable custody."""

    artifact_id: str
    digest: str
    media_type: str
    source: SourceReadScope
    runtime: ArchiveRuntimeScope
    destination_key: str
    max_bytes: int


Preflight = Callable[[ArchiveCopyBinding, Phase], bool]


@dataclass(frozen=True)
class ArchiveCopyObservation:
    """One independently collectable observation, never a full release receipt."""

    binding: ArchiveCopyBinding
    object_version: str
    content_length: int
    status: str = field(default="ARCHIVE_BYTES_VERIFIED_NOT_RELEASE_PUBLICATION", init=False)

    def as_readback_observation(self) -> dict[str, Any]:
        scope = self.binding.runtime
        return {
            "artifact_id": self.binding.artifact_id,
            "destination": {"kind": "s3", "bucket": scope.destination_bucket,
                            "key": self.binding.destination_key,
                            "sse_algorithm": scope.sse_algorithm, "kms_key_arn": scope.kms_key_arn},
            "digest": self.binding.digest,
            "object_version": self.object_version,
        }


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ArchiveCopyRejected(code)


def _matches(pattern: re.Pattern[str], value: Any) -> bool:
    return type(value) is str and pattern.fullmatch(value) is not None


def _version(value: Any) -> bool:
    return (type(value) is str and 0 < len(value) <= 1024 and value.lower() != "null"
            and all(33 <= ord(character) <= 126 for character in value))


def _bucket(value: Any) -> bool:
    return (_matches(BUCKET, value) and ".." not in value and ".-" not in value and "-." not in value
            and not re.fullmatch(r"[0-9]+(?:\.[0-9]+){3}", value)
            and not value.endswith(("--x-s3", "--ol-s3", "-s3alias", ".mrap", "--table-s3")))


def _object(value: Any, fields: set[str]) -> None:
    _require(type(value) is dict and set(value) == fields, "COPY_INPUT_SHAPE_INVALID")


def _binding(copy_row: dict, source_read_scope: dict, runtime_scope: dict, max_bytes: int) -> ArchiveCopyBinding:
    row, source, runtime = deepcopy((copy_row, source_read_scope, runtime_scope))
    _object(row, {"artifact_id", "kind", "digest", "media_type", "source", "destination"})
    _object(row["source"], {"uri", "digest"})
    _object(row["destination"], {"kind", "bucket", "key", "sse_algorithm", "kms_key_arn"})
    _object(source, set(SourceReadScope.__dataclass_fields__))
    _object(runtime, set(ArchiveRuntimeScope.__dataclass_fields__))
    _require(type(max_bytes) is int and 0 < max_bytes <= MAX_ARCHIVE_BYTES, "COPY_SIZE_LIMIT_INVALID")
    _require(type(row["artifact_id"]) is str and row["artifact_id"] in RUNTIME_ARTIFACT_IDS
             and row["kind"] == "archive" and row["destination"]["kind"] == "s3", "ARCHIVE_COPY_REQUIRED")
    _require(_matches(DIGEST, row["digest"]) and row["source"]["digest"] == row["digest"], "COPY_DIGEST_INVALID")
    allowed_media = {"application/gzip", "application/zip"} if row["artifact_id"] == FRONTEND else {"application/zip"}
    _require(type(row["media_type"]) is str and row["media_type"] in allowed_media, "ARCHIVE_MEDIA_UNSUPPORTED")
    _require(_bucket(source["bucket"]) and _version(source["version_id"])
             and _matches(ACCOUNT, source["owner_account_id"]) and _matches(REGION, source["region"]),
             "SOURCE_SCOPE_INVALID")
    _require(type(source["key"]) is str and row["source"]["uri"] == f"s3://{source['bucket']}/{source['key']}",
             "SOURCE_LOCATOR_MISMATCH")
    _content_key(source["key"], row["digest"], "")
    _require(_matches(ACCOUNT, runtime["account_id"]) and _matches(REGION, runtime["region"])
             and _matches(DEPLOYMENT, runtime["deployment_id"]) and _bucket(runtime["destination_bucket"]),
             "RUNTIME_SCOPE_INVALID")
    _require(runtime["promotion_role_arn"] == f"arn:aws:iam::{runtime['account_id']}:role/ScanalyzeCustomer-Promotion",
             "PROMOTION_SCOPE_INVALID")
    destination = row["destination"]
    _require(destination["bucket"] == runtime["destination_bucket"]
             and destination["sse_algorithm"] == runtime["sse_algorithm"]
             and destination["kms_key_arn"] == runtime["kms_key_arn"], "DESTINATION_SCOPE_MISMATCH")
    frontend = row["artifact_id"] == FRONTEND
    prefix = (f"releases/{runtime['deployment_id']}/" if frontend
              else f"deployments/{runtime['deployment_id']}/artifacts/")
    _content_key(destination["key"], row["digest"], prefix)
    if frontend:
        _require(runtime["sse_algorithm"] == "AES256" and runtime["kms_key_arn"] is None,
                 "FRONTEND_ENCRYPTION_INVALID")
    else:
        key_prefix = f"arn:aws:kms:{runtime['region']}:{runtime['account_id']}:key/"
        key_pattern = re.compile(re.escape(key_prefix) + r"(?:[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}|mrk-[a-f0-9]{32})\Z")
        _require(runtime["sse_algorithm"] == "aws:kms" and _matches(key_pattern, runtime["kms_key_arn"]),
                 "LAMBDA_ENCRYPTION_INVALID")
        _require(runtime["destination_bucket"] == runtime["deployment_id"].replace("_", "-").lower() + "-cicd-artifacts",
                 "LAMBDA_BUCKET_SCOPE_INVALID")
    return ArchiveCopyBinding(row["artifact_id"], row["digest"], row["media_type"],
                              SourceReadScope(**source), ArchiveRuntimeScope(**runtime), destination["key"], max_bytes)


def _client(client: S3Client, region: str) -> None:
    try:
        retries = client.meta.config.retries
        valid = (client.meta.region_name == region
                 and client.meta.endpoint_url == f"https://s3.{region}.amazonaws.com"
                 and client.meta.service_model.service_name == "s3"
                 and type(retries.get("total_max_attempts")) is int and retries["total_max_attempts"] == 1
                 and callable(client.meta.events.register_first) and callable(client.meta.events.unregister))
    except (AttributeError, TypeError):
        valid = False
    _require(valid, "S3_CLIENT_SCOPE_OR_RETRY_INVALID")


def _once(client: S3Client, method: str, **kwargs: Any) -> dict:
    # S3 region-redirect handlers can request another send independently of the
    # normal SDK retry limit. Guard all S3 sends, including a recovery HeadBucket.
    # Dedicated clients are required: do not attach this guard to shared traffic.
    sent = False

    def before_send(**_kwargs: Any) -> None:
        nonlocal sent
        _require(not sent, "S3_SECOND_SEND_BLOCKED")
        sent = True

    event, identifier = "before-send.s3", "scanalyze-archive-copy-" + uuid4().hex
    client.meta.events.register_first(event, before_send, unique_id=identifier)
    try:
        return getattr(client, method)(**kwargs)
    finally:
        client.meta.events.unregister(event, unique_id=identifier)


def _metadata(response: Any, status: int = 200) -> None:
    metadata = response.get("ResponseMetadata") if type(response) is dict else None
    _require(type(metadata) is dict and type(metadata.get("HTTPStatusCode")) is int
             and metadata["HTTPStatusCode"] == status and type(metadata.get("RetryAttempts")) is int
             and metadata["RetryAttempts"] == 0, "S3_RESPONSE_NOT_SINGLE_ATTEMPT_SUCCESS")


def _encryption(response: dict, binding: ArchiveCopyBinding) -> None:
    scope = binding.runtime
    _require(response.get("ServerSideEncryption") == scope.sse_algorithm, "DESTINATION_ENCRYPTION_MISMATCH")
    if scope.sse_algorithm == "aws:kms":
        _require(response.get("SSEKMSKeyId") == scope.kms_key_arn, "DESTINATION_KMS_KEY_MISMATCH")
    else:
        _require(response.get("SSEKMSKeyId") is None and response.get("BucketKeyEnabled") in {None, False},
                 "DESTINATION_KMS_KEY_MISMATCH")


def _read(client: S3Client, *, bucket: str, key: str, owner: str, version: str,
          binding: ArchiveCopyBinding, destination: bool = False) -> bytes:
    response = _once(client, "get_object", Bucket=bucket, Key=key, VersionId=version, ExpectedBucketOwner=owner)
    body = response.get("Body") if type(response) is dict else None
    try:
        _metadata(response)
        _require(response.get("VersionId") == version and response.get("DeleteMarker") in {None, False}
                 and "ContentRange" not in response, "SOURCE_OR_READBACK_VERSION_INVALID")
        length = response.get("ContentLength")
        _require(type(length) is int and 0 < length <= binding.max_bytes, "ARCHIVE_LENGTH_INVALID")
        _require(callable(getattr(body, "read", None)) and callable(getattr(body, "close", None)), "ARCHIVE_STREAM_INVALID")
        if destination:
            _encryption(response, binding)
            _require(response.get("ContentType") == binding.media_type
                     and not response.get("ContentEncoding") and not response.get("WebsiteRedirectLocation")
                     and response.get("Metadata", {}) == {}, "DESTINATION_METADATA_MISMATCH")
        # Read at most declared length + one byte; ContentLength alone does not
        # attest completeness. Every SDK stream is closed, including rejects.
        payload = bytearray()
        while len(payload) <= length:
            requested = min(READ_CHUNK_BYTES, length + 1 - len(payload))
            chunk = body.read(requested)
            _require(type(chunk) is bytes and len(chunk) <= requested, "ARCHIVE_STREAM_INVALID")
            if not chunk:
                break
            payload.extend(chunk)
        _require(len(payload) == length, "ARCHIVE_LENGTH_MISMATCH")
        _require("sha256:" + hashlib.sha256(payload).hexdigest() == binding.digest, "ARCHIVE_DIGEST_MISMATCH")
        return bytes(payload)
    finally:
        if callable(getattr(body, "close", None)):
            body.close()


def _preflight(binding: ArchiveCopyBinding, phase: Phase, source_client: S3Client, destination_client: S3Client,
               runtime_preflight: Preflight, require_consumed_claim: Preflight) -> None:
    _client(source_client, binding.source.region)
    _client(destination_client, binding.runtime.region)
    _require(runtime_preflight(binding, phase) is True, "RUNTIME_PREFLIGHT_REJECTED")
    _require(require_consumed_claim(binding, phase) is True, "DURABLE_CLAIM_REJECTED")
    # A callback may refresh its client; its resulting configuration must still
    # preserve endpoint and one-attempt behavior before this transport uses it.
    _client(source_client, binding.source.region)
    _client(destination_client, binding.runtime.region)


def _definite_write_error(error: Exception) -> type[ArchiveCopyRejected] | None:
    response = getattr(error, "response", None)
    if type(response) is not dict or type(response.get("Error")) is not dict:
        return None
    metadata = response.get("ResponseMetadata")
    if (type(metadata) is not dict or type(metadata.get("RetryAttempts")) is not int
            or metadata["RetryAttempts"] != 0 or type(metadata.get("HTTPStatusCode")) is not int):
        return None
    code = response["Error"].get("Code")
    if type(code) is not str:
        return None
    pair = (code, metadata["HTTPStatusCode"])
    if pair in {("PreconditionFailed", 412), ("ConditionalRequestConflict", 409)}:
        return ArchiveCopyConflict
    if pair in {("AccessDenied", 403), ("InvalidAccessKeyId", 403), ("SignatureDoesNotMatch", 403),
                ("ExpiredToken", 400), ("NoSuchBucket", 404), ("BadDigest", 400)}:
        return ArchiveCopyRejected
    return None


def copy_publication_archive(
    *, copy_row: dict, source_read_scope: dict, runtime_scope: dict,
    source_client: S3Client, destination_client: S3Client,
    require_consumed_claim: Preflight, runtime_preflight: Preflight,
    max_bytes: int = MAX_ARCHIVE_BYTES,
) -> ArchiveCopyObservation:
    """Copy one previously admitted archive under externally enforced custody.

    Scope dictionaries have exactly the fields of SourceReadScope and
    ArchiveRuntimeScope. Both callbacks take (immutable_binding, phase), must
    return exactly True, and must fail if their externally authenticated scope,
    action-time release admission, identity/session tags or durable consumed
    claim no longer covers this operation. No callback is supplied by default.
    The callbacks must bind the actual dedicated SDK clients, not just labels.

    Definite pre-write rejection does not release or recreate the claim. After a
    write has possibly occurred, any failed readback/preflight is UNCERTAIN.
    Neither error category authorizes a retry or deletes partial artifacts.
    """
    try:
        _require(callable(runtime_preflight) and callable(require_consumed_claim), "EXTERNAL_PREFLIGHT_REQUIRED")
        binding = _binding(copy_row, source_read_scope, runtime_scope, max_bytes)
        _preflight(binding, "before_read", source_client, destination_client, runtime_preflight, require_consumed_claim)
        payload = _read(source_client, bucket=binding.source.bucket, key=binding.source.key,
                        owner=binding.source.owner_account_id, version=binding.source.version_id, binding=binding)
        _preflight(binding, "before_write", source_client, destination_client, runtime_preflight, require_consumed_claim)
        scope = binding.runtime
        request = dict(Bucket=scope.destination_bucket, Key=binding.destination_key,
                       Body=payload, ContentLength=len(payload), ContentType=binding.media_type,
                       ExpectedBucketOwner=scope.account_id, IfNoneMatch="*", ServerSideEncryption=scope.sse_algorithm,
                       ChecksumSHA256=base64.b64encode(hashlib.sha256(payload).digest()).decode("ascii"))
        if scope.kms_key_arn is not None:
            request["SSEKMSKeyId"] = scope.kms_key_arn
    except Exception:
        raise ArchiveCopyRejected("ARCHIVE_COPY_PREWRITE_REJECTED") from None

    try:
        response = _once(destination_client, "put_object", **request)
    except Exception as error:
        try:
            definite = _definite_write_error(error)
        except Exception:
            definite = None
        if definite is not None:
            raise definite("ARCHIVE_COPY_CONDITIONAL_CONFLICT" if definite is ArchiveCopyConflict
                           else "ARCHIVE_COPY_WRITE_REJECTED") from None
        raise ArchiveCopyUncertain("ARCHIVE_COPY_WRITE_UNCERTAIN") from None

    try:
        _metadata(response)
        _encryption(response, binding)
        version = response.get("VersionId")
        _require(_version(version), "DESTINATION_VERSION_REQUIRED")
        _preflight(binding, "before_readback", source_client, destination_client, runtime_preflight, require_consumed_claim)
        copied = _read(destination_client, bucket=scope.destination_bucket, key=binding.destination_key,
                       owner=scope.account_id, version=version, binding=binding, destination=True)
        _require(len(copied) == len(payload), "DESTINATION_LENGTH_MISMATCH")
        _preflight(binding, "after_readback", source_client, destination_client, runtime_preflight, require_consumed_claim)
        return ArchiveCopyObservation(binding, version, len(copied))
    except Exception:
        raise ArchiveCopyUncertain("ARCHIVE_COPY_READBACK_UNCERTAIN") from None
