from dataclasses import dataclass
from typing import Any, Mapping

from .contracts import OWNERSHIP_SCHEMA_VERSION
from .storage import build_document_prefix, build_ocr_artifact_key


ALLOWED_DOCUMENT_ROUTES = frozenset({"platform", "bank", "personal", "gov", "default"})


@dataclass(frozen=True)
class AuthorizedDocument:
    customer_id: str
    deployment_id: str
    document_id: str
    document_route: str
    source_bucket: str
    source_key: str
    artifact_bucket: str
    artifact_key: str
    item: Mapping[str, Any]


def authorize_document_boundary(
    *,
    item: Any,
    message_customer_id: str,
    message_deployment_id: str,
    message_document_id: str,
    message_source_bucket: str,
    message_source_key: str,
    runtime_customer_id: str,
    runtime_deployment_id: str,
    trusted_source_bucket: str,
    trusted_artifact_bucket: str,
) -> AuthorizedDocument:
    """Bind a worker message to one authoritative, deployment-local document."""

    if not isinstance(item, Mapping) or not item:
        raise RuntimeError("Authoritative document was not found")

    expected_owner = (runtime_customer_id, runtime_deployment_id, OWNERSHIP_SCHEMA_VERSION)
    message_owner = (
        message_customer_id,
        message_deployment_id,
        OWNERSHIP_SCHEMA_VERSION,
    )
    stored_owner = (
        item.get("customer_id"),
        item.get("deployment_id"),
        item.get("ownership_schema_version"),
    )
    if message_owner != expected_owner or stored_owner != expected_owner:
        raise RuntimeError("Document ownership does not match the OCR deployment boundary")

    if item.get("documentId") not in (None, message_document_id):
        raise RuntimeError("Authoritative document identifier does not match the message")

    route = item.get("documentRoute")
    if not isinstance(route, str) or route not in ALLOWED_DOCUMENT_ROUTES:
        raise RuntimeError("Authoritative document route is missing or invalid")

    source = item.get("input")
    if not isinstance(source, Mapping):
        raise RuntimeError("Authoritative source locator is missing")
    stored_bucket = source.get("bucket")
    stored_key = source.get("key")
    expected_prefix = build_document_prefix(
        runtime_customer_id,
        runtime_deployment_id,
        message_document_id,
    )
    if (
        not isinstance(stored_bucket, str)
        or not isinstance(stored_key, str)
        or stored_bucket != trusted_source_bucket
        or message_source_bucket != stored_bucket
        or message_source_key != stored_key
        or not stored_key.startswith(expected_prefix)
        or stored_key == expected_prefix
    ):
        raise RuntimeError("Source locator does not match trusted document metadata")

    artifact_key = build_ocr_artifact_key(
        runtime_customer_id,
        runtime_deployment_id,
        message_document_id,
    )
    return AuthorizedDocument(
        customer_id=runtime_customer_id,
        deployment_id=runtime_deployment_id,
        document_id=message_document_id,
        document_route=route,
        source_bucket=stored_bucket,
        source_key=stored_key,
        artifact_bucket=trusted_artifact_bucket,
        artifact_key=artifact_key,
        item=item,
    )


def require_poll_checkpoint(
    authorized: AuthorizedDocument,
    *,
    textract_job_id: str,
    source_bucket: str,
    source_key: str,
    artifact_bucket: str,
    artifact_key: str,
    source_message_id: str | None = None,
) -> Mapping[str, Any]:
    checkpoint = authorized.item.get("ocrPollHandoff")
    if not isinstance(checkpoint, Mapping):
        raise RuntimeError("Authoritative OCR poll checkpoint is missing")
    checkpoint_status = checkpoint.get("status")
    if checkpoint_status not in {"PENDING", "ENQUEUED"}:
        raise RuntimeError("Authoritative OCR poll checkpoint status is invalid")
    if checkpoint_status == "ENQUEUED" and not (
        isinstance(checkpoint.get("messageId"), str)
        and checkpoint.get("messageId").strip()
    ):
        raise RuntimeError("Authoritative OCR poll checkpoint is missing its message id")
    if (
        source_message_id is not None
        and checkpoint_status == "ENQUEUED"
        and checkpoint.get("messageId") != source_message_id
    ):
        raise RuntimeError("OCR poll message does not match the authoritative checkpoint")
    if (
        checkpoint.get("textractJobId") != textract_job_id
        or checkpoint.get("source")
        != {"bucket": source_bucket, "key": source_key}
        or checkpoint.get("artifact")
        != {"bucket": artifact_bucket, "key": artifact_key}
        or checkpoint.get("documentRoute") != authorized.document_route
    ):
        raise RuntimeError("OCR poll checkpoint does not match trusted document metadata")
    return checkpoint
