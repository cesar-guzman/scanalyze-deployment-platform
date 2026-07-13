from __future__ import annotations

import base64
import json
import os
import re
import uuid
import structlog
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from botocore.exceptions import ClientError

from ..auth import AuthContext
from ..authorization import (
    ObjectAction,
    ObjectOwnership,
    authorize_batch,
    authorize_document,
)
from ..aws_clients import s3_client, sqs_client
from ..config import CANONICAL_FIRST_STAGE, get_settings
from ..errors import AppError
from ..logging import bind_context, get_logger
from ..repositories.documents import DocumentsRepository
from ..repositories.batches import BatchesRepository
from ..api.v1.models import IngestEnvelopeV2

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)

def _iso(dt: datetime) -> str:
    return dt.isoformat()

filename_re = re.compile(r"[^A-Za-z0-9.-]+")
object_id_re = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")

# Active worker-v1 artifact contracts. These are exact producer contracts, not
# request-controlled prefixes and not an ownership fallback. GUG-89 owns their
# replacement with the canonical owner-bound prefix across the async pipeline.
worker_v1_ocr_routes = frozenset({"platform", "bank", "personal", "gov"})
worker_v1_structured_routes = frozenset({"bank", "personal", "gov"})


class _MissingSqsAcknowledgement(RuntimeError):
    """SQS accepted the API call without returning the required MessageId."""


def sanitize_filename(name: str) -> str:
    # Evita path traversal y caracteres raros
    name = (name or "").strip()
    name = name.split("/")[-1].split("\\")[-1]
    name = filename_re.sub("", name)
    if not name:
        return "upload.bin"
    if len(name) > 128:
        # Trunca conservador
        parts = name.split(".")
        if len(parts) > 1:
            ext = parts[-1][:10]
            base = "_".join(parts[:-1])[:100]
            return f"{base}.{ext}"
        return name[:128]
    return name

def _b64url_encode(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode("utf-8")).decode("utf-8").rstrip("=")

def _b64url_decode(s: str) -> str:
    pad_len = (-len(s)) % 4
    return base64.urlsafe_b64decode(s + ("=" * pad_len)).decode("utf-8")

@dataclass(frozen=True)
class ArtifactRef:
    artifact_id: str
    bucket: str
    key: str
    uri: str
    bucket_alias: str

class DocumentsService:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.repo = DocumentsRepository()
        self.batches_repo = BatchesRepository()
        self.s3 = s3_client()
        self.sqs = sqs_client()
        self.logger = get_logger()

    def _require(self, cond: bool, code: str, message: str, status: int = 500, details: Optional[Dict[str, Any]] = None) -> None:
        if not cond:
            raise AppError(code=code, message=message, status_code=status, details=details or {})

    def create_document(
        self,
        auth: AuthContext,
        subject: Optional[str],
        email: Optional[str],
        name: Optional[str],
        filename: Optional[str],
        content_type: str,
        content_length: Optional[int] = None,
        batch_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        ownership = ObjectOwnership.from_auth(auth)
        authorize_document(
            auth,
            ownership.record_fields(),
            ObjectAction.WRITE,
        )
        tenant = ownership.customer_id

        # Requiere buckets/table
        table = self.settings.documents_table_name
        raw_bucket = self.settings.get_bucket("raw")

        self._require(bool(table), "CONFIG_ERROR", "DOCUMENTS_TABLE_NAME is required", 500)
        self._require(bool(raw_bucket), "CONFIG_ERROR", "RAW_BUCKET/BUCKETS_JSON.raw is required", 500)

        doc_id = uuid.uuid4().hex
        bind_context(documentId=doc_id, tenant=tenant)
        if subject:
            bind_context(uploaderUserId=subject)

        safe_name = sanitize_filename(filename or "upload.bin")

        if batch_id:
            batch = self.batches_repo.get_batch(batch_id)
            authorize_batch(auth, batch, ObjectAction.WRITE)

        prefix = ownership.document_prefix(doc_id)
        raw_key = f"{prefix}{safe_name}"

        now = _utc_now()
        expires_at = now + timedelta(seconds=self.settings.upload_url_ttl_seconds)

        # Presigned PUT. Forzamos Content-Type (cliente debe enviar el mismo header).
        try:
            params = {
                "Bucket": raw_bucket,
                "Key": raw_key,
                "ContentType": content_type,
            }
            upload_url = self.s3.generate_presigned_url(
                ClientMethod="put_object",
                Params=params,
                ExpiresIn=self.settings.upload_url_ttl_seconds,
            )
        except ClientError as e:
            self.logger.error("presign_put_failed", errorType=type(e).__name__)
            raise AppError(code="S3_PRESIGN_FAILED", message="Failed to generate upload URL", status_code=502, details={})

        ctx = structlog.contextvars.get_contextvars()
        correlation_id = ctx.get("correlationId", uuid.uuid4().hex)
        trace_id = ctx.get("traceId", "")

        item: Dict[str, Any] = {
            # Guardamos documentId siempre (útil para lectura humana)
            "documentId": doc_id,
            "tenantId": tenant,
            **ownership.record_fields(),
            "createdAt": _iso(now),
            "updatedAt": _iso(now),
            "status": "CREATED",
            "version": 1,
            "traceId": trace_id,
            "correlationId": correlation_id,
            "input": {
                "filename": safe_name,
                "contentType": content_type,
                "contentLength": int(content_length) if content_length is not None else None,
                "bucket": raw_bucket,
                "key": raw_key,
            },
            "stages": {},
            "artifacts": {},
        }

        # Si hay subject, lo guardamos como createdBy y uploaderUserId
        if subject:
            item["createdBy"] = subject
            item["uploaderUserId"] = subject
            item["createdByUserSub"] = subject
        if email:
            item["createdByEmail"] = email
        if name:
            item["createdByDisplayName"] = name

        # This value is deployment contract data. The request model exposes no
        # processing-domain field and customer identity is never used as a route.
        trusted_processing_domain = getattr(self.settings, "processing_domain", None)
        item["documentRoute"] = trusted_processing_domain or "platform"
        if trusted_processing_domain is not None:
            item["processing_domain"] = trusted_processing_domain
            
        if batch_id:
            item["batchId"] = batch_id
            item["ownership_batch_key"] = ownership.batch_partition(batch_id)
            item["source"] = "web-bulk-upload"
        else:
            item["source"] = "web-single-upload"

        # Limpia None en input
        if item["input"]["contentLength"] is None:
            del item["input"]["contentLength"]

        # El repo decide PK/SK reales; nosotros duplicamos campos si hace falta.
        # Repo usa PutItem; debemos incluir PK/SK con template si el schema lo requiere.
        # Como el repo no expone schema públicamente, replicamos la key via get_document fallback:
        # - Simplificación: en la mayoría de despliegues, PK = documentId y no hay SK.
        # Si tu tabla usa PK/SK distinto, setea DOCUMENTS_TABLE_PK_NAME/PK_TEMPLATE/SK_NAME/SK_TEMPLATE en ECS.
        pk_name = os.getenv("DOCUMENTS_TABLE_PK_NAME", "documentId")
        pk_template = os.getenv("DOCUMENTS_TABLE_PK_TEMPLATE", "{document_id}")
        item[pk_name] = pk_template.format(document_id=doc_id)
        sk_name = os.getenv("DOCUMENTS_TABLE_SK_NAME")
        if sk_name:
            sk_template = os.getenv("DOCUMENTS_TABLE_SK_TEMPLATE", "METADATA")
            item[sk_name] = sk_template.format(document_id=doc_id)

        self.repo.create_document(item, ownership=ownership)

        return {
            "documentId": doc_id,
            "uploadUrl": upload_url,
            "expiresAt": _iso(expires_at),
            "uploadMethod": "PUT",
            "requiredHeaders": {
                "Content-Type": content_type,
            },
        }

    def submit_document(
        self,
        auth: AuthContext,
        document_id: str,
        stage: Optional[str] = None,
    ) -> Dict[str, Any]:
        configured_stage = getattr(self.settings, "first_stage", None)
        if configured_stage != CANONICAL_FIRST_STAGE:
            raise AppError(
                code="CONFIG_ERROR",
                message="Canonical ingress stage is not configured",
                status_code=500,
                details={},
            )
        if stage is not None and (
            not isinstance(stage, str)
            or stage.lower().strip() != configured_stage
        ):
            raise AppError(
                code="INVALID_STAGE",
                message="Requested stage is not available",
                status_code=400,
                details={},
            )

        # The request may confirm the canonical value, but never establishes it.
        stage_name = configured_stage
        ownership = ObjectOwnership.from_auth(auth)
        tenant = ownership.customer_id
        bind_context(documentId=document_id, tenant=tenant, stage=stage_name)
        doc = self.repo.get_document(document_id)
        authorize_document(auth, doc, ObjectAction.WRITE)
        input_info = doc.get("input") or {}
        raw_bucket, raw_key = self._validate_artifact_locator(
            ownership,
            document_id,
            input_info.get("bucket"),
            input_info.get("key"),
        )

        trusted_processing_domain = getattr(self.settings, "processing_domain", None)
        stored_processing_domain = doc.get("processing_domain")
        if stored_processing_domain != trusted_processing_domain:
            raise AppError(
                code="INVALID_PROCESSING_DOMAIN",
                message="Document processing domain is invalid",
                status_code=409,
                details={},
            )

        queue_url = self.settings.get_queue_url(stage_name)
        self._require(bool(queue_url), "CONFIG_ERROR", f"SQS queue URL for stage '{stage_name}' is not configured", 500)

        enqueue_id = uuid.uuid4().hex

        # Build and validate the complete envelope before claiming the pending
        # state so local contract errors can never strand the document.
        ctx = structlog.contextvars.get_contextvars()
        
        envelope = IngestEnvelopeV2(
            documentId=document_id,
            customer_id=ownership.customer_id,
            deployment_id=ownership.deployment_id,
            processing_domain=trusted_processing_domain,
            enqueue_id=enqueue_id,
            raw={"bucket": raw_bucket, "key": raw_key},
            contentType=input_info.get("contentType"),
            _metadata={
                "correlationId": ctx.get("correlationId", doc.get("correlationId", uuid.uuid4().hex)),
                "traceId": ctx.get("traceId") or doc.get("traceId") or None,
            },
        )
        body = envelope.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        )

        try:
            # Idempotency by canonical stage using the owner-bound Dynamo condition.
            can_enqueue = self.repo.set_stage_enqueue_pending(
                document_id=document_id,
                stage=stage_name,
                enqueue_id=enqueue_id,
                ownership=ownership,
            )
            if not can_enqueue:
                return {
                    "documentId": document_id,
                    "stage": stage_name,
                    "enqueued": False,
                    "message": "Already submitted for this stage",
                }

            resp = self.sqs.send_message(
                QueueUrl=queue_url,
                MessageBody=json.dumps(body),
                MessageAttributes={
                    "customer_id": {"DataType": "String", "StringValue": tenant},
                    "deployment_id": {
                        "DataType": "String",
                        "StringValue": ownership.deployment_id,
                    },
                    "documentId": {"DataType": "String", "StringValue": document_id},
                    "pipeline_stage": {"DataType": "String", "StringValue": stage_name},
                    "enqueue_id": {"DataType": "String", "StringValue": enqueue_id},
                },
            )
            message_id = resp.get("MessageId") if isinstance(resp, dict) else None
            if not isinstance(message_id, str) or not message_id.strip():
                raise _MissingSqsAcknowledgement(
                    "SQS did not acknowledge the message"
                )
            message_id = message_id.strip()
            self.repo.set_stage_enqueued(
                document_id=document_id,
                stage=stage_name,
                enqueue_id=enqueue_id,
                queue_url=queue_url,
                message_id=message_id,
                ownership=ownership,
            )

            return {
                "documentId": document_id,
                "stage": stage_name,
                "enqueued": True,
                "sqsMessageId": message_id,
            }

        except Exception as exc:
            err_code = "SQS_ERROR"
            if isinstance(exc, ClientError):
                err_code = exc.response.get("Error", {}).get("Code", err_code)
            elif isinstance(exc, _MissingSqsAcknowledgement):
                err_code = "SQS_ACK_MISSING"

            try:
                self.repo.set_stage_enqueue_failed(
                    document_id=document_id,
                    stage=stage_name,
                    enqueue_id=enqueue_id,
                    error_code=err_code,
                    error_message="Failed to enqueue message",
                    ownership=ownership,
                )
            except Exception as recovery_error:
                self.logger.error(
                    "sqs_enqueue_recovery_failed",
                    errorType=type(recovery_error).__name__,
                )
                raise AppError(
                    code="SQS_ENQUEUE_RECOVERY_FAILED",
                    message="Failed to recover document enqueue state",
                    status_code=502,
                    details={"stage": stage_name},
                ) from exc

            self.logger.error(
                "sqs_send_failed",
                sqsErrorCode=err_code,
                errorType=type(exc).__name__,
            )
            raise AppError(
                code="SQS_ENQUEUE_FAILED",
                message="Failed to enqueue document",
                status_code=502,
                details={"stage": stage_name},
            ) from exc

    def get_document_status(self, auth: AuthContext, document_id: str) -> Dict[str, Any]:
        tenant = auth.customer_id
        bind_context(documentId=document_id, tenant=tenant)
        doc = self.repo.get_document(document_id)
        authorize_document(auth, doc, ObjectAction.READ)
        doc_tenant = doc.get("customer_id")

        # Metadata mínima, evitando exponer buckets/keys salvo en artifacts endpoints
        input_info = doc.get("input") or {}
        stages = doc.get("stages") or {}

        return {
            "documentId": doc.get("documentId", document_id),
            "tenantId": doc_tenant,
            "batchId": doc.get("batchId"),
            "status": doc.get("status"),
            "createdAt": doc.get("createdAt"),
            "updatedAt": doc.get("updatedAt"),
            "uploaderUserId": doc.get("uploaderUserId"),
            "correlationId": doc.get("correlationId"),
            "input": {
                "filename": input_info.get("filename"),
                "contentType": input_info.get("contentType"),
            },
            "stages": stages,
        }

    def _doc_prefix(self, doc: Dict[str, Any]) -> str:
        input_info = doc.get("input") or {}
        prefix = input_info.get("prefix")
        if prefix:
            if not prefix.endswith("/"):
                prefix += "/"
            return prefix

        # fallback: deriva del key
        k = input_info.get("key") or ""
        if "/" in k:
            return k.rsplit("/", 1)[0] + "/"
        return ""

    def _resolve_final_artifact(self, doc: Dict[str, Any]) -> Tuple[str, str, str]:
        """
        Unified resolver for the FINAL structured artifact.
        Implements the formal Result contract:
        1. Checks stages.persist.artifactRef (v1.0.0 explicit contract)
        2. Fallback to artifacts.structured (legacy anchor / backward compatibility)
        3. Fallback to artifacts.result
        """
        # 1. New formal contract source of truth
        stages = doc.get("stages", {})
        persist_stage = stages.get("persist", {})
        artifact_ref = persist_stage.get("artifactRef")
        if artifact_ref and artifact_ref.get("bucket") and artifact_ref.get("key"):
            return artifact_ref["bucket"], artifact_ref["key"], artifact_ref.get("alias", "structured")

        # 2. Backward compatible anchors
        artifacts_dict = doc.get("artifacts", {})
        
        # 2a. Default structured
        structured = artifacts_dict.get("structured")
        if structured and structured.get("bucket") and structured.get("key"):
            return structured["bucket"], structured["key"], "structured"
            
        # 2b. Legacy result
        result = artifacts_dict.get("result")
        if result and result.get("bucket") and result.get("key"):
            return result["bucket"], result["key"], "result"
            
        raise AppError(code="RESULT_NOT_READY", message="Final result artifact not found in manifest", status_code=404, details={})

    def _get_artifact_locator(self, doc: Dict[str, Any], artifact_id: str) -> Tuple[str, str, str]:
        if artifact_id in ("structured", "result", "final"):
            try:
                return self._resolve_final_artifact(doc)
            except AppError:
                pass # fall through to explicit check if needed

        artifacts_dict = doc.get("artifacts", {})
        artifact_info = artifacts_dict.get(artifact_id)

        if not artifact_info or not artifact_info.get("bucket") or not artifact_info.get("key"):
            raise AppError(code="NOT_FOUND", message=f"Artifact '{artifact_id}' not found in manifest", status_code=404, details={})

        return artifact_info["bucket"], artifact_info["key"], artifact_id

    def _validate_artifact_locator(
        self,
        ownership: ObjectOwnership,
        document_id: str,
        bucket: Any,
        key: Any,
    ) -> Tuple[str, str]:
        allowed_buckets = {
            configured
            for alias in ("raw", "ocr", "structured", "errors")
            if (configured := self.settings.get_bucket(alias))
        }
        expected_prefix = ownership.document_prefix(document_id)
        canonical_locator = (
            isinstance(key, str)
            and key.startswith(expected_prefix)
            and ".." not in key.split("/")
        )
        worker_v1_locator = self._is_exact_worker_v1_artifact_locator(
            document_id=document_id,
            bucket=bucket,
            key=key,
        )
        if (
            not isinstance(bucket, str)
            or bucket not in allowed_buckets
            or not (canonical_locator or worker_v1_locator)
        ):
            self.logger.warning(
                "artifact_authorization_failed",
                reason="untrusted_stored_locator",
            )
            raise AppError(
                code="NOT_FOUND",
                message="Artifact not found",
                status_code=404,
                details={},
            )
        return bucket, key

    def _is_exact_worker_v1_artifact_locator(
        self,
        *,
        document_id: str,
        bucket: Any,
        key: Any,
    ) -> bool:
        """Match only artifact keys emitted by the current reviewed workers.

        The object has already passed exact customer/deployment authorization.
        This compatibility contract additionally binds the locator to one
        configured deployment bucket, the exact stored document id, a fixed
        route, and a fixed artifact filename. Arbitrary legacy prefixes remain
        denied.
        """
        if (
            not isinstance(bucket, str)
            or not isinstance(key, str)
            or not object_id_re.fullmatch(document_id)
        ):
            return False

        ocr_bucket = self.settings.get_bucket("ocr")
        if bucket == ocr_bucket and key in {
            f"{route}/{document_id}/ocr.json" for route in worker_v1_ocr_routes
        }:
            return True

        structured_bucket = self.settings.get_bucket("structured")
        return bucket == structured_bucket and key in {
            f"{route}/{document_id}/result.json"
            for route in worker_v1_structured_routes
        }

    def get_trusted_artifact_locator(
        self,
        auth: AuthContext,
        doc: Dict[str, Any],
        artifact_id: str,
    ) -> Tuple[str, str, str]:
        ownership = authorize_document(auth, doc, ObjectAction.EXPORT)
        document_id = doc.get("documentId")
        if not isinstance(document_id, str) or not document_id:
            raise AppError(
                code="NOT_FOUND",
                message="Document not found",
                status_code=404,
                details={},
            )
        bucket, key, resolved_alias = self._get_artifact_locator(doc, artifact_id)
        trusted_bucket, trusted_key = self._validate_artifact_locator(
            ownership,
            document_id,
            bucket,
            key,
        )
        return trusted_bucket, trusted_key, resolved_alias

    def list_artifacts(self, auth: AuthContext, document_id: str) -> Dict[str, Any]:
        tenant = auth.customer_id
        bind_context(documentId=document_id, tenant=tenant)
        doc = self.repo.get_document(document_id)
        ownership = authorize_document(auth, doc, ObjectAction.READ)

        artifacts_dict = doc.get("artifacts", {})
        artifacts = []

        for alias, info in artifacts_dict.items():
            bucket = info.get("bucket")
            key = info.get("key")
            if not bucket or not key:
                raise AppError(
                    code="NOT_FOUND",
                    message="Artifact not found",
                    status_code=404,
                    details={},
                )
            bucket, key = self._validate_artifact_locator(
                ownership,
                document_id,
                bucket,
                key,
            )

            # The artifact_id is just the alias itself
            artifacts.append({
                "artifactId": alias,
                "bucketAlias": alias,
                "uri": f"s3://{bucket}/{key}"
            })

        prefix = ownership.document_prefix(document_id)
        return {
            "documentId": document_id,
            "prefix": prefix,
            "artifacts": artifacts,
        }

    def _generate_presigned_download(self, document_id: str, artifact_id: str, bucket: str, key: str) -> Dict[str, Any]:
        expires_at = _utc_now() + timedelta(seconds=self.settings.download_url_ttl_seconds)
        try:
            url = self.s3.generate_presigned_url(
                ClientMethod="get_object",
                Params={
                    "Bucket": bucket,
                    "Key": key,
                    "ResponseContentDisposition": "attachment",
                },
                ExpiresIn=self.settings.download_url_ttl_seconds,
            )
        except ClientError as e:
            self.logger.error("presign_get_failed", errorType=type(e).__name__)
            raise AppError(code="S3_PRESIGN_FAILED", message="Failed to generate download URL", status_code=502, details={})

        return {
            "documentId": document_id,
            "artifactId": artifact_id,
            "downloadUrl": url,
            "expiresAt": _iso(expires_at),
        }

    def presign_artifact_download(
        self,
        auth: AuthContext,
        document_id: str,
        artifact_id: str,
    ) -> Dict[str, Any]:
        tenant = auth.customer_id
        bind_context(documentId=document_id, tenant=tenant)

        doc = self.repo.get_document(document_id)
        authorize_document(auth, doc, ObjectAction.EXPORT)
        bucket, key, resolved_alias = self.get_trusted_artifact_locator(
            auth,
            doc,
            artifact_id,
        )
        
        return self._generate_presigned_download(document_id, resolved_alias, bucket, key)

    def get_result(self, auth: AuthContext, document_id: str) -> Dict[str, Any]:
        tenant = auth.customer_id
        bind_context(documentId=document_id, tenant=tenant)
        doc = self.repo.get_document(document_id)
        authorize_document(auth, doc, ObjectAction.EXPORT)

        status = doc.get("status")
        if status != "COMPLETED":
            raise AppError(code="RESULT_NOT_READY", message=f"Result not ready, status is {status}", status_code=409, details={})

        bucket, key, resolved_alias = self.get_trusted_artifact_locator(
            auth,
            doc,
            "final",
        )
        return self._generate_presigned_download(document_id, resolved_alias, bucket, key)
