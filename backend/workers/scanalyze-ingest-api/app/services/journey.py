"""Versioned, owner-bound document journey orchestration for GUG-354.

The service reserves one stable resource identity before a business write,
never persists ephemeral capabilities, and reconciles ambiguous outcomes with
strongly consistent reads.  All dependencies are injectable so focused tests
cannot construct real cloud clients.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import threading
import uuid
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta, timezone
from typing import Any

from pydantic import ValidationError

from ..auth import AuthContext
from ..authorization import (
    ObjectAction,
    ObjectOwnership,
    authorize_batch,
    authorize_document,
)
from ..config import Settings, get_settings
from ..errors import AppError
from ..journey_contract import (
    CONTRACT_VERSION,
    BatchCreateRequest,
    BatchCreateResponse,
    BatchDurableResponse,
    BankStatementResult,
    DocumentLifecycle,
    DocumentCreateRequest,
    DocumentCreateResponse,
    DocumentDurableResponse,
    DocumentStatusResponse,
    JourneyContractError,
    LedgerState,
    MalformedInternalResult,
    OperationKind,
    OwnerScope,
    ReconciliationFailureCode,
    ReconciliationResponse,
    SubmitDocumentRequest,
    SubmitDocumentResponse,
    UploadCapability,
    UploadCapabilityResponse,
    UploadRequiredHeaders,
    adapt_internal_document_status,
    canonical_request_digest,
    idempotency_key_digest,
    owner_scope_from_auth,
    project_bank_statement_result,
    strict_json_object,
)
from ..logging import current_log_reference
from ..repositories.batches import BatchesRepository
from ..repositories.documents import DocumentsRepository
from ..repositories.operations import (
    DynamoOperationsRepository,
    OperationConflict,
    OperationContractError,
    OperationIdentity,
    OperationPersistenceAmbiguous,
    OperationRecord,
)
from .documents import DocumentsService, sanitize_filename


_RESOURCE_SCHEMA_VERSION = 1
_MAX_LIMITER_ENTRIES = 10_000


class BoundedIntervalLimiter:
    """Small process-local abuse bound keyed only by safe digests/references."""

    def __init__(self, *, max_entries: int = _MAX_LIMITER_ENTRIES) -> None:
        self._max_entries = max_entries
        self._claims: dict[str, datetime] = {}
        self._lock = threading.Lock()

    def claim(self, key: str, *, now: datetime, interval_seconds: int) -> int | None:
        if not isinstance(key, str) or not key or interval_seconds < 1:
            raise ValueError("rate-limit contract is invalid")
        with self._lock:
            previous = self._claims.get(key)
            if previous is not None:
                remaining = interval_seconds - (now - previous).total_seconds()
                if remaining > 0:
                    return max(1, math.ceil(remaining))
            if len(self._claims) >= self._max_entries:
                oldest = min(self._claims, key=self._claims.__getitem__)
                self._claims.pop(oldest, None)
            self._claims[key] = now
        return None


_PROCESS_LIMITER = BoundedIntervalLimiter()


class JourneyService:
    """Orchestrate the reviewed v2 contract without broadening legacy v1."""

    def __init__(
        self,
        *,
        settings: Settings | Any | None = None,
        operations: DynamoOperationsRepository | Any | None = None,
        batches_repo: BatchesRepository | Any | None = None,
        documents_repo: DocumentsRepository | Any | None = None,
        s3: Any | None = None,
        legacy_documents_service: DocumentsService | Any | None = None,
        clock: Callable[[], datetime] | None = None,
        id_factory: Callable[[], str] | None = None,
        limiter: BoundedIntervalLimiter | Any | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.id_factory = id_factory or (lambda: uuid.uuid4().hex)
        self.limiter = limiter or _PROCESS_LIMITER

        if operations is None:
            documents_table = getattr(self.settings, "documents_table_name", None)
            ledger_table = getattr(self.settings, "operation_ledger_table_name", None)
            if not ledger_table or ledger_table != documents_table:
                raise AppError(
                    code="SERVICE_UNAVAILABLE",
                    message="The journey ledger is not configured.",
                    status_code=503,
                    details={},
                )
            from ..aws_clients import dynamodb_resource

            operations = DynamoOperationsRepository(
                dynamodb_resource().Table(ledger_table)
            )
        self.operations = operations
        self.batches_repo = batches_repo or BatchesRepository()
        self.documents_repo = documents_repo or DocumentsRepository()
        if s3 is None:
            from ..aws_clients import s3_client

            s3 = s3_client()
        self.s3 = s3
        self._legacy_documents_service = legacy_documents_service

    def create_batch(
        self,
        *,
        auth: AuthContext,
        idempotency_key: str,
        request: BatchCreateRequest,
    ) -> BatchCreateResponse:
        ownership, scope = self._owner(auth)
        authorize_batch(auth, ownership.record_fields(), ObjectAction.WRITE)
        request_digest = canonical_request_digest(OperationKind.BATCH_CREATE, request)
        identity = self._operation_identity(
            scope, OperationKind.BATCH_CREATE, idempotency_key
        )
        now = self._now()
        batch_id = self._new_resource_id()
        durable = BatchDurableResponse(batch_id=batch_id, created_at=now)
        outcome = self._reserve(
            identity=identity,
            request_digest=request_digest,
            resource_type="batch",
            resource_id=batch_id,
            durable_response=durable.model_dump(mode="json", by_alias=True),
            now=now,
        )

        if outcome.created_here:
            item = {
                "batch_id": batch_id,
                "batchId": batch_id,
                "tenantId": ownership.customer_id,
                **ownership.record_fields(),
                "createdAt": self._iso(now),
                "status": "OPEN",
                "metadata": {},
                "source": "document-journey-v2",
                **self._journey_binding(
                    scope,
                    operation=OperationKind.BATCH_CREATE,
                    request_digest=request_digest,
                ),
            }
            record = self._write_business_once(
                identity=identity,
                pending=outcome.record,
                writer=lambda: self.batches_repo.create_batch(
                    item, ownership=ownership
                ),
            )
        else:
            record = self._resolve_existing(identity, outcome.record)
        parsed = self._batch_response(record)
        return BatchCreateResponse(
            replayed=not outcome.created_here,
            durable_response=parsed,
        )

    def create_document(
        self,
        *,
        auth: AuthContext,
        idempotency_key: str,
        request: DocumentCreateRequest,
    ) -> DocumentCreateResponse:
        ownership, scope = self._owner(auth)
        authorize_document(auth, ownership.record_fields(), ObjectAction.WRITE)
        raw_bucket = self.settings.get_bucket("raw")
        if not isinstance(raw_bucket, str) or not raw_bucket:
            raise AppError(
                code="SERVICE_UNAVAILABLE",
                message="Document storage is not configured.",
                status_code=503,
                details={},
            )
        # Resolve and validate the exact persisted key segment before the
        # idempotency reservation. A locally invalid filename must never leave
        # a successful durable operation without an upload capability.
        filename = sanitize_filename(request.filename or "upload.bin")
        if filename in {".", ".."} or "/" in filename or "\\" in filename:
            raise AppError(
                code="SEMANTIC_VALIDATION_FAILED",
                message="Document metadata is invalid.",
                status_code=422,
                details={},
            )
        if request.batch_id is not None:
            batch = self.batches_repo.get_batch(request.batch_id, consistent=True)
            self._authorize_journey_record(
                auth,
                scope,
                batch,
                resource_type="batch",
                resource_id=request.batch_id,
                action=ObjectAction.WRITE,
            )

        request_digest = canonical_request_digest(
            OperationKind.DOCUMENT_CREATE, request
        )
        identity = self._operation_identity(
            scope, OperationKind.DOCUMENT_CREATE, idempotency_key
        )
        now = self._now()
        document_id = self._new_resource_id()
        durable = DocumentDurableResponse(
            document_id=document_id,
            batch_id=request.batch_id,
            content_type=request.content_type,
            created_at=now,
        )
        outcome = self._reserve(
            identity=identity,
            request_digest=request_digest,
            resource_type="document",
            resource_id=document_id,
            durable_response=durable.model_dump(
                mode="json", by_alias=True, exclude_none=True
            ),
            now=now,
        )

        if outcome.created_here:
            raw_key = f"{ownership.document_prefix(document_id)}{filename}"
            input_record: dict[str, Any] = {
                "filename": filename,
                "contentType": request.content_type.value,
                "bucket": raw_bucket,
                "key": raw_key,
            }
            if request.content_length is not None:
                input_record["contentLength"] = request.content_length
            item: dict[str, Any] = {
                "documentId": document_id,
                "tenantId": ownership.customer_id,
                **ownership.record_fields(),
                "createdAt": self._iso(now),
                "updatedAt": self._iso(now),
                "status": "CREATED",
                "version": 1,
                "correlationReference": current_log_reference(
                    "correlationId", document_id
                ),
                "input": input_record,
                "stages": {},
                "artifacts": {},
                "documentRoute": getattr(
                    self.settings, "processing_domain", None
                )
                or "platform",
                "source": (
                    "document-journey-v2-batch"
                    if request.batch_id is not None
                    else "document-journey-v2-single"
                ),
                **self._journey_binding(
                    scope,
                    operation=OperationKind.DOCUMENT_CREATE,
                    request_digest=request_digest,
                ),
            }
            processing_domain = getattr(self.settings, "processing_domain", None)
            if processing_domain is not None:
                item["processing_domain"] = processing_domain
            if request.batch_id is not None:
                item["batchId"] = request.batch_id
                item["ownership_batch_key"] = ownership.batch_partition(
                    request.batch_id
                )
            key_builder = getattr(self.documents_repo, "_key_for", None)
            if callable(key_builder):
                item.update(key_builder(document_id))
            else:
                pk_name = os.getenv("DOCUMENTS_TABLE_PK_NAME", "documentId")
                pk_template = os.getenv(
                    "DOCUMENTS_TABLE_PK_TEMPLATE", "{document_id}"
                )
                item[pk_name] = pk_template.format(document_id=document_id)
                sk_name = os.getenv("DOCUMENTS_TABLE_SK_NAME")
                if sk_name:
                    item[sk_name] = os.getenv(
                        "DOCUMENTS_TABLE_SK_TEMPLATE", "METADATA"
                    ).format(document_id=document_id)
            record = self._write_business_once(
                identity=identity,
                pending=outcome.record,
                writer=lambda: self.documents_repo.create_document(
                    item, ownership=ownership
                ),
            )
        else:
            record = self._resolve_existing(identity, outcome.record)

        parsed = self._document_response(record)
        capability: UploadCapability | None
        try:
            capability = self._mint_upload_capability(
                auth=auth,
                scope=scope,
                document_id=parsed.document_id,
                enforce_refresh_limit=not outcome.created_here,
            )
        except AppError as error:
            # The durable create response remains replayable after the upload
            # window closes. Only a replay may omit the now-invalid ephemeral
            # capability; the first create must still return one.
            if outcome.created_here or error.code != "STATE_CONFLICT":
                raise
            capability = None
        return DocumentCreateResponse(
            replayed=not outcome.created_here,
            durable_response=parsed,
            upload_capability=capability,
        )

    def reconcile(
        self,
        *,
        auth: AuthContext,
        operation: OperationKind,
        idempotency_key: str,
    ) -> ReconciliationResponse:
        _ownership, scope = self._owner(auth)
        now = self._now()
        retry_after = self.limiter.claim(
            f"reconcile:{scope.actor_digest}:{operation.value}",
            now=now,
            interval_seconds=getattr(
                self.settings,
                "journey_reconciliation_min_interval_seconds",
                1,
            ),
        )
        if retry_after is not None:
            raise AppError(
                code="RATE_LIMITED",
                message="Reconciliation is rate limited.",
                status_code=429,
                details={"retryAfterSeconds": retry_after},
                retry_after_seconds=retry_after,
            )
        identity = self._operation_identity(scope, operation, idempotency_key)
        try:
            record = self.operations.load(identity)
        except OperationContractError as error:
            raise self._internal_contract_error() from error
        except Exception as error:
            raise self._unavailable_error() from error
        if record is None:
            raise AppError(
                code="NOT_FOUND",
                message="Operation not found.",
                status_code=404,
                details={},
            )
        record = self._expire(record, identity, now=now)
        if record.state is LedgerState.PENDING:
            completed = self._reconcile_business_record(identity, record)
            if completed is not None:
                record = completed
            elif self._pending_is_stale(record, now=now):
                quarantined = self._mark_unknown(identity, record)
                if quarantined is None:
                    raise self._unknown_write_error()
                record = quarantined
        durable = None
        if record.state is LedgerState.SUCCEEDED:
            durable = (
                self._batch_response(record)
                if operation is OperationKind.BATCH_CREATE
                else self._document_response(record)
            )
        failure = {
            LedgerState.FAILED_RETRYABLE: ReconciliationFailureCode.CREATE_FAILED_RETRYABLE,
            LedgerState.FAILED_TERMINAL: ReconciliationFailureCode.CREATE_FAILED_TERMINAL,
            LedgerState.UNKNOWN_OR_QUARANTINED: ReconciliationFailureCode.UNKNOWN_WRITE_OUTCOME,
            LedgerState.EXPIRED: ReconciliationFailureCode.OPERATION_EXPIRED,
        }.get(record.state)
        try:
            return ReconciliationResponse(
                operation=operation,
                ledger_state=record.state,
                durable_response=durable,
                failure_code=failure,
                created_at=record.created_at,
                updated_at=record.updated_at,
                completed_at=record.completed_at,
                expires_at=record.expires_at,
            )
        except (JourneyContractError, ValidationError) as error:
            raise self._internal_contract_error() from error

    def refresh_upload_capability(
        self,
        *,
        auth: AuthContext,
        document_id: str,
    ) -> UploadCapabilityResponse:
        _ownership, scope = self._owner(auth)
        capability = self._mint_upload_capability(
            auth=auth,
            scope=scope,
            document_id=document_id,
            enforce_refresh_limit=True,
        )
        return UploadCapabilityResponse(
            document_id=document_id,
            upload_capability=capability,
        )

    def get_document_status(
        self,
        *,
        auth: AuthContext,
        document_id: str,
    ) -> DocumentStatusResponse:
        _ownership, scope = self._owner(auth)
        document = self.documents_repo.get_document(document_id, consistent=True)
        self._authorize_journey_record(
            auth,
            scope,
            document,
            resource_type="document",
            resource_id=document_id,
            action=ObjectAction.READ,
        )
        try:
            return adapt_internal_document_status(document, now=self._now())
        except (JourneyContractError, ValidationError, TypeError) as error:
            raise AppError(
                code="UNSUPPORTED_STATE",
                message="Document state is unsupported.",
                status_code=500,
                details={},
            ) from error

    def submit_document(
        self,
        *,
        auth: AuthContext,
        document_id: str,
        request: SubmitDocumentRequest,
    ) -> SubmitDocumentResponse:
        _ownership, scope = self._owner(auth)
        document = self.documents_repo.get_document(document_id, consistent=True)
        self._authorize_journey_record(
            auth,
            scope,
            document,
            resource_type="document",
            resource_id=document_id,
            action=ObjectAction.WRITE,
        )
        if not self._can_begin_submit(document):
            raise self._state_conflict_error()
        service = self._legacy_documents_service
        if service is None:
            service = DocumentsService()
            self._legacy_documents_service = service
        try:
            response = service.submit_document(
                auth=auth,
                document_id=document_id,
                stage=request.stage,
            )
        except AppError as error:
            current = self.documents_repo.get_document(
                document_id, consistent=True
            )
            self._authorize_journey_record(
                auth,
                scope,
                current,
                resource_type="document",
                resource_id=document_id,
                action=ObjectAction.WRITE,
            )
            if not (
                self._can_begin_submit(current)
                or self._is_existing_submission(current)
            ):
                raise self._state_conflict_error() from error
            raise
        if not isinstance(response, Mapping):
            raise self._internal_contract_error()
        enqueued = response.get("enqueued")
        if not isinstance(enqueued, bool):
            raise self._internal_contract_error()
        if not enqueued:
            current = self.documents_repo.get_document(
                document_id, consistent=True
            )
            self._authorize_journey_record(
                auth,
                scope,
                current,
                resource_type="document",
                resource_id=document_id,
                action=ObjectAction.WRITE,
            )
            if not self._is_existing_submission(current):
                raise self._state_conflict_error()
        return SubmitDocumentResponse(
            document_id=document_id,
            stage="ingest",
            enqueued=enqueued,
        )

    def get_result(
        self,
        *,
        auth: AuthContext,
        document_id: str,
    ) -> BankStatementResult:
        ownership, scope = self._owner(auth)
        document = self.documents_repo.get_document(document_id, consistent=True)
        self._authorize_journey_record(
            auth,
            scope,
            document,
            resource_type="document",
            resource_id=document_id,
            action=ObjectAction.EXPORT,
        )
        # Family selection is owner-metadata-only and precedes all lifecycle
        # projection or storage access so unsupported routes have one stable
        # public outcome even when their private stage schema differs.
        self._require_supported_result_domain(document)
        try:
            status = adapt_internal_document_status(document, now=self._now())
        except (JourneyContractError, ValidationError, TypeError) as error:
            raise AppError(
                code="UNSUPPORTED_STATE",
                message="Document state is unsupported.",
                status_code=500,
                details={},
            ) from error
        if status.lifecycle is not DocumentLifecycle.COMPLETED:
            raise AppError(
                code="RESULT_NOT_READY",
                message="Document result is not ready.",
                status_code=409,
                details={},
            )
        bucket, key = self._trusted_result_locator(
            ownership, document_id, document
        )
        expected_content_sha256, expected_metadata = (
            self._trusted_bank_extraction_evidence(
                ownership,
                document_id,
                document,
                bucket=bucket,
                key=key,
            )
        )
        maximum = getattr(self.settings, "journey_result_max_bytes", 5_242_880)
        try:
            response = self.s3.get_object(Bucket=bucket, Key=key)
            body = response.get("Body")
            try:
                if body is None or not callable(getattr(body, "read", None)):
                    raise MalformedInternalResult("stored result body is missing")
                length = response.get("ContentLength")
                if length is not None and (
                    not isinstance(length, int)
                    or isinstance(length, bool)
                    or length < 0
                    or length > maximum
                ):
                    raise MalformedInternalResult("stored result size is invalid")
                if response.get("Metadata") != expected_metadata:
                    raise MalformedInternalResult(
                        "stored result evidence is invalid"
                    )
                raw = body.read(maximum + 1)
            finally:
                close = getattr(body, "close", None)
                if callable(close):
                    close()
        except MalformedInternalResult as error:
            raise AppError(
                code="MALFORMED_INTERNAL_RESULT",
                message="Stored result is invalid.",
                status_code=500,
                details={},
            ) from error
        except Exception as error:
            raise AppError(
                code="UPSTREAM_ERROR",
                message="Result storage is unavailable.",
                status_code=502,
                details={},
            ) from error
        if not isinstance(raw, (bytes, str)):
            raise AppError(
                code="MALFORMED_INTERNAL_RESULT",
                message="Stored result is invalid.",
                status_code=500,
                details={},
            )
        raw_bytes = raw if isinstance(raw, bytes) else raw.encode("utf-8")
        if (
            len(raw_bytes) > maximum
            or hashlib.sha256(raw_bytes).hexdigest()
            != expected_content_sha256
        ):
            raise AppError(
                code="MALFORMED_INTERNAL_RESULT",
                message="Stored result is invalid.",
                status_code=500,
                details={},
            )
        try:
            payload = strict_json_object(raw, max_bytes=maximum)
        except JourneyContractError as error:
            raise AppError(
                code="MALFORMED_INTERNAL_RESULT",
                message="Stored result is invalid.",
                status_code=500,
                details={},
            ) from error
        document_type = payload.get("docType")
        if not isinstance(document_type, str):
            raise AppError(
                code="MALFORMED_INTERNAL_RESULT",
                message="Stored result discriminator is invalid.",
                status_code=500,
                details={},
            )
        if document_type != "bank_statement":
            raise AppError(
                code="UNSUPPORTED_RESULT_TYPE",
                message="Document result type is unsupported.",
                status_code=422,
                details={},
            )
        try:
            return project_bank_statement_result(
                payload,
                document_id=document_id,
            )
        except (MalformedInternalResult, JourneyContractError, ValidationError) as error:
            raise AppError(
                code="MALFORMED_INTERNAL_RESULT",
                message="Stored result is invalid.",
                status_code=500,
                details={},
            ) from error

    def _owner(self, auth: AuthContext) -> tuple[ObjectOwnership, OwnerScope]:
        try:
            return ObjectOwnership.from_auth(auth), owner_scope_from_auth(auth)
        except (JourneyContractError, TypeError, ValueError) as error:
            raise AppError(
                code="AUTHORIZATION_DENIED",
                message="Principal is not authorized.",
                status_code=403,
                details={},
            ) from error

    def _operation_identity(
        self,
        scope: OwnerScope,
        operation: OperationKind,
        raw_key: str,
    ) -> OperationIdentity:
        try:
            key_digest = idempotency_key_digest(raw_key)
            return OperationIdentity(
                contract_version=CONTRACT_VERSION,
                operation=operation.value,
                actor_digest=scope.actor_digest,
                customer_id=scope.customer_id,
                deployment_id=scope.deployment_id,
                key_digest=key_digest,
            )
        except (JourneyContractError, OperationContractError) as error:
            raise AppError(
                code="MALFORMED_REQUEST",
                message="Idempotency key is invalid.",
                status_code=400,
                details={"field": "Idempotency-Key"},
            ) from error

    def _reserve(
        self,
        *,
        identity: OperationIdentity,
        request_digest: str,
        resource_type: str,
        resource_id: str,
        durable_response: Mapping[str, Any],
        now: datetime,
    ) -> Any:
        try:
            return self.operations.reserve(
                identity,
                request_digest=request_digest,
                resource_type=resource_type,
                resource_id=resource_id,
                durable_response=durable_response,
                now=now,
                expires_at=now
                + timedelta(
                    seconds=getattr(
                        self.settings,
                        "journey_operation_retention_seconds",
                        2_592_000,
                    )
                ),
            )
        except OperationConflict as error:
            raise AppError(
                code="IDEMPOTENCY_CONFLICT",
                message="Idempotency key is already bound.",
                status_code=409,
                details={"operation": identity.operation},
            ) from error
        except OperationPersistenceAmbiguous as error:
            raise self._unknown_write_error() from error
        except OperationContractError as error:
            raise self._internal_contract_error() from error

    def _write_business_once(
        self,
        *,
        identity: OperationIdentity,
        pending: OperationRecord,
        writer: Callable[[], None],
    ) -> OperationRecord:
        try:
            writer()
        except Exception as write_error:
            reconciled = self._reconcile_business_record(identity, pending)
            if reconciled is not None:
                return reconciled
            self._mark_unknown(identity, pending)
            raise self._unknown_write_error() from write_error
        return self._transition_success(identity, pending)

    def _resolve_existing(
        self,
        identity: OperationIdentity,
        record: OperationRecord,
    ) -> OperationRecord:
        record = self._expire(record, identity, now=self._now())
        if record.state is LedgerState.SUCCEEDED:
            return record
        if record.state is LedgerState.PENDING:
            reconciled = self._reconcile_business_record(identity, record)
            if reconciled is not None:
                return reconciled
            raise self._unknown_write_error()
        if record.state is LedgerState.EXPIRED:
            raise AppError(
                code="EXPIRED_OPERATION",
                message="Operation key is expired.",
                status_code=409,
                details={"operation": identity.operation},
            )
        if record.state is LedgerState.FAILED_RETRYABLE:
            raise self._unavailable_error()
        if record.state is LedgerState.FAILED_TERMINAL:
            raise self._state_conflict_error()
        if record.state is LedgerState.UNKNOWN_OR_QUARANTINED:
            raise self._unknown_write_error()
        raise self._internal_contract_error()

    def _reconcile_business_record(
        self,
        identity: OperationIdentity,
        pending: OperationRecord,
    ) -> OperationRecord | None:
        try:
            if pending.resource_type == "batch":
                resource = self.batches_repo.get_batch(
                    pending.resource_id, consistent=True
                )
            else:
                resource = self.documents_repo.get_document(
                    pending.resource_id, consistent=True
                )
        except Exception as error:
            raise self._unknown_write_error() from error
        if resource is None:
            return None
        if not self._business_binding_matches(pending, resource):
            self._mark_unknown(identity, pending)
            raise self._unknown_write_error()
        return self._transition_success(identity, pending)

    def _transition_success(
        self,
        identity: OperationIdentity,
        pending: OperationRecord,
    ) -> OperationRecord:
        now = self._now()
        try:
            return self.operations.transition(
                identity,
                expected_state=LedgerState.PENDING,
                expected_version=pending.version,
                next_state=LedgerState.SUCCEEDED,
                durable_response=pending.durable_response,
                completed_at=now,
                updated_at=now,
            )
        except OperationConflict as error:
            try:
                current = self.operations.load(identity)
            except Exception as read_error:
                raise self._unknown_write_error() from read_error
            if current is not None and current.state is LedgerState.SUCCEEDED:
                return current
            raise self._unknown_write_error() from error
        except (OperationPersistenceAmbiguous, OperationContractError) as error:
            raise self._unknown_write_error() from error

    def _mark_unknown(
        self,
        identity: OperationIdentity,
        pending: OperationRecord,
    ) -> OperationRecord | None:
        now = self._now()
        try:
            return self.operations.transition(
                identity,
                expected_state=LedgerState.PENDING,
                expected_version=pending.version,
                next_state=LedgerState.UNKNOWN_OR_QUARANTINED,
                durable_response=pending.durable_response,
                failure_code="UNKNOWN_WRITE_OUTCOME",
                completed_at=now,
                updated_at=now,
            )
        except OperationConflict:
            try:
                current = self.operations.load(identity)
            except Exception:
                return None
            if (
                current is not None
                and current.state is LedgerState.UNKNOWN_OR_QUARANTINED
            ):
                return current
            return None
        except Exception:
            # The public response remains UNKNOWN; a later strongly consistent
            # reconciliation read is the only authorized next action.
            return None

    def _pending_is_stale(
        self,
        record: OperationRecord,
        *,
        now: datetime,
    ) -> bool:
        grace_seconds = getattr(
            self.settings,
            "journey_pending_reconciliation_grace_seconds",
            30,
        )
        if (
            not isinstance(grace_seconds, int)
            or isinstance(grace_seconds, bool)
            or grace_seconds < 1
        ):
            raise self._internal_contract_error()
        return now >= record.updated_at + timedelta(seconds=grace_seconds)

    @staticmethod
    def _can_begin_submit(document: Mapping[str, Any]) -> bool:
        status = document.get("status")
        stages = document.get("stages")
        if not isinstance(stages, Mapping):
            return False
        ingest = stages.get("ingest")
        if status in {"CREATED", "UPLOADED"}:
            return ingest is None or ingest == {}
        return (
            status == "SUBMITTED"
            and isinstance(ingest, Mapping)
            and ingest.get("status") == "ENQUEUE_FAILED"
        )

    @staticmethod
    def _is_existing_submission(document: Mapping[str, Any]) -> bool:
        stages = document.get("stages")
        if not isinstance(stages, Mapping):
            return False
        ingest = stages.get("ingest")
        return (
            document.get("status") == "SUBMITTED"
            and isinstance(ingest, Mapping)
            and ingest.get("status") in {"ENQUEUE_PENDING", "ENQUEUED"}
        )

    def _expire(
        self,
        record: OperationRecord,
        identity: OperationIdentity,
        *,
        now: datetime,
    ) -> OperationRecord:
        if now < record.expires_at or record.state is LedgerState.EXPIRED:
            return record
        try:
            return self.operations.transition(
                identity,
                expected_state=record.state,
                expected_version=record.version,
                next_state=LedgerState.EXPIRED,
                durable_response=record.durable_response,
                updated_at=now,
            )
        except OperationConflict:
            current = self.operations.load(identity)
            if current is not None and current.state is LedgerState.EXPIRED:
                return current
            raise self._unknown_write_error()
        except Exception as error:
            raise self._unknown_write_error() from error

    def _business_binding_matches(
        self,
        operation: OperationRecord,
        resource: Mapping[str, Any],
    ) -> bool:
        if not isinstance(resource, Mapping):
            return False
        resource_id_field = (
            "batchId" if operation.resource_type == "batch" else "documentId"
        )
        if (
            resource.get(resource_id_field) != operation.resource_id
            or resource.get("customer_id") != operation.customer_id
            or resource.get("deployment_id") != operation.deployment_id
            or resource.get("ownership_schema_version") != 1
            or resource.get("journey_contract_version") != operation.contract_version
            or resource.get("journey_operation") != operation.operation
            or resource.get("journey_actor_digest") != operation.actor_digest
            or resource.get("journey_request_digest") != operation.request_digest
            or resource.get("journey_resource_schema_version")
            != _RESOURCE_SCHEMA_VERSION
        ):
            return False
        durable = operation.durable_response
        if resource.get("createdAt") != durable.get("createdAt"):
            return False
        if operation.resource_type == "batch":
            return resource.get("status") == "OPEN"
        input_record = resource.get("input")
        return (
            isinstance(input_record, Mapping)
            and input_record.get("contentType") == durable.get("contentType")
            and resource.get("batchId") == durable.get("batchId")
            and resource.get("status") == "CREATED"
        )

    def _authorize_journey_record(
        self,
        auth: AuthContext,
        scope: OwnerScope,
        resource: Mapping[str, Any] | None,
        *,
        resource_type: str,
        resource_id: str,
        action: ObjectAction,
    ) -> None:
        if resource_type == "batch":
            authorize_batch(auth, resource, action)
            id_field = "batchId"
            operation = OperationKind.BATCH_CREATE.value
        else:
            authorize_document(auth, resource, action)
            id_field = "documentId"
            operation = OperationKind.DOCUMENT_CREATE.value
        if not isinstance(resource, Mapping) or any(
            (
                resource.get(id_field) != resource_id,
                resource.get("journey_contract_version") != CONTRACT_VERSION,
                resource.get("journey_operation") != operation,
                resource.get("journey_actor_digest") != scope.actor_digest,
                resource.get("journey_resource_schema_version")
                != _RESOURCE_SCHEMA_VERSION,
            )
        ):
            raise AppError(
                code="NOT_FOUND",
                message="Resource not found.",
                status_code=404,
                details={},
            )

    def _mint_upload_capability(
        self,
        *,
        auth: AuthContext,
        scope: OwnerScope,
        document_id: str,
        enforce_refresh_limit: bool,
    ) -> UploadCapability:
        document = self.documents_repo.get_document(document_id, consistent=True)
        self._authorize_journey_record(
            auth,
            scope,
            document,
            resource_type="document",
            resource_id=document_id,
            action=ObjectAction.WRITE,
        )
        stages = document.get("stages")
        if (
            document.get("status") != "CREATED"
            or not isinstance(stages, Mapping)
            or bool(stages)
        ):
            raise self._state_conflict_error()
        now = self._now()
        if enforce_refresh_limit:
            retry_after = self.limiter.claim(
                f"capability:{scope.actor_digest}:{document_id}",
                now=now,
                interval_seconds=getattr(
                    self.settings,
                    "journey_capability_refresh_min_interval_seconds",
                    1,
                ),
            )
            if retry_after is not None:
                raise AppError(
                    code="RATE_LIMITED",
                    message="Capability refresh is rate limited.",
                    status_code=429,
                    details={"retryAfterSeconds": retry_after},
                    retry_after_seconds=retry_after,
                )
        input_record = document.get("input")
        if not isinstance(input_record, Mapping):
            raise self._internal_contract_error()
        bucket = input_record.get("bucket")
        key = input_record.get("key")
        content_type = input_record.get("contentType")
        expected_prefix = ObjectOwnership.from_auth(auth).document_prefix(document_id)
        if (
            bucket != self.settings.get_bucket("raw")
            or not isinstance(key, str)
            or not key.startswith(expected_prefix)
            or ".." in key.split("/")
            or not isinstance(content_type, str)
        ):
            raise AppError(
                code="NOT_FOUND",
                message="Document not found.",
                status_code=404,
                details={},
            )
        ttl = getattr(self.settings, "upload_url_ttl_seconds", 900)
        try:
            url = self.s3.generate_presigned_url(
                ClientMethod="put_object",
                Params={
                    "Bucket": bucket,
                    "Key": key,
                    "ContentType": content_type,
                },
                ExpiresIn=ttl,
            )
            return UploadCapability(
                url=url,
                expires_at=now + timedelta(seconds=ttl),
                required_headers=UploadRequiredHeaders(
                    **{"Content-Type": content_type}
                ),
            )
        except (ValidationError, ValueError, TypeError) as error:
            raise AppError(
                code="UPSTREAM_ERROR",
                message="Upload capability is unavailable.",
                status_code=502,
                details={},
            ) from error
        except Exception as error:
            raise AppError(
                code="UPSTREAM_ERROR",
                message="Upload capability is unavailable.",
                status_code=502,
                details={},
            ) from error

    def _trusted_result_locator(
        self,
        ownership: ObjectOwnership,
        document_id: str,
        document: Mapping[str, Any],
    ) -> tuple[str, str]:
        artifact: Any = None
        stages = document.get("stages")
        if isinstance(stages, Mapping):
            persist = stages.get("persist")
            if isinstance(persist, Mapping):
                artifact = persist.get("artifactRef")
        artifacts = document.get("artifacts")
        if not isinstance(artifact, Mapping) and isinstance(artifacts, Mapping):
            artifact = artifacts.get("structured") or artifacts.get("result")
        if not isinstance(artifact, Mapping):
            raise AppError(
                code="MALFORMED_INTERNAL_RESULT",
                message="Stored result is invalid.",
                status_code=500,
                details={},
            )
        bucket = artifact.get("bucket")
        key = artifact.get("key")
        structured_bucket = self.settings.get_bucket("structured")
        canonical_key = (
            f"{ownership.document_prefix(document_id)}"
            "structured/bank/result.json"
        )
        if bucket != structured_bucket or key != canonical_key:
            raise AppError(
                code="MALFORMED_INTERNAL_RESULT",
                message="Stored result is invalid.",
                status_code=500,
                details={},
            )
        return bucket, key

    @staticmethod
    def _require_supported_result_domain(document: Mapping[str, Any]) -> None:
        """Select the sole reviewed public result family before any S3 read."""

        processing_domain = document.get("processing_domain")
        document_route = document.get("documentRoute")
        if processing_domain == "bank" and document_route == "bank":
            return
        if (
            processing_domain in {"personal", "gov"}
            and document_route == processing_domain
        ) or (processing_domain is None and document_route == "platform"):
            raise AppError(
                code="UNSUPPORTED_RESULT_TYPE",
                message="Document result type is unsupported.",
                status_code=422,
                details={},
            )
        raise AppError(
            code="UNSUPPORTED_STATE",
            message="Document state is unsupported.",
            status_code=500,
            details={},
        )

    def _trusted_bank_extraction_evidence(
        self,
        ownership: ObjectOwnership,
        document_id: str,
        document: Mapping[str, Any],
        *,
        bucket: str,
        key: str,
    ) -> tuple[str, dict[str, str]]:
        """Require the bank worker's closed owner/locator/content checkpoint."""

        stages = document.get("stages")
        bank_extract = (
            stages.get("bank_extract") if isinstance(stages, Mapping) else None
        )
        proof = (
            bank_extract.get("artifact")
            if isinstance(bank_extract, Mapping)
            else None
        )
        checkpoint_id = (
            proof.get("checkpoint_id") if isinstance(proof, Mapping) else None
        )
        content_sha256 = (
            proof.get("content_sha256") if isinstance(proof, Mapping) else None
        )
        if (
            not isinstance(bank_extract, Mapping)
            or bank_extract.get("status") != "COMPLETED"
            or not self._is_lower_hex(checkpoint_id, length=32)
            or not self._is_lower_hex(content_sha256, length=64)
        ):
            raise self._unsupported_result_state()

        expected_proof = {
            "bucket": bucket,
            "key": key,
            "customer_id": ownership.customer_id,
            "deployment_id": ownership.deployment_id,
            "document_id": document_id,
            "processing_domain": "bank",
            "ownership_schema_version": 1,
            "pipeline_stage": "bank-extract",
            "writer": "scanalyze-bank-worker",
            "artifact_schema_version": "1.0",
            "checkpoint_id": checkpoint_id,
            "content_sha256": content_sha256,
        }
        if dict(proof) != expected_proof:
            raise self._unsupported_result_state()

        artifacts = document.get("artifacts")
        structured = (
            artifacts.get("structured") if isinstance(artifacts, Mapping) else None
        )
        if not isinstance(structured, Mapping) or dict(structured) != {
            "bucket": bucket,
            "key": key,
        }:
            raise self._unsupported_result_state()
        for alias in ("result",):
            alternate = artifacts.get(alias) if isinstance(artifacts, Mapping) else None
            if alternate is not None and (
                not isinstance(alternate, Mapping)
                or alternate.get("bucket") != bucket
                or alternate.get("key") != key
            ):
                raise self._unsupported_result_state()
        top_level_structured = document.get("structured")
        if top_level_structured is not None and (
            not isinstance(top_level_structured, Mapping)
            or top_level_structured.get("bucket") != bucket
            or top_level_structured.get("key") != key
        ):
            raise self._unsupported_result_state()
        return content_sha256, {
            "customer-id": ownership.customer_id,
            "deployment-id": ownership.deployment_id,
            "document-id": document_id,
            "processing-domain": "bank",
            "ownership-schema-version": "1",
            "pipeline-stage": "bank-extract",
            "writer": "scanalyze-bank-worker",
            "artifact-schema-version": "1.0",
            "checkpoint-id": checkpoint_id,
            "content-sha256": content_sha256,
        }

    @staticmethod
    def _is_lower_hex(value: Any, *, length: int) -> bool:
        return (
            isinstance(value, str)
            and len(value) == length
            and all(character in "0123456789abcdef" for character in value)
        )

    @staticmethod
    def _unsupported_result_state() -> AppError:
        return AppError(
            code="UNSUPPORTED_STATE",
            message="Document state is unsupported.",
            status_code=500,
            details={},
        )

    def _batch_response(self, record: OperationRecord) -> BatchDurableResponse:
        try:
            return BatchDurableResponse.model_validate(dict(record.durable_response))
        except ValidationError as error:
            raise self._internal_contract_error() from error

    def _document_response(
        self, record: OperationRecord
    ) -> DocumentDurableResponse:
        try:
            return DocumentDurableResponse.model_validate(
                dict(record.durable_response)
            )
        except ValidationError as error:
            raise self._internal_contract_error() from error

    def _journey_binding(
        self,
        scope: OwnerScope,
        *,
        operation: OperationKind,
        request_digest: str,
    ) -> dict[str, Any]:
        return {
            "journey_resource_schema_version": _RESOURCE_SCHEMA_VERSION,
            "journey_contract_version": CONTRACT_VERSION,
            "journey_operation": operation.value,
            "journey_actor_digest": scope.actor_digest,
            "journey_request_digest": request_digest,
        }

    def _new_resource_id(self) -> str:
        value = self.id_factory()
        if not isinstance(value, str) or not len(value) == 32 or any(
            character not in "0123456789abcdef" for character in value
        ):
            raise self._internal_contract_error()
        return value

    def _now(self) -> datetime:
        value = self.clock()
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise self._internal_contract_error()
        return value.astimezone(timezone.utc)

    @staticmethod
    def _iso(value: datetime) -> str:
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    @staticmethod
    def _unknown_write_error() -> AppError:
        return AppError(
            code="UNKNOWN_WRITE_OUTCOME",
            message="Write outcome requires reconciliation.",
            status_code=500,
            details={},
            retry_class="RETRY_ONLY_AFTER_RECONCILIATION",
        )

    @staticmethod
    def _unavailable_error() -> AppError:
        return AppError(
            code="SERVICE_UNAVAILABLE",
            message="The service is temporarily unavailable.",
            status_code=503,
            details={},
            retry_class="RETRYABLE_WITH_BACKOFF",
        )

    @staticmethod
    def _state_conflict_error() -> AppError:
        return AppError(
            code="STATE_CONFLICT",
            message="The document state does not allow this operation.",
            status_code=409,
            details={},
            retry_class="TERMINAL",
        )

    @staticmethod
    def _internal_contract_error() -> AppError:
        return AppError(
            code="INTERNAL_ERROR",
            message="The service could not complete the request.",
            status_code=500,
            details={},
            retry_class="UNKNOWN_OR_QUARANTINED",
        )


__all__ = ["BoundedIntervalLimiter", "JourneyService"]
