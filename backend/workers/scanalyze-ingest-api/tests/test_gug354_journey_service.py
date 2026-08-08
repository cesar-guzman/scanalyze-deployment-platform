from __future__ import annotations

import copy
import hashlib
import io
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from app.auth import AuthContext
from app.errors import AppError
from app.journey_contract import (
    BatchCreateRequest,
    DocumentCreateRequest,
    DocumentDurableResponse,
    LedgerState,
    OperationKind,
    ReconciliationFailureCode,
    SubmitDocumentRequest,
    canonical_request_digest,
)
from app.repositories.operations import (
    OPERATION_SCHEMA_VERSION,
    DynamoOperationsRepository,
    OperationConflict,
    OperationIdentity,
    OperationRecord,
    OperationState,
    ReservationOutcome,
)
from app.services.journey import BoundedIntervalLimiter, JourneyService
from tests.test_gug354_journey_repository import FakeTable


NOW = datetime(2026, 8, 7, 18, 0, tzinfo=timezone.utc)
CUSTOMER_A = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW"
CUSTOMER_B = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAX"
DEPLOYMENT_A = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
DEPLOYMENT_B = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAW"
KEY_A = "00000000-0000-4000-8000-000000000001"
KEY_B = "00000000-0000-4000-8000-000000000002"


def _auth(
    *,
    actor: str = "synthetic-actor-a",
    customer: str = CUSTOMER_A,
    deployment: str = DEPLOYMENT_A,
) -> AuthContext:
    return AuthContext(
        customer_id=customer,
        deployment_id=deployment,
        principal_type="user",
        subject=actor,
        client_id=None,
        scopes=(),
        granted_actions=(),
        email=None,
        name=None,
        auth_source="synthetic-test",
    )


class FakeSettings:
    journey_operation_retention_seconds = 30 * 24 * 60 * 60
    journey_result_max_bytes = 1024 * 1024
    journey_capability_refresh_min_interval_seconds = 30
    journey_reconciliation_min_interval_seconds = 1
    journey_pending_reconciliation_grace_seconds = 30
    upload_url_ttl_seconds = 300
    processing_domain = "bank"

    def get_bucket(self, alias: str) -> str | None:
        return {
            "raw": "synthetic-raw-bucket",
            "structured": "synthetic-structured-bucket",
        }.get(alias)


class MutableClock:
    def __init__(self, now: datetime = NOW) -> None:
        self.value = now

    def __call__(self) -> datetime:
        return self.value

    def advance(self, *, seconds: int) -> None:
        self.value += timedelta(seconds=seconds)


class IdSequence:
    def __init__(self) -> None:
        self._value = 0
        self._lock = threading.Lock()

    def __call__(self) -> str:
        with self._lock:
            self._value += 1
            return f"{self._value:032x}"


class InMemoryOperations:
    """Thread-safe semantic ledger fake; it stores no raw request/key values."""

    def __init__(self) -> None:
        self.records: dict[OperationIdentity, OperationRecord] = {}
        self._lock = threading.Lock()

    def reserve(
        self,
        identity: OperationIdentity,
        *,
        request_digest: str,
        resource_type: str,
        resource_id: str,
        durable_response: dict[str, Any],
        now: datetime,
        expires_at: datetime,
    ) -> ReservationOutcome:
        with self._lock:
            current = self.records.get(identity)
            if current is not None:
                if current.request_digest != request_digest:
                    raise OperationConflict()
                return ReservationOutcome(record=current, created_here=False)
            record = OperationRecord(
                schema_version=OPERATION_SCHEMA_VERSION,
                contract_version=identity.contract_version,
                operation=identity.operation,
                actor_digest=identity.actor_digest,
                customer_id=identity.customer_id,
                deployment_id=identity.deployment_id,
                key_digest=identity.key_digest,
                request_digest=request_digest,
                resource_type=resource_type,
                resource_id=resource_id,
                durable_response=copy.deepcopy(durable_response),
                state=OperationState.PENDING,
                version=1,
                created_at=now,
                updated_at=now,
                expires_at=expires_at,
            )
            self.records[identity] = record
            return ReservationOutcome(record=record, created_here=True)

    def load(self, identity: OperationIdentity) -> OperationRecord | None:
        with self._lock:
            return self.records.get(identity)

    def transition(
        self,
        identity: OperationIdentity,
        *,
        expected_state: OperationState,
        expected_version: int,
        next_state: OperationState,
        durable_response: dict[str, Any] | None = None,
        failure_code: str | None = None,
        completed_at: datetime | None = None,
        updated_at: datetime,
    ) -> OperationRecord:
        with self._lock:
            current = self.records.get(identity)
            if (
                current is None
                or current.state is not expected_state
                or current.version != expected_version
            ):
                raise OperationConflict()
            changed = replace(
                current,
                state=next_state,
                version=current.version + 1,
                durable_response=copy.deepcopy(
                    durable_response
                    if durable_response is not None
                    else current.durable_response
                ),
                failure_code=failure_code,
                completed_at=(
                    current.completed_at or updated_at
                    if next_state is OperationState.EXPIRED
                    and completed_at is None
                    else completed_at
                ),
                updated_at=updated_at,
            )
            self.records[identity] = changed
            return changed


class FakeBatchesRepository:
    def __init__(self) -> None:
        self.items: dict[str, dict[str, Any]] = {}
        self.create_effects = 0
        self._lock = threading.Lock()

    def create_batch(self, item: dict[str, Any], *, ownership: Any) -> None:
        del ownership
        with self._lock:
            batch_id = item["batchId"]
            if batch_id in self.items:
                raise RuntimeError("synthetic duplicate batch")
            self.items[batch_id] = copy.deepcopy(item)
            self.create_effects += 1

    def get_batch(
        self, batch_id: str, *, consistent: bool = False
    ) -> dict[str, Any] | None:
        del consistent
        with self._lock:
            value = self.items.get(batch_id)
            return copy.deepcopy(value) if value is not None else None


class FakeDocumentsRepository:
    def __init__(self) -> None:
        self.items: dict[str, dict[str, Any]] = {}
        self.create_effects = 0
        self.raise_after_next_create = False
        self._lock = threading.Lock()

    @staticmethod
    def _key_for(document_id: str) -> dict[str, str]:
        return {"documentId": document_id}

    def create_document(self, item: dict[str, Any], *, ownership: Any) -> None:
        del ownership
        with self._lock:
            document_id = item["documentId"]
            if document_id in self.items:
                raise RuntimeError("synthetic duplicate document")
            self.items[document_id] = copy.deepcopy(item)
            self.create_effects += 1
            if self.raise_after_next_create:
                self.raise_after_next_create = False
                raise RuntimeError("synthetic response lost after durable write")

    def get_document(
        self, document_id: str, *, consistent: bool = False
    ) -> dict[str, Any] | None:
        del consistent
        with self._lock:
            value = self.items.get(document_id)
            return copy.deepcopy(value) if value is not None else None


class FakeS3:
    def __init__(self) -> None:
        self.capability_calls = 0
        self.get_calls = 0
        self.objects: dict[tuple[str, str], bytes] = {}
        self.metadata: dict[tuple[str, str], dict[str, str]] = {}
        self.last_body: io.BytesIO | None = None

    def generate_presigned_url(self, **request: Any) -> str:
        assert request["ClientMethod"] == "put_object"
        assert request["ExpiresIn"] == 300
        self.capability_calls += 1
        return f"https://upload.invalid/capability/{self.capability_calls}"

    def get_object(self, *, Bucket: str, Key: str) -> dict[str, Any]:
        self.get_calls += 1
        payload = self.objects[(Bucket, Key)]
        self.last_body = io.BytesIO(payload)
        return {
            "ContentLength": len(payload),
            "Body": self.last_body,
            "Metadata": copy.deepcopy(self.metadata.get((Bucket, Key), {})),
        }


class FakeLegacyDocumentsService:
    def __init__(
        self,
        documents: FakeDocumentsRepository,
        *,
        response_enqueued: bool = True,
        resulting_status: str = "ENQUEUED",
        raise_after_transition: bool = False,
    ) -> None:
        self.documents = documents
        self.response_enqueued = response_enqueued
        self.resulting_status = resulting_status
        self.raise_after_transition = raise_after_transition
        self.calls = 0

    def submit_document(
        self,
        *,
        auth: AuthContext,
        document_id: str,
        stage: str | None,
    ) -> dict[str, Any]:
        del auth, stage
        self.calls += 1
        with self.documents._lock:
            document = self.documents.items[document_id]
            if self.resulting_status == "COMPLETED":
                document["status"] = "COMPLETED"
                document["completedAt"] = "2026-08-07T18:01:00Z"
                document["updatedAt"] = "2026-08-07T18:01:00Z"
                document["stages"] = {
                    "persist": {
                        "status": "DONE",
                        "finalStatus": "COMPLETED",
                        "completedAt": "2026-08-07T18:01:00Z",
                    }
                }
            else:
                document["status"] = "SUBMITTED"
                document["stages"] = {
                    "ingest": {"status": self.resulting_status}
                }
        if self.raise_after_transition:
            raise AppError(
                code="SQS_ENQUEUE_RECOVERY_FAILED",
                message="Synthetic transition race",
                status_code=502,
                details={},
            )
        return {
            "documentId": document_id,
            "stage": "ingest",
            "enqueued": self.response_enqueued,
        }


def _service() -> tuple[
    JourneyService,
    InMemoryOperations,
    FakeBatchesRepository,
    FakeDocumentsRepository,
    FakeS3,
    MutableClock,
]:
    operations = InMemoryOperations()
    batches = FakeBatchesRepository()
    documents = FakeDocumentsRepository()
    s3 = FakeS3()
    clock = MutableClock()
    service = JourneyService(
        settings=FakeSettings(),
        operations=operations,
        batches_repo=batches,
        documents_repo=documents,
        s3=s3,
        clock=clock,
        id_factory=IdSequence(),
        limiter=BoundedIntervalLimiter(),
    )
    return service, operations, batches, documents, s3, clock


def _create_document(
    service: JourneyService,
    *,
    auth: AuthContext | None = None,
    key: str = KEY_A,
    content_type: str = "application/pdf",
) -> Any:
    return service.create_document(
        auth=auth or _auth(),
        idempotency_key=key,
        request=DocumentCreateRequest(contentType=content_type),
    )


def test_batch_and_document_first_create_have_one_business_effect_each() -> None:
    service, operations, batches, documents, _s3, _clock = _service()

    batch = service.create_batch(
        auth=_auth(), idempotency_key=KEY_A, request=BatchCreateRequest()
    )
    document = _create_document(service, key=KEY_B)

    assert batch.replayed is False
    assert batch.durable_response.status == "OPEN"
    assert document.replayed is False
    assert document.durable_response.status == "UPLOAD_PENDING"
    assert batches.create_effects == 1
    assert documents.create_effects == 1
    assert len(operations.records) == 2
    assert {record.state for record in operations.records.values()} == {
        OperationState.SUCCEEDED
    }


def test_exact_replay_keeps_durable_identity_but_mints_fresh_capability() -> None:
    service, operations, _batches, documents, s3, _clock = _service()

    first = _create_document(service)
    replay = _create_document(service)

    assert first.replayed is False
    assert replay.replayed is True
    assert replay.durable_response == first.durable_response
    assert replay.upload_capability.url != first.upload_capability.url
    assert documents.create_effects == 1
    assert s3.capability_calls == 2
    with pytest.raises(AppError) as rate_limited:
        _create_document(service)
    assert rate_limited.value.code == "RATE_LIMITED"
    assert rate_limited.value.retry_after_seconds == 30
    serialized_ledger = json.dumps(
        [
            {
                "keyDigest": record.key_digest,
                "durableResponse": dict(record.durable_response),
            }
            for record in operations.records.values()
        ],
        sort_keys=True,
    )
    assert KEY_A not in serialized_ledger
    assert "upload.invalid" not in serialized_ledger
    assert "url" not in serialized_ledger.lower()


@pytest.mark.parametrize(
    ("status", "stages"),
    [
        ("UPLOADED", {}),
        ("SUBMITTED", {"ingest": {"status": "ENQUEUED"}}),
        (
            "COMPLETED",
            {
                "persist": {
                    "status": "DONE",
                    "finalStatus": "COMPLETED",
                }
            },
        ),
    ],
    ids=["uploaded", "submitted", "terminal"],
)
def test_exact_replay_after_uploadable_state_returns_durable_without_capability(
    status: str,
    stages: dict[str, Any],
) -> None:
    service, _operations, _batches, documents, s3, _clock = _service()
    first = _create_document(service)
    document_id = first.durable_response.document_id
    documents.items[document_id]["status"] = status
    documents.items[document_id]["stages"] = stages

    replay = _create_document(service)

    assert replay.replayed is True
    assert replay.durable_response == first.durable_response
    assert replay.upload_capability is None
    assert documents.create_effects == 1
    assert s3.capability_calls == 1


def test_same_key_with_different_semantic_payload_is_a_conflict() -> None:
    service, _operations, _batches, documents, _s3, _clock = _service()
    _create_document(service, content_type="application/pdf")

    with pytest.raises(AppError) as captured:
        _create_document(service, content_type="image/png")

    assert captured.value.code == "IDEMPOTENCY_CONFLICT"
    assert captured.value.status_code == 409
    assert documents.create_effects == 1


def test_sanitized_dot_segment_is_rejected_before_reservation_or_business_write() -> None:
    service, operations, _batches, documents, s3, _clock = _service()

    with pytest.raises(AppError) as captured:
        service.create_document(
            auth=_auth(),
            idempotency_key=KEY_A,
            request=DocumentCreateRequest(
                filename=".$",
                contentType="application/pdf",
            ),
        )

    assert captured.value.code == "SEMANTIC_VALIDATION_FAILED"
    assert captured.value.status_code == 422
    assert operations.records == {}
    assert documents.create_effects == 0
    assert s3.capability_calls == 0


def test_concurrent_same_key_creates_at_most_one_business_resource() -> None:
    service, _operations, _batches, documents, _s3, _clock = _service()
    gate = threading.Barrier(12)

    def invoke() -> tuple[str, str | None]:
        gate.wait()
        try:
            response = _create_document(service)
            return "ok", response.durable_response.document_id
        except AppError as error:
            return error.code, None

    with ThreadPoolExecutor(max_workers=12) as executor:
        outcomes = list(executor.map(lambda _index: invoke(), range(12)))

    successful_ids = {resource_id for code, resource_id in outcomes if code == "ok"}
    error_codes = {code for code, _resource_id in outcomes if code != "ok"}
    assert documents.create_effects == 1
    assert len(successful_ids) <= 1
    assert error_codes.issubset({"RATE_LIMITED", "UNKNOWN_WRITE_OUTCOME"})


def test_lost_business_write_response_is_reconciled_without_second_effect() -> None:
    service, operations, _batches, documents, _s3, _clock = _service()
    documents.raise_after_next_create = True

    response = _create_document(service)

    assert response.replayed is False
    assert documents.create_effects == 1
    assert next(iter(operations.records.values())).state is OperationState.SUCCEEDED
    replay = _create_document(service)
    assert replay.durable_response.document_id == response.durable_response.document_id
    assert documents.create_effects == 1


@pytest.mark.parametrize("resource_type", ["batch", "document"])
def test_lost_http_response_reconciles_by_original_key_without_second_effect(
    resource_type: str,
) -> None:
    service, _operations, batches, documents, _s3, _clock = _service()
    if resource_type == "batch":
        created = service.create_batch(
            auth=_auth(), idempotency_key=KEY_A, request=BatchCreateRequest()
        )
        operation = OperationKind.BATCH_CREATE
        expected_id = created.durable_response.batch_id
        effects = lambda: batches.create_effects
    else:
        created = _create_document(service)
        operation = OperationKind.DOCUMENT_CREATE
        expected_id = created.durable_response.document_id
        effects = lambda: documents.create_effects

    # The caller discards the create response and has no resource identifier.
    reconciled = service.reconcile(
        auth=_auth(),
        operation=operation,
        idempotency_key=KEY_A,
    )

    assert reconciled.ledger_state is LedgerState.SUCCEEDED
    assert reconciled.durable_response is not None
    actual_id = (
        reconciled.durable_response.batch_id
        if resource_type == "batch"
        else reconciled.durable_response.document_id
    )
    assert actual_id == expected_id
    assert effects() == 1

    if resource_type == "batch":
        replay = service.create_batch(
            auth=_auth(), idempotency_key=KEY_A, request=BatchCreateRequest()
        )
    else:
        replay = _create_document(service)
    assert replay.replayed is True
    assert effects() == 1


@pytest.mark.parametrize(
    ("state", "expected_failure", "completed"),
    [
        (OperationState.PENDING, None, False),
        (OperationState.SUCCEEDED, None, True),
        (
            OperationState.FAILED_RETRYABLE,
            ReconciliationFailureCode.CREATE_FAILED_RETRYABLE,
            False,
        ),
        (
            OperationState.FAILED_TERMINAL,
            ReconciliationFailureCode.CREATE_FAILED_TERMINAL,
            True,
        ),
        (
            OperationState.UNKNOWN_OR_QUARANTINED,
            ReconciliationFailureCode.UNKNOWN_WRITE_OUTCOME,
            True,
        ),
        (
            OperationState.EXPIRED,
            ReconciliationFailureCode.OPERATION_EXPIRED,
            True,
        ),
    ],
)
def test_reconciliation_returns_every_closed_ledger_state(
    state: OperationState,
    expected_failure: ReconciliationFailureCode | None,
    completed: bool,
) -> None:
    service, operations, _batches, documents, _s3, _clock = _service()
    created = _create_document(service)
    identity, record = next(iter(operations.records.items()))

    if state is OperationState.PENDING:
        documents.items.pop(created.durable_response.document_id)
    if state is OperationState.EXPIRED:
        created_at = NOW - timedelta(seconds=2)
        expires_at = NOW - timedelta(seconds=1)
    else:
        created_at = record.created_at
        expires_at = record.expires_at
    operations.records[identity] = replace(
        record,
        state=state,
        created_at=created_at,
        updated_at=NOW,
        expires_at=expires_at,
        completed_at=NOW if completed else None,
        failure_code=(
            expected_failure.value if expected_failure is not None else None
        ),
    )

    response = service.reconcile(
        auth=_auth(),
        operation=OperationKind.DOCUMENT_CREATE,
        idempotency_key=KEY_A,
    )

    assert response.ledger_state is state
    assert response.failure_code is expected_failure
    assert (response.completed_at is not None) is completed
    assert (response.durable_response is not None) is (
        state is OperationState.SUCCEEDED
    )


def test_stale_pending_without_business_row_is_quarantined_without_replay() -> None:
    service, operations, _batches, documents, _s3, clock = _service()
    created = _create_document(service)
    identity, record = next(iter(operations.records.items()))
    documents.items.pop(created.durable_response.document_id)
    operations.records[identity] = replace(
        record,
        state=OperationState.PENDING,
        completed_at=None,
        failure_code=None,
        updated_at=NOW,
    )
    clock.advance(
        seconds=FakeSettings.journey_pending_reconciliation_grace_seconds
    )

    response = service.reconcile(
        auth=_auth(),
        operation=OperationKind.DOCUMENT_CREATE,
        idempotency_key=KEY_A,
    )

    assert response.ledger_state is OperationState.UNKNOWN_OR_QUARANTINED
    assert response.failure_code is ReconciliationFailureCode.UNKNOWN_WRITE_OUTCOME
    assert documents.create_effects == 1
    assert documents.items == {}
    assert operations.records[identity].state is OperationState.UNKNOWN_OR_QUARANTINED


def test_reconciliation_is_bound_to_original_actor_scope() -> None:
    service, _operations, _batches, _documents, _s3, _clock = _service()
    _create_document(service)

    with pytest.raises(AppError) as hidden:
        service.reconcile(
            auth=_auth(actor="synthetic-actor-b"),
            operation=OperationKind.DOCUMENT_CREATE,
            idempotency_key=KEY_A,
        )

    assert hidden.value.code == "NOT_FOUND"
    assert hidden.value.status_code == 404


def test_reconciliation_rate_boundary_returns_exact_retry_after() -> None:
    service, _operations, _batches, _documents, _s3, clock = _service()
    _create_document(service)

    first = service.reconcile(
        auth=_auth(),
        operation=OperationKind.DOCUMENT_CREATE,
        idempotency_key=KEY_A,
    )
    assert first.ledger_state is OperationState.SUCCEEDED

    with pytest.raises(AppError) as limited:
        service.reconcile(
            auth=_auth(),
            operation=OperationKind.DOCUMENT_CREATE,
            idempotency_key=KEY_A,
        )
    assert limited.value.code == "RATE_LIMITED"
    assert limited.value.retry_after_seconds == 1

    clock.advance(seconds=1)
    second = service.reconcile(
        auth=_auth(),
        operation=OperationKind.DOCUMENT_CREATE,
        idempotency_key=KEY_A,
    )
    assert second.durable_response == first.durable_response


@pytest.mark.parametrize(
    "foreign_auth",
    [
        _auth(actor="synthetic-actor-b"),
        _auth(customer=CUSTOMER_B),
        _auth(deployment=DEPLOYMENT_B),
    ],
    ids=["actor", "customer", "deployment"],
)
def test_resource_capability_is_hidden_across_every_owner_axis(
    foreign_auth: AuthContext,
) -> None:
    service, _operations, _batches, _documents, _s3, _clock = _service()
    created = _create_document(service)

    with pytest.raises(AppError) as captured:
        service.refresh_upload_capability(
            auth=foreign_auth,
            document_id=created.durable_response.document_id,
        )

    assert captured.value.code == "NOT_FOUND"
    assert captured.value.status_code == 404


def test_same_raw_key_is_independent_across_actor_customer_and_deployment() -> None:
    service, operations, _batches, documents, _s3, _clock = _service()
    responses = [
        _create_document(service, auth=_auth()),
        _create_document(service, auth=_auth(actor="synthetic-actor-b")),
        _create_document(service, auth=_auth(customer=CUSTOMER_B)),
        _create_document(service, auth=_auth(deployment=DEPLOYMENT_B)),
    ]

    assert len({item.durable_response.document_id for item in responses}) == 4
    assert len(operations.records) == 4
    assert documents.create_effects == 4


def test_capability_refresh_is_state_bound_rate_limited_and_never_durable() -> None:
    service, operations, _batches, documents, _s3, clock = _service()
    created = _create_document(service)
    document_id = created.durable_response.document_id

    refreshed = service.refresh_upload_capability(auth=_auth(), document_id=document_id)
    assert refreshed.upload_capability.url.startswith("https://")
    with pytest.raises(AppError) as limited:
        service.refresh_upload_capability(auth=_auth(), document_id=document_id)
    assert limited.value.code == "RATE_LIMITED"
    assert limited.value.retry_after_seconds == 30

    clock.advance(seconds=30)
    documents.items[document_id]["status"] = "UPLOADED"
    with pytest.raises(AppError) as wrong_state:
        service.refresh_upload_capability(auth=_auth(), document_id=document_id)
    assert wrong_state.value.code == "STATE_CONFLICT"
    assert wrong_state.value.status_code == 409

    ledger_text = json.dumps(
        [dict(record.durable_response) for record in operations.records.values()],
        sort_keys=True,
    )
    assert "https://" not in ledger_text
    assert "capability" not in ledger_text.lower()


def test_capability_rejects_created_document_with_pipeline_stage_evidence() -> None:
    service, _operations, _batches, documents, s3, _clock = _service()
    created = _create_document(service)
    document_id = created.durable_response.document_id
    documents.items[document_id]["stages"] = {"ingest": {}}

    replay = _create_document(service)
    assert replay.replayed is True
    assert replay.durable_response == created.durable_response
    assert replay.upload_capability is None

    with pytest.raises(AppError) as wrong_state:
        service.refresh_upload_capability(auth=_auth(), document_id=document_id)

    assert wrong_state.value.code == "STATE_CONFLICT"
    assert wrong_state.value.status_code == 409
    assert s3.capability_calls == 1


def test_expired_upload_capability_is_replaced_only_after_fresh_owner_state_check() -> None:
    service, _operations, _batches, _documents, _s3, clock = _service()
    created = _create_document(service)
    original = created.upload_capability

    clock.advance(seconds=FakeSettings.upload_url_ttl_seconds + 1)
    refreshed = service.refresh_upload_capability(
        auth=_auth(),
        document_id=created.durable_response.document_id,
    ).upload_capability

    assert refreshed.url != original.url
    assert refreshed.expires_at > original.expires_at
    assert refreshed.expires_at == clock.value + timedelta(
        seconds=FakeSettings.upload_url_ttl_seconds
    )


def test_logical_expiry_keeps_tombstone_and_rejects_key_reuse() -> None:
    service, operations, _batches, _documents, _s3, clock = _service()
    _create_document(service)
    clock.advance(seconds=FakeSettings.journey_operation_retention_seconds + 1)

    with pytest.raises(AppError) as expired:
        _create_document(service)

    assert expired.value.code == "EXPIRED_OPERATION"
    assert len(operations.records) == 1
    assert next(iter(operations.records.values())).state is OperationState.EXPIRED


@pytest.mark.parametrize(
    ("state", "failure_code"),
    [
        (OperationState.PENDING, None),
        (OperationState.SUCCEEDED, None),
        (OperationState.FAILED_TERMINAL, "CREATE_FAILED_TERMINAL"),
        (OperationState.UNKNOWN_OR_QUARANTINED, "UNKNOWN_WRITE_OUTCOME"),
    ],
    ids=["pending", "succeeded", "failed-terminal", "unknown"],
)
def test_service_expiry_uses_repository_completion_timestamp_contract(
    state: OperationState,
    failure_code: str | None,
) -> None:
    table = FakeTable()
    operations = DynamoOperationsRepository(table)
    batches = FakeBatchesRepository()
    documents = FakeDocumentsRepository()
    s3 = FakeS3()
    clock = MutableClock()
    service = JourneyService(
        settings=FakeSettings(),
        operations=operations,
        batches_repo=batches,
        documents_repo=documents,
        s3=s3,
        clock=clock,
        id_factory=IdSequence(),
        limiter=BoundedIntervalLimiter(),
    )
    request = DocumentCreateRequest(contentType="application/pdf")
    _ownership, scope = service._owner(_auth())
    identity = service._operation_identity(
        scope,
        OperationKind.DOCUMENT_CREATE,
        KEY_A,
    )
    document_id = "00000000000000000000000000000001"
    created_at = NOW - timedelta(hours=2)
    completed_at = NOW - timedelta(hours=1)
    durable = DocumentDurableResponse(
        documentId=document_id,
        contentType="application/pdf",
        createdAt=created_at,
    )
    record = operations.reserve(
        identity,
        request_digest=canonical_request_digest(
            OperationKind.DOCUMENT_CREATE,
            request,
        ),
        resource_type="document",
        resource_id=document_id,
        durable_response=durable.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        ),
        now=created_at,
        expires_at=NOW,
    ).record
    if state is not OperationState.PENDING:
        record = operations.transition(
            identity,
            expected_state=OperationState.PENDING,
            expected_version=record.version,
            next_state=state,
            durable_response=record.durable_response,
            failure_code=failure_code,
            completed_at=completed_at,
            updated_at=completed_at,
        )

    expired = service._expire(record, identity, now=NOW)

    assert expired.state is OperationState.EXPIRED
    assert expired.completed_at == (
        NOW if state is OperationState.PENDING else completed_at
    )
    assert operations.load(identity) == expired


def test_create_replay_of_terminal_operation_returns_stable_state_conflict() -> None:
    service, operations, _batches, _documents, _s3, _clock = _service()
    _create_document(service)
    identity, record = next(iter(operations.records.items()))
    operations.records[identity] = replace(
        record,
        state=OperationState.FAILED_TERMINAL,
        failure_code="CREATE_FAILED_TERMINAL",
        completed_at=NOW,
    )

    with pytest.raises(AppError) as conflict:
        _create_document(service)

    assert conflict.value.code == "STATE_CONFLICT"
    assert conflict.value.status_code == 409


def test_unknown_internal_status_fails_closed() -> None:
    service, _operations, _batches, documents, _s3, _clock = _service()
    created = _create_document(service)
    document_id = created.durable_response.document_id
    documents.items[document_id]["status"] = "SYNTHETIC_UNREVIEWED_STATE"

    with pytest.raises(AppError) as captured:
        service.get_document_status(auth=_auth(), document_id=document_id)

    assert captured.value.code == "UNSUPPORTED_STATE"
    assert captured.value.status_code == 500


def test_submit_accepts_only_reviewed_start_or_retry_state() -> None:
    service, _operations, _batches, documents, _s3, _clock = _service()
    created = _create_document(service)
    document_id = created.durable_response.document_id
    legacy = FakeLegacyDocumentsService(documents)
    service._legacy_documents_service = legacy

    first = service.submit_document(
        auth=_auth(),
        document_id=document_id,
        request=SubmitDocumentRequest(),
    )
    assert first.enqueued is True
    assert legacy.calls == 1

    documents.items[document_id]["stages"]["ingest"]["status"] = (
        "ENQUEUE_FAILED"
    )
    retried = service.submit_document(
        auth=_auth(),
        document_id=document_id,
        request=SubmitDocumentRequest(),
    )
    assert retried.enqueued is True
    assert legacy.calls == 2


def test_submit_rejects_terminal_state_before_legacy_mutation() -> None:
    service, _operations, _batches, documents, _s3, _clock = _service()
    created = _create_document(service)
    document_id = created.durable_response.document_id
    document = documents.items[document_id]
    document.update(
        {
            "status": "COMPLETED",
            "updatedAt": "2026-08-07T18:00:00Z",
            "completedAt": "2026-08-07T18:00:00Z",
            "validation": {"status": "PASS"},
            "stages": {
                "persist": {
                    "status": "DONE",
                    "finalStatus": "COMPLETED",
                    "completedAt": "2026-08-07T18:00:00Z",
                }
            },
        }
    )
    legacy = FakeLegacyDocumentsService(documents)
    service._legacy_documents_service = legacy

    with pytest.raises(AppError) as conflict:
        service.submit_document(
            auth=_auth(),
            document_id=document_id,
            request=SubmitDocumentRequest(),
        )

    assert conflict.value.code == "STATE_CONFLICT"
    assert conflict.value.status_code == 409
    assert legacy.calls == 0


def test_submit_race_rereads_state_and_fails_closed() -> None:
    service, _operations, _batches, documents, _s3, _clock = _service()
    created = _create_document(service)
    document_id = created.durable_response.document_id
    legacy = FakeLegacyDocumentsService(
        documents,
        response_enqueued=False,
        resulting_status="COMPLETED",
    )
    service._legacy_documents_service = legacy

    with pytest.raises(AppError) as conflict:
        service.submit_document(
            auth=_auth(),
            document_id=document_id,
            request=SubmitDocumentRequest(),
        )

    assert conflict.value.code == "STATE_CONFLICT"
    assert legacy.calls == 1


def test_submit_atomic_transition_error_maps_terminal_race_to_conflict() -> None:
    service, _operations, _batches, documents, _s3, _clock = _service()
    created = _create_document(service)
    document_id = created.durable_response.document_id
    legacy = FakeLegacyDocumentsService(
        documents,
        resulting_status="COMPLETED",
        raise_after_transition=True,
    )
    service._legacy_documents_service = legacy

    with pytest.raises(AppError) as conflict:
        service.submit_document(
            auth=_auth(),
            document_id=document_id,
            request=SubmitDocumentRequest(),
        )

    assert conflict.value.code == "STATE_CONFLICT"
    assert conflict.value.status_code == 409
    assert legacy.calls == 1


def test_submit_concurrent_winner_is_reported_without_second_enqueue() -> None:
    service, _operations, _batches, documents, _s3, _clock = _service()
    created = _create_document(service)
    document_id = created.durable_response.document_id
    legacy = FakeLegacyDocumentsService(
        documents,
        response_enqueued=False,
        resulting_status="ENQUEUED",
    )
    service._legacy_documents_service = legacy

    response = service.submit_document(
        auth=_auth(),
        document_id=document_id,
        request=SubmitDocumentRequest(),
    )

    assert response.enqueued is False
    assert legacy.calls == 1


def _bank_artifact(document_id: str) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "prompt_version": "1.2.3",
        "tenant": "bank",
        "documentId": document_id,
        "docType": "bank_statement",
        "generatedAt": "2026-08-07T18:01:00Z",
        "model": {
            "provider": "bedrock",
            "modelId": "synthetic-model",
            "usage": None,
        },
        "bank": {"name": "Synthetic Bank"},
        "account": {
            "holder": "Synthetic Holder",
            "number": "0000111122223333",
            "numberMasked": "****3333",
            "clabe": "000011112222333344",
            "clabeMasked": "**************3344",
            "currency": "MXN",
        },
        "statement": {
            "periodStart": "2026-07-01",
            "periodEnd": "2026-07-31",
        },
        "balances": {
            "opening": 100.0,
            "closing": 125.0,
            "totalCredits": 25.0,
            "totalDebits": 0.0,
        },
        "transactions": [
            {
                "date": "2026-07-15",
                "description": "Synthetic transfer",
                "reference": "synthetic-ref",
                "direction": "credit",
                "amount": 25.0,
                "balanceAfter": 125.0,
                "category": "transferencia",
            }
        ],
        "overallConfidence": 99.0,
    }


def _completed_document(
    service: JourneyService,
    documents: FakeDocumentsRepository,
    s3: FakeS3,
) -> tuple[str, str]:
    created = _create_document(service)
    document_id = created.durable_response.document_id
    key = (
        f"customers/{CUSTOMER_A}/deployments/{DEPLOYMENT_A}/"
        f"documents/{document_id}/structured/bank/result.json"
    )
    payload = json.dumps(_bank_artifact(document_id)).encode()
    content_sha256 = hashlib.sha256(payload).hexdigest()
    document = documents.items[document_id]
    document.update(
        {
            "status": "COMPLETED",
            "updatedAt": "2026-08-07T18:00:00Z",
            "completedAt": "2026-08-07T18:00:00Z",
            "validation": {"status": "PASS"},
            "stages": {
                "bank_extract": {
                    "status": "COMPLETED",
                    "artifact": {
                        "bucket": "synthetic-structured-bucket",
                        "key": key,
                        "customer_id": CUSTOMER_A,
                        "deployment_id": DEPLOYMENT_A,
                        "document_id": document_id,
                        "processing_domain": "bank",
                        "ownership_schema_version": 1,
                        "pipeline_stage": "bank-extract",
                        "writer": "scanalyze-bank-worker",
                        "artifact_schema_version": "1.0",
                        "checkpoint_id": "a" * 32,
                        "content_sha256": content_sha256,
                    },
                },
                "persist": {
                    "status": "DONE",
                    "finalStatus": "COMPLETED",
                    "completedAt": "2026-08-07T18:00:00Z",
                }
            },
            "artifacts": {
                "structured": {
                    "bucket": "synthetic-structured-bucket",
                    "key": key,
                }
            },
        }
    )
    s3.objects[("synthetic-structured-bucket", key)] = payload
    s3.metadata[("synthetic-structured-bucket", key)] = (
        _bank_artifact_metadata(document_id, content_sha256)
    )
    return document_id, key


def _bank_artifact_metadata(
    document_id: str, content_sha256: str
) -> dict[str, str]:
    return {
        "customer-id": CUSTOMER_A,
        "deployment-id": DEPLOYMENT_A,
        "document-id": document_id,
        "processing-domain": "bank",
        "ownership-schema-version": "1",
        "pipeline-stage": "bank-extract",
        "writer": "scanalyze-bank-worker",
        "artifact-schema-version": "1.0",
        "checkpoint-id": "a" * 32,
        "content-sha256": content_sha256,
    }


def _replace_bank_artifact(
    documents: FakeDocumentsRepository,
    s3: FakeS3,
    document_id: str,
    key: str,
    artifact: dict[str, Any],
) -> None:
    payload = json.dumps(artifact).encode()
    s3.objects[("synthetic-structured-bucket", key)] = payload
    documents.items[document_id]["stages"]["bank_extract"]["artifact"][
        "content_sha256"
    ] = hashlib.sha256(payload).hexdigest()
    s3.metadata[("synthetic-structured-bucket", key)] = _bank_artifact_metadata(
        document_id, hashlib.sha256(payload).hexdigest()
    )


def test_bank_result_is_typed_and_strips_provider_and_full_account_values() -> None:
    service, _operations, _batches, documents, s3, _clock = _service()
    document_id, _key = _completed_document(service, documents, s3)

    result = service.get_result(auth=_auth(), document_id=document_id)
    public = result.model_dump(mode="json", by_alias=True)
    serialized = json.dumps(public, ensure_ascii=False)

    assert public["documentType"] == "bank_statement"
    assert public["resultId"] == f"result_{document_id}_v1"
    assert public["data"]["account"]["numberMasked"] == "****3333"
    assert "synthetic-model" not in serialized
    assert "bedrock" not in serialized
    assert "0000111122223333" not in serialized
    assert "000011112222333344" not in serialized


def test_bank_result_masks_identifier_tokens_in_every_public_text_projection() -> None:
    service, _operations, _batches, documents, s3, _clock = _service()
    document_id, key = _completed_document(service, documents, s3)
    artifact = _bank_artifact(document_id)
    full_account = "1111222233334444"
    formatted_account = "1111-2222-3333-4444"
    full_clabe = "123456789012345678"
    artifact["bank"]["name"] = f"Synthetic Bank {full_account}"
    artifact["account"]["holder"] = f"Holder {full_clabe}"
    artifact["transactions"][0]["description"] = (
        f"Transfer from {formatted_account}"
    )
    artifact["transactions"][0]["reference"] = f"Ref {full_clabe}"
    artifact["transactions"][0]["category"] = full_account
    artifact["summaryText"] = f"Statement account {full_account}"
    _replace_bank_artifact(documents, s3, document_id, key, artifact)

    public = service.get_result(
        auth=_auth(), document_id=document_id
    ).model_dump(mode="json", by_alias=True)
    serialized = json.dumps(public, ensure_ascii=False)

    assert public["data"]["bank"]["name"] == "Synthetic Bank ****4444"
    assert public["data"]["account"]["holder"] == "Holder ****5678"
    assert (
        public["data"]["transactions"][0]["description"]
        == "Transfer from ****4444"
    )
    assert public["data"]["transactions"][0]["reference"] == "Ref ****5678"
    assert public["data"]["transactions"][0]["category"] == "otro"
    assert public["data"]["summaryText"] == "Statement account ****4444"
    for forbidden in (full_account, formatted_account, full_clabe):
        assert forbidden not in serialized


@pytest.mark.parametrize("domain", ["personal", "gov"])
def test_non_bank_result_family_is_rejected_before_storage_read(domain: str) -> None:
    service, _operations, _batches, documents, s3, _clock = _service()
    document_id, _key = _completed_document(service, documents, s3)
    documents.items[document_id]["processing_domain"] = domain
    documents.items[document_id]["documentRoute"] = domain

    with pytest.raises(AppError) as unsupported:
        service.get_result(auth=_auth(), document_id=document_id)

    assert unsupported.value.code == "UNSUPPORTED_RESULT_TYPE"
    assert unsupported.value.status_code == 422
    assert s3.get_calls == 0


def test_conflicting_result_domain_is_rejected_before_storage_read() -> None:
    service, _operations, _batches, documents, s3, _clock = _service()
    document_id, _key = _completed_document(service, documents, s3)
    documents.items[document_id]["documentRoute"] = "personal"

    with pytest.raises(AppError) as unsupported:
        service.get_result(auth=_auth(), document_id=document_id)

    assert unsupported.value.code == "UNSUPPORTED_STATE"
    assert unsupported.value.status_code == 500
    assert s3.get_calls == 0


def test_terminal_result_without_locator_is_malformed_not_retryable_pending() -> None:
    service, _operations, _batches, documents, s3, _clock = _service()
    document_id, _key = _completed_document(service, documents, s3)
    documents.items[document_id]["artifacts"] = {}

    with pytest.raises(AppError) as malformed:
        service.get_result(auth=_auth(), document_id=document_id)

    assert malformed.value.code == "MALFORMED_INTERNAL_RESULT"
    assert malformed.value.status_code == 500
    assert s3.get_calls == 0


def test_terminal_result_with_noncanonical_locator_is_malformed_before_read() -> None:
    service, _operations, _batches, documents, s3, _clock = _service()
    document_id, _key = _completed_document(service, documents, s3)
    documents.items[document_id]["artifacts"]["structured"]["key"] = (
        f"customers/{CUSTOMER_A}/deployments/{DEPLOYMENT_A}/"
        f"documents/{document_id}/result.json"
    )

    with pytest.raises(AppError) as malformed:
        service.get_result(auth=_auth(), document_id=document_id)

    assert malformed.value.code == "MALFORMED_INTERNAL_RESULT"
    assert malformed.value.status_code == 500
    assert s3.get_calls == 0


def test_result_rejects_contradictory_extraction_evidence_before_storage_read() -> None:
    service, _operations, _batches, documents, s3, _clock = _service()
    document_id, _key = _completed_document(service, documents, s3)
    evidence = documents.items[document_id]["stages"]["bank_extract"]["artifact"]
    evidence["pipeline_stage"] = "personal-extract"

    with pytest.raises(AppError) as unsupported:
        service.get_result(auth=_auth(), document_id=document_id)

    assert unsupported.value.code == "UNSUPPORTED_STATE"
    assert unsupported.value.status_code == 500
    assert s3.get_calls == 0


def test_result_rejects_object_that_disagrees_with_durable_content_digest() -> None:
    service, _operations, _batches, documents, s3, _clock = _service()
    document_id, key = _completed_document(service, documents, s3)
    artifact = _bank_artifact(document_id)
    artifact["summaryText"] = "Changed after the durable checkpoint"
    s3.objects[("synthetic-structured-bucket", key)] = json.dumps(artifact).encode()

    with pytest.raises(AppError) as malformed:
        service.get_result(auth=_auth(), document_id=document_id)

    assert malformed.value.code == "MALFORMED_INTERNAL_RESULT"
    assert malformed.value.status_code == 500
    assert s3.get_calls == 1


def test_result_rejects_s3_metadata_that_disagrees_with_checkpoint() -> None:
    service, _operations, _batches, documents, s3, _clock = _service()
    document_id, key = _completed_document(service, documents, s3)
    s3.metadata[("synthetic-structured-bucket", key)]["pipeline-stage"] = (
        "personal-extract"
    )

    with pytest.raises(AppError) as malformed:
        service.get_result(auth=_auth(), document_id=document_id)

    assert malformed.value.code == "MALFORMED_INTERNAL_RESULT"
    assert malformed.value.status_code == 500
    assert s3.get_calls == 1
    assert s3.last_body is not None
    assert s3.last_body.closed is True


def test_result_rejects_not_ready_malformed_and_unsupported_artifacts() -> None:
    service, _operations, _batches, documents, s3, _clock = _service()
    created = _create_document(service)
    with pytest.raises(AppError) as not_ready:
        service.get_result(
            auth=_auth(), document_id=created.durable_response.document_id
        )
    assert not_ready.value.code == "RESULT_NOT_READY"

    service, _operations, _batches, documents, s3, _clock = _service()
    document_id, key = _completed_document(service, documents, s3)
    s3.objects[("synthetic-structured-bucket", key)] = b'{"docType":"bank_statement"'
    with pytest.raises(AppError) as malformed:
        service.get_result(auth=_auth(), document_id=document_id)
    assert malformed.value.code == "MALFORMED_INTERNAL_RESULT"
    assert s3.last_body is not None
    assert s3.last_body.closed is True

    artifact = _bank_artifact(document_id)
    artifact["docType"] = "invoice"
    _replace_bank_artifact(documents, s3, document_id, key, artifact)
    with pytest.raises(AppError) as unsupported:
        service.get_result(auth=_auth(), document_id=document_id)
    assert unsupported.value.code == "UNSUPPORTED_RESULT_TYPE"
    assert unsupported.value.status_code == 422


def test_result_rejects_terminal_stage_contradiction_before_storage_read() -> None:
    service, _operations, _batches, documents, s3, _clock = _service()
    document_id, _key = _completed_document(service, documents, s3)
    documents.items[document_id]["stages"]["persist"]["finalStatus"] = "FAILED"

    with pytest.raises(AppError) as unsupported:
        service.get_result(auth=_auth(), document_id=document_id)

    assert unsupported.value.code == "UNSUPPORTED_STATE"
    assert unsupported.value.status_code == 500
    assert s3.last_body is None


def test_result_closes_storage_body_when_read_raises() -> None:
    service, _operations, _batches, documents, s3, _clock = _service()
    document_id, key = _completed_document(service, documents, s3)

    class ExplodingBody:
        def __init__(self) -> None:
            self.closed = False

        def read(self, _size: int) -> bytes:
            raise OSError("synthetic read failure")

        def close(self) -> None:
            self.closed = True

    body = ExplodingBody()
    s3.get_object = lambda **_request: {  # type: ignore[method-assign]
        "ContentLength": 1,
        "Body": body,
        "Metadata": s3.metadata[("synthetic-structured-bucket", key)],
    }

    with pytest.raises(AppError) as upstream:
        service.get_result(auth=_auth(), document_id=document_id)

    assert upstream.value.code == "UPSTREAM_ERROR"
    assert body.closed is True


def test_result_closes_storage_body_before_rejecting_oversized_response() -> None:
    service, _operations, _batches, documents, s3, _clock = _service()
    document_id, key = _completed_document(service, documents, s3)

    class UnreadBody:
        def __init__(self) -> None:
            self.closed = False
            self.read_calls = 0

        def read(self, _size: int) -> bytes:
            self.read_calls += 1
            return b""

        def close(self) -> None:
            self.closed = True

    body = UnreadBody()
    s3.get_object = lambda **_request: {  # type: ignore[method-assign]
        "ContentLength": FakeSettings.journey_result_max_bytes + 1,
        "Body": body,
        "Metadata": s3.metadata[("synthetic-structured-bucket", key)],
    }

    with pytest.raises(AppError) as malformed:
        service.get_result(auth=_auth(), document_id=document_id)

    assert malformed.value.code == "MALFORMED_INTERNAL_RESULT"
    assert body.read_calls == 0
    assert body.closed is True
