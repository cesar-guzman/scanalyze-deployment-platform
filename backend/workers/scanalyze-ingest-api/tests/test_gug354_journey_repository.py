from __future__ import annotations

import copy
import hashlib
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from app.repositories.operations import (
    OPERATION_SCHEMA_VERSION,
    DynamoOperationsRepository,
    OperationConflict,
    OperationContractError,
    OperationIdentity,
    OperationPersistenceAmbiguous,
    OperationState,
)


NOW = datetime(2026, 8, 7, 18, 0, tzinfo=timezone.utc)
EXPIRES_AT = NOW + timedelta(hours=24)
CONTRACT_VERSION = "scanalyze.document-journey.v1"


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _identity(
    *,
    customer_id: str = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAV",
    deployment_id: str = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV",
    actor: str = "synthetic-actor",
    raw_key: str = "018f9342-19b5-7c40-b9a7-a9120a744e91",
    operation: str = "documents.create",
) -> OperationIdentity:
    return OperationIdentity(
        contract_version=CONTRACT_VERSION,
        operation=operation,
        actor_digest=_digest(actor),
        customer_id=customer_id,
        deployment_id=deployment_id,
        key_digest=_digest(raw_key),
    )


def _document_response(
    document_id: str,
    *,
    status: str = "UPLOAD_PENDING",
    batch_id: str | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schemaVersion": "scanalyze.document-create-result.v1",
        "contractVersion": CONTRACT_VERSION,
        "operation": "documents.create",
        "documentId": document_id,
        "status": status,
        "createdAt": "2026-08-07T18:00:00Z",
        "contentType": "application/pdf",
    }
    if batch_id is not None:
        result["batchId"] = batch_id
    return result


def _batch_response(batch_id: str, *, status: str = "OPEN") -> dict[str, Any]:
    return {
        "schemaVersion": "scanalyze.batch-create-result.v1",
        "contractVersion": CONTRACT_VERSION,
        "operation": "batches.create",
        "batchId": batch_id,
        "status": status,
        "createdAt": "2026-08-07T18:00:00Z",
    }


class SyntheticWriteError(RuntimeError):
    pass


class ConditionalFailure(RuntimeError):
    def __init__(self) -> None:
        super().__init__("synthetic conditional failure")
        self.response = {"Error": {"Code": "ConditionalCheckFailedException"}}


class FakeTable:
    """Thread-safe, expression-specific DynamoDB fake with no SDK/network use."""

    def __init__(self) -> None:
        self.items: dict[tuple[str, str], dict[str, Any]] = {}
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.raise_after_next_put = False
        self.raise_before_next_put = False
        self.raise_after_next_update = False
        self.raise_before_next_update = False
        self.raise_next_get = False
        self._lock = threading.Lock()

    @staticmethod
    def _key(value: dict[str, Any]) -> tuple[str, str]:
        return str(value["pk"]), str(value["sk"])

    def scan(self, **request: Any) -> None:  # pragma: no cover - invariant guard
        raise AssertionError(f"ledger scan attempted: {request}")

    def put_item(self, **request: Any) -> dict[str, Any]:
        with self._lock:
            self.calls.append(("put_item", copy.deepcopy(request)))
            if self.raise_before_next_put:
                self.raise_before_next_put = False
                raise SyntheticWriteError("synthetic response loss before apply")
            item = copy.deepcopy(request["Item"])
            key = self._key(item)
            if key in self.items:
                raise ConditionalFailure()
            self.items[key] = item
            if self.raise_after_next_put:
                self.raise_after_next_put = False
                raise SyntheticWriteError("synthetic response loss after apply")
            return {}

    def get_item(self, **request: Any) -> dict[str, Any]:
        with self._lock:
            self.calls.append(("get_item", copy.deepcopy(request)))
            if self.raise_next_get:
                self.raise_next_get = False
                raise SyntheticWriteError("synthetic consistent read unavailable")
            item = self.items.get(self._key(request["Key"]))
            return {"Item": copy.deepcopy(item)} if item is not None else {}

    def update_item(self, **request: Any) -> dict[str, Any]:
        with self._lock:
            self.calls.append(("update_item", copy.deepcopy(request)))
            if self.raise_before_next_update:
                self.raise_before_next_update = False
                raise SyntheticWriteError("synthetic response loss before update")
            key = self._key(request["Key"])
            item = self.items.get(key)
            values = request["ExpressionAttributeValues"]
            expected_fields = {
                "state": values[":expected_state"],
                "version": values[":expected_version"],
                "schema_version": values[":schema_version"],
                "contract_version": values[":contract_version"],
                "operation": values[":operation"],
                "actor_digest": values[":actor_digest"],
                "customer_id": values[":customer_id"],
                "deployment_id": values[":deployment_id"],
                "key_digest": values[":key_digest"],
                "request_digest": values[":request_digest"],
                "resource_type": values[":resource_type"],
                "resource_id": values[":resource_id"],
            }
            if item is None or any(
                item.get(name) != value for name, value in expected_fields.items()
            ):
                raise ConditionalFailure()

            item["state"] = values[":next_state"]
            item["version"] = values[":next_version"]
            item["updated_at"] = values[":updated_at"]
            item["durable_response"] = copy.deepcopy(values[":durable_response"])
            if ":failure_code" in values:
                item["failure_code"] = values[":failure_code"]
            else:
                item.pop("failure_code", None)
            if ":completed_at" in values:
                item["completed_at"] = values[":completed_at"]
            else:
                item.pop("completed_at", None)

            if self.raise_after_next_update:
                self.raise_after_next_update = False
                raise SyntheticWriteError("synthetic response loss after update")
            return {}


def _reserve_document(
    repository: DynamoOperationsRepository,
    identity: OperationIdentity,
    *,
    document_id: str = "018f934219b57c40b9a7a9120a744e92",
    request: str = "canonical-document-request",
) -> Any:
    return repository.reserve(
        identity,
        request_digest=_digest(request),
        resource_type="document",
        resource_id=document_id,
        durable_response=_document_response(document_id),
        now=NOW,
        expires_at=EXPIRES_AT,
    )


def test_reservation_is_create_only_and_replay_read_is_strongly_consistent() -> None:
    table = FakeTable()
    repository = DynamoOperationsRepository(table)
    identity = _identity()

    first = _reserve_document(repository, identity)
    replay = _reserve_document(
        repository,
        identity,
        document_id="018f934219b57c40b9a7a9120a744e99",
    )

    assert first.created_here is True
    assert replay.created_here is False
    assert replay.record.resource_id == first.record.resource_id
    assert replay.record.durable_response == first.record.durable_response
    put = next(request for call, request in table.calls if call == "put_item")
    assert put["ConditionExpression"] == (
        "attribute_not_exists(#pk) AND attribute_not_exists(#sk)"
    )
    assert all(
        request["ConsistentRead"] is True
        for call, request in table.calls
        if call == "get_item"
    )


def test_concurrent_contenders_converge_on_first_winner_resource_and_response() -> None:
    table = FakeTable()
    repository = DynamoOperationsRepository(table)
    identity = _identity()
    candidates = [f"018f934219b57c40b9a7{index:012x}" for index in range(16)]

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(
            executor.map(
                lambda document_id: _reserve_document(
                    repository,
                    identity,
                    document_id=document_id,
                ),
                candidates,
            )
        )

    winners = {outcome.record.resource_id for outcome in results}
    responses = {
        json.dumps(dict(outcome.record.durable_response), sort_keys=True)
        for outcome in results
    }
    assert len(winners) == 1
    assert len(responses) == 1
    assert sum(outcome.created_here for outcome in results) == 1
    assert len(table.items) == 1


def test_same_key_with_changed_canonical_request_is_a_conflict() -> None:
    table = FakeTable()
    repository = DynamoOperationsRepository(table)
    identity = _identity()
    original = _reserve_document(repository, identity)

    with pytest.raises(OperationConflict):
        _reserve_document(repository, identity, request="changed-canonical-request")

    assert repository.load(identity) == original.record
    assert len(table.items) == 1


def test_owner_actor_and_operation_are_all_part_of_the_isolated_keyspace() -> None:
    table = FakeTable()
    repository = DynamoOperationsRepository(table)
    original_identity = _identity()
    foreign_customer = _identity(customer_id="cust_01ARZ3NDEKTSV4RRFFQ69G5FAW")
    foreign_actor = _identity(actor="foreign-synthetic-actor")
    foreign_operation = _identity(operation="batches.create")

    _reserve_document(repository, original_identity)

    assert repository.load(foreign_customer) is None
    assert repository.load(foreign_actor) is None
    assert repository.load(foreign_operation) is None
    keys = list(table.items)
    assert original_identity.customer_id not in keys[0][0]
    assert original_identity.deployment_id not in keys[0][0]
    assert original_identity.actor_digest.removeprefix("sha256:") in keys[0][1]
    assert original_identity.key_digest.removeprefix("sha256:") in keys[0][1]


def test_only_digests_and_allowlisted_durable_projection_are_persisted() -> None:
    raw_key = "018f9342-19b5-7c40-b9a7-a9120a744e91"
    raw_actor = "synthetic.actor@example.invalid"
    table = FakeTable()
    repository = DynamoOperationsRepository(table)
    _reserve_document(repository, _identity(raw_key=raw_key, actor=raw_actor))

    serialized = json.dumps(next(iter(table.items.values())), sort_keys=True)
    assert raw_key not in serialized
    assert raw_actor not in serialized
    assert "https://" not in serialized
    assert "uploadCapability" not in serialized
    assert "request_body" not in serialized
    assert "ttl" not in next(iter(table.items.values()))


@pytest.mark.parametrize(
    "mutator",
    [
        lambda response: response.update({"uploadUrl": "https://example.invalid/private"}),
        lambda response: response.update({"metadata": "private"}),
        lambda response: response.update({"headers": "private"}),
        lambda response: response.update({"payload": {"private": True}}),
        lambda response: response.update({"documentId": "different-resource"}),
        lambda response: response.update({"operation": "batches.create"}),
        lambda response: response.update({"createdAt": "x" * 513}),
    ],
)
def test_durable_response_rejects_ephemeral_sensitive_or_noncanonical_fields(mutator: Any) -> None:
    table = FakeTable()
    response = _document_response("018f934219b57c40b9a7a9120a744e92")
    mutator(response)

    with pytest.raises(OperationContractError):
        DynamoOperationsRepository(table).reserve(
            _identity(),
            request_digest=_digest("canonical-document-request"),
            resource_type="document",
            resource_id="018f934219b57c40b9a7a9120a744e92",
            durable_response=response,
            now=NOW,
            expires_at=EXPIRES_AT,
        )

    assert table.items == {}


def test_batch_projection_uses_the_same_ledger_without_document_shape_leakage() -> None:
    table = FakeTable()
    repository = DynamoOperationsRepository(table)
    identity = _identity(operation="batches.create")
    batch_id = "018f934219b57c40b9a7a9120a744e93"

    outcome = repository.reserve(
        identity,
        request_digest=_digest("canonical-batch-request"),
        resource_type="batch",
        resource_id=batch_id,
        durable_response=_batch_response(batch_id),
        now=NOW,
        expires_at=EXPIRES_AT,
    )

    assert outcome.record.resource_type == "batch"
    assert outcome.record.durable_response["batchId"] == batch_id
    assert "documentId" not in outcome.record.durable_response


def test_ambiguous_reserve_response_is_reconciled_after_a_consistent_read() -> None:
    table = FakeTable()
    table.raise_after_next_put = True
    repository = DynamoOperationsRepository(table)

    outcome = _reserve_document(repository, _identity())

    assert outcome.created_here is True
    assert outcome.record.state is OperationState.PENDING
    assert any(
        call == "get_item" and request["ConsistentRead"] is True
        for call, request in table.calls
    )


def test_unprovable_reserve_outcome_fails_closed_as_ambiguous() -> None:
    table = FakeTable()
    table.raise_before_next_put = True

    with pytest.raises(OperationPersistenceAmbiguous):
        _reserve_document(DynamoOperationsRepository(table), _identity())

    assert table.items == {}


def test_transition_uses_exact_version_cas_and_reconciles_lost_write_response() -> None:
    table = FakeTable()
    repository = DynamoOperationsRepository(table)
    identity = _identity()
    pending = _reserve_document(repository, identity).record
    succeeded_response = _document_response(pending.resource_id)
    completed_at = NOW + timedelta(seconds=3)
    table.raise_after_next_update = True

    succeeded = repository.transition(
        identity,
        expected_state=OperationState.PENDING,
        expected_version=1,
        next_state=OperationState.SUCCEEDED,
        durable_response=succeeded_response,
        completed_at=completed_at,
        updated_at=completed_at,
    )
    replay = repository.transition(
        identity,
        expected_state=OperationState.PENDING,
        expected_version=1,
        next_state=OperationState.SUCCEEDED,
        durable_response=succeeded_response,
        completed_at=completed_at,
        updated_at=completed_at + timedelta(seconds=5),
    )

    assert succeeded == replay
    assert succeeded.state is OperationState.SUCCEEDED
    assert succeeded.version == 2
    assert succeeded.completed_at == completed_at
    update = next(request for call, request in table.calls if call == "update_item")
    assert "#version = :expected_version" in update["ConditionExpression"]
    for binding in (
        "actor_digest",
        "customer_id",
        "deployment_id",
        "key_digest",
        "request_digest",
        "resource_type",
        "resource_id",
    ):
        assert f"{binding} = :{binding}" in update["ConditionExpression"]


def test_concurrent_cas_transition_cannot_apply_two_different_outcomes() -> None:
    table = FakeTable()
    repository = DynamoOperationsRepository(table)
    identity = _identity()
    pending = _reserve_document(repository, identity).record
    transition_at = NOW + timedelta(seconds=1)

    def succeed() -> str:
        try:
            repository.transition(
                identity,
                expected_state=OperationState.PENDING,
                expected_version=1,
                next_state=OperationState.SUCCEEDED,
                durable_response=_document_response(pending.resource_id),
                completed_at=transition_at,
                updated_at=transition_at,
            )
            return "SUCCEEDED"
        except OperationConflict:
            return "CONFLICT"

    def fail() -> str:
        try:
            repository.transition(
                identity,
                expected_state=OperationState.PENDING,
                expected_version=1,
                next_state=OperationState.FAILED_TERMINAL,
                failure_code="REQUEST_REJECTED",
                completed_at=transition_at,
                updated_at=transition_at,
            )
            return "FAILED_TERMINAL"
        except OperationConflict:
            return "CONFLICT"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = [executor.submit(succeed), executor.submit(fail)]
        outcomes = [result.result() for result in results]

    assert outcomes.count("CONFLICT") == 1
    current = repository.load(identity)
    assert current is not None
    assert current.state in {OperationState.SUCCEEDED, OperationState.FAILED_TERMINAL}
    assert current.version == 2


def test_failed_retryable_can_resume_pending_with_an_exact_next_version() -> None:
    table = FakeTable()
    repository = DynamoOperationsRepository(table)
    identity = _identity()
    _reserve_document(repository, identity)

    failed = repository.transition(
        identity,
        expected_state=OperationState.PENDING,
        expected_version=1,
        next_state=OperationState.FAILED_RETRYABLE,
        failure_code="DEPENDENCY_UNAVAILABLE",
        updated_at=NOW + timedelta(seconds=1),
    )
    resumed = repository.transition(
        identity,
        expected_state=OperationState.FAILED_RETRYABLE,
        expected_version=2,
        next_state=OperationState.PENDING,
        updated_at=NOW + timedelta(seconds=2),
    )

    assert failed.failure_code == "DEPENDENCY_UNAVAILABLE"
    assert failed.completed_at is None
    assert resumed.state is OperationState.PENDING
    assert resumed.version == 3
    assert resumed.failure_code is None
    assert resumed.completed_at is None


def test_logical_expiry_retains_record_and_prevents_key_reuse() -> None:
    table = FakeTable()
    repository = DynamoOperationsRepository(table)
    identity = _identity()
    original = _reserve_document(repository, identity).record

    with pytest.raises(OperationContractError):
        repository.transition(
            identity,
            expected_state=OperationState.PENDING,
            expected_version=1,
            next_state=OperationState.EXPIRED,
            updated_at=EXPIRES_AT - timedelta(microseconds=1),
        )

    expired = repository.transition(
        identity,
        expected_state=OperationState.PENDING,
        expected_version=1,
        next_state=OperationState.EXPIRED,
        updated_at=EXPIRES_AT,
    )
    replay = _reserve_document(
        repository,
        identity,
        document_id="018f934219b57c40b9a7a9120a744e98",
    )

    assert expired.state is OperationState.EXPIRED
    assert expired.resource_id == original.resource_id
    assert expired.completed_at == EXPIRES_AT
    assert replay.created_here is False
    assert replay.record == expired
    assert len(table.items) == 1
    assert "ttl" not in next(iter(table.items.values()))


def test_closed_state_and_exact_state_machine_reject_unknown_or_terminal_reentry() -> None:
    table = FakeTable()
    repository = DynamoOperationsRepository(table)
    identity = _identity()
    pending = _reserve_document(repository, identity).record

    with pytest.raises(OperationContractError):
        repository.transition(
            identity,
            expected_state=OperationState.PENDING,
            expected_version=1,
            next_state="NOT_A_STATE",  # type: ignore[arg-type]
            updated_at=NOW + timedelta(seconds=1),
        )

    succeeded = repository.transition(
        identity,
        expected_state=OperationState.PENDING,
        expected_version=1,
        next_state=OperationState.SUCCEEDED,
        durable_response=_document_response(pending.resource_id),
        updated_at=NOW + timedelta(seconds=2),
    )
    with pytest.raises(OperationContractError):
        repository.transition(
            identity,
            expected_state=OperationState.SUCCEEDED,
            expected_version=succeeded.version,
            next_state=OperationState.PENDING,
            updated_at=NOW + timedelta(seconds=3),
        )


def test_corrupt_or_cross_bound_persisted_item_is_never_returned() -> None:
    table = FakeTable()
    repository = DynamoOperationsRepository(table)
    identity = _identity()
    _reserve_document(repository, identity)
    item = next(iter(table.items.values()))
    item["customer_id"] = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW"

    with pytest.raises(OperationContractError):
        repository.load(identity)


def test_record_schema_and_timestamps_are_closed_and_versioned() -> None:
    table = FakeTable()
    record = _reserve_document(DynamoOperationsRepository(table), _identity()).record

    assert record.schema_version == OPERATION_SCHEMA_VERSION
    assert record.state is OperationState.PENDING
    assert record.version == 1
    assert record.created_at == NOW
    assert record.updated_at == NOW
    assert record.expires_at == EXPIRES_AT
    assert record.completed_at is None
    assert record.failure_code is None


@pytest.mark.parametrize(
    "resource_id",
    [
        "018f9342-19b5-7c40-b9a7-a9120a744e92",
        "018F934219B57C40B9A7A9120A744E92",
        "018f934219b57c40b9a7a9120a744e9",
        "018f934219b57c40b9a7a9120a744e920",
        "../018f934219b57c40b9a7a9120a744e92",
    ],
)
def test_resource_identity_is_exact_lowercase_hex32(resource_id: str) -> None:
    table = FakeTable()

    with pytest.raises(OperationContractError):
        DynamoOperationsRepository(table).reserve(
            _identity(),
            request_digest=_digest("canonical-document-request"),
            resource_type="document",
            resource_id=resource_id,
            durable_response=_document_response(resource_id),
            now=NOW,
            expires_at=EXPIRES_AT,
        )

    assert table.items == {}


@pytest.mark.parametrize(
    "content_type",
    [
        "text/plain",
        "application/octet-stream",
        "application/pdf; charset=utf-8",
        "APPLICATION/PDF",
        "image/gif",
    ],
)
def test_document_projection_accepts_only_reviewed_content_types(
    content_type: str,
) -> None:
    table = FakeTable()
    document_id = "018f934219b57c40b9a7a9120a744e92"
    response = _document_response(document_id)
    response["contentType"] = content_type

    with pytest.raises(OperationContractError):
        DynamoOperationsRepository(table).reserve(
            _identity(),
            request_digest=_digest("canonical-document-request"),
            resource_type="document",
            resource_id=document_id,
            durable_response=response,
            now=NOW,
            expires_at=EXPIRES_AT,
        )

    assert table.items == {}


def test_persisted_timestamp_invariants_are_state_specific_and_fail_closed() -> None:
    table = FakeTable()
    repository = DynamoOperationsRepository(table)
    identity = _identity()
    _reserve_document(repository, identity)
    pending_item = next(iter(table.items.values()))

    pending_item["updated_at"] = pending_item["expires_at"]
    with pytest.raises(OperationContractError):
        repository.load(identity)

    pending_item["updated_at"] = "2026-08-07T18:00:00Z"
    pending_item["completed_at"] = "2026-08-07T18:00:01Z"
    with pytest.raises(OperationContractError):
        repository.load(identity)

    pending_item.pop("completed_at")
    expired = repository.transition(
        identity,
        expected_state=OperationState.PENDING,
        expected_version=1,
        next_state=OperationState.EXPIRED,
        updated_at=EXPIRES_AT,
    )
    assert expired.updated_at >= expired.expires_at
    assert expired.completed_at == EXPIRES_AT

    expired_item = next(iter(table.items.values()))
    expired_item["updated_at"] = "2026-08-08T17:59:59Z"
    with pytest.raises(OperationContractError):
        repository.load(identity)


def test_logical_expiry_preserves_an_existing_terminal_completion_time() -> None:
    table = FakeTable()
    repository = DynamoOperationsRepository(table)
    identity = _identity()
    pending = _reserve_document(repository, identity).record
    completed_at = NOW + timedelta(seconds=3)
    succeeded = repository.transition(
        identity,
        expected_state=OperationState.PENDING,
        expected_version=1,
        next_state=OperationState.SUCCEEDED,
        durable_response=_document_response(pending.resource_id),
        completed_at=completed_at,
        updated_at=completed_at,
    )

    expired = repository.transition(
        identity,
        expected_state=OperationState.SUCCEEDED,
        expected_version=succeeded.version,
        next_state=OperationState.EXPIRED,
        updated_at=EXPIRES_AT,
    )

    assert expired.completed_at == completed_at
