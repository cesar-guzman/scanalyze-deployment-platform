"""Synthetic bank history/CSV contracts; no cloud clients or customer data."""
from __future__ import annotations

import csv
import io
import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import analytics as routes
from app.auth import AuthContext, get_auth_context
from app.authorization import ObjectOwnership
from app.errors import AppError, register_exception_handlers
from app.journey_contract import CONTRACT_VERSION, owner_scope_from_auth, project_bank_statement_result
from app.repositories.documents import DocumentsRepository, DynamoKeySchema
from app.services import analytics
from app.services.analytics import AnalyticsService
from test_gug354_journey_service import (
    _bank_artifact,
    _completed_document,
    _service as journey_fixture,
)


CUSTOMER = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW"
DEPLOYMENT = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
DOC_A = "a" * 32
DOC_B = "b" * 32


def auth(**changes: object) -> AuthContext:
    values = dict(
        customer_id=CUSTOMER, deployment_id=DEPLOYMENT,
        principal_type="user", subject="synthetic-actor-a", auth_source="synthetic-test",
    )
    values.update(changes)
    return AuthContext(**values)


def record(document_id: str = DOC_A, *, actor: AuthContext | None = None, **changes: object) -> dict:
    actor = actor or auth()
    value = {
        **ObjectOwnership.from_auth(actor).record_fields(),
        "documentId": document_id, "status": "CREATED",
        "createdAt": "2026-08-08T18:00:00+00:00", "updatedAt": "2026-08-08T18:01:00+00:00",
        "stages": {}, "processing_domain": "bank", "documentRoute": "bank",
        "journey_contract_version": CONTRACT_VERSION, "journey_operation": "documents.create",
        "journey_actor_digest": owner_scope_from_auth(actor).actor_digest,
        "journey_resource_schema_version": 1,
        "input": {"filename": "synthetic.pdf", "key": "SYNTHETIC_PRIVATE_KEY"},
        "provider": "SYNTHETIC_PRIVATE_PROVIDER", "raw": "SYNTHETIC_PRIVATE_DATA",
    }
    value.update(changes)
    return value


def service(*records: dict, next_id: str | None = None) -> AnalyticsService:
    svc = AnalyticsService.__new__(AnalyticsService)
    svc.settings = SimpleNamespace()
    svc.repo = MagicMock()
    svc.repo.list_owned_documents_page.return_value = (list(records), next_id)
    by_id = {item["documentId"]: item for item in records}
    svc.repo.get_document.side_effect = lambda document_id, **kwargs: by_id.get(document_id)
    return svc


def result(document_id: str = DOC_A, **changes: object):
    artifact = _bank_artifact(document_id)
    artifact.update(changes)
    return project_bank_statement_result(artifact, document_id=document_id)


def test_history_projects_only_current_actor_canonical_bank_metadata() -> None:
    svc = service(
        record(), record(DOC_B, actor=auth(subject="synthetic-other-actor")),
        record("c" * 32, processing_domain="personal", documentRoute="personal"),
        record("d" * 32, journey_contract_version="legacy"),
        record("e" * 32, journey_operation="batches.create"),
        record("f" * 32, journey_resource_schema_version=2),
    )
    page = svc.get_bank_documents(auth())
    assert page == {"documents": [{
        "documentId": DOC_A, "filename": "synthetic.pdf", "status": "UPLOAD_PENDING",
        "createdAt": "2026-08-08T18:00:00+00:00",
    }], "nextCursor": None}
    assert "SYNTHETIC_PRIVATE" not in json.dumps(page)
    svc.repo.list_owned_documents_page.assert_called_once_with(
        ownership=ObjectOwnership.from_auth(auth()), limit=50, after_document_id=None,
    )


@pytest.mark.parametrize("filename", [None, "../synthetic.pdf", "a\\b.pdf", "a\nb.pdf", "a" * 129])
def test_history_omits_unsafe_filename(filename: object) -> None:
    page = service(record(input={"filename": filename})).get_bank_documents(auth())
    assert page["documents"][0]["filename"] is None


@pytest.mark.parametrize("changes", [
    {"customer_id": "cust_01ARZ3NDEKTSV4RRFFQ69G5FAX"},
    {"deployment_id": "dep_01ARZ3NDEKTSV4RRFFQ69G5FAW"},
    {"ownership_key": "foreign"}, {"ownership_schema_version": 0},
])
def test_history_rejects_poisoned_index_ownership(changes: dict) -> None:
    with pytest.raises(AppError) as error:
        service(record(**changes)).get_bank_documents(auth())
    assert error.value.status_code == 404


@pytest.mark.parametrize("changes", [{"documentId": "invalid"}, {"status": "UNKNOWN"}])
def test_history_does_not_project_malformed_bank_state(changes: dict) -> None:
    with pytest.raises(AppError) as error:
        service(record(**changes)).get_bank_documents(auth())
    assert error.value.status_code == 500


def test_cursor_continues_empty_page_ending_in_other_actor_without_authorizing_position() -> None:
    svc = service(record(DOC_B, actor=auth(subject="another-actor")), next_id=DOC_B)
    page = svc.get_bank_documents(auth(), limit=1)
    assert page["documents"] == []
    cursor = page["nextCursor"]
    assert len(cursor) == 100
    assert owner_scope_from_auth(auth()).actor_digest not in cursor
    svc.repo.list_owned_documents_page.return_value = ([record()], None)
    continued = svc.get_bank_documents(auth(), limit=1, cursor=cursor)
    assert continued["documents"][0]["documentId"] == DOC_A
    assert continued["nextCursor"] is None
    assert svc.repo.list_owned_documents_page.call_count == 2
    assert svc.repo.list_owned_documents_page.call_args.kwargs["after_document_id"] == DOC_B
    svc.repo.get_document.assert_not_called()


@pytest.mark.parametrize("changes", [
    {"subject": "another-actor"}, {"customer_id": "cust_01ARZ3NDEKTSV4RRFFQ69G5FAX"},
    {"deployment_id": "dep_01ARZ3NDEKTSV4RRFFQ69G5FAW"},
    {"principal_type": "m2m", "client_id": "synthetic-actor-a", "granted_actions": ("read",)},
])
def test_cursor_cannot_replay_in_different_actor_or_owner_scope(changes: dict) -> None:
    svc = service(record(), next_id=DOC_A)
    cursor = svc.get_bank_documents(auth())["nextCursor"]
    svc.repo.reset_mock()
    with pytest.raises(AppError) as error:
        svc.get_bank_documents(auth(**changes), cursor=cursor)
    assert error.value.status_code == 422
    svc.repo.list_owned_documents_page.assert_not_called()


@pytest.mark.parametrize("cursor", ["v1:" + DOC_A, "v2:" + DOC_A + ":" + "0" * 64, "{}", "v1:" + DOC_A + ":" + "0" * 64])
def test_malformed_or_wrong_bound_cursor_is_rejected_before_query(cursor: str) -> None:
    svc = service()
    with pytest.raises(AppError) as error:
        svc.get_bank_documents(auth(), cursor=cursor)
    assert error.value.status_code == 422
    svc.repo.list_owned_documents_page.assert_not_called()


def repository(response: dict) -> DocumentsRepository:
    repo = DocumentsRepository.__new__(DocumentsRepository)
    repo.table_name = "synthetic-documents"
    repo.schema = DynamoKeySchema("documentId")
    repo.table = MagicMock()
    repo.table.query.return_value = response
    return repo


def test_repository_uses_one_bounded_ownership_query_and_reconstructs_exact_keys() -> None:
    ownership = ObjectOwnership.from_auth(auth())
    repo = repository({"Items": [record(DOC_B)], "LastEvaluatedKey": {
        "documentId": DOC_B, "ownership_key": ownership.partition,
    }})
    rows, next_id = repo.list_owned_documents_page(ownership=ownership, limit=50, after_document_id=DOC_A)
    assert rows == [record(DOC_B)] and next_id == DOC_B
    repo.table.query.assert_called_once_with(
        IndexName="OwnershipIndex", KeyConditionExpression="#ownership_key = :ownership_key",
        ExpressionAttributeNames={"#ownership_key": "ownership_key"},
        ExpressionAttributeValues={":ownership_key": ownership.partition}, Limit=50,
        ExclusiveStartKey={"documentId": DOC_A, "ownership_key": ownership.partition},
    )
    repo.table.scan.assert_not_called()


@pytest.mark.parametrize("response", [
    {"Items": "invalid"}, {"Items": [None]},
    {"Items": [record()], "LastEvaluatedKey": {"documentId": DOC_A, "ownership_key": "foreign"}},
    {"Items": [record()], "LastEvaluatedKey": {"documentId": DOC_A}},
    {"Items": [], "LastEvaluatedKey": {"documentId": DOC_A}},
    {"Items": [record()], "LastEvaluatedKey": []},
    {"Items": [record()], "LastEvaluatedKey": {"documentId": DOC_A, "ownership_key": ObjectOwnership.from_auth(auth()).partition, "extra": "invalid"}},
    {"Items": [record()] * 51},
])
def test_repository_rejects_malformed_or_foreign_page_continuation(response: dict) -> None:
    with pytest.raises(AppError) as error:
        repository(response).list_owned_documents_page(ownership=ObjectOwnership.from_auth(auth()), limit=50)
    assert error.value.status_code == 500


@pytest.mark.parametrize("limit,after", [(0, None), (101, None), (True, None), (1, "invalid"), (1, {})])
def test_repository_rejects_invalid_request_before_query(limit: object, after: object) -> None:
    repo = repository({"Items": []})
    with pytest.raises(AppError) as error:
        repo.list_owned_documents_page(ownership=ObjectOwnership.from_auth(auth()), limit=limit, after_document_id=after)
    assert error.value.status_code == 422
    repo.table.query.assert_not_called()


def test_repository_closes_provider_error_without_exposing_details() -> None:
    repo = repository({})
    repo.table.query.side_effect = ClientError({"Error": {"Code": "Denied", "Message": "SYNTHETIC_PRIVATE"}}, "Query")
    with pytest.raises(AppError) as error:
        repo.list_owned_documents_page(ownership=ObjectOwnership.from_auth(auth()), limit=50)
    assert error.value.code == "QUERY_FAILED"
    assert "SYNTHETIC_PRIVATE" not in error.value.message


@pytest.mark.parametrize("ids", ["", "invalid", DOC_A + ",", DOC_A + "," + DOC_A, ",".join(f"{i:032x}" for i in range(11))])
def test_export_rejects_invalid_duplicate_or_excessive_ids_before_read(ids: str) -> None:
    svc = service()
    with pytest.raises(AppError) as error:
        svc.export_bank_data(auth(), document_ids=ids)
    assert error.value.status_code == 422
    svc.repo.get_document.assert_not_called()


@pytest.mark.parametrize("changes", [
    {"actor": auth(subject="other-actor")},
    {"actor": auth(customer_id="cust_01ARZ3NDEKTSV4RRFFQ69G5FAX")},
    {"actor": auth(deployment_id="dep_01ARZ3NDEKTSV4RRFFQ69G5FAW")},
    {"journey_contract_version": "legacy"}, {"journey_operation": "batches.create"},
    {"journey_resource_schema_version": 2},
])
def test_export_authorizes_all_ids_before_first_result(monkeypatch: pytest.MonkeyPatch, changes: dict) -> None:
    constructor = MagicMock()
    monkeypatch.setattr(analytics, "JourneyService", constructor)
    svc = service(record(), record(DOC_B, **changes))
    with pytest.raises(AppError) as error:
        svc.export_bank_data(auth(), document_ids=f"{DOC_A},{DOC_B}")
    assert error.value.status_code == 404
    assert svc.repo.get_document.call_count == 2
    constructor.assert_not_called()


def test_export_missing_second_record_never_reads_first_result(monkeypatch: pytest.MonkeyPatch) -> None:
    constructor = MagicMock()
    monkeypatch.setattr(analytics, "JourneyService", constructor)
    with pytest.raises(AppError) as error:
        service(record()).export_bank_data(auth(), document_ids=f"{DOC_A},{DOC_B}")
    assert error.value.status_code == 404
    constructor.assert_not_called()


def test_export_canonical_projection_neutralizes_formulas_preserves_null_and_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    artifact = _bank_artifact(DOC_A)
    artifact["bank"]["name"] = "=synthetic_formula"
    first = artifact["transactions"][0]
    first.update(description="+synthetic_formula", reference='synthetic, "quoted"', amount=None, balanceAfter=0.0)
    projected = project_bank_statement_result(artifact, document_id=DOC_A)
    journey = MagicMock()
    journey.get_result.return_value = projected
    monkeypatch.setattr(analytics, "JourneyService", MagicMock(return_value=journey))
    response = service(record()).export_bank_data(auth(), document_ids=DOC_A)
    rows = list(csv.DictReader(io.StringIO(response.body.decode())))
    assert len(rows) == 1
    assert rows[0]["bankName"] == "'=synthetic_formula"
    assert rows[0]["description"] == "'+synthetic_formula"
    assert rows[0]["reference"] == 'synthetic, "quoted"'
    assert rows[0]["amount"] == "" and rows[0]["balanceAfter"] == "0.0"
    assert rows[0]["accountNumberMasked"] == "****3333"
    assert "modelId" not in rows[0] and "holder" not in rows[0]
    assert "0000111122223333" not in response.body.decode()
    assert response.headers["cache-control"] == "no-store"
    assert "bank_statements.csv" in response.headers["content-disposition"]
    journey.get_result.assert_called_once_with(auth=auth(), document_id=DOC_A)


def test_export_empty_transactions_retains_statement_without_inventing_amounts(monkeypatch: pytest.MonkeyPatch) -> None:
    journey = MagicMock()
    journey.get_result.return_value = result(transactions=[])
    monkeypatch.setattr(analytics, "JourneyService", MagicMock(return_value=journey))
    response = service(record()).export_bank_data(auth(), document_ids=DOC_A)
    rows = list(csv.DictReader(io.StringIO(response.body.decode())))
    assert len(rows) == 1 and rows[0]["documentId"] == DOC_A
    assert rows[0]["amount"] == rows[0]["balanceAfter"] == rows[0]["transactionDate"] == ""


@pytest.mark.parametrize("bound,value", [("MAX_BANK_EXPORT_BYTES", 1), ("MAX_BANK_EXPORT_ROWS", 0)])
def test_export_is_prebuffered_and_bounded(monkeypatch: pytest.MonkeyPatch, bound: str, value: int) -> None:
    journey = MagicMock()
    journey.get_result.return_value = result()
    monkeypatch.setattr(analytics, "JourneyService", MagicMock(return_value=journey))
    monkeypatch.setattr(analytics, bound, value)
    with pytest.raises(AppError) as error:
        service(record()).export_bank_data(auth(), document_ids=DOC_A)
    assert error.value.status_code == 413


def test_export_failure_on_later_result_returns_no_partial_response(monkeypatch: pytest.MonkeyPatch) -> None:
    journey = MagicMock()
    journey.get_result.side_effect = [result(), AppError(code="MALFORMED_INTERNAL_RESULT", message="Invalid result.", status_code=500, details={})]
    monkeypatch.setattr(analytics, "JourneyService", MagicMock(return_value=journey))
    with pytest.raises(AppError) as error:
        service(record(), record(DOC_B)).export_bank_data(auth(), document_ids=f"{DOC_A},{DOC_B}")
    assert error.value.status_code == 500


def test_export_reads_real_canonical_journey_from_synthetic_storage(monkeypatch: pytest.MonkeyPatch) -> None:
    journey, _, _, documents, storage, _ = journey_fixture()
    document_id, _ = _completed_document(journey, documents, storage)
    svc = service()
    svc.repo = documents
    monkeypatch.setattr(analytics, "JourneyService", lambda **kwargs: journey)
    response = svc.export_bank_data(auth(), document_ids=document_id)
    rows = list(csv.DictReader(io.StringIO(response.body.decode())))
    assert rows[0]["documentId"] == document_id
    assert rows[0]["amount"] == "25.0"
    assert "synthetic-model" not in response.body.decode()


def client(actions: tuple[str, ...] = ("read", "admin")) -> tuple[TestClient, MagicMock]:
    app = FastAPI()
    register_exception_handlers(app)
    app.include_router(routes.router, prefix="/api/v1/analytics")
    actor = auth(principal_type="m2m", client_id="synthetic-client", auth_source="m2m_identity_binding_v1", granted_actions=actions)
    app.dependency_overrides[get_auth_context] = lambda: actor
    svc = MagicMock()
    svc.get_bank_documents.return_value = {"documents": [], "nextCursor": None}
    svc.export_bank_data.return_value = analytics.Response("synthetic,csv\n", media_type="text/csv")
    app.dependency_overrides[routes._svc] = lambda: svc
    return TestClient(app), svc


def test_history_route_defaults_and_export_permission_remain_distinct() -> None:
    http, svc = client(("read",))
    response = http.get("/api/v1/analytics/docs?classRoute=bank-extract")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert svc.get_bank_documents.call_args.kwargs["limit"] == 50
    assert http.get(f"/api/v1/analytics/export-bank?documentIds={DOC_A}").status_code == 403
    svc.export_bank_data.assert_not_called()


def test_export_route_authorizes_reviewed_read_admin_operation() -> None:
    http, svc = client()
    response = http.get(f"/api/v1/analytics/export-bank?documentIds={DOC_A}")
    assert response.status_code == 200
    assert svc.export_bank_data.call_args.kwargs["document_ids"] == DOC_A


@pytest.mark.parametrize("query", [
    "limit=0", "limit=101", "limit=1&limit=2", "classRoute=personal", "unknown=value",
    "cursor=v1:invalid", "classRoute=bank-extract&classRoute=bank-extract",
])
def test_history_route_rejects_unknown_duplicate_and_out_of_bounds_query(query: str) -> None:
    http, svc = client()
    assert http.get("/api/v1/analytics/docs?" + query).status_code == 422
    svc.get_bank_documents.assert_not_called()


@pytest.mark.parametrize("query", ["", "documentIds=" + DOC_A + "&documentIds=" + DOC_B, "documentIds=" + DOC_A + "&unknown=value"])
def test_export_route_rejects_missing_duplicate_or_unknown_query(query: str) -> None:
    http, svc = client()
    assert http.get("/api/v1/analytics/export-bank?" + query).status_code == 422
    svc.export_bank_data.assert_not_called()
