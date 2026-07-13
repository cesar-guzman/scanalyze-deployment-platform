from __future__ import annotations

import hashlib
import json
import re
import time
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import structlog
from botocore.exceptions import ClientError
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.api.v1.addons import employee_profiles as employee_profile_routes
from app.api.v1.documents import submit_document as submit_document_route
from app.api.v1.models import (
    CreateDocumentRequest,
    DocumentStatusResponse,
    SubmitDocumentRequest,
)
from app.auth import AuthContext
from app.authorization import ObjectOwnership
from app.enterprise_authorization import (
    AUTHORIZATION_CONTEXT_SCHEMA_VERSION,
    AUTHZ_SCHEMA_VERSION,
    MEMBERSHIP_SOURCE,
    POLICY_DIGEST,
    POLICY_VERSION,
    ROLE_CATALOG_VERSION,
    SCOPE_CATALOG_VERSION,
    AuthorizationPath,
    HumanAuthorizationSnapshot,
    HumanRole,
)
from app.errors import AppError
from app.logging import (
    bind_context,
    clear_context,
    opaque_log_reference,
    sanitize_log_identifiers,
)
from app.middleware import RequestContextMiddleware
from app.services.batches import _project_batch_metadata
from app.services.analytics import AnalyticsService
from app.services.documents import DocumentsService
from app.services.employee_profiles import EmployeeProfileService
from app.services.employee_profiles_masking import mask_identifier


CUSTOMER_ID = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW"
DEPLOYMENT_ID = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
BATCH_ID = "batch-synthetic-privacy"
REFERENCE_PATTERN = re.compile(r"^ref_[0-9a-f]{32}$")


def _auth(*, role: HumanRole | None = None) -> AuthContext:
    human_authorization = None
    if role is not None:
        human_authorization = HumanAuthorizationSnapshot(
            schema_version=AUTHORIZATION_CONTEXT_SCHEMA_VERSION,
            authorization_path=AuthorizationPath.MEMBERSHIP,
            authorization_source=MEMBERSHIP_SOURCE,
            subject=f"synthetic-{role.value}",
            customer_id=CUSTOMER_ID,
            deployment_id=DEPLOYMENT_ID,
            membership_state="active",
            role_id=role,
            membership_version="membership-v1",
            temporary_grant_id=None,
            temporary_grant_type=None,
            temporary_grant_state=None,
            temporary_grant_version=None,
            allowed_operation_ids=frozenset(),
            allowed_data_classes=frozenset(),
            expires_at_epoch=None,
            authz_schema_version=AUTHZ_SCHEMA_VERSION,
            scope_catalog_version=SCOPE_CATALOG_VERSION,
            role_catalog_version=ROLE_CATALOG_VERSION,
            policy_version=POLICY_VERSION,
            policy_digest=POLICY_DIGEST,
            issued_at_epoch=int(time.time()),
            assurance=None,
            authenticated_at_epoch=None,
        )
    return AuthContext(
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
        principal_type="user",
        subject=f"synthetic-{role.value if role else 'user'}",
        auth_source="cognito_jwt",
        human_authorization=human_authorization,
    )


def test_document_status_returns_only_allowlisted_stage_metadata() -> None:
    ownership = ObjectOwnership(CUSTOMER_ID, DEPLOYMENT_ID)
    service = DocumentsService.__new__(DocumentsService)
    service.repo = MagicMock()
    service.repo.get_document.return_value = {
        "documentId": "document-synthetic-privacy",
        **ownership.record_fields(),
        "status": "COMPLETED",
        "uploaderUserId": "SYNTHETIC-PRIVATE-UPLOADER",
        "correlationId": "Bearer.SYNTHETIC-PRIVATE-CORRELATION",
        "stages": {
            "ocr": {
                "status": "COMPLETED",
                "startedAt": "2026-07-13T10:00:00+00:00",
                "endedAt": "2026-07-13T10:01:00+00:00",
                "attempt": 2,
                "pagesProcessed": 4,
                "artifactRef": {
                    "bucket": "synthetic-secret-bucket",
                    "key": "customers/private/document.json",
                },
                "prefix": "customers/private/",
                "digest": "synthetic-secret-digest",
                "queueUrl": "https://sqs.invalid/private",
                "messageId": "synthetic-secret-message-id",
                "payload": {"pii": "SYNTHETIC-PRIVATE-PAYLOAD"},
                "error": {"document": "SYNTHETIC-PRIVATE-ERROR"},
                "errorMessage": "SYNTHETIC-PRIVATE-ERROR-MESSAGE",
            },
            "persist": {
                "status": {"key": "synthetic-secret-key"},
                "completedAt": "not-a-timestamp:SYNTHETIC-PRIVATE-VALUE",
                "retryCount": -1,
                "unknown": {"bucket": "synthetic-secret-bucket"},
            },
            "SYNTHETIC_PRIVATE_STAGE": {
                "status": "COMPLETED",
            },
        },
    }

    result = service.get_document_status(
        _auth(),
        "document-synthetic-privacy",
    )

    assert result["stages"] == {
        "ocr": {
            "status": "COMPLETED",
            "startedAt": "2026-07-13T10:00:00+00:00",
            "endedAt": "2026-07-13T10:01:00+00:00",
            "attempt": 2,
            "pagesProcessed": 4,
        },
        "persist": {},
    }
    assert "uploaderUserId" not in result
    assert "correlationId" not in result
    response = DocumentStatusResponse.model_validate(result).model_dump()
    assert response["uploaderUserId"] is None
    assert response["correlationId"] is None
    defensive_response = DocumentStatusResponse.model_validate(
        {
            **result,
            "uploaderUserId": "SYNTHETIC-PRIVATE-UPLOADER",
            "correlationId": "SYNTHETIC-PRIVATE-CORRELATION",
        }
    ).model_dump()
    assert defensive_response["uploaderUserId"] is None
    assert defensive_response["correlationId"] is None
    serialized = json.dumps(result, sort_keys=True)
    for marker in (
        "synthetic-secret",
        "SYNTHETIC-PRIVATE",
        "queueUrl",
        "messageId",
        "artifactRef",
        "payload",
        "errorMessage",
        "SYNTHETIC-PRIVATE-UPLOADER",
        "SYNTHETIC-PRIVATE-CORRELATION",
    ):
        assert marker not in serialized


def _profile_service() -> EmployeeProfileService:
    service = EmployeeProfileService.__new__(EmployeeProfileService)
    service.settings = SimpleNamespace(
        employee_profiles_enabled=True,
        employee_profiles_enabled_tenants="*",
        get_bucket=lambda _alias: "synthetic-structured-bucket",
    )
    service.s3 = MagicMock()
    service.logger = MagicMock()
    service._load_batch_profiles = MagicMock(
        return_value=(
            [
                {
                    "profileId": "profile-synthetic-privacy",
                    "fullName": "SYNTHETIC PRIVATE PERSON",
                    "status": "READY",
                    "maskedIdentifiers": {"employeeId": "***1234"},
                    "sourceDocuments": ["document-synthetic-privacy"],
                    "batchId": BATCH_ID,
                }
            ],
            ObjectOwnership(CUSTOMER_ID, DEPLOYMENT_ID),
        )
    )
    return service


def test_batch_metadata_suppresses_legacy_creator_identity() -> None:
    marker = "SYNTHETIC-PRIVATE-BATCH-CREATOR"

    result = _project_batch_metadata(
        {
            "batchId": BATCH_ID,
            "tenantId": CUSTOMER_ID,
            "createdAt": "2026-07-13T10:00:00+00:00",
            "createdBy": marker,
            "createdByEmail": "private@example.invalid",
            "createdByDisplayName": "SYNTHETIC PRIVATE PERSON",
            "status": "OPEN",
            "metadata": {
                "email": "private@example.invalid",
                "locator": {"bucket": "SYNTHETIC-PRIVATE-BUCKET"},
                "payload": "SYNTHETIC-PRIVATE-PAYLOAD",
            },
        }
    )

    assert result["createdBy"] is None
    assert marker not in json.dumps(result, sort_keys=True)
    assert "createdByEmail" not in result
    assert "createdByDisplayName" not in result
    assert result["metadata"] == {}
    assert "SYNTHETIC-PRIVATE" not in json.dumps(result, sort_keys=True)


def test_profile_job_metadata_uses_closed_non_identifying_projection() -> None:
    service = _profile_service()
    ownership = ObjectOwnership(CUSTOMER_ID, DEPLOYMENT_ID)
    job_id = "job-synthetic-privacy"
    marker = "SYNTHETIC-PRIVATE-JOB-CREATOR"
    service._read_s3_json = MagicMock(
        return_value={
            "jobId": job_id,
            "batchId": BATCH_ID,
            **ownership.record_fields(),
            "ownership_batch_key": ownership.batch_partition(BATCH_ID),
            "status": "COMPLETED",
            "profileCount": 3,
            "createdAt": "2026-07-13T10:00:00+00:00",
            "updatedAt": "2026-07-13T10:01:00+00:00",
            "createdBy": marker,
            "sourceFingerprint": "SYNTHETIC-PRIVATE-FINGERPRINT",
            "errorMessage": "SYNTHETIC-PRIVATE-ERROR",
            "futureField": {"private": "SYNTHETIC-PRIVATE-FUTURE"},
        }
    )
    service._load_batch = MagicMock(return_value=({}, ownership))

    result = service.get_job(_auth(), job_id)

    assert result == {
        "jobId": job_id,
        "batchId": BATCH_ID,
        "status": "COMPLETED",
        "profileCount": 3,
        "createdAt": "2026-07-13T10:00:00+00:00",
        "updatedAt": "2026-07-13T10:01:00+00:00",
        "startedAt": None,
        "completedAt": None,
    }
    serialized = json.dumps(result, sort_keys=True)
    assert marker not in serialized
    assert "SYNTHETIC-PRIVATE" not in serialized


def test_document_create_never_binds_uploader_subject_to_log_context() -> None:
    service = DocumentsService.__new__(DocumentsService)
    service.settings = SimpleNamespace(
        documents_table_name="synthetic-documents",
        get_bucket=lambda _alias: "synthetic-raw-bucket",
        upload_url_ttl_seconds=60,
    )
    service.s3 = MagicMock()
    service.s3.generate_presigned_url.side_effect = ClientError(
        {"Error": {"Code": "SyntheticFailure", "Message": "redacted"}},
        "GeneratePresignedUrl",
    )
    service.logger = MagicMock()
    service.batches_repo = MagicMock()
    marker = "SYNTHETIC-PRIVATE-UPLOADER-SUBJECT"

    clear_context()
    try:
        with pytest.raises(AppError):
            service.create_document(
                auth=_auth(),
                subject=marker,
                email=None,
                name=None,
                filename="synthetic.pdf",
                content_type="application/pdf",
            )
        evidence = json.dumps(structlog.contextvars.get_contextvars())
        assert marker not in evidence
        assert "uploaderUserId" not in evidence
    finally:
        clear_context()


def test_submit_route_never_binds_request_stage_to_log_context() -> None:
    marker = "synthetic-private-stage"
    service = MagicMock()
    service.submit_document.side_effect = AppError(
        code="INVALID_STAGE",
        message="Requested stage is not available",
        status_code=400,
        details={},
    )

    clear_context()
    try:
        with pytest.raises(AppError):
            submit_document_route(
                req=SubmitDocumentRequest(stage=marker),
                auth=_auth(),
                svc=service,
                document_id="document-synthetic-privacy",
            )
        evidence = json.dumps(structlog.contextvars.get_contextvars())
        assert marker not in evidence
        assert "stage" not in structlog.contextvars.get_contextvars()
    finally:
        clear_context()


@pytest.mark.parametrize(
    "role",
    [HumanRole.DOCUMENT_OPERATOR, HumanRole.DOCUMENT_REVIEWER],
)
def test_masked_profile_list_redacts_name_for_non_admin_roles(
    role: HumanRole,
) -> None:
    service = _profile_service()

    result = service.list_profiles(
        auth=_auth(role=role),
        batch_id=BATCH_ID,
    )

    assert result["profiles"][0]["fullName"] == "[REDACTED]"
    assert "SYNTHETIC PRIVATE PERSON" not in json.dumps(result)


def test_masked_profile_list_rebuilds_a_closed_projection_from_raw_values() -> None:
    raw_curp = "synthetic-curp-value"
    raw_rfc = "synthetic-rfc-value"
    marker = "SYNTHETIC-PRIVATE-STORED-MASK"
    service = _profile_service()
    service._load_batch_profiles.return_value = (
        [
            {
                "profileId": "profile-synthetic-privacy",
                "batchId": BATCH_ID,
                "fullName": "SYNTHETIC PRIVATE PERSON",
                "status": {"payload": marker},
                "completenessScore": {"payload": marker},
                "generatedAt": marker,
                "identifiers": {
                    "curp": raw_curp,
                    "rfc": raw_rfc,
                    "future": {"pii": marker},
                },
                "maskedIdentifiers": {
                    "curp": raw_curp,
                    "future": {"pii": marker},
                },
                "sourceDocuments": ["document-synthetic"],
                "warnings": [{"payload": marker}],
                "missingFields": [{"payload": marker}],
                "futureField": {"payload": marker},
            }
        ],
        ObjectOwnership(CUSTOMER_ID, DEPLOYMENT_ID),
    )

    result = service.list_profiles(auth=_auth(), batch_id=BATCH_ID)
    profile = result["profiles"][0]

    assert profile["identifiers"] == {
        "curp": mask_identifier(raw_curp, "curp"),
        "rfc": mask_identifier(raw_rfc, "rfc"),
    }
    assert profile["maskedIdentifiers"] == profile["identifiers"]
    assert profile["status"] is None
    assert profile["completenessScore"] is None
    assert profile["generatedAt"] is None
    serialized = json.dumps(profile, sort_keys=True)
    assert marker not in serialized
    assert raw_curp not in serialized
    assert raw_rfc not in serialized
    assert "future" not in serialized


@pytest.mark.parametrize(
    "options",
    [
        {"force": {"pii": "SYNTHETIC-PRIVATE-OPTION"}},
        {"force": "true"},
        {"includeIncomplete": 1},
        {"futureOption": False},
    ],
)
def test_profile_generation_options_are_strict_and_closed(options: object) -> None:
    with pytest.raises(ValidationError):
        employee_profile_routes.GenerateProfilesRequest.model_validate(
            {"batchId": BATCH_ID, "options": options}
        )

    service = _profile_service()
    service._load_batch = MagicMock()
    with pytest.raises(AppError) as captured:
        service.generate_profiles(
            auth=_auth(),
            batch_id=BATCH_ID,
            options=options,  # type: ignore[arg-type]
        )
    assert captured.value.status_code == 400
    service._load_batch.assert_not_called()
    service.logger.info.assert_not_called()


def _poisoned_profile() -> dict[str, object]:
    return {
        "profileId": "profile-synthetic-privacy",
        "batchId": BATCH_ID,
        "fullName": "SYNTHETIC PRIVATE FULL NAME",
        "firstNames": "SYNTHETIC PRIVATE FIRST NAMES",
        "lastNames": "SYNTHETIC PRIVATE LAST NAMES",
        "birthDate": "SYNTHETIC-PRIVATE-BIRTH-DATE",
        "address": "SYNTHETIC PRIVATE ADDRESS",
        "sex": "SYNTHETIC-PRIVATE-SEX",
        "nationality": "SYNTHETIC-PRIVATE-NATIONALITY",
        "identifiers": {
            "curp": "synthetic-curp-value",
            "rfc": "synthetic-rfc-value",
            "future": {"pii": "SYNTHETIC-PRIVATE-NESTED"},
        },
        "maskedIdentifiers": {
            "curp": "synthetic-curp-value",
            "future": {"pii": "SYNTHETIC-PRIVATE-NESTED"},
        },
        "status": "COMPLETE",
        "completenessScore": 0.8,
        "sourceDocuments": [{"payload": "SYNTHETIC-PRIVATE-SOURCE"}],
        "missingFields": [{"payload": "SYNTHETIC-PRIVATE-MISSING"}],
        "warnings": [{"payload": "SYNTHETIC-PRIVATE-WARNING"}],
        "generatedAt": "2026-07-13T10:00:00+00:00",
        "futureField": {"pii": "SYNTHETIC-PRIVATE-FUTURE"},
    }


def test_all_masked_profile_exports_use_the_same_closed_projection() -> None:
    profile = _poisoned_profile()
    service = MagicMock()
    service.get_batch_profiles.return_value = [profile]
    service.get_profile.return_value = profile

    responses = [
        employee_profile_routes.export_csv_batch(
            batchId=BATCH_ID,
            masked=True,
            auth=_auth(),
            svc=service,
        ),
        employee_profile_routes.export_json(
            profile_id="profile-synthetic-privacy",
            batchId=BATCH_ID,
            masked=True,
            auth=_auth(),
            svc=service,
        ),
        employee_profile_routes.export_csv_individual(
            profile_id="profile-synthetic-privacy",
            batchId=BATCH_ID,
            masked=True,
            auth=_auth(),
            svc=service,
        ),
    ]

    for response in responses:
        serialized = response.body.decode("utf-8")
        assert "SYNTHETIC PRIVATE" not in serialized
        assert "SYNTHETIC-PRIVATE" not in serialized
        assert "synthetic-curp-value" not in serialized
        assert "synthetic-rfc-value" not in serialized
    assert json.loads(responses[1].body)["fullName"] == "[REDACTED]"


@pytest.mark.parametrize(
    "content_type",
    [
        "SYNTHETIC PRIVATE PERSON",
        "application/synthetic-private-person",
        "APPLICATION/PDF",
        "text/plain",
        "application/pdf; charset=utf-8",
    ],
)
def test_document_create_rejects_unreviewed_content_types(
    content_type: str,
) -> None:
    with pytest.raises(ValidationError):
        CreateDocumentRequest(contentType=content_type)


def test_legacy_content_type_is_normalized_before_aggregate_responses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = "SYNTHETIC PRIVATE PERSON"
    document = {
        "status": "COMPLETED",
        "pagesScanned": 2,
        "createdAt": "2026-07-13T10:00:00+00:00",
        "input": {"contentType": marker},
    }
    service = AnalyticsService.__new__(AnalyticsService)
    service.logger = MagicMock()
    service._owned_documents = MagicMock(return_value=[document])

    by_type = service.get_by_doc_type(_auth())
    assert by_type == [
        {"docType": "Unknown", "pagesScanned": 2, "documentsCount": 1}
    ]

    monkeypatch.setenv("SCANALYZE_ENV", "synthetic")
    ssm = MagicMock()
    ssm.get_parameter.side_effect = RuntimeError("synthetic unavailable")
    monkeypatch.setattr("app.services.analytics.boto3.client", lambda *_args: ssm)
    costs = service.get_costs_dashboard(_auth())
    assert costs["cost_by_doc_type"][0]["document_type"] == "Unknown"
    assert marker not in json.dumps({"byType": by_type, "costs": costs})


@pytest.mark.parametrize(
    "role",
    [HumanRole.DOCUMENT_OPERATOR, HumanRole.DOCUMENT_REVIEWER],
)
@pytest.mark.parametrize("query", ["SYNTHETIC PRIVATE", "", "   "])
def test_profile_name_search_is_rejected_before_any_profile_lookup(
    role: HumanRole,
    query: str,
) -> None:
    service = _profile_service()

    with pytest.raises(AppError) as exc_info:
        service.list_profiles(
            auth=_auth(role=role),
            batch_id=BATCH_ID,
            q=query,
        )

    assert exc_info.value.status_code == 400
    assert exc_info.value.code == "UNSUPPORTED_FILTER"
    assert exc_info.value.details == {}
    if query:
        assert query not in exc_info.value.message
    service._load_batch_profiles.assert_not_called()
    service.s3.list_objects_v2.assert_not_called()
    service.s3.get_object.assert_not_called()


class _ContextCapturingLogger:
    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []

    def info(self, event: str, **kwargs: object) -> None:
        self.events.append(
            {
                **structlog.contextvars.get_contextvars(),
                **kwargs,
                "event": event,
            }
        )


def _middleware_client(monkeypatch: pytest.MonkeyPatch):
    logger = _ContextCapturingLogger()
    monkeypatch.setattr("app.middleware.get_logger", lambda: logger)
    app = FastAPI()
    app.add_middleware(RequestContextMiddleware)

    @app.get("/context")
    def get_context() -> dict[str, object]:
        return structlog.contextvars.get_contextvars()

    @app.get("/documents/{document_id}")
    def get_document(document_id: str) -> dict[str, str]:
        return {"documentId": document_id}

    return TestClient(app), logger


def test_request_context_hashes_external_correlation_headers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, logger = _middleware_client(monkeypatch)
    raw_headers = {
        "x-request-id": "Bearer.SYNTHETIC-TOKEN-LIKE-REQUEST",
        "x-correlation-id": "Synthetic Person <pii@example.invalid>",
        "traceparent": "SYNTHETIC-TRACE-PRIVATE-MARKER",
    }

    response = client.get("/context", headers=raw_headers)

    assert response.status_code == 200
    expected = {
        header: "ref_" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]
        for header, value in raw_headers.items()
    }
    assert response.headers["x-request-id"] == expected["x-request-id"]
    assert response.headers["x-correlation-id"] == expected["x-correlation-id"]
    assert response.headers["x-trace-id"] == expected["traceparent"]
    assert response.json() == {
        "requestId": expected["x-request-id"],
        "correlationId": expected["x-correlation-id"],
        "traceId": expected["traceparent"],
    }

    evidence = json.dumps(
        {"response": dict(response.headers), "logs": logger.events},
        sort_keys=True,
    )
    assert all(raw not in evidence for raw in raw_headers.values())
    assert all(REFERENCE_PATTERN.fullmatch(value) for value in expected.values())


def test_request_context_generates_opaque_references_when_headers_are_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, logger = _middleware_client(monkeypatch)

    response = client.get("/context")

    assert response.status_code == 200
    references = {
        response.headers["x-request-id"],
        response.headers["x-correlation-id"],
        response.headers["x-trace-id"],
    }
    assert len(references) == 3
    assert all(REFERENCE_PATTERN.fullmatch(value) for value in references)
    assert logger.events


def test_request_logging_uses_route_template_not_dynamic_object_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, logger = _middleware_client(monkeypatch)
    object_id = "document-SYNTHETIC-PRIVATE-123"

    response = client.get(f"/documents/{object_id}")

    assert response.status_code == 200
    evidence = json.dumps(logger.events, sort_keys=True)
    assert object_id not in evidence
    assert any(
        event.get("route") == "/documents/{document_id}"
        for event in logger.events
    )


def test_context_and_direct_log_identifiers_are_always_pseudonymized() -> None:
    values = {
        "documentId": "document-SYNTHETIC-PRIVATE-123",
        "batchId": "batch-SYNTHETIC-PRIVATE-123",
        "jobId": "job-SYNTHETIC-PRIVATE-123",
        "tenant": CUSTOMER_ID,
    }
    clear_context()
    try:
        bind_context(
            documentId=values["documentId"],
            batchId=values["batchId"],
            tenant=values["tenant"],
        )
        context = dict(structlog.contextvars.get_contextvars())
    finally:
        clear_context()

    assert context == {
        "documentId": opaque_log_reference(values["documentId"]),
        "batchId": opaque_log_reference(values["batchId"]),
        "tenant": opaque_log_reference(values["tenant"]),
    }

    direct_event = sanitize_log_identifiers(
        None,
        "info",
        {**values, "event": "synthetic_event"},
    )
    for field, raw_value in values.items():
        assert direct_event[field] == opaque_log_reference(raw_value)
        assert raw_value not in json.dumps(direct_event, sort_keys=True)
