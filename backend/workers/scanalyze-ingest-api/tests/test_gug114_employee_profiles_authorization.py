"""Focused GUG-114 authorization tests for Employee Profiles."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from app.auth import AuthContext
from app.authorization import ObjectOwnership
from app.errors import AppError
from app.services.employee_profiles import EmployeeProfileService


CUSTOMER = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW"
FOREIGN_CUSTOMER = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAX"
DEPLOYMENT = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
BATCH_ID = "batch-synthetic-0001"


def _auth() -> AuthContext:
    return AuthContext(
        customer_id=CUSTOMER,
        deployment_id=DEPLOYMENT,
        principal_type="user",
        subject="synthetic-user",
    )


def _batch(customer_id: str = CUSTOMER) -> dict:
    ownership = ObjectOwnership(customer_id, DEPLOYMENT)
    return {
        "batch_id": BATCH_ID,
        "batchId": BATCH_ID,
        "tenantId": customer_id,
        **ownership.record_fields(),
    }


def _document(customer_id: str = CUSTOMER) -> dict:
    ownership = ObjectOwnership(customer_id, DEPLOYMENT)
    return {
        "documentId": "document-synthetic-0001",
        "batchId": BATCH_ID,
        "tenantId": customer_id,
        **ownership.record_fields(),
        "ownership_batch_key": ownership.batch_partition(BATCH_ID),
        "status": "COMPLETED",
    }


def _profile() -> dict:
    ownership = ObjectOwnership(CUSTOMER, DEPLOYMENT)
    return {
        "entityType": "EMPLOYEE_PROFILE",
        "profileId": "profile-synthetic-0001",
        "batchId": BATCH_ID,
        "tenantId": CUSTOMER,
        **ownership.record_fields(),
        "ownership_batch_key": ownership.batch_partition(BATCH_ID),
        "fullName": "Synthetic Person",
        "identifiers": {"curp": "SYNTHETIC"},
    }


def _job(customer_id: str = CUSTOMER) -> dict:
    ownership = ObjectOwnership(customer_id, DEPLOYMENT)
    return {
        "entityType": "EMPLOYEE_PROFILE_GENERATION_JOB",
        "jobId": "job-synthetic-0001",
        "batchId": BATCH_ID,
        "tenantId": customer_id,
        **ownership.record_fields(),
        "ownership_batch_key": ownership.batch_partition(BATCH_ID),
        "status": "COMPLETED",
        "sourceFingerprint": "synthetic-fingerprint",
    }


def _service() -> EmployeeProfileService:
    service = EmployeeProfileService.__new__(EmployeeProfileService)
    service.settings = SimpleNamespace(
        employee_profiles_enabled=True,
        employee_profiles_enabled_tenants="*",
        employee_profiles_max_docs_per_batch=200,
        employee_profiles_mode="sync",
        get_bucket=lambda alias: "synthetic-structured-bucket",
    )
    service.repo = MagicMock()
    service.batches_repo = MagicMock()
    service.documents_service = MagicMock()
    service.s3 = MagicMock()
    service.logger = MagicMock()
    return service


def test_generate_rejects_foreign_batch_before_document_query() -> None:
    service = _service()
    service.batches_repo.get_batch.return_value = _batch(FOREIGN_CUSTOMER)

    with pytest.raises(AppError) as exc_info:
        service.generate_profiles(auth=_auth(), batch_id=BATCH_ID)

    assert exc_info.value.status_code == 404
    assert exc_info.value.message == "Batch not found"
    service.repo.get_documents_by_batch.assert_not_called()
    service.s3.get_object.assert_not_called()


def test_generate_rejects_mixed_ownership_before_s3() -> None:
    service = _service()
    service.batches_repo.get_batch.return_value = _batch()
    service.repo.get_documents_by_batch.return_value = [
        _document(),
        _document(FOREIGN_CUSTOMER),
    ]

    with pytest.raises(AppError) as exc_info:
        service.generate_profiles(auth=_auth(), batch_id=BATCH_ID)

    assert exc_info.value.status_code == 404
    assert exc_info.value.message == "Batch not found"
    ownership = ObjectOwnership(CUSTOMER, DEPLOYMENT)
    service.repo.get_documents_by_batch.assert_called_once_with(
        BATCH_ID,
        ownership=ownership,
    )
    service.repo.get_document.assert_not_called()
    service.s3.get_object.assert_not_called()


def test_empty_generation_persists_dual_bound_job_and_namespace() -> None:
    service = _service()
    service.batches_repo.get_batch.return_value = _batch()
    service.repo.get_documents_by_batch.return_value = []
    service._read_s3_json = MagicMock(return_value=None)
    service._read_s3_json_with_version = MagicMock(return_value=(None, None))
    service._write_s3_json = MagicMock()

    result = service.generate_profiles(auth=_auth(), batch_id=BATCH_ID)

    assert result["status"] == "COMPLETED"
    writes = service._write_s3_json.call_args_list
    assert writes
    job = writes[0].args[2]
    assert job["customer_id"] == CUSTOMER
    assert job["deployment_id"] == DEPLOYMENT
    assert job["ownership_batch_key"] == ObjectOwnership(
        CUSTOMER,
        DEPLOYMENT,
    ).batch_partition(BATCH_ID)
    assert f"customers/{CUSTOMER}/deployments/{DEPLOYMENT}/" in writes[0].args[1]


def test_force_generation_rejects_foreign_existing_job_before_overwrite() -> None:
    service = _service()
    service.batches_repo.get_batch.return_value = _batch()
    service.repo.get_documents_by_batch.return_value = []
    service._read_s3_json = MagicMock(return_value=_job(FOREIGN_CUSTOMER))
    service._write_s3_json = MagicMock()

    with pytest.raises(AppError) as exc_info:
        service.generate_profiles(
            auth=_auth(),
            batch_id=BATCH_ID,
            options={"force": True},
        )

    assert exc_info.value.status_code == 404
    assert exc_info.value.message == "Employee profile job not found"
    service._write_s3_json.assert_not_called()


def test_s3_owned_write_uses_version_precondition() -> None:
    service = _service()
    service._read_s3_json_with_version = MagicMock(
        return_value=(_profile(), '"synthetic-etag"')
    )

    service._write_owned_batch_child(
        auth=_auth(),
        ownership=ObjectOwnership(CUSTOMER, DEPLOYMENT),
        batch_id=BATCH_ID,
        bucket="synthetic-structured-bucket",
        key="synthetic-profile-key",
        record=_profile(),
        object_kind="Employee profile",
        identity_field="profileId",
        identity_value="profile-synthetic-0001",
    )

    kwargs = service.s3.put_object.call_args.kwargs
    assert kwargs["IfMatch"] == '"synthetic-etag"'
    assert "IfNoneMatch" not in kwargs


def test_s3_owned_write_rejects_foreign_existing_record() -> None:
    service = _service()
    foreign = _profile()
    foreign.update(ObjectOwnership(FOREIGN_CUSTOMER, DEPLOYMENT).record_fields())
    foreign["tenantId"] = FOREIGN_CUSTOMER
    foreign["ownership_batch_key"] = ObjectOwnership(
        FOREIGN_CUSTOMER,
        DEPLOYMENT,
    ).batch_partition(BATCH_ID)
    service._read_s3_json_with_version = MagicMock(
        return_value=(foreign, '"synthetic-etag"')
    )

    with pytest.raises(AppError) as exc_info:
        service._write_owned_batch_child(
            auth=_auth(),
            ownership=ObjectOwnership(CUSTOMER, DEPLOYMENT),
            batch_id=BATCH_ID,
            bucket="synthetic-structured-bucket",
            key="synthetic-profile-key",
            record=_profile(),
            object_kind="Employee profile",
            identity_field="profileId",
            identity_value="profile-synthetic-0001",
        )

    assert exc_info.value.status_code == 404
    service.s3.put_object.assert_not_called()


def test_batch_profile_export_rejects_unbound_record_without_post_filtering() -> None:
    service = _service()
    service.batches_repo.get_batch.return_value = _batch()
    service._read_s3_json = MagicMock(return_value=[{"profileId": "legacy-profile"}])

    with pytest.raises(AppError) as exc_info:
        service.get_batch_profiles(auth=_auth(), batch_id=BATCH_ID)

    assert exc_info.value.status_code == 404
    assert exc_info.value.message == "Employee profile not found"


def test_batch_profile_export_returns_exactly_owned_profiles() -> None:
    service = _service()
    service.batches_repo.get_batch.return_value = _batch()
    service._read_s3_json = MagicMock(return_value=[_profile()])

    assert service.get_batch_profiles(auth=_auth(), batch_id=BATCH_ID) == [_profile()]
    requested_key = service._read_s3_json.call_args.args[1]
    assert f"customers/{CUSTOMER}/deployments/{DEPLOYMENT}/" in requested_key
