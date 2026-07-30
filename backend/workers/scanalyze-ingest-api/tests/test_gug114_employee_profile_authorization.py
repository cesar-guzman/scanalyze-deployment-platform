"""GUG-114 employee-profile object and full-PII authorization tests."""
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
BATCH = "batch-synthetic-0001"


def _auth(*actions: str, principal_type: str = "user") -> AuthContext:
    return AuthContext(
        customer_id=CUSTOMER,
        deployment_id=DEPLOYMENT,
        principal_type=principal_type,  # type: ignore[arg-type]
        subject="synthetic-principal",
        client_id="synthetic-client" if principal_type == "m2m" else None,
        granted_actions=actions,
        auth_source=(
            "m2m_identity_binding_v1" if principal_type == "m2m" else "cognito_jwt"
        ),
    )


def _batch(customer: str = CUSTOMER) -> dict:
    ownership = ObjectOwnership(customer, DEPLOYMENT)
    return {
        "batchId": BATCH,
        "batch_id": BATCH,
        "tenantId": customer,
        **ownership.record_fields(),
    }


def _profile(customer: str = CUSTOMER) -> dict:
    ownership = ObjectOwnership(customer, DEPLOYMENT)
    return {
        "profileId": "profile-synthetic-0001",
        "batchId": BATCH,
        "tenantId": customer,
        **ownership.record_fields(),
        "ownership_batch_key": ownership.batch_partition(BATCH),
        "identifiers": {"curp": "synthetic-redacted"},
    }


def _service(batch: dict) -> EmployeeProfileService:
    service = EmployeeProfileService.__new__(EmployeeProfileService)
    service.settings = SimpleNamespace(
        employee_profiles_enabled=True,
        employee_profiles_enabled_tenants="*",
        get_bucket=lambda alias: "synthetic-structured-bucket",
    )
    service.batches_repo = MagicMock()
    service.batches_repo.get_batch.return_value = batch
    service.repo = MagicMock()
    service.documents_service = MagicMock()
    service.s3 = MagicMock()
    service.logger = MagicMock()
    return service


def test_profile_s3_namespace_binds_customer_and_deployment() -> None:
    service = _service(_batch())
    ownership = ObjectOwnership.from_auth(_auth())

    prefix = service._profiles_prefix(ownership)

    assert f"customers/{CUSTOMER}/" in prefix
    assert f"deployments/{DEPLOYMENT}/" in prefix


def test_full_pii_batch_export_rejects_foreign_batch_before_s3() -> None:
    service = _service(_batch(FOREIGN_CUSTOMER))

    with pytest.raises(AppError) as exc_info:
        service.get_batch_profiles(auth=_auth(), batch_id=BATCH)

    assert exc_info.value.status_code == 404
    service.s3.get_object.assert_not_called()


def test_full_pii_batch_export_rejects_mixed_profile_ownership() -> None:
    service = _service(_batch())
    service._read_s3_json = MagicMock(return_value=[_profile(), _profile(FOREIGN_CUSTOMER)])

    with pytest.raises(AppError) as exc_info:
        service.get_batch_profiles(auth=_auth(), batch_id=BATCH)

    assert exc_info.value.status_code == 404


def test_read_only_m2m_cannot_export_full_pii_profiles() -> None:
    service = _service(_batch())

    with pytest.raises(AppError) as exc_info:
        service.get_batch_profiles(
            auth=_auth("read", principal_type="m2m"),
            batch_id=BATCH,
        )

    assert exc_info.value.status_code == 403
    service.s3.get_object.assert_not_called()
