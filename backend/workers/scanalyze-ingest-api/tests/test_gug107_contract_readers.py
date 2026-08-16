"""Contract-reader coverage for employee-profile structured artifacts."""

from unittest.mock import MagicMock

import pytest

from app.authorization import ObjectOwnership
from app.services.employee_profiles import EmployeeProfileService


DOCUMENT_ID = "synthetic-document-107"
OWNERSHIP = ObjectOwnership(
    customer_id="cust_01ARZ3NDEKTSV4RRFFQ69G5FAW",
    deployment_id="dep_01ARZ3NDEKTSV4RRFFQ69G5FAV",
)
PAYLOAD = {
    "documentType": "synthetic",
    "person": {"fullName": "Synthetic Employee"},
}


@pytest.mark.parametrize(
    ("document", "bucket", "key"),
    [
        pytest.param(
            {
                "documentId": DOCUMENT_ID,
                "stages": {
                    "persist": {
                        "artifactRef": {
                            "bucket": "synthetic-persist-bucket",
                            "key": "structured/persist.json",
                        }
                    }
                },
            },
            "synthetic-persist-bucket",
            "structured/persist.json",
            id="stages-persist-artifact-ref",
        ),
        pytest.param(
            {
                "documentId": DOCUMENT_ID,
                "artifacts": {
                    "structured": {
                        "bucket": "synthetic-structured-bucket",
                        "key": "structured/artifact.json",
                    }
                },
            },
            "synthetic-structured-bucket",
            "structured/artifact.json",
            id="artifacts-structured",
        ),
        pytest.param(
            {
                "documentId": DOCUMENT_ID,
                "artifacts": {
                    "result": {
                        "bucket": "synthetic-result-bucket",
                        "key": "structured/result.json",
                    }
                },
            },
            "synthetic-result-bucket",
            "structured/result.json",
            id="artifacts-result",
        ),
        pytest.param(
            {
                "documentId": DOCUMENT_ID,
                "structured": {
                    "bucket": "synthetic-top-level-bucket",
                    "key": "structured/top-level.json",
                },
            },
            "synthetic-top-level-bucket",
            "structured/top-level.json",
            id="top-level-structured",
        ),
    ],
)
def test_load_structured_artifact_reads_each_contract_locator(
    document: dict[str, object],
    bucket: str,
    key: str,
) -> None:
    service = EmployeeProfileService.__new__(EmployeeProfileService)
    service.documents_service = MagicMock()
    service.documents_service._validate_artifact_locator.return_value = (bucket, key)
    service._read_s3_json = MagicMock(return_value=PAYLOAD)

    result = service._load_structured_artifact(document, OWNERSHIP)

    assert result == PAYLOAD
    service.documents_service._validate_artifact_locator.assert_called_once_with(
        OWNERSHIP,
        DOCUMENT_ID,
        bucket,
        key,
    )
    service._read_s3_json.assert_called_once_with(bucket, key)
