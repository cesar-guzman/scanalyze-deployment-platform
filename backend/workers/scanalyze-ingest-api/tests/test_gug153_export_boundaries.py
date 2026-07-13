from __future__ import annotations

import asyncio
import csv
import io
import json
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from app.services.analytics import AnalyticsService
from app.services.batches import BatchesService
from app.services.employee_profiles_export import export_profiles_csv


BATCH_ID = "batch-synthetic-export"
DOCUMENT_ID = "document-synthetic-export"
ORDINARY_QUOTED_VALUE = 'synthetic, "quoted" value'


async def _consume_stream(response: object) -> str:
    chunks: list[str] = []
    async for chunk in response.body_iterator:  # type: ignore[attr-defined]
        chunks.append(chunk.decode("utf-8") if isinstance(chunk, bytes) else chunk)
    return "".join(chunks)


def _csv_rows(value: str) -> list[list[str]]:
    return list(csv.reader(io.StringIO(value)))


def _batch_manifest(error_message: str) -> dict[str, object]:
    return {
        "manifestVersion": "1.0",
        "batchId": BATCH_ID,
        "generatedAt": "2026-07-13T10:00:00+00:00",
        "summary": {"total": 1, "completed": 0, "failed": 1, "pending": 0},
        "documents": [
            {
                "batchId": BATCH_ID,
                "documentId": DOCUMENT_ID,
                "docType": ORDINARY_QUOTED_VALUE,
                "status": "FAILED",
                "generatedAt": "2026-07-13T10:00:00+00:00",
                "artifactReferences": [],
                "errorCode": "synthetic_error",
                "errorMessage": error_message,
            }
        ],
    }


def _batch_service(manifest: dict[str, object]) -> BatchesService:
    service = BatchesService.__new__(BatchesService)
    service._build_manifest = MagicMock(return_value=(manifest, {}))
    service.logger = MagicMock()
    return service


def test_employee_profile_csv_neutralizes_formula_cell_and_preserves_quoting() -> None:
    dangerous_value = "=synthetic_employee_formula"
    result = export_profiles_csv(
        [
            {
                "profileId": "profile-synthetic-export",
                "fullName": dangerous_value,
                "firstNames": ORDINARY_QUOTED_VALUE,
                "lastNames": "synthetic-last-names",
                "birthDate": "",
                "sex": "",
                "nationality": "",
                "address": "",
                "identifiers": {},
                "status": "synthetic-status",
                "completenessScore": 0,
                "sourceDocuments": [],
                "missingFields": [],
                "warnings": [],
                "generatedAt": "2026-07-13T10:00:00+00:00",
            }
        ]
    )

    rows = _csv_rows(result)
    columns = rows[0]
    assert rows[1][columns.index("fullName")] == f"'{dangerous_value}"
    assert rows[1][columns.index("firstNames")] == ORDINARY_QUOTED_VALUE


def test_batch_stream_csv_neutralizes_formula_after_leading_spaces() -> None:
    dangerous_value = "  +synthetic_batch_stream_formula"
    service = _batch_service(_batch_manifest(dangerous_value))

    response = service.export_csv(SimpleNamespace(customer_id="customer-synthetic"), BATCH_ID)
    rows = _csv_rows(asyncio.run(_consume_stream(response)))
    columns = rows[0]

    assert rows[1][columns.index("errorMessage")] == f"'{dangerous_value}"
    assert rows[1][columns.index("docType")] == ORDINARY_QUOTED_VALUE


def test_batch_zip_csv_neutralizes_formula_after_leading_control_character() -> None:
    dangerous_value = "\t-synthetic_batch_zip_formula"
    service = _batch_service(_batch_manifest(dangerous_value))

    response = service.export_zip(SimpleNamespace(customer_id="customer-synthetic"), BATCH_ID)
    archive_path = Path(response.path)
    try:
        with zipfile.ZipFile(archive_path) as archive:
            rows = _csv_rows(archive.read("summary.csv").decode("utf-8"))
    finally:
        archive_path.unlink(missing_ok=True)
    columns = rows[0]

    assert rows[1][columns.index("errorMessage")] == f"'{dangerous_value}"
    assert rows[1][columns.index("docType")] == ORDINARY_QUOTED_VALUE


def test_analytics_csv_neutralizes_formula_after_leading_control_character(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dangerous_value = "\x00@synthetic_analytics_formula"
    service = AnalyticsService.__new__(AnalyticsService)
    service.logger = MagicMock()
    service._owned_documents = MagicMock(
        return_value=[
            {
                "documentId": DOCUMENT_ID,
                "status": "COMPLETED",
                "createdAt": "2026-07-13T10:00:00+00:00",
                "uploaderUserId": ORDINARY_QUOTED_VALUE,
            }
        ]
    )
    service.document_service = MagicMock()
    service.document_service.get_trusted_artifact_locator.return_value = (
        "synthetic-bucket",
        "synthetic-key",
        "final",
    )
    s3 = MagicMock()
    s3.get_object.return_value = {
        "Body": io.BytesIO(
            json.dumps(
                {
                    "docType": "personal_doc",
                    "subType": "synthetic-subtype",
                    "person": {"fullName": dangerous_value, "dob": ""},
                    "identifiers": {},
                    "overallConfidence": 0,
                }
            ).encode("utf-8")
        )
    }
    monkeypatch.setattr("app.services.analytics.s3_client", lambda: s3)

    response = service.export_ine_data(
        SimpleNamespace(customer_id="customer-synthetic")
    )
    rows = _csv_rows(asyncio.run(_consume_stream(response)))
    columns = rows[0]

    assert rows[1][columns.index("fullName")] == f"'{dangerous_value}"
    assert rows[1][columns.index("uploaderUserId")] == ORDINARY_QUOTED_VALUE


def test_batch_document_listing_closes_legacy_poisoned_content_type() -> None:
    dangerous_value = "=synthetic_legacy_content_type"
    service = BatchesService.__new__(BatchesService)
    service._load_batch = MagicMock(return_value=({"batchId": BATCH_ID}, object()))
    service._load_batch_documents = MagicMock(
        return_value=[
            {
                "documentId": DOCUMENT_ID,
                "status": "COMPLETED",
                "createdAt": "2026-07-13T10:00:00+00:00",
                "input": {
                    "filename": "synthetic.pdf",
                    "contentType": dangerous_value,
                },
            }
        ]
    )

    result = service.get_batch_documents(
        SimpleNamespace(customer_id="customer-synthetic"), BATCH_ID
    )

    assert result[0]["input"]["contentType"] == "Unknown"
    assert dangerous_value not in json.dumps(result, sort_keys=True)
