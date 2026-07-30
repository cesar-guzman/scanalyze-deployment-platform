import pytest
from pydantic import ValidationError
from ocr_worker.contracts import IngestMessage, OcrPollMessage


CUSTOMER_ID = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW"
DEPLOYMENT_ID = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"


def _ownership(stage: str) -> dict:
    return {
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "ownership_schema_version": 1,
        "pipeline_stage": stage,
    }


def _poll_data() -> dict:
    return {
        "schemaVersion": "scanalyze.ocr-poll.v2",
        **_ownership("ocr"),
        "documentId": "123",
        "textractJobId": "abc",
        "sourceBucket": "raw-bucket",
        "sourceKey": (
            f"customers/{CUSTOMER_ID}/deployments/{DEPLOYMENT_ID}/"
            "documents/123/source.pdf"
        ),
        "documentRoute": "bank",
        "artifactBucket": "art-bucket",
        "artifactKey": (
            f"customers/{CUSTOMER_ID}/deployments/{DEPLOYMENT_ID}/"
            "documents/123/ocr.json"
        ),
        "submittedAt": "2023-01-01T00:00:00Z",
        "_metadata": {"correlationId": "correlation-1", "traceId": "trace-1"},
    }

def test_ocr_poll_message_strict_validation():
    msg = OcrPollMessage(**_poll_data())
    assert msg.documentId == "123"
    assert msg.schemaVersion == "scanalyze.ocr-poll.v2"
    assert msg.customer_id == CUSTOMER_ID
    assert msg.deployment_id == DEPLOYMENT_ID

def test_ocr_poll_message_missing_fields():
    invalid_data = _poll_data()
    invalid_data.pop("deployment_id")
    with pytest.raises(ValidationError):
        OcrPollMessage(**invalid_data)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schemaVersion", "scanalyze.ocr-poll.v1"),
        ("ownership_schema_version", 2),
        ("pipeline_stage", "ingest"),
        ("deployment_id", "deployment-test"),
    ],
)
def test_ocr_poll_rejects_noncanonical_contract(field, value):
    invalid_data = _poll_data()
    invalid_data[field] = value
    with pytest.raises(ValidationError):
        OcrPollMessage(**invalid_data)


def test_ocr_poll_rejects_unknown_fields_and_untrusted_metadata():
    invalid_data = _poll_data()
    invalid_data["tenantId"] = CUSTOMER_ID
    with pytest.raises(ValidationError):
        OcrPollMessage(**invalid_data)

    invalid_metadata = _poll_data()
    invalid_metadata["_metadata"]["uploaderUserId"] = "sensitive-user"
    with pytest.raises(ValidationError):
        OcrPollMessage(**invalid_metadata)


def test_ingest_v2_requires_ownership_stage_and_complete_raw_locator():
    key = (
        f"customers/{CUSTOMER_ID}/deployments/{DEPLOYMENT_ID}/"
        "documents/doc-1/source.pdf"
    )
    msg = IngestMessage(
        schemaVersion="scanalyze.ingest.v2",
        **_ownership("ingest"),
        enqueue_id="enqueue-1",
        documentId="doc-1",
        raw={"bucket": "raw-bucket", "key": key},
        contentType="application/pdf",
        uploadedAt="2023-01-01T00:00:00Z",
    )
    assert msg.raw.bucket == "raw-bucket"
    assert msg.raw.key == key

    for missing in ("customer_id", "deployment_id", "ownership_schema_version", "pipeline_stage"):
        invalid = msg.model_dump(by_alias=True)
        invalid.pop(missing)
        with pytest.raises(ValidationError):
            IngestMessage(**invalid)


def test_ingest_v2_rejects_legacy_s3_alias_and_extra_fields():
    payload = {
        "schemaVersion": "scanalyze.ingest.v2",
        **_ownership("ingest"),
        "documentId": "doc-1",
        "enqueue_id": "enqueue-1",
        "s3": {"bucket": "raw-bucket", "key": "legacy-key"},
    }
    with pytest.raises(ValidationError):
        IngestMessage(**payload)


@pytest.mark.parametrize("document_id", ["../foreign", "nested/document", "doc#other"])
def test_ingest_v2_rejects_document_ids_that_can_escape_the_owned_prefix(document_id):
    payload = {
        "schemaVersion": "scanalyze.ingest.v2",
        **_ownership("ingest"),
        "documentId": document_id,
        "enqueue_id": "enqueue-1",
        "raw": {"bucket": "raw-bucket", "key": "synthetic-key"},
    }
    with pytest.raises(ValidationError):
        IngestMessage(**payload)
