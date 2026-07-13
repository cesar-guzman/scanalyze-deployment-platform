import copy
import importlib.util
import json
from pathlib import Path
import sys

import jsonschema
import pytest


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schemas/async-message.v2.schema.json").read_text())
VALIDATOR = jsonschema.Draft202012Validator(SCHEMA)

CUSTOMER_ID = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW"
DEPLOYMENT_ID = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV"
DOCUMENT_ID = "doc-gug89-synthetic"
RAW = {"bucket": "synthetic-raw", "key": "owned/source.pdf"}
OCR = {"bucket": "synthetic-ocr", "key": "owned/ocr.json"}
STRUCTURED = {
    "bucket": "synthetic-structured",
    "key": "owned/structured/bank/result.json",
}


def _load_classifier_contracts():
    module_name = "gug89_classifier_contracts"
    module_path = (
        ROOT
        / "backend/workers/scanalyze-classifier-worker/src/classifier_worker/contracts.py"
    )
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _load_personal_contracts():
    module_name = "gug89_personal_contracts"
    module_path = (
        ROOT
        / "backend/workers/scanalyze-personal-worker/src/personal_worker/contracts.py"
    )
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _owner() -> dict:
    return {
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "ownership_schema_version": 1,
    }


@pytest.fixture(
    params=["ingest", "ocr", "classify", "extract", "validate", "persist", "notify"]
)
def valid_message(request) -> dict:
    messages = {
        "ingest": {
            "schemaVersion": "scanalyze.ingest.v2",
            **_owner(),
            "pipeline_stage": "ingest",
            "processing_domain": "bank",
            "enqueue_id": "enqueue-synthetic-1",
            "documentId": DOCUMENT_ID,
            "raw": RAW,
            "contentType": "application/pdf",
            "_metadata": {"correlationId": "correlation-synthetic-1"},
        },
        "ocr": {
            "schemaVersion": "scanalyze.ocr-poll.v2",
            **_owner(),
            "pipeline_stage": "ocr",
            "documentId": DOCUMENT_ID,
            "textractJobId": "textract-synthetic-1",
            "sourceBucket": RAW["bucket"],
            "sourceKey": RAW["key"],
            "documentRoute": "bank",
            "artifactBucket": OCR["bucket"],
            "artifactKey": OCR["key"],
            "submittedAt": "2026-07-12T00:00:00+00:00",
            "attempt": 0,
            "_metadata": {"traceId": "trace-synthetic-1"},
        },
        "classify": {
            "schemaVersion": "scanalyze.classify.v2",
            **_owner(),
            "pipeline_stage": "classify",
            "documentId": DOCUMENT_ID,
            "ocr": OCR,
            "raw": RAW,
            "textract": {
                "jobId": "textract-synthetic-1",
                "api": "StartDocumentTextDetection",
            },
            "meta": {"pages": 1, "env": "test", "tenant": "platform"},
            "_metadata": {"correlationId": "correlation-synthetic-1"},
        },
        "extract": {
            "schemaVersion": "scanalyze.extract.v2",
            **_owner(),
            "pipeline_stage": "bank-extract",
            "processing_domain": "bank",
            "documentId": DOCUMENT_ID,
            "ocr": OCR,
            "raw": RAW,
            "attempt": 0,
            "_metadata": {"correlationId": "correlation-synthetic-1"},
        },
        "validate": {
            "schemaVersion": "scanalyze.validate.v2",
            **_owner(),
            "pipeline_stage": "validate",
            "processing_domain": "bank",
            "documentId": DOCUMENT_ID,
            "structured": STRUCTURED,
            "meta": {
                "env": "test",
                "tenant": "bank",
                "schema_version": "1.0",
                "prompt_version": "synthetic-v1",
            },
        },
        "persist": {
            "schemaVersion": "scanalyze.persist.v2",
            **_owner(),
            "pipeline_stage": "persist",
            "processing_domain": "bank",
            "documentId": DOCUMENT_ID,
            "structured": STRUCTURED,
            "validation": {
                "status": "PASS",
                "errors": [],
                "validatedAt": "2026-07-12T00:01:00+00:00",
            },
            "meta": {
                "env": "test",
                "tenant": "bank",
                "schema_version": "1.0",
                "prompt_version": "synthetic-v1",
            },
        },
        "notify": {
            "schemaVersion": "scanalyze.notify.v2",
            **_owner(),
            "pipeline_stage": "notify",
            "processing_domain": "bank",
            "documentId": DOCUMENT_ID,
            "result": {
                "finalStatus": "COMPLETED",
                "completedAt": "2026-07-12T00:02:00+00:00",
                "validationStatus": "PASS",
            },
            "meta": {"env": "test", "tenant": "bank"},
        },
    }
    return copy.deepcopy(messages[request.param])


def test_every_canonical_message_is_valid(valid_message):
    VALIDATOR.validate(valid_message)


@pytest.mark.parametrize(
    "field", ["customer_id", "deployment_id", "ownership_schema_version"]
)
def test_every_message_requires_complete_ownership(valid_message, field):
    valid_message.pop(field)
    with pytest.raises(jsonschema.ValidationError):
        VALIDATOR.validate(valid_message)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("customer_id", "customer-legacy"),
        ("deployment_id", "deployment-legacy"),
        ("ownership_schema_version", 2),
        ("tenantId", CUSTOMER_ID),
        ("customerStack", "foreign-stack"),
    ],
)
def test_malformed_legacy_and_spoofed_authority_is_rejected(
    valid_message, field, value
):
    valid_message[field] = value
    with pytest.raises(jsonschema.ValidationError):
        VALIDATOR.validate(valid_message)


def test_extract_stage_and_processing_domain_must_match():
    message = {
        "schemaVersion": "scanalyze.extract.v2",
        **_owner(),
        "pipeline_stage": "bank-extract",
        "processing_domain": "personal",
        "documentId": DOCUMENT_ID,
        "ocr": OCR,
        "raw": RAW,
    }
    with pytest.raises(jsonschema.ValidationError):
        VALIDATOR.validate(message)


def test_metadata_cannot_carry_authority():
    message = {
        "schemaVersion": "scanalyze.ingest.v2",
        **_owner(),
        "pipeline_stage": "ingest",
        "enqueue_id": "enqueue-synthetic-1",
        "documentId": DOCUMENT_ID,
        "raw": RAW,
        "_metadata": {
            "correlationId": "correlation-synthetic-1",
            "customer_id": "cust_01BX5ZZKBKACTAV9WEVGEMMVS1",
        },
    }
    with pytest.raises(jsonschema.ValidationError):
        VALIDATOR.validate(message)


def test_schema_declares_exact_canonical_stage_set():
    assert {
        "ingest",
        "ocr",
        "classify",
        "bank-extract",
        "personal-extract",
        "gov-extract",
        "validate",
        "persist",
        "notify",
    } == {
        "ingest",
        SCHEMA["$defs"]["ocr_poll"]["allOf"][1]["properties"]["pipeline_stage"]["const"],
        "classify",
        *SCHEMA["$defs"]["extract"]["allOf"][1]["properties"]["pipeline_stage"]["enum"],
        "validate",
        "persist",
        "notify",
    }


def test_classifier_runtime_models_serialize_to_the_canonical_schema():
    contracts = _load_classifier_contracts()

    classify = contracts.ClassifyMessage(
        schemaVersion="scanalyze.classify.v2",
        **_owner(),
        pipeline_stage="classify",
        processing_domain=None,
        documentId=DOCUMENT_ID,
        ocr=OCR,
        raw=RAW,
        textract={
            "jobId": "textract-synthetic-1",
            "api": "StartDocumentTextDetection",
        },
        meta={"pages": 1, "env": "test", "tenant": "platform"},
    )
    extract = contracts.ExtractMessage(
        schemaVersion="scanalyze.extract.v2",
        **_owner(),
        pipeline_stage="bank-extract",
        processing_domain="bank",
        documentId=DOCUMENT_ID,
        ocr=OCR,
        raw=RAW,
        attempt=0,
    )

    VALIDATOR.validate(classify.model_dump(mode="json"))
    VALIDATOR.validate(extract.model_dump(mode="json"))


def test_personal_extract_runtime_contract_is_closed_to_the_canonical_schema():
    contracts = _load_personal_contracts()
    message = contracts.PersonalExtractMessage(
        schemaVersion="scanalyze.extract.v2",
        **_owner(),
        pipeline_stage="personal-extract",
        processing_domain="personal",
        documentId=DOCUMENT_ID,
        ocr=OCR,
        raw=RAW,
        attempt=0,
    )

    schema_fields = set(SCHEMA["$defs"]["ownership"]["properties"]) | set(
        SCHEMA["$defs"]["extract"]["allOf"][1]["properties"]
    )
    schema_fields.remove("_metadata")

    assert set(contracts.PersonalExtractMessage.model_fields) == schema_fields
    VALIDATOR.validate(message.model_dump(mode="json", exclude_none=True))
