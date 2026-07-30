import pytest
import pydantic
from bank_worker.contracts import BankExtractMessage, ValidateMessage

CUSTOMER_ID = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAV"
DEPLOYMENT_ID = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAW"

def test_bank_extract_message():
    msg = BankExtractMessage(
        schemaVersion="scanalyze.extract.v2",
        documentId="doc-123",
        customer_id=CUSTOMER_ID,
        deployment_id=DEPLOYMENT_ID,
        ownership_schema_version=1,
        pipeline_stage="bank-extract",
        processing_domain="bank",
        raw={"bucket": "raw", "key": "raw-key"},
        ocr={"bucket": "b", "key": "k"},
    )
    assert msg.documentId == "doc-123"
    assert msg.schemaVersion == "scanalyze.extract.v2"
    assert msg.ocr.bucket == "b"
    assert msg.ocr.key == "k"
    
def test_bank_extract_message_missing_document_id():
    with pytest.raises(pydantic.ValidationError):
        BankExtractMessage(ocr={"bucket": "b", "key": "k"})
