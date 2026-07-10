import pytest
import pydantic
from bank_worker.contracts import BankExtractMessage, ValidateMessage

def test_bank_extract_message():
    msg = BankExtractMessage(
        documentId="doc-123",
        ocr={"bucket": "b", "key": "k"}
    )
    assert msg.documentId == "doc-123"
    assert msg.schemaVersion == "scanalyze.bank-extract.v1"
    assert msg.ocr.bucket == "b"
    assert msg.ocr.key == "k"
    
def test_bank_extract_message_missing_document_id():
    with pytest.raises(pydantic.ValidationError):
        BankExtractMessage(ocr={"bucket": "b", "key": "k"})
