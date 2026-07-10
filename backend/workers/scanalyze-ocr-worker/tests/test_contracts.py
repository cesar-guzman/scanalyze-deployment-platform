import pytest
from pydantic import ValidationError
from ocr_worker.contracts import OcrPollMessage

def test_ocr_poll_message_strict_validation():
    # Test valid creation
    valid_data = {
        "documentId": "123",
        "textractJobId": "abc",
        "sourceBucket": "raw-bucket",
        "sourceKey": "raw-key",
        "serviceTenant": "tenant",
        "documentRoute": "bank",
        "artifactBucket": "art-bucket",
        "artifactKey": "art-key",
        "submittedAt": "2023-01-01T00:00:00Z"
    }
    
    msg = OcrPollMessage(**valid_data)
    assert msg.documentId == "123"
    assert msg.schemaVersion == "scanalyze.ocr-poll.v1"

def test_ocr_poll_message_missing_fields():
    # Missing required field `artifactBucket`
    invalid_data = {
        "documentId": "123",
        "textractJobId": "abc",
        "sourceBucket": "raw-bucket",
        "sourceKey": "raw-key",
        "serviceTenant": "tenant",
        "documentRoute": "bank",
        "artifactKey": "art-key",
        "submittedAt": "2023-01-01T00:00:00Z"
    }
    
    with pytest.raises(ValidationError):
        OcrPollMessage(**invalid_data)
