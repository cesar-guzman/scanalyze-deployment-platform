import pytest
from pydantic import ValidationError
from gov_worker.contracts import GovDocSchema

def test_valid_strict_schema():
    payload = {
        "schema_version": "1.0",
        "prompt_version": "1.0.0",
        "tenant": "gov",
        "documentId": "123",
        "docType": "gov_document",
        "generatedAt": "2026-03-01T12:00:00Z",
        "model": {
            "provider": "bedrock",
            "modelId": "anthropic.claude-3-haiku-20240307-v1:0"
        },
        "document": {},
        "issuer": {},
        "recipient": {},
        "dates": {},
        "amounts": {
            "currency": "MXN",
            "total": 100.50
        },
        "references": [],
        "signatories": []
    }
    
    # Should not raise
    obj = GovDocSchema(**payload)
    assert obj.tenant == "gov"

def test_extra_fields_forbidden():
    payload = {
        "schema_version": "1.0",
        "prompt_version": "1.0.0",
        "tenant": "gov",
        "documentId": "123",
        "docType": "gov_document",
        "generatedAt": "2026-03-01T12:00:00Z",
        "model": {
            "provider": "bedrock",
            "modelId": "anthropic.claude-3-haiku-20240307-v1:0"
        },
        "document": {},
        "issuer": {},
        "recipient": {},
        "dates": {},
        "amounts": {},
        "references": [],
        "signatories": [],
        "extra_field": "should fail"
    }
    
    with pytest.raises(ValidationError):
        GovDocSchema(**payload)

def test_amount_type_coercion():
    payload = {
        "schema_version": "1.0",
        "prompt_version": "1.0.0",
        "tenant": "gov",
        "documentId": "123",
        "docType": "gov_document",
        "generatedAt": "2026-03-01T12:00:00Z",
        "model": {
            "provider": "bedrock",
            "modelId": "anthropic.claude-3-haiku-20240307-v1:0"
        },
        "document": {},
        "issuer": {},
        "recipient": {},
        "dates": {},
        "amounts": {
            "total": "200.5" # string should be coerced to float
        },
        "references": [],
        "signatories": []
    }
    
    obj = GovDocSchema(**payload)
    assert isinstance(obj.amounts.total, float)
    assert obj.amounts.total == 200.5
