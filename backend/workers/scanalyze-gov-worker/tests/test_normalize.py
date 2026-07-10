import pytest
from gov_worker.normalize import clean_json_string, parse_and_normalize

def test_clean_json_string():
    raw_response = "```json\n{\"test\": 123}\n```"
    cleaned = clean_json_string(raw_response)
    assert cleaned == "{\"test\": 123}"
    
    raw_with_text = "Here is the result:\n```json\n{\"data\": 1}\n```\nHope it helps."
    cleaned_2 = clean_json_string(raw_with_text)
    assert cleaned_2 == "{\"data\": 1}"

def test_parse_and_normalize_valid_minimum():
    raw_bedrock = """{
        "document": {},
        "issuer": {},
        "recipient": {},
        "dates": {},
        "amounts": {
            "currency": "mxn",
            "total": "99.9"
        }
    }"""
    
    res = parse_and_normalize(raw_bedrock, "doc-123", "1.0.0", "model-x")
    
    assert res["schema_version"] == "1.0"
    assert res["tenant"] == "gov"
    assert res["documentId"] == "doc-123"
    assert res["docType"] == "gov_document"
    assert res["amounts"]["currency"] == "MXN" # Uppercased by normalizer logic
    assert res["amounts"]["total"] == 99.9     # Coerced by pydantic
    assert res["references"] == []             # Defaulted by normalizer
    assert res["signatories"] == []            # Defaulted by normalizer
    assert res["model"]["provider"] == "bedrock"

def test_parse_and_normalize_invalid():
    raw_bedrock = "not json"
    with pytest.raises(ValueError):
         parse_and_normalize(raw_bedrock, "doc-123", "1.0.0", "model-x")
         
def test_parse_and_normalize_invalid_json():
    # json-repair will try to fix it, which will lead to a ValueError because it returns a string/list instead of a dict
    with pytest.raises(ValueError, match="dictionary"):
         parse_and_normalize("{bad json", "doc-123", "1.0.0", "model-xxx")
