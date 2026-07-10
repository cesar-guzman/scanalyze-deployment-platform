from src.postprocess_worker.validators.generic import GenericValidator

def test_generic_validator_valid():
    validator = GenericValidator()
    payload = {
        "documentId": "123",
        "docType": "invoice",
        "schema_version": "1.0"
    }
    result = validator.validate("123", payload)
    assert result.status == "PASS"
    assert len(result.errors) == 0

def test_generic_validator_missing_fields():
    validator = GenericValidator()
    payload = {
        "documentId": "123",
    }
    result = validator.validate("123", payload)
    assert result.status == "FAIL"
    assert len(result.errors) == 2
    error_codes = [e.code for e in result.errors]
    assert "MISSING_FIELD" in error_codes

def test_generic_validator_id_mismatch():
    validator = GenericValidator()
    payload = {
        "documentId": "456",
        "docType": "invoice",
        "schema_version": "1.0"
    }
    result = validator.validate("123", payload)
    assert result.status == "FAIL"
    error_codes = [e.code for e in result.errors]
    assert "ID_MISMATCH" in error_codes


def test_generic_validator_rejects_present_but_degraded_required_fields():
    validator = GenericValidator()
    payload = {
        "documentId": None,
        "docType": " ",
        "schema_version": None,
    }

    result = validator.validate("123", payload)

    assert result.status == "FAIL"
    assert {error.path for error in result.errors} == {
        "documentId",
        "docType",
        "schema_version",
    }
