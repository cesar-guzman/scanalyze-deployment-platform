import json
import logging

import pytest
from personal_worker.normalize import (
    clean_json_string,
    parse_and_normalize,
    validate_curp_format,
    detect_mrz_in_curp,
    cross_validate_curp_dob,
    cross_validate_curp_name,
    fix_mrz_in_curp,
    _is_valid_curp_format,
    _validate_curp_vs_clave_elector,
    validate_nss_format,
    _validate_payroll_employer_guards,
    _normalize_contact,
)

def test_clean_json_string():
    raw_bedrock = "```json\n{\n  \"schema_version\": \"1.0\"\n}\n```"
    cleaned = clean_json_string(raw_bedrock)
    assert cleaned == "{\n  \"schema_version\": \"1.0\"\n}"
    
    dirty = "Aquí tienes la extracción en JSON:\n\n```\n{\"a\": 1}\n```\n\nEspero te sirva."
    cleaned_dirty = clean_json_string(dirty)
    assert cleaned_dirty == "{\"a\": 1}"

def test_parse_and_normalize_success():
    raw_json = """{
        "subType": "ine_mx",
        "person": {"fullName": "LOPEZ ORTEGA SERGIO", "dob": "1979-09-18"},
        "document": {"numberMasked": "XXXX1234"},
        "identifiers": {"curp": "LOOS790918HDFPRR03"},
        "overallConfidence": 95.0
    }"""
    
    result = parse_and_normalize(raw_json, "doc-123", "1.3.0", "model-xxx")
    
    assert result["docType"] == "personal_doc"
    assert result["tenant"] == "personal"
    assert result["documentId"] == "doc-123"
    assert result["subType"] == "ine_mx"
    assert result["model"]["modelId"] == "model-xxx"
    assert result["person"]["fullName"] == "LOPEZ ORTEGA SERGIO"
    assert result["document"]["numberMasked"] == "XXXX1234"
    assert result["identifiers"]["curp"] == "LOOS790918HDFPRR03"
    # fieldConfidence should now be present
    assert result["fieldConfidence"] is not None
    assert result["fieldConfidence"]["curp"]["valid"] is True
    # Confidence should remain high for a valid extraction
    assert result["overallConfidence"] >= 85.0

def test_parse_and_normalize_invalid_json():
    # json-repair may either fail to parse (ValueError "dictionary") or repair it
    # to a partial dict that fails Pydantic validation (ValueError "Schema violation").
    # Either way it should raise ValueError.
    with pytest.raises(ValueError):
         parse_and_normalize("{bad json", "doc-123", "1.3.0", "model-xxx")
         
def test_parse_and_normalize_schema_violation_wrong_subtype():
    raw_json = """{
        "subType": "wrong_subtype",
        "person": {},
        "document": {},
        "identifiers": {}
    }"""
    
    with pytest.raises(ValueError, match="Schema violation"):
         parse_and_normalize(raw_json, "doc-123", "1.3.0", "model-xxx")


def test_schema_violation_does_not_log_input(caplog):
    sensitive_value = "SYNTHETIC-SENSITIVE-VALUE"
    raw_json = json.dumps({
        "subType": sensitive_value,
        "person": {},
        "document": {},
        "identifiers": {},
    })

    with caplog.at_level(logging.DEBUG), pytest.raises(ValueError, match="Schema violation"):
        parse_and_normalize(raw_json, "doc-security", "1.3.0", "model-xxx")

    assert sensitive_value not in caplog.text

def test_parse_and_normalize_extra_fields_ignored():
    """Extra fields should now be silently ignored (extra='ignore')."""
    raw_json = """{
        "subType": "ine_mx",
        "person": {"fullName": "GARCIA MARTINEZ DAVID", "dob": "1988-09-03"},
        "document": {},
        "identifiers": {"curp": "GAMD880903HDFRRV08"},
        "extra_invented_field": "fake data"
    }"""
    
    # Should NOT raise — extra fields are ignored now
    result = parse_and_normalize(raw_json, "doc-123", "1.3.0", "model-xxx")
    assert result["documentId"] == "doc-123"
    assert "extra_invented_field" not in result

# --- CURP validation ---

def test_validate_curp_format_valid():
    valid, issue = validate_curp_format("LOOS790918HDFPRR03")
    assert valid is True
    assert issue is None

def test_validate_curp_format_invalid():
    valid, issue = validate_curp_format("INEE007087Cld.G")
    assert valid is False

def test_validate_curp_format_none():
    valid, issue = validate_curp_format(None)
    assert valid is False
    assert issue == "missing"

def test_validate_curp_format_wrong_length():
    valid, issue = validate_curp_format("9212118M3212312MEX<03")
    assert valid is False
    assert "length" in issue

def test_detect_mrz_in_curp_with_angle_bracket():
    assert detect_mrz_in_curp("9212118M3212312MEX<03") is True

def test_detect_mrz_in_curp_with_mex():
    assert detect_mrz_in_curp("9106215H3412318MEX") is True

def test_detect_mrz_in_curp_valid_curp():
    assert detect_mrz_in_curp("LOOS790918HDFPRR03") is False

def test_detect_mrz_in_curp_none():
    assert detect_mrz_in_curp(None) is False

def test_cross_validate_curp_dob_match():
    assert cross_validate_curp_dob("LOOS790918HDFPRR03", "1979-09-18") is True

def test_cross_validate_curp_dob_mismatch():
    assert cross_validate_curp_dob("LOOS790918HDFPRR03", "1980-01-01") is False

def test_cross_validate_curp_name_match():
    assert cross_validate_curp_name("LOOS790918HDFPRR03", "LOPEZ ORTEGA SERGIO") is True

def test_cross_validate_curp_name_mismatch():
    assert cross_validate_curp_name("LOOS790918HDFPRR03", "GARCIA MARTINEZ") is False

def test_fix_mrz_in_curp_corrects_mrz():
    data = {"identifiers": {"curp": "9212118M3212312MEX<03", "mrz": None}}
    issue = fix_mrz_in_curp(data)
    assert issue is not None
    assert data["identifiers"]["curp"] is None
    assert data["identifiers"]["mrz"] == "9212118M3212312MEX<03"

def test_fix_mrz_in_curp_leaves_valid():
    data = {"identifiers": {"curp": "LOOS790918HDFPRR03", "mrz": None}}
    issue = fix_mrz_in_curp(data)
    assert issue is None
    assert data["identifiers"]["curp"] == "LOOS790918HDFPRR03"

def test_confidence_reduced_for_bad_curp():
    """Documents with invalid CURP should have lower confidence."""
    raw_json = """{
        "subType": "ine_mx",
        "person": {"fullName": "VALERIA ESPINOSA", "dob": "1992-12-11"},
        "document": {},
        "identifiers": {"curp": "9212118M3212312MEX<03"},
        "overallConfidence": 95.0
    }"""
    
    result = parse_and_normalize(raw_json, "doc-bad", "1.3.0", "model-xxx")
    # MRZ should have been moved out of CURP
    assert result["identifiers"]["curp"] is None
    # Confidence should be penalized (missing CURP = -15)
    assert result["overallConfidence"] < 85.0


# ══════════════════════════════════════════════════════════════
# TAREA 5: Tests for _validate_curp_vs_clave_elector
# ══════════════════════════════════════════════════════════════

class TestValidateCurpVsClaveElector:
    """Tests for the deterministic CURP/claveElector post-processing."""

    def test_curp_misplaced_in_clave_elector(self):
        """CURP certificate: curp is invalid, claveElector has valid CURP → move it."""
        data = {
            "subType": "curp_mx",
            "identifiers": {
                "curp": "ACMA790226MDFCRR03",  # wrong person
                "claveElector": "AUHM770923MDFCRR03",  # real CURP
            }
        }
        # Without classifier hint, curp_mx subType should clear claveElector
        # Since both are valid CURPs and subType=curp_mx, we use classifier hint
        result, reasons = _validate_curp_vs_clave_elector(
            data, classifier_hints={"subType": "curp_mx"}
        )
        assert result["identifiers"]["claveElector"] is None
        assert "CLAVE_ELECTOR_CLEARED_CURP_DOC" in reasons

    def test_curp_misplaced_move_when_curp_invalid(self):
        """CURP certificate: curp is invalid format, claveElector has valid CURP → move it."""
        data = {
            "subType": "curp_mx",
            "identifiers": {
                "curp": "INVALID_BAD",
                "claveElector": "AUHM770923MDFCRR03",
            }
        }
        result, reasons = _validate_curp_vs_clave_elector(data)
        assert result["identifiers"]["curp"] == "AUHM770923MDFCRR03"
        assert result["identifiers"]["claveElector"] is None
        assert "MOVED_CURP_FROM_CLAVE_ELECTOR" in reasons

    def test_curp_certificate_never_outputs_clave_elector(self):
        """CURP certificate should never have claveElector in output."""
        data = {
            "subType": "curp_mx",
            "identifiers": {
                "curp": "AUHM770923MDFCRR03",
                "claveElector": "ACHRMR77092309M801",  # not a valid CURP
            }
        }
        result, reasons = _validate_curp_vs_clave_elector(data)
        assert result["identifiers"]["claveElector"] is None
        assert "CLAVE_ELECTOR_CLEARED_NON_INE" in reasons

    def test_ine_preserves_clave_elector(self):
        """INE should preserve claveElector (no modification)."""
        data = {
            "subType": "ine_mx",
            "identifiers": {
                "curp": "LOOS790918HDFPRR03",
                "claveElector": "ACHRMR77092309M801",
            }
        }
        result, reasons = _validate_curp_vs_clave_elector(data)
        assert result["identifiers"]["claveElector"] == "ACHRMR77092309M801"
        assert len(reasons) == 0

    def test_ine_does_not_move_clave_to_curp(self):
        """INE should NOT move a real claveElector into curp even if claveElector has CURP format."""
        data = {
            "subType": "ine_mx",
            "identifiers": {
                "curp": "LOOS790918HDFPRR03",
                "claveElector": "GAMD880903HDFRRV08",  # looks like CURP format
            }
        }
        result, reasons = _validate_curp_vs_clave_elector(data)
        # Should preserve both since subType is ine_mx
        assert result["identifiers"]["curp"] == "LOOS790918HDFPRR03"
        assert result["identifiers"]["claveElector"] == "GAMD880903HDFRRV08"
        assert len(reasons) == 0

    def test_rfc_sat_clears_clave_elector(self):
        """RFC/SAT document should never have claveElector."""
        data = {
            "subType": "rfc_sat",
            "identifiers": {
                "curp": "LOOS790918HDFPRR03",
                "claveElector": "SOMETHING",
            }
        }
        result, reasons = _validate_curp_vs_clave_elector(data)
        assert result["identifiers"]["claveElector"] is None

    def test_nss_clears_clave_elector(self):
        """NSS/IMSS document should never have claveElector."""
        data = {
            "subType": "nss_imss",
            "identifiers": {
                "curp": "LOOS790918HDFPRR03",
                "claveElector": "EXTRA_DATA",
            }
        }
        result, reasons = _validate_curp_vs_clave_elector(data)
        assert result["identifiers"]["claveElector"] is None

    def test_subtype_corrected_by_classifier(self):
        """When LLM says ine_mx but classifier says curp_mx → correct subType."""
        data = {
            "subType": "ine_mx",
            "identifiers": {
                "curp": "INVALID",
                "claveElector": "AUHM770923MDFCRR03",
            }
        }
        result, reasons = _validate_curp_vs_clave_elector(
            data, classifier_hints={"subType": "curp_mx"}
        )
        assert result["subType"] == "curp_mx"
        assert "SUBTYPE_CORRECTED_BY_CLASSIFIER" in reasons
        assert result["identifiers"]["curp"] == "AUHM770923MDFCRR03"
        assert result["identifiers"]["claveElector"] is None
        assert "MOVED_CURP_FROM_CLAVE_ELECTOR" in reasons

    def test_null_strings_cleaned(self):
        """String 'null' should be treated as None."""
        data = {
            "subType": "curp_mx",
            "identifiers": {
                "curp": "AUHM770923MDFCRR03",
                "claveElector": "null",
            }
        }
        result, reasons = _validate_curp_vs_clave_elector(data)
        assert result["identifiers"]["claveElector"] is None
        assert result["identifiers"]["curp"] == "AUHM770923MDFCRR03"

    def test_no_clave_elector_no_changes(self):
        """When there's no claveElector, nothing should change."""
        data = {
            "subType": "curp_mx",
            "identifiers": {
                "curp": "AUHM770923MDFCRR03",
            }
        }
        result, reasons = _validate_curp_vs_clave_elector(data)
        assert result["identifiers"]["curp"] == "AUHM770923MDFCRR03"
        assert len(reasons) == 0

    def test_subtype_promoted_by_classifier(self):
        """When LLM says personal_doc_generic but classifier says payroll_cfdi_mx → promote."""
        data = {
            "subType": "personal_doc_generic",
            "identifiers": {"curp": "LOOS790918HDFPRR03"},
        }
        result, reasons = _validate_curp_vs_clave_elector(
            data, classifier_hints={"subType": "payroll_cfdi_mx"}
        )
        assert result["subType"] == "payroll_cfdi_mx"
        assert "SUBTYPE_PROMOTED_BY_CLASSIFIER" in reasons


class TestCurpMxFullPipeline:
    """End-to-end tests with parse_and_normalize for curp_mx documents."""

    def test_curp_mx_document_accepted(self):
        """curp_mx subType should be accepted by schema."""
        raw_json = """{
            "subType": "curp_mx",
            "person": {"fullName": "MARTHA MARCELA ACUNA HERNANDEZ", "dob": "1977-09-23"},
            "document": {"numberMasked": "XXXX770923MDFCRR03"},
            "identifiers": {"curp": "AUHM770923MDFCRR03"},
            "overallConfidence": 80.0
        }"""
        result = parse_and_normalize(raw_json, "doc-curp", "1.3.0", "model-xxx")
        assert result["subType"] == "curp_mx"
        assert result["identifiers"]["curp"] == "AUHM770923MDFCRR03"

    def test_curp_mx_with_misplaced_clave(self):
        """Full pipeline: curp_mx with CURP in claveElector should be corrected."""
        raw_json = """{
            "subType": "curp_mx",
            "person": {"fullName": "MARTHA MARCELA ACUNA HERNANDEZ", "dob": "1977-09-23"},
            "document": {},
            "identifiers": {
                "curp": "INVALID_BAD_VALUE",
                "claveElector": "AUHM770923MDFCRR03"
            },
            "overallConfidence": 75.0
        }"""
        result = parse_and_normalize(
            raw_json, "doc-fix", "1.3.0", "model-xxx",
            classifier_hints={"subType": "curp_mx"},
        )
        assert result["identifiers"]["curp"] == "AUHM770923MDFCRR03"
        assert result["identifiers"]["claveElector"] is None
        assert "MOVED_CURP_FROM_CLAVE_ELECTOR" in result.get("extractionReasonCodes", [])

    def test_rfc_sat_document_accepted(self):
        """rfc_sat subType should be accepted by schema."""
        raw_json = """{
            "subType": "rfc_sat",
            "person": {"fullName": "LOPEZ ORTEGA SERGIO"},
            "document": {},
            "identifiers": {"rfc": "LOOS790918821", "curp": "LOOS790918HDFPRR03"},
            "overallConfidence": 85.0
        }"""
        result = parse_and_normalize(raw_json, "doc-rfc", "1.3.0", "model-xxx")
        assert result["subType"] == "rfc_sat"
        assert result["identifiers"]["rfc"] == "LOOS790918821"

    def test_nss_imss_document_accepted(self):
        """nss_imss subType should be accepted by schema."""
        raw_json = """{
            "subType": "nss_imss",
            "person": {"fullName": "GARCIA HERNANDEZ PEDRO"},
            "document": {},
            "identifiers": {"curp": "GAHP850312HDFRRR09"},
            "overallConfidence": 80.0
        }"""
        result = parse_and_normalize(raw_json, "doc-nss", "1.3.0", "model-xxx")
        assert result["subType"] == "nss_imss"

    def test_ine_subtype_still_works(self):
        """INE documents should still work as before."""
        raw_json = """{
            "subType": "ine_mx",
            "person": {"fullName": "LOPEZ ORTEGA SERGIO", "dob": "1979-09-18"},
            "document": {"numberMasked": "XXXX1234"},
            "identifiers": {
                "curp": "LOOS790918HDFPRR03",
                "claveElector": "ACHRMR77092309M801"
            },
            "overallConfidence": 95.0
        }"""
        result = parse_and_normalize(raw_json, "doc-ine", "1.3.0", "model-xxx")
        assert result["subType"] == "ine_mx"
        assert result["identifiers"]["curp"] == "LOOS790918HDFPRR03"
        assert result["identifiers"]["claveElector"] == "ACHRMR77092309M801"

    def test_variant_field_preserved(self):
        """Variant field should be preserved through schema validation."""
        raw_json = """{
            "subType": "curp_mx",
            "variant": "curp_certificate",
            "person": {"fullName": "TEST PERSON"},
            "document": {},
            "identifiers": {"curp": "TEPE900101HDFRRR01"},
            "overallConfidence": 70.0
        }"""
        result = parse_and_normalize(raw_json, "doc-var", "1.3.0", "model-xxx")
        assert result["variant"] == "curp_certificate"


class TestIsValidCurpFormat:
    """Tests for the _is_valid_curp_format helper."""

    def test_valid_curp(self):
        assert _is_valid_curp_format("LOOS790918HDFPRR03") is True

    def test_invalid_short(self):
        assert _is_valid_curp_format("LOOS") is False

    def test_invalid_empty(self):
        assert _is_valid_curp_format("") is False

    def test_invalid_mrz(self):
        assert _is_valid_curp_format("9212118M3212312MEX<03") is False

    def test_female_curp(self):
        assert _is_valid_curp_format("AUHM770923MDFCRR03") is True


# ══════════════════════════════════════════════════════════════
# v1.3.0: New tests for payroll, employer, contact, NSS, subType
# ══════════════════════════════════════════════════════════════

class TestPayrollSubType:
    """Tests for payroll subType consistency."""

    def test_payroll_cfdi_mx_accepted(self):
        """payroll_cfdi_mx subType should be accepted by schema."""
        raw_json = """{
            "subType": "payroll_cfdi_mx",
            "person": {"fullName": "GARCIA MARTINEZ MARIA"},
            "document": {"type": "CFDI", "uuid": "abc12345-1234-5678-9abc-def012345678"},
            "identifiers": {"curp": "GAMM850101MDFRRR01", "rfc": "GAMM850101XXX", "nss": "12345678901"},
            "employer": {"name": "EMPRESA SA DE CV", "rfc": "EMP123456789"},
            "payroll": {
                "position": "ANALISTA CONTABLE",
                "department": "FINANZAS",
                "grossPay": 15000.50,
                "deductions": 3500.25,
                "taxWithheld": 1200.00,
                "netPay": 11500.25,
                "paymentDate": "2026-04-30"
            },
            "overallConfidence": 85.0
        }"""
        result = parse_and_normalize(raw_json, "doc-payroll", "1.3.0", "model-xxx")
        assert result["subType"] == "payroll_cfdi_mx"
        assert result["payroll"]["netPay"] == 11500.25
        assert result["payroll"]["grossPay"] == 15000.50
        assert result["payroll"]["position"] == "ANALISTA CONTABLE"
        assert result["employer"]["name"] == "EMPRESA SA DE CV"
        assert result["employer"]["rfc"] == "EMP123456789"
        assert result["document"]["uuid"] == "abc12345-1234-5678-9abc-def012345678"
        assert result["identifiers"]["nss"] == "12345678901"

    def test_payroll_fields_are_numeric(self):
        """payroll.netPay and payroll.grossPay must be numbers."""
        raw_json = """{
            "subType": "payroll_cfdi_mx",
            "person": {"fullName": "TEST PERSON"},
            "document": {},
            "identifiers": {},
            "payroll": {"netPay": 8500.0, "grossPay": 12000.0},
            "overallConfidence": 70.0
        }"""
        result = parse_and_normalize(raw_json, "doc-pay-num", "1.3.0", "model-xxx")
        assert isinstance(result["payroll"]["netPay"], float)
        assert isinstance(result["payroll"]["grossPay"], float)

    def test_payroll_removed_from_non_payroll(self):
        """payroll object should be None for non-payroll docs."""
        raw_json = """{
            "subType": "ine_mx",
            "person": {"fullName": "LOPEZ ORTEGA SERGIO"},
            "document": {},
            "identifiers": {"curp": "LOOS790918HDFPRR03"},
            "payroll": {"netPay": 5000.0},
            "overallConfidence": 90.0
        }"""
        result = parse_and_normalize(raw_json, "doc-ine-no-pay", "1.3.0", "model-xxx")
        assert result["payroll"] is None
        assert "PAYROLL_CLEARED_NON_PAYROLL_DOC" in result.get("extractionReasonCodes", [])

    def test_subtype_promoted_from_generic_to_payroll(self):
        """personal_doc_generic → payroll_cfdi_mx when classifier says so."""
        raw_json = """{
            "subType": "personal_doc_generic",
            "person": {"fullName": "GARCIA MARTINEZ MARIA"},
            "document": {},
            "identifiers": {},
            "payroll": {"netPay": 8000.0},
            "overallConfidence": 60.0
        }"""
        result = parse_and_normalize(
            raw_json, "doc-promo", "1.3.0", "model-xxx",
            classifier_hints={"subType": "payroll_cfdi_mx"},
        )
        assert result["subType"] == "payroll_cfdi_mx"
        assert "SUBTYPE_PROMOTED_BY_CLASSIFIER" in result.get("extractionReasonCodes", [])
        # payroll should be preserved since subType is now payroll_cfdi_mx
        assert result["payroll"]["netPay"] == 8000.0

    def test_subtype_not_degraded_without_reason(self):
        """payroll_cfdi_mx should not be degraded to generic."""
        raw_json = """{
            "subType": "payroll_cfdi_mx",
            "person": {"fullName": "EMPLOYEE PERSON"},
            "document": {},
            "identifiers": {},
            "payroll": {"netPay": 12000.0},
            "overallConfidence": 75.0
        }"""
        result = parse_and_normalize(raw_json, "doc-no-degrade", "1.3.0", "model-xxx")
        assert result["subType"] == "payroll_cfdi_mx"


class TestEmployerGuard:
    """Tests for employer object eligibility."""

    def test_employer_allowed_for_payroll(self):
        """employer is valid for payroll_cfdi_mx."""
        raw_json = """{
            "subType": "payroll_cfdi_mx",
            "person": {"fullName": "TEST"},
            "document": {},
            "identifiers": {},
            "employer": {"name": "ACME SA", "rfc": "ACM123456789"},
            "overallConfidence": 70.0
        }"""
        result = parse_and_normalize(raw_json, "doc-emp-pay", "1.3.0", "model-xxx")
        assert result["employer"] is not None
        assert result["employer"]["name"] == "ACME SA"

    def test_employer_allowed_for_imss(self):
        """employer is valid for nss_imss."""
        raw_json = """{
            "subType": "nss_imss",
            "person": {"fullName": "TEST"},
            "document": {},
            "identifiers": {"nss": "12345678901"},
            "employer": {"name": "PATRON SA", "registrationNumber": "Y12345678"},
            "overallConfidence": 70.0
        }"""
        result = parse_and_normalize(raw_json, "doc-emp-nss", "1.3.0", "model-xxx")
        assert result["employer"] is not None
        assert result["employer"]["name"] == "PATRON SA"

    def test_employer_allowed_for_labor_certificate(self):
        """employer is valid for labor_certificate."""
        raw_json = """{
            "subType": "labor_certificate",
            "person": {"fullName": "TEST"},
            "document": {},
            "identifiers": {},
            "employer": {"name": "LABOR CO"},
            "overallConfidence": 70.0
        }"""
        result = parse_and_normalize(raw_json, "doc-emp-labor", "1.3.0", "model-xxx")
        assert result["employer"] is not None

    def test_employer_cleared_for_cv(self):
        """employer should be None for cv_resume."""
        raw_json = """{
            "subType": "cv_resume",
            "person": {"fullName": "TEST"},
            "document": {},
            "identifiers": {},
            "employer": {"name": "SHOULD BE CLEARED"},
            "overallConfidence": 70.0
        }"""
        result = parse_and_normalize(raw_json, "doc-emp-cv", "1.3.0", "model-xxx")
        assert result["employer"] is None
        assert "EMPLOYER_CLEARED_NON_ELIGIBLE_DOC" in result.get("extractionReasonCodes", [])

    def test_employer_cleared_for_ine(self):
        """employer should be None for ine_mx."""
        raw_json = """{
            "subType": "ine_mx",
            "person": {"fullName": "TEST", "dob": "1990-01-01"},
            "document": {},
            "identifiers": {"curp": "TEPE900101HDFRRR01"},
            "employer": {"name": "SHOULD BE CLEARED"},
            "overallConfidence": 80.0
        }"""
        result = parse_and_normalize(raw_json, "doc-emp-ine", "1.3.0", "model-xxx")
        assert result["employer"] is None


class TestContactObject:
    """Tests for the contact object."""

    def test_contact_from_cv(self):
        """CV should have contact object with email and phone."""
        raw_json = """{
            "subType": "cv_resume",
            "person": {"fullName": "DEVELOPER PERSON"},
            "document": {},
            "identifiers": {},
            "contact": {"email": "dev@test.com", "phone": "+52 55 1234 5678"},
            "overallConfidence": 70.0
        }"""
        result = parse_and_normalize(raw_json, "doc-cv-contact", "1.3.0", "model-xxx")
        assert result["contact"] is not None
        assert result["contact"]["email"] == "dev@test.com"
        assert result["contact"]["phone"] == "+52 55 1234 5678"

    def test_contact_promoted_from_person(self):
        """If LLM puts email in person, it should be promoted to contact."""
        raw_json = """{
            "subType": "cv_resume",
            "person": {"fullName": "DEVELOPER PERSON", "email": "fromPerson@test.com", "phone": "5551234567"},
            "document": {},
            "identifiers": {},
            "overallConfidence": 70.0
        }"""
        result = parse_and_normalize(raw_json, "doc-cv-promote", "1.3.0", "model-xxx")
        assert result["contact"] is not None
        assert result["contact"]["email"] == "fromPerson@test.com"
        assert result["contact"]["phone"] == "5551234567"
        # person should not have email/phone
        assert "email" not in result["person"]
        assert "phone" not in result["person"]
        assert "CONTACT_PROMOTED_FROM_PERSON" in result.get("extractionReasonCodes", [])

    def test_no_contact_for_ine(self):
        """INE should not have contact unless explicitly extracted."""
        raw_json = """{
            "subType": "ine_mx",
            "person": {"fullName": "PERSON", "dob": "1990-01-01"},
            "document": {},
            "identifiers": {"curp": "TEPE900101HDFRRR01"},
            "overallConfidence": 85.0
        }"""
        result = parse_and_normalize(raw_json, "doc-ine-no-contact", "1.3.0", "model-xxx")
        assert result["contact"] is None


class TestNssValidation:
    """Tests for NSS format validation."""

    def test_nss_full_visible(self):
        """Full 11-digit NSS should be preserved."""
        raw_json = """{
            "subType": "nss_imss",
            "person": {"fullName": "TEST PERSON"},
            "document": {},
            "identifiers": {"nss": "12345678901"},
            "overallConfidence": 80.0
        }"""
        result = parse_and_normalize(raw_json, "doc-nss-full", "1.3.0", "model-xxx")
        assert result["identifiers"]["nss"] == "12345678901"

    def test_nss_invalid_format_cleared(self):
        """NSS with wrong format should be cleared."""
        raw_json = """{
            "subType": "nss_imss",
            "person": {"fullName": "TEST PERSON"},
            "document": {"numberMasked": "XXXXX8901"},
            "identifiers": {"nss": "123ABC"},
            "overallConfidence": 70.0
        }"""
        result = parse_and_normalize(raw_json, "doc-nss-bad", "1.3.0", "model-xxx")
        assert result["identifiers"]["nss"] is None
        assert "NSS_INVALID_FORMAT_CLEARED" in result.get("extractionReasonCodes", [])

    def test_nss_partial_only_masked(self):
        """Partial NSS should only be in numberMasked, not in identifiers.nss."""
        raw_json = """{
            "subType": "nss_imss",
            "person": {"fullName": "TEST PERSON"},
            "document": {"numberMasked": "XXXXXXX8901"},
            "identifiers": {"nss": "8901"},
            "overallConfidence": 65.0
        }"""
        result = parse_and_normalize(raw_json, "doc-nss-partial", "1.3.0", "model-xxx")
        assert result["identifiers"]["nss"] is None
        assert result["document"]["numberMasked"] == "XXXXXXX8901"

    def test_validate_nss_format_valid(self):
        assert validate_nss_format("12345678901") is True

    def test_validate_nss_format_invalid_letters(self):
        assert validate_nss_format("1234567890A") is False

    def test_validate_nss_format_too_short(self):
        assert validate_nss_format("123456") is False

    def test_validate_nss_format_none(self):
        assert validate_nss_format(None) is False


class TestImssGuard:
    """Tests for IMSS object eligibility."""

    def test_imss_allowed_for_nss_imss(self):
        """imss object is valid for nss_imss."""
        raw_json = """{
            "subType": "nss_imss",
            "person": {"fullName": "TEST"},
            "document": {},
            "identifiers": {"nss": "12345678901"},
            "imss": {"weeksContributed": 520},
            "overallConfidence": 80.0
        }"""
        result = parse_and_normalize(raw_json, "doc-imss-ok", "1.3.0", "model-xxx")
        assert result["imss"] is not None
        assert result["imss"]["weeksContributed"] == 520

    def test_imss_cleared_for_ine(self):
        """imss object should be None for ine_mx."""
        raw_json = """{
            "subType": "ine_mx",
            "person": {"fullName": "TEST", "dob": "1990-01-01"},
            "document": {},
            "identifiers": {"curp": "TEPE900101HDFRRR01"},
            "imss": {"weeksContributed": 100},
            "overallConfidence": 85.0
        }"""
        result = parse_and_normalize(raw_json, "doc-imss-ine", "1.3.0", "model-xxx")
        assert result["imss"] is None
        assert "IMSS_CLEARED_NON_IMSS_DOC" in result.get("extractionReasonCodes", [])


class TestPayrollEmployerGuardUnit:
    """Unit tests for _validate_payroll_employer_guards."""

    def test_payroll_cleared_non_payroll(self):
        data = {"subType": "ine_mx", "payroll": {"netPay": 5000}}
        reasons = _validate_payroll_employer_guards(data)
        assert data["payroll"] is None
        assert "PAYROLL_CLEARED_NON_PAYROLL_DOC" in reasons

    def test_employer_cleared_non_eligible(self):
        data = {"subType": "cv_resume", "employer": {"name": "ACME"}}
        reasons = _validate_payroll_employer_guards(data)
        assert data["employer"] is None
        assert "EMPLOYER_CLEARED_NON_ELIGIBLE_DOC" in reasons

    def test_imss_cleared_non_imss(self):
        data = {"subType": "curp_mx", "imss": {"weeksContributed": 100}}
        reasons = _validate_payroll_employer_guards(data)
        assert data["imss"] is None
        assert "IMSS_CLEARED_NON_IMSS_DOC" in reasons

    def test_all_allowed_for_payroll(self):
        data = {
            "subType": "payroll_cfdi_mx",
            "payroll": {"netPay": 5000},
            "employer": {"name": "ACME"},
        }
        reasons = _validate_payroll_employer_guards(data)
        assert len(reasons) == 0
        assert data["payroll"] is not None
        assert data["employer"] is not None


class TestContactNormalizationUnit:
    """Unit tests for _normalize_contact."""

    def test_email_promoted(self):
        data = {"person": {"fullName": "X", "email": "a@b.com"}, "contact": None}
        reasons = _normalize_contact(data)
        assert data["contact"]["email"] == "a@b.com"
        assert "email" not in data["person"]
        assert "CONTACT_PROMOTED_FROM_PERSON" in reasons

    def test_phone_promoted(self):
        data = {"person": {"fullName": "X", "phone": "555"}, "contact": None}
        reasons = _normalize_contact(data)
        assert data["contact"]["phone"] == "555"
        assert "CONTACT_PROMOTED_FROM_PERSON" in reasons

    def test_no_promotion_if_contact_already_has(self):
        data = {"person": {"fullName": "X", "email": "old@b.com"}, "contact": {"email": "existing@b.com"}}
        reasons = _normalize_contact(data)
        assert data["contact"]["email"] == "existing@b.com"

    def test_no_contact_data(self):
        data = {"person": {"fullName": "X"}, "contact": None}
        reasons = _normalize_contact(data)
        assert data["contact"] is None
        assert len(reasons) == 0
