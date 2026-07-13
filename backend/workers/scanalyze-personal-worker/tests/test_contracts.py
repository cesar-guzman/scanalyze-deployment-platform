import pytest
import pydantic
from personal_worker.contracts import PersonalExtractMessage, ValidateMessage, PersonalDocSchema, VALID_SUBTYPES

CUSTOMER_ID = "cust_01ARZ3NDEKTSV4RRFFQ69G5FAV"
DEPLOYMENT_ID = "dep_01ARZ3NDEKTSV4RRFFQ69G5FAW"


def _extract_message(**overrides):
    payload = {
        "schemaVersion": "scanalyze.extract.v2",
        "documentId": "doc-123",
        "customer_id": CUSTOMER_ID,
        "deployment_id": DEPLOYMENT_ID,
        "ownership_schema_version": 1,
        "pipeline_stage": "personal-extract",
        "processing_domain": "personal",
        "raw": {"bucket": "raw", "key": "raw-key"},
        "ocr": {"bucket": "ocr", "key": "ocr-key"},
    }
    payload.update(overrides)
    return PersonalExtractMessage(**payload)

def test_personal_extract_message():
    msg = _extract_message()
    assert msg.documentId == "doc-123"
    assert msg.ocr.bucket == "ocr"
    assert msg.ocr.key == "ocr-key"


def test_personal_extract_message_rejects_unknown_fields():
    with pytest.raises(pydantic.ValidationError):
        _extract_message(extra_classifier_field="not-allowed")
    
def test_personal_extract_message_missing_document_id():
    with pytest.raises(pydantic.ValidationError):
        PersonalExtractMessage(ocr={"bucket": "b", "key": "k"})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("canonicalDocType", "personal_doc"),
        ("subType", "curp_mx"),
        ("routeIntent", "personal-extract"),
        ("reasonCodes", ["KW_SEGOB"]),
        ("identitySignals", {"curp": "SYNTHETIC"}),
        ("classifierSchemaVersion", "scanalyze.classifier-output.v1.1"),
        ("taxonomyVersion", "scanalyze-doc-taxonomy-v1"),
    ],
)
def test_personal_extract_message_rejects_legacy_classifier_hints(field, value):
    with pytest.raises(pydantic.ValidationError):
        _extract_message(**{field: value})


class TestPersonalDocSchemaSubTypes:
    """Tests for expanded subType validation in PersonalDocSchema."""

    @pytest.mark.parametrize("sub_type", [
        "ine_mx", "curp_mx", "rfc_sat", "nss_imss",
        "imss_weeks_certificate", "birth_certificate",
        "passport", "mx_driver_license",
        "cv_resume", "personal_doc_generic", "unknown",
    ])
    def test_valid_subtypes_accepted(self, sub_type):
        """All classifier taxonomy v1.1 subtypes should be accepted."""
        schema = PersonalDocSchema(
            prompt_version="1.2.0",
            documentId="doc-test",
            subType=sub_type,
            model={"provider": "bedrock", "modelId": "test"},
            person={},
            document={},
            identifiers={},
        )
        assert schema.subType == sub_type

    def test_invalid_subtype_rejected(self):
        """Invalid subtypes should be rejected."""
        with pytest.raises(pydantic.ValidationError):
            PersonalDocSchema(
                prompt_version="1.2.0",
                documentId="doc-test",
                subType="curp_certificate",  # not a valid subType
                model={"provider": "bedrock", "modelId": "test"},
                person={},
                document={},
                identifiers={},
            )

    def test_variant_field(self):
        """Variant field should be accepted."""
        schema = PersonalDocSchema(
            prompt_version="1.2.0",
            documentId="doc-test",
            subType="curp_mx",
            variant="curp_certificate",
            model={"provider": "bedrock", "modelId": "test"},
            person={},
            document={},
            identifiers={},
        )
        assert schema.variant == "curp_certificate"

    def test_extraction_reason_codes(self):
        """extractionReasonCodes should be accepted."""
        schema = PersonalDocSchema(
            prompt_version="1.2.0",
            documentId="doc-test",
            subType="curp_mx",
            extractionReasonCodes=["MOVED_CURP_FROM_CLAVE_ELECTOR"],
            model={"provider": "bedrock", "modelId": "test"},
            person={},
            document={},
            identifiers={},
        )
        assert schema.extractionReasonCodes == ["MOVED_CURP_FROM_CLAVE_ELECTOR"]

    def test_valid_subtypes_frozenset(self):
        """VALID_SUBTYPES should contain all expected values."""
        assert "curp_mx" in VALID_SUBTYPES
        assert "rfc_sat" in VALID_SUBTYPES
        assert "nss_imss" in VALID_SUBTYPES
        assert "ine_mx" in VALID_SUBTYPES
        assert "curp_certificate" not in VALID_SUBTYPES  # NOT a valid subType
