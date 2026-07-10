import pytest
import pydantic
from personal_worker.contracts import PersonalExtractMessage, ValidateMessage, PersonalDocSchema, VALID_SUBTYPES

def test_personal_extract_message():
    msg = PersonalExtractMessage(
        documentId="doc-123",
        ocr={"bucket": "b", "key": "k"},
        extra_classifier_field="should act as pass-through and be ignored by Pydantic's extra=ignore model_config"
    )
    assert msg.documentId == "doc-123"
    assert getattr(msg, "extra_classifier_field", None) is None
    assert msg.ocr.bucket == "b"
    assert msg.ocr.key == "k"
    
def test_personal_extract_message_missing_document_id():
    with pytest.raises(pydantic.ValidationError):
        PersonalExtractMessage(ocr={"bucket": "b", "key": "k"})


class TestPersonalExtractMessageHints:
    """Tests for classifier hints in PersonalExtractMessage."""

    def test_accepts_classifier_hints(self):
        """Classifier hints should be accepted and preserved."""
        msg = PersonalExtractMessage(
            documentId="doc-456",
            canonicalDocType="personal_doc",
            subType="curp_mx",
            routeIntent="personal-extract",
            reasonCodes=["KW_SEGOB", "PRIORITY_CURP_CERTIFICATE"],
            classifierSchemaVersion="scanalyze.classifier-output.v1.1",
            taxonomyVersion="scanalyze-doc-taxonomy-v1",
        )
        assert msg.subType == "curp_mx"
        assert msg.canonicalDocType == "personal_doc"
        assert msg.reasonCodes == ["KW_SEGOB", "PRIORITY_CURP_CERTIFICATE"]
        assert msg.classifierSchemaVersion == "scanalyze.classifier-output.v1.1"
        assert msg.taxonomyVersion == "scanalyze-doc-taxonomy-v1"

    def test_backward_compatible_no_hints(self):
        """Messages without hints should still work (all optional)."""
        msg = PersonalExtractMessage(documentId="doc-old")
        assert msg.subType is None
        assert msg.canonicalDocType is None
        assert msg.reasonCodes is None

    def test_identity_signals(self):
        """Identity signals from classifier should be accepted."""
        msg = PersonalExtractMessage(
            documentId="doc-789",
            identitySignals={"curp": "AUHM770923MDFCRR03", "fullName": "MARTHA ACUNA"},
        )
        assert msg.identitySignals["curp"] == "AUHM770923MDFCRR03"


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
