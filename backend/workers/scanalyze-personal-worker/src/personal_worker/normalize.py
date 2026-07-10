import json
import re
import logging
import json_repair
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone
from .contracts import PersonalDocSchema, FieldConfidenceSchema, FieldValidation, VALID_SUBTYPES
from .logger import log_event, safe_error_details
from pydantic import ValidationError

logger = logging.getLogger(__name__)

# Official CURP regex: 4 letters + 6 digits + H/M + 5 letters + 1 alphanumeric + 1 digit
CURP_REGEX = re.compile(r'^[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]\d$')

# MRZ indicators — if these appear in the CURP field, it's a MRZ value, not a CURP
MRZ_INDICATORS = ['<', 'MEX']


def _is_valid_curp_format(value: str) -> bool:
    """Check if a string has valid CURP format (18 alphanumeric chars)."""
    if not value or len(value) != 18:
        return False
    return bool(CURP_REGEX.match(value.upper()))


def validate_curp_format(curp: Optional[str]) -> Tuple[bool, Optional[str]]:
    """Validates CURP against the official Mexican format. Returns (is_valid, issue_description)."""
    if not curp or curp.lower() == 'null':
        return False, "missing"
    if len(curp) != 18:
        return False, f"length={len(curp)}, expected 18"
    if not CURP_REGEX.match(curp.upper()):
        return False, "format mismatch"
    return True, None


def detect_mrz_in_curp(curp: Optional[str]) -> bool:
    """Detects if a CURP field actually contains MRZ data."""
    if not curp:
        return False
    return any(indicator in curp for indicator in MRZ_INDICATORS) or len(curp) > 18


def cross_validate_curp_dob(curp: str, dob: Optional[str]) -> bool:
    """Checks if CURP digits 5-10 match the DOB (YYMMDD)."""
    if not dob or len(curp) < 10:
        return False
    try:
        # Parse DOB — could be YYYY-MM-DD or DD/MM/YYYY
        dob_clean = dob.replace('-', '').replace('/', '')
        if len(dob_clean) == 8:
            # YYYYMMDD → extract YYMMDD
            yy = dob_clean[2:8]
            return curp[4:10] == yy
    except Exception:
        pass
    return False


def cross_validate_curp_name(curp: str, fullname: Optional[str]) -> bool:
    """Checks if the first letter of CURP matches the first letter of the paternal surname."""
    if not fullname or len(curp) < 1:
        return False
    # Typical INE name order: SURNAMES GIVEN_NAMES or PATERNAL MATERNAL GIVEN
    # CURP first letter = first letter of paternal surname
    parts = fullname.upper().strip().split()
    if len(parts) >= 1:
        return curp[0] == parts[0][0]
    return False


def fix_mrz_in_curp(data: Dict[str, Any]) -> Optional[str]:
    """If CURP field contains MRZ data, moves it to mrz field and nullifies curp. Returns the issue."""
    identifiers = data.get('identifiers', {})
    curp = identifiers.get('curp')
    
    if curp and detect_mrz_in_curp(curp):
        logger.warning(f"MRZ detected in CURP field. Moving to mrz field.")
        # Only overwrite mrz if it's empty
        if not identifiers.get('mrz'):
            identifiers['mrz'] = curp
        identifiers['curp'] = None
        data['identifiers'] = identifiers
        return f"MRZ value was in CURP field — corrected"
    return None


def _validate_curp_vs_clave_elector(
    data: Dict[str, Any],
    classifier_hints: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, Any], List[str]]:
    """Deterministic post-Bedrock validation of CURP vs claveElector.

    Rules:
    1. If subType != ine_mx → claveElector must be null.
    2. If claveElector has CURP format and subType != ine_mx → move to curp.
    3. If subType == curp_mx → claveElector always null.
    4. If subType == ine_mx → preserve claveElector only if valid.

    Returns (corrected_data, list_of_reason_codes).
    """
    ids = data.get("identifiers", {})
    sub_type = data.get("subType", "unknown")
    reason_codes: List[str] = []

    curp_val = ids.get("curp")
    clave_val = ids.get("claveElector")

    # Normalize null-like strings
    if curp_val and str(curp_val).lower() in ("null", "none", ""):
        curp_val = None
        ids["curp"] = None
    if clave_val and str(clave_val).lower() in ("null", "none", ""):
        clave_val = None
        ids["claveElector"] = None

    # ── Rule 1 & 3: Non-INE subTypes cannot have claveElector ──
    if sub_type != "ine_mx" and clave_val:
        clave_is_curp_format = _is_valid_curp_format(str(clave_val))
        curp_is_valid = _is_valid_curp_format(str(curp_val)) if curp_val else False

        if clave_is_curp_format and not curp_is_valid:
            # ── Rule 2: Move misplaced CURP from claveElector ──
            logger.warning(f"[normalize] Moving CURP from claveElector to identifiers.curp (subType={sub_type})")
            ids["curp"] = clave_val
            ids["claveElector"] = None
            reason_codes.append("MOVED_CURP_FROM_CLAVE_ELECTOR")
        elif clave_is_curp_format and curp_is_valid:
            # Both look like CURPs — check if classifier hints can resolve
            classifier_sub = (classifier_hints or {}).get("subType", "")
            if classifier_sub == "curp_mx":
                # For CURP certificate, the claveElector is likely the real CURP
                # and the "curp" field may be a secondary one
                # Trust classifier: clear claveElector, keep as-is but flag
                ids["claveElector"] = None
                reason_codes.append("CLAVE_ELECTOR_CLEARED_CURP_DOC")
            else:
                # Ambiguous — clear claveElector for non-INE
                ids["claveElector"] = None
                reason_codes.append("CLAVE_ELECTOR_CLEARED_NON_INE")
        else:
            # claveElector doesn't look like CURP, just clear it
            ids["claveElector"] = None
            reason_codes.append("CLAVE_ELECTOR_CLEARED_NON_INE")

    # ── Rule: Align subType with classifier hint ──
    classifier_sub = (classifier_hints or {}).get("subType")
    if classifier_sub and classifier_sub in VALID_SUBTYPES:
        if sub_type == "ine_mx" and classifier_sub == "curp_mx":
            # LLM said ine_mx but classifier says curp_mx — trust classifier
            data["subType"] = "curp_mx"
            reason_codes.append("SUBTYPE_CORRECTED_BY_CLASSIFIER")
            # Also clear claveElector since it's now curp_mx
            if ids.get("claveElector"):
                clave_val = ids["claveElector"]
                if _is_valid_curp_format(str(clave_val)) and not _is_valid_curp_format(str(ids.get("curp", ""))):
                    ids["curp"] = clave_val
                    reason_codes.append("MOVED_CURP_FROM_CLAVE_ELECTOR")
                ids["claveElector"] = None
        elif sub_type == "unknown" and classifier_sub != "unknown":
            # LLM couldn't decide but classifier has a hint
            data["subType"] = classifier_sub
            reason_codes.append("SUBTYPE_RESOLVED_BY_CLASSIFIER")
        elif sub_type == "personal_doc_generic" and classifier_sub not in ("unknown", "personal_doc_generic"):
            # LLM fell back to generic but classifier has a specific hint — promote
            data["subType"] = classifier_sub
            reason_codes.append("SUBTYPE_PROMOTED_BY_CLASSIFIER")

    data["identifiers"] = ids
    return data, reason_codes


# ── NSS validation ──

NSS_REGEX = re.compile(r'^\d{11}$')

def validate_nss_format(nss: Optional[str]) -> bool:
    """Validates NSS is exactly 11 digits."""
    if not nss:
        return False
    return bool(NSS_REGEX.match(nss.strip()))


# ── Payroll / Employer guards ──

_PAYROLL_ELIGIBLE_SUBTYPES = frozenset({"payroll_cfdi_mx"})
_EMPLOYER_ELIGIBLE_SUBTYPES = frozenset({
    "payroll_cfdi_mx", "nss_imss", "imss_weeks_certificate", "labor_certificate",
})
_IMSS_ELIGIBLE_SUBTYPES = frozenset({"nss_imss", "imss_weeks_certificate"})


def _validate_payroll_employer_guards(data: Dict[str, Any]) -> List[str]:
    """Ensures payroll/employer/imss objects only exist for eligible subTypes."""
    reasons: List[str] = []
    sub_type = data.get("subType", "unknown")

    if data.get("payroll") and sub_type not in _PAYROLL_ELIGIBLE_SUBTYPES:
        data["payroll"] = None
        reasons.append("PAYROLL_CLEARED_NON_PAYROLL_DOC")

    if data.get("employer") and sub_type not in _EMPLOYER_ELIGIBLE_SUBTYPES:
        data["employer"] = None
        reasons.append("EMPLOYER_CLEARED_NON_ELIGIBLE_DOC")

    if data.get("imss") and sub_type not in _IMSS_ELIGIBLE_SUBTYPES:
        data["imss"] = None
        reasons.append("IMSS_CLEARED_NON_IMSS_DOC")

    return reasons


# ── Contact normalization ──

def _normalize_contact(data: Dict[str, Any]) -> List[str]:
    """Moves person.email/phone to contact object if LLM put them there."""
    reasons: List[str] = []
    person = data.get("person") or {}
    contact = data.get("contact") or {}

    # Promote person.email → contact.email
    person_email = person.pop("email", None)
    if person_email and not contact.get("email"):
        contact["email"] = person_email
        reasons.append("CONTACT_PROMOTED_FROM_PERSON")

    # Promote person.phone → contact.phone
    person_phone = person.pop("phone", None)
    if person_phone and not contact.get("phone"):
        contact["phone"] = person_phone
        reasons.append("CONTACT_PROMOTED_FROM_PERSON")

    # If contact has data, set it; otherwise leave as None
    if any(v for v in contact.values() if v):
        data["contact"] = contact
    else:
        data["contact"] = None

    data["person"] = person
    return reasons


def compute_field_confidence(data: Dict[str, Any], ocr_char_count: int = 0) -> Tuple[FieldConfidenceSchema, float]:
    """
    Computes real per-field confidence and an adjusted overallConfidence
    based on actual validation results, not the LLM's self-assessment.
    """
    person = data.get('person', {})
    identifiers = data.get('identifiers', {})
    
    llm_confidence = data.get('overallConfidence', 95.0) or 95.0
    
    # --- CURP validation ---
    curp = identifiers.get('curp')
    curp_valid, curp_issue = validate_curp_format(curp)
    curp_matches_dob = cross_validate_curp_dob(curp, person.get('dob')) if curp_valid else False
    curp_matches_name = cross_validate_curp_name(curp, person.get('fullName')) if curp_valid else False
    
    curp_score = 95.0
    if not curp or curp.lower() == 'null':
        curp_score = 0.0
        curp_issue = "missing"
    elif not curp_valid:
        curp_score = 20.0
    else:
        if not curp_matches_dob:
            curp_score -= 15.0
            if not curp_matches_name:
                curp_score -= 10.0
    
    curp_validation = FieldValidation(
        valid=curp_valid,
        present=bool(curp and curp.lower() != 'null'),
        matchesDob=curp_matches_dob,
        matchesName=curp_matches_name,
        score=max(curp_score, 0.0),
        issue=curp_issue
    )
    
    # --- FullName validation ---
    fullname = person.get('fullName')
    name_present = bool(fullname and fullname.strip())
    name_score = 95.0 if name_present else 0.0
    
    name_validation = FieldValidation(
        present=name_present,
        score=name_score,
        issue=None if name_present else "missing"
    )
    
    # --- DOB validation ---
    dob = person.get('dob')
    dob_present = bool(dob and dob.strip())
    dob_score = 95.0 if dob_present else 0.0
    
    dob_validation = FieldValidation(
        present=dob_present,
        matchesCurp=curp_matches_dob if curp_valid else None,
        score=dob_score,
        issue=None if dob_present else "missing"
    )
    
    field_confidence = FieldConfidenceSchema(
        curp=curp_validation,
        fullName=name_validation,
        dob=dob_validation
    )
    
    # --- Compute adjusted overallConfidence ---
    # Start from LLM confidence, apply penalties for real validation failures
    adjusted = float(llm_confidence)
    
    if not curp_valid and curp and curp.lower() != 'null':
        adjusted -= 25.0  # Invalid CURP format is a major red flag
    elif not curp or curp.lower() == 'null':
        adjusted -= 15.0  # Missing CURP
    else:
        if not curp_matches_dob:
            adjusted -= 10.0
            if not curp_matches_name:
                adjusted -= 5.0
    
    if not name_present:
        adjusted -= 15.0
    
    if not dob_present:
        adjusted -= 10.0
    
    # Penalize very short OCR (indicates blurry or partial image)
    if ocr_char_count > 0 and ocr_char_count < 200:
        adjusted -= 20.0
    
    adjusted = max(min(adjusted, 100.0), 0.0)
    
    return field_confidence, round(adjusted, 1)


def clean_json_string(raw_text: str) -> str:
    """
    Strips markdown code fences and extracts the first balanced JSON object.
    Because sometimes Claude ignores strict system prompts.
    """
    text = raw_text.strip()
    
    # Strip markdown block quotes
    if text.startswith("```"):
        lines = text.split("\n")
        # Remove first line if it's ```json or ```
        if lines[0].startswith("```"):
            lines.pop(0)
        # Remove last line if it's ```
        if lines and lines[-1].strip().startswith("```"):
            lines.pop(-1)
        text = "\n".join(lines).strip()
        
    # Extra protection: find first { and last }
    start_idx = text.find("{")
    end_idx = text.rfind("}")
    
    if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
        text = text[start_idx:end_idx+1]
        
    return text

def parse_and_normalize(
    raw_json: str, document_id: str, prompt_version: str, model_id: str,
    ocr_char_count: int = 0,
    classifier_hints: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Validates against strict Pydantic schema, applies post-extraction validation,
    and computes real confidence based on data quality.
    """
    cleaned = clean_json_string(raw_json)
    
    try:
        data = json_repair.loads(cleaned)
        if not isinstance(data, dict):
            raise ValueError(f"Parsed JSON is not a dictionary. Got: {type(data)}")
    except Exception as e:
        log_event(
            "bedrock_json_parse_failed",
            documentId=document_id,
            **safe_error_details(e),
        )
        raise ValueError("Bedrock returned invalid JSON dictionary") from None
    
    # --- Post-extraction fixes BEFORE schema validation ---
    
    # Fix MRZ leaked into CURP field
    mrz_issue = fix_mrz_in_curp(data)
    if mrz_issue:
        logger.warning("CURP normalization applied", extra={"reasonCode": mrz_issue})
    
    # Validate CURP vs claveElector (deterministic post-processing)
    data, extraction_reasons = _validate_curp_vs_clave_elector(data, classifier_hints)
    if extraction_reasons:
        logger.info("Post-processing applied", extra={"reasonCodes": extraction_reasons})
    
    # Validate NSS format
    nss_val = (data.get("identifiers") or {}).get("nss")
    if nss_val and not validate_nss_format(nss_val):
        data.setdefault("identifiers", {})["nss"] = None
        extraction_reasons.append("NSS_INVALID_FORMAT_CLEARED")
        logger.info("NSS invalid format cleared")
    
    # Payroll / Employer / IMSS guards
    guard_reasons = _validate_payroll_employer_guards(data)
    extraction_reasons.extend(guard_reasons)
    if guard_reasons:
        logger.info("Validation guards applied", extra={"reasonCodes": guard_reasons})
    
    # Contact normalization: person.email/phone → contact
    contact_reasons = _normalize_contact(data)
    extraction_reasons.extend(contact_reasons)
    
    # Enforce static schema requirements
    data["schema_version"] = "1.0"
    data["prompt_version"] = prompt_version
    data["tenant"] = "personal"
    data["documentId"] = document_id
    data["docType"] = "personal_doc"
    data["generatedAt"] = datetime.now(timezone.utc).isoformat()
    
    data["model"] = {
        "provider": "bedrock",
        "modelId": model_id,
        "usage": None  # Populated later from metrics
    }
    
    # Store extraction reason codes
    if extraction_reasons:
        data["extractionReasonCodes"] = extraction_reasons
    
    # Compute field-level confidence and adjusted overall confidence
    field_confidence, adjusted_confidence = compute_field_confidence(data, ocr_char_count)
    data["fieldConfidence"] = field_confidence.model_dump(exclude_none=False)
    data["overallConfidence"] = adjusted_confidence
    
    logger.info("Confidence adjusted", extra={"adjustedConfidence": adjusted_confidence})
    
    try:
        # Validate through Pydantic (will cast floats properly if they are strings, drop extra fields)
        validated_obj = PersonalDocSchema(**data)
        # Re-export exactly matching schema, dropping extras
        return validated_obj.model_dump(exclude_none=False)
    except ValidationError as ve:
        log_event(
            "bedrock_schema_validation_failed",
            documentId=document_id,
            **safe_error_details(ve),
        )
        raise ValueError("Schema violation") from None
