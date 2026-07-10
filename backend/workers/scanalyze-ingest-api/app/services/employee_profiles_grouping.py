"""Grouping, normalisation and merge logic for Employee Profiles.

All functions are pure (no I/O) so they can be unit-tested without mocking AWS.
"""
from __future__ import annotations

import hashlib
import re
import unicodedata
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# ──────────────────────────────────────────────
# Normalisation helpers
# ──────────────────────────────────────────────

_NON_ALNUM = re.compile(r"[^A-Z0-9]")
_MULTI_SPACE = re.compile(r"\s+")
_DATE_SLASH = re.compile(r"^(\d{1,2})[/\-](\d{1,2})[/\-](\d{4})$")
_DATE_ISO = re.compile(r"^(\d{4})[/\-](\d{1,2})[/\-](\d{1,2})$")


def normalize_name(name: Optional[str]) -> str:
    """Trim, uppercase, remove accents, collapse spaces."""
    if not name:
        return ""
    # Remove accents
    nfkd = unicodedata.normalize("NFKD", name)
    ascii_only = "".join(c for c in nfkd if not unicodedata.combining(c))
    return _MULTI_SPACE.sub(" ", ascii_only.upper().strip())


def normalize_identifier(value: Optional[str], id_type: str = "curp") -> str:
    """Trim, uppercase, remove non-alphanumeric chars."""
    if not value:
        return ""
    return _NON_ALNUM.sub("", value.upper().strip())


def normalize_date(value: Optional[str]) -> str:
    """Try to normalise a date string to ISO YYYY-MM-DD."""
    if not value:
        return ""
    v = value.strip()

    # Already ISO?
    m = _DATE_ISO.match(v)
    if m:
        return f"{m.group(1)}-{m.group(2).zfill(2)}-{m.group(3).zfill(2)}"

    # DD/MM/YYYY or DD-MM-YYYY?
    m = _DATE_SLASH.match(v)
    if m:
        return f"{m.group(3)}-{m.group(2).zfill(2)}-{m.group(1).zfill(2)}"

    return v  # return as-is if unrecognised


# ──────────────────────────────────────────────
# Person key derivation
# ──────────────────────────────────────────────

def derive_person_key(extracted: Dict[str, Any]) -> Tuple[str, str]:
    """Derive a stable person key from extracted document data.

    Returns (person_key, key_source) where key_source indicates which
    identifier was used.

    Priority:
      1. Normalised CURP
      2. Normalised RFC
      3. Normalised claveElector
      4. normalisedName + birthDate  (weak)
      5. documentId hash fallback    (NEEDS_REVIEW)
    """
    ids = extracted.get("identifiers") or {}
    person = extracted.get("person") or {}

    curp = normalize_identifier(ids.get("curp"), "curp")
    if curp and len(curp) == 18:
        return f"CURP:{curp}", "curp"

    rfc = normalize_identifier(ids.get("rfc"), "rfc")
    if rfc and len(rfc) >= 12:
        return f"RFC:{rfc}", "rfc"

    clave = normalize_identifier(ids.get("claveElector"), "claveElector")
    if clave and len(clave) >= 10:
        return f"CLAVE:{clave}", "claveElector"

    name = normalize_name(person.get("fullName"))
    dob = normalize_date(person.get("dob"))
    if name and dob:
        return f"NAME_DOB:{name}|{dob}", "name_dob"

    # Ultimate fallback — use documentId
    doc_id = extracted.get("documentId", "unknown")
    return f"DOCID:{doc_id}", "document_fallback"


# ──────────────────────────────────────────────
# Grouping
# ──────────────────────────────────────────────

def group_documents_by_person(
    documents: List[Dict[str, Any]],
) -> Dict[str, List[Dict[str, Any]]]:
    """Group a list of extracted documents by person key.

    Documents with conflicting strong identifiers are never merged.
    """
    groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for doc in documents:
        person_key, _source = derive_person_key(doc)
        groups[person_key].append(doc)

    return dict(groups)


# ──────────────────────────────────────────────
# Field merging
# ──────────────────────────────────────────────

# Priority of document sub-types for each field
_FIELD_DOC_PRIORITY: Dict[str, List[str]] = {
    "curp": ["curp_doc", "ine_mx", "personal_doc"],
    "rfc": ["rfc_doc", "constancia_fiscal", "personal_doc", "ine_mx"],
    "claveElector": ["ine_mx", "personal_doc"],
    "cic": ["ine_mx"],
    "ocr_id": ["ine_mx"],
    "mrz": ["passport", "ine_mx"],
    "nss": ["nss_doc", "personal_doc"],
    "fullName": ["ine_mx", "passport", "personal_doc"],
    "dob": ["ine_mx", "passport", "curp_doc", "personal_doc"],
    "sex": ["ine_mx", "passport", "curp_doc", "personal_doc"],
    "nationality": ["passport", "ine_mx", "personal_doc"],
    "address": ["comprobante_domicilio", "ine_mx", "personal_doc"],
}


def _pick_best_value(
    candidates: List[Tuple[Any, str, Optional[float]]],
    field_name: str,
) -> Tuple[Any, Dict[str, Any]]:
    """Pick the best value from candidates (value, docType, confidence).

    Returns (chosen_value, field_source_info).
    """
    if not candidates:
        return None, {}

    priority = _FIELD_DOC_PRIORITY.get(field_name, [])

    def sort_key(item: Tuple[Any, str, Optional[float]]) -> Tuple[int, float]:
        val, doc_type, conf = item
        try:
            prio_idx = priority.index(doc_type)
        except ValueError:
            prio_idx = 999
        return (prio_idx, -(conf or 0.0))

    candidates.sort(key=sort_key)
    best_val, best_type, best_conf = candidates[0]

    source = {
        "documentType": best_type,
        "confidence": best_conf,
    }
    return best_val, source


def merge_profile_fields(
    group: List[Dict[str, Any]],
    person_key: str,
) -> Dict[str, Any]:
    """Merge fields from a group of documents for the same person.

    Returns a profile dict with merged data, field sources, missing fields,
    and warnings.
    """
    warnings: List[Dict[str, Any]] = []
    field_sources: Dict[str, Any] = {}

    # Collect candidates per field
    id_candidates: Dict[str, List[Tuple[Any, str, Optional[float]]]] = defaultdict(list)
    person_candidates: Dict[str, List[Tuple[Any, str, Optional[float]]]] = defaultdict(list)
    source_documents: List[Dict[str, Any]] = []

    for doc in group:
        doc_id = doc.get("documentId", "")
        doc_type = doc.get("subType") or doc.get("docType") or "personal_doc"
        batch_id = doc.get("batchId", "")
        overall_conf = doc.get("overallConfidence")

        ids = doc.get("identifiers") or {}
        person = doc.get("person") or {}

        used_fields: List[str] = []

        # Identifiers
        for id_field in ["curp", "rfc", "claveElector", "cic", "ocr", "mrz"]:
            val = ids.get(id_field)
            if val and str(val).lower() not in ("null", "none", ""):
                norm_val = normalize_identifier(val, id_field) if id_field in ("curp", "rfc", "claveElector") else val
                id_candidates[id_field].append((norm_val, doc_type, overall_conf))
                used_fields.append(id_field)

        # Person fields
        for p_field in ["fullName", "givenNames", "surnames", "dob", "sex", "nationality", "address"]:
            val = person.get(p_field)
            if val and str(val).lower() not in ("null", "none", ""):
                norm_val = val
                if p_field == "dob":
                    norm_val = normalize_date(val)
                person_candidates[p_field].append((norm_val, doc_type, overall_conf))
                used_fields.append(p_field)

        source_documents.append({
            "documentId": doc_id,
            "documentType": doc_type,
            "batchId": batch_id,
            "status": "COMPLETED",
            "usedFields": used_fields,
        })

    # Merge identifiers
    identifiers: Dict[str, Optional[str]] = {}
    for id_field in ["curp", "rfc", "claveElector", "cic", "ocr", "mrz"]:
        cands = id_candidates.get(id_field, [])
        if cands:
            chosen, source = _pick_best_value(cands, id_field)
            identifiers[id_field] = chosen
            field_sources[id_field] = source

            # Check for conflicts
            unique_vals = set(c[0] for c in cands if c[0])
            if len(unique_vals) > 1:
                warnings.append({
                    "code": f"CONFLICT_{id_field.upper()}",
                    "severity": "WARN",
                    "message": f"Multiple different values found for {id_field}: {len(unique_vals)} variants",
                })
        else:
            identifiers[id_field] = None

    # Merge person fields
    person_data: Dict[str, Optional[str]] = {}
    for p_field in ["fullName", "givenNames", "surnames", "dob", "sex", "nationality", "address"]:
        cands = person_candidates.get(p_field, [])
        if cands:
            chosen, source = _pick_best_value(cands, p_field)
            person_data[p_field] = chosen
            field_sources[p_field] = source
        else:
            person_data[p_field] = None

    # Calculate missing fields
    recommended = ["fullName", "dob", "sex", "nationality", "curp", "rfc", "claveElector", "address"]
    present_vals = {**{k: v for k, v in identifiers.items() if v}, **{k: v for k, v in person_data.items() if v}}
    missing_fields = [f for f in recommended if f not in present_vals]

    # Calculate completeness
    completeness = calculate_completeness(identifiers, person_data)

    # Determine status
    has_strong_id = any(identifiers.get(k) for k in ("curp", "rfc", "claveElector"))
    has_name = bool(person_data.get("fullName"))

    if person_key.startswith("DOCID:") or person_key.startswith("NAME_DOB:"):
        status = "NEEDS_REVIEW"
        if not has_strong_id:
            warnings.append({
                "code": "NO_STRONG_IDENTIFIER",
                "severity": "WARN",
                "message": "No CURP, RFC, or clave de elector found. Profile may need manual review.",
            })
    elif len(missing_fields) <= 2 and has_name and has_strong_id:
        status = "COMPLETE"
    else:
        status = "PARTIAL"

    return {
        "personKey": person_key,
        "status": status,
        "completenessScore": completeness,
        "fullName": person_data.get("fullName"),
        "firstNames": person_data.get("givenNames"),
        "lastNames": person_data.get("surnames"),
        "birthDate": person_data.get("dob"),
        "sex": person_data.get("sex"),
        "nationality": person_data.get("nationality"),
        "address": person_data.get("address"),
        "identifiers": identifiers,
        "fieldSources": field_sources,
        "sourceDocuments": source_documents,
        "missingFields": missing_fields,
        "warnings": warnings,
    }


def calculate_completeness(
    identifiers: Dict[str, Optional[str]],
    person_data: Dict[str, Optional[str]],
) -> float:
    """Calculate a 0.0–1.0 completeness score.

    Weights:
      - fullName: 20%
      - CURP: 15%
      - RFC: 10%
      - claveElector: 5%
      - dob: 15%
      - sex: 5%
      - nationality: 5%
      - address: 10%
      - givenNames + surnames: 5% each
      - cic/ocr/mrz: 5% combined bonus
    """
    weights = {
        "fullName": 0.20,
        "curp": 0.15,
        "rfc": 0.10,
        "claveElector": 0.05,
        "dob": 0.15,
        "sex": 0.05,
        "nationality": 0.05,
        "address": 0.10,
        "givenNames": 0.05,
        "surnames": 0.05,
    }

    score = 0.0
    all_vals = {**person_data, **identifiers}
    for field, weight in weights.items():
        if all_vals.get(field):
            score += weight

    # Bonus for having secondary ID fields
    if any(identifiers.get(k) for k in ("cic", "ocr", "mrz")):
        score += 0.05

    return round(min(score, 1.0), 2)


def build_profile_id(tenant_id: str, batch_id: str, person_key: str) -> str:
    """Deterministic profile ID from tenant + batch + person key."""
    raw = f"{tenant_id}|{batch_id}|{person_key}"
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


def build_job_id(tenant_id: str, batch_id: str, options_hash: str) -> str:
    """Deterministic job ID from tenant + batch + options."""
    raw = f"{tenant_id}|{batch_id}|{options_hash}"
    return hashlib.sha256(raw.encode()).hexdigest()[:24]
