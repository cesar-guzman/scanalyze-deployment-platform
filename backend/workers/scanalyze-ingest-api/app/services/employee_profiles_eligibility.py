"""Document eligibility for worker profiles — shared helper.

Single source of truth for determining whether a classified document
is relevant for employee profile generation. Used by both:
- Lambda add-on (service.py)
- In-process ingest-api (employee_profiles.py)

Based on classifier v1.1 metadata: subType, canonicalDocType,
routeIntent, terminalReason, confidence.

Zero core imports. Pure logic.
"""
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple


# ── Classifier v1.1 subtype → EP category mapping ──
# Maps classifier subType to the employee-profiles document category
# used by adapters and checklist.

SUBTYPE_TO_CATEGORY: Dict[str, str] = {
    # Identity documents
    "ine_mx": "ine",
    "passport_mx": "ine",  # treated as identity doc
    "mx_driver_license": "ine",

    # CURP
    "curp_mx": "curp",

    # RFC / SAT
    "rfc_sat": "rfc",

    # NSS / IMSS
    "nss_imss": "nss",
    "imss_weeks_certificate": "nss",

    # Birth certificate
    "birth_certificate": "birth_certificate",

    # Bank
    "bank_statement_mx": "bank_statement",
    "bank_clabe": "bank_statement",

    # Education / Professional
    "professional_license_mx": "education",
    "professional_title_mx": "education",
    "technical_certificate": "education",
    "study_certificate": "education",

    # CV / Resume
    "cv_resume": "cv",

    # Recommendation
    "recommendation_letter": "recommendation",

    # Work certificate
    "labor_certificate": "work_certificate",

    # Payroll
    "payroll_cfdi_mx": "payroll",

    # Address proof (all utility bill variants)
    "address_proof_mx": "address_proof",
    "utility_bill_phone_internet": "address_proof",
    "utility_bill_cfe": "address_proof",
    "utility_bill_water": "address_proof",
    "utility_bill_gas": "address_proof",
}

# ── SubTypes that are NEVER eligible ──
# These are classifier v1.1 "junk" subtypes that should never
# participate in profile generation.
_DISCARD_SUBTYPES = frozenset({
    "blank_page",
    "low_text",
    "photo_only",
    "qr_only",
    "speed_test",
    "lorem_ipsum",
    "unknown",
})

# ── Documents that should go to review bucket instead of profile ──
_REVIEW_ROUTE_INTENTS = frozenset({
    "needs_review",
})

_DISCARD_ROUTE_INTENTS = frozenset({
    "discard",
})

_DISCARD_TERMINAL_REASONS = frozenset({
    "CLASSIFIER_DISCARD",
    "DISCARD",
})

_IRRELEVANT_CANONICAL_TYPES = frozenset({
    "irrelevant",
})

# ── Legacy route fallback for pre-v1.1 documents ──
_LEGACY_ELIGIBLE_ROUTES = frozenset({
    "personal-extract", "personal_extract", "personal_doc",
    "bank-extract", "bank_extract",
    "gov-extract", "gov_extract",
    "ine_mx", "ine", "passport", "mx_driver_license",
})

# ── Minimum confidence for auto-include ──
_MIN_CONFIDENCE_AUTO = 0.4
_MIN_CONFIDENCE_REVIEW = 0.2


# ── Public API ──

def supports_classifier_v11(doc: Dict[str, Any]) -> bool:
    """Check if a document was classified by classifier v1.1+.

    v1.1 documents have classification.subType and/or classification.routeIntent.
    Pre-v1.1 documents only have docType/classificationRoute.
    """
    classification = doc.get("classification") or {}
    stages = doc.get("stages") or {}
    classify_stage = stages.get("classify") or {}

    has_subtype = bool(
        classification.get("subType")
        or classify_stage.get("subType")
    )
    has_route_intent = bool(
        classification.get("routeIntent")
        or classify_stage.get("routeIntent")
    )
    return has_subtype or has_route_intent


def get_document_subtype(doc: Dict[str, Any]) -> str:
    """Extract the classifier subType from a document.

    Checks multiple locations in order of precedence:
    1. classification.subType
    2. stages.classify.subType
    3. Derived from docType/documentType
    """
    classification = doc.get("classification") or {}
    stages = doc.get("stages") or {}
    classify_stage = stages.get("classify") or {}

    sub = (
        classification.get("subType")
        or classify_stage.get("subType")
        or ""
    )
    if sub:
        return str(sub).strip()

    # Fallback: derive from docType for legacy docs
    doc_type = (
        doc.get("docType")
        or classification.get("documentType")
        or classify_stage.get("documentType")
        or classify_stage.get("docType")
        or ""
    )
    return str(doc_type).strip()


def _get_route_intent(doc: Dict[str, Any]) -> str:
    """Extract routeIntent from a document."""
    classification = doc.get("classification") or {}
    stages = doc.get("stages") or {}
    classify_stage = stages.get("classify") or {}

    return str(
        classification.get("routeIntent")
        or classify_stage.get("routeIntent")
        or ""
    ).strip()


def _get_terminal_reason(doc: Dict[str, Any]) -> str:
    """Extract terminalReason from a document."""
    classification = doc.get("classification") or {}
    stages = doc.get("stages") or {}
    classify_stage = stages.get("classify") or {}

    return str(
        classification.get("terminalReason")
        or classify_stage.get("terminalReason")
        or ""
    ).strip()


def _get_canonical_doc_type(doc: Dict[str, Any]) -> str:
    """Extract canonicalDocType from a document."""
    classification = doc.get("classification") or {}
    stages = doc.get("stages") or {}
    classify_stage = stages.get("classify") or {}

    return str(
        classification.get("canonicalDocType")
        or classify_stage.get("canonicalDocType")
        or ""
    ).strip()


def _get_confidence(doc: Dict[str, Any]) -> float:
    """Extract classification confidence from a document."""
    classification = doc.get("classification") or {}
    stages = doc.get("stages") or {}
    classify_stage = stages.get("classify") or {}

    conf = (
        classification.get("confidence")
        or classify_stage.get("confidence")
        or doc.get("overallConfidence")
    )
    if conf is not None:
        try:
            return float(conf)
        except (TypeError, ValueError):
            pass
    return 0.0


def _get_legacy_route(doc: Dict[str, Any]) -> str:
    """Extract legacy classification route for pre-v1.1 fallback."""
    route = (
        doc.get("classificationRoute")
        or doc.get("routingTarget")
        or doc.get("classification", {}).get("route", "")
        or ""
    )
    if not route:
        classify_stage = (doc.get("stages") or {}).get("classify") or {}
        route = classify_stage.get("route") or ""
    return str(route).lower().strip()


class EligibilityResult:
    """Result of document eligibility check."""

    __slots__ = ("eligible", "role", "reason", "review_required", "category")

    def __init__(
        self,
        eligible: bool,
        role: str = "",
        reason: str = "",
        review_required: bool = False,
        category: str = "",
    ):
        self.eligible = eligible
        self.role = role  # "identity", "financial", "education", "employment", etc.
        self.reason = reason  # human-readable reason
        self.review_required = review_required
        self.category = category  # EP category: "ine", "curp", "rfc", etc.

    def to_dict(self) -> Dict[str, Any]:
        return {
            "eligible": self.eligible,
            "role": self.role,
            "reason": self.reason,
            "reviewRequired": self.review_required,
            "category": self.category,
        }


# Role mapping from category
_CATEGORY_ROLES: Dict[str, str] = {
    "ine": "identity",
    "curp": "identity",
    "rfc": "fiscal",
    "nss": "social_security",
    "birth_certificate": "civil_registry",
    "bank_statement": "financial",
    "education": "education",
    "cv": "employment",
    "recommendation": "employment",
    "work_certificate": "employment",
    "payroll": "employment",
    "address_proof": "address",
    "photo": "identity",
    "unknown": "unknown",
}


def is_document_relevant_for_worker_profile(
    doc: Dict[str, Any],
) -> EligibilityResult:
    """Determine if a document should participate in worker profile generation.

    This is THE single source of truth for document eligibility.
    Both Lambda add-on and in-process ingest-api must use this function.

    Decision tree:
    1. Document must be COMPLETED status.
    2. If classifier v1.1: use subType, routeIntent, terminalReason, canonicalDocType.
    3. If legacy: use classificationRoute fallback.
    4. Discards and irrelevant docs → not eligible.
    5. Needs-review docs → eligible but flagged for review.
    6. Known subtypes → eligible with category mapping.
    7. Unknown subtypes → eligible but flagged for review.
    """
    status = (doc.get("status") or "").upper()
    if status != "COMPLETED":
        return EligibilityResult(
            eligible=False,
            reason="document_not_completed",
        )

    # ── Classifier v1.1 path ──
    if supports_classifier_v11(doc):
        return _evaluate_v11(doc)

    # ── Legacy path (pre-v1.1) ──
    return _evaluate_legacy(doc)


def _evaluate_v11(doc: Dict[str, Any]) -> EligibilityResult:
    """Evaluate eligibility using classifier v1.1 metadata."""
    sub_type = get_document_subtype(doc)
    route_intent = _get_route_intent(doc)
    terminal_reason = _get_terminal_reason(doc)
    canonical_type = _get_canonical_doc_type(doc)
    confidence = _get_confidence(doc)

    # 1. Hard discard: terminal reason
    if terminal_reason in _DISCARD_TERMINAL_REASONS:
        return EligibilityResult(
            eligible=False,
            reason=f"terminal_reason_discard:{terminal_reason}",
        )

    # 2. Hard discard: routeIntent=discard
    if route_intent in _DISCARD_ROUTE_INTENTS:
        return EligibilityResult(
            eligible=False,
            reason=f"route_intent_discard:{route_intent}",
        )

    # 3. Hard discard: canonicalDocType=irrelevant
    if canonical_type in _IRRELEVANT_CANONICAL_TYPES:
        return EligibilityResult(
            eligible=False,
            reason=f"canonical_type_irrelevant:{canonical_type}",
        )

    # 4. Hard discard: known junk subtypes
    if sub_type in _DISCARD_SUBTYPES:
        return EligibilityResult(
            eligible=False,
            reason=f"discard_subtype:{sub_type}",
        )

    # 5. Very low confidence → discard
    if confidence > 0 and confidence < _MIN_CONFIDENCE_REVIEW:
        return EligibilityResult(
            eligible=False,
            reason=f"confidence_too_low:{confidence:.2f}",
        )

    # 6. Needs-review → eligible but flagged
    if route_intent in _REVIEW_ROUTE_INTENTS:
        category = SUBTYPE_TO_CATEGORY.get(sub_type, "unknown")
        role = _CATEGORY_ROLES.get(category, "unknown")
        return EligibilityResult(
            eligible=True,
            role=role,
            reason=f"needs_review:{route_intent}",
            review_required=True,
            category=category,
        )

    # 7. Low confidence → eligible but flagged
    if 0 < confidence < _MIN_CONFIDENCE_AUTO:
        category = SUBTYPE_TO_CATEGORY.get(sub_type, "unknown")
        role = _CATEGORY_ROLES.get(category, "unknown")
        return EligibilityResult(
            eligible=True,
            role=role,
            reason=f"low_confidence:{confidence:.2f}",
            review_required=True,
            category=category,
        )

    # 8. Known subtype → eligible
    category = SUBTYPE_TO_CATEGORY.get(sub_type, "")
    if category:
        role = _CATEGORY_ROLES.get(category, "unknown")
        return EligibilityResult(
            eligible=True,
            role=role,
            reason=f"known_subtype:{sub_type}",
            review_required=False,
            category=category,
        )

    # 9. Unknown subtype but not discarded → eligible with review
    if sub_type:
        return EligibilityResult(
            eligible=True,
            role="unknown",
            reason=f"unknown_subtype:{sub_type}",
            review_required=True,
            category="unknown",
        )

    # 10. No subtype at all → fall back to legacy
    return _evaluate_legacy(doc)


def _evaluate_legacy(doc: Dict[str, Any]) -> EligibilityResult:
    """Evaluate eligibility using legacy classification route."""
    route = _get_legacy_route(doc)

    if not route:
        return EligibilityResult(
            eligible=False,
            reason="no_classification_route",
        )

    if route in _LEGACY_ELIGIBLE_ROUTES or "personal" in route or "ine" in route:
        # Legacy eligible — determine category from route
        category = _category_from_legacy_route(route)
        role = _CATEGORY_ROLES.get(category, "unknown")
        return EligibilityResult(
            eligible=True,
            role=role,
            reason=f"legacy_route:{route}",
            review_required=False,
            category=category,
        )

    # Legacy route not in eligible set
    return EligibilityResult(
        eligible=False,
        reason=f"legacy_route_not_eligible:{route}",
    )


def _category_from_legacy_route(route: str) -> str:
    """Derive EP category from a legacy classification route."""
    if "bank" in route:
        return "bank_statement"
    if "gov" in route:
        return "birth_certificate"  # conservative: gov goes to generic
    if "personal" in route or "ine" in route:
        return "ine"  # conservative default for personal route
    return "unknown"


def get_worker_profile_document_role(doc: Dict[str, Any]) -> str:
    """Get the role a document plays in a worker profile.

    Returns: "identity", "fiscal", "social_security", "financial",
             "education", "employment", "address", "civil_registry",
             "unknown", or "" if not eligible.
    """
    result = is_document_relevant_for_worker_profile(doc)
    return result.role if result.eligible else ""


def filter_eligible_documents(
    docs: list,
    tenant: str,
    include_incomplete: bool = False,
) -> Tuple[list, list, list]:
    """Filter a list of documents into eligible, review, and excluded.

    Returns:
        (eligible_docs, review_docs, excluded_docs)

    - eligible_docs: docs that should participate in profile generation.
    - review_docs: docs flagged for review (still participate but marked).
    - excluded_docs: docs that should not participate.

    All three lists contain the original doc dicts.
    """
    eligible = []
    review = []
    excluded = []

    for doc in docs:
        # Tenant guard
        doc_tenant = doc.get("tenantId", tenant)
        if doc_tenant != tenant:
            excluded.append(doc)
            continue

        # Allow incomplete if flag set
        status = (doc.get("status") or "").upper()
        if status != "COMPLETED" and not include_incomplete:
            excluded.append(doc)
            continue

        result = is_document_relevant_for_worker_profile(doc)
        if not result.eligible:
            excluded.append(doc)
        elif result.review_required:
            review.append(doc)
            eligible.append(doc)  # review docs still participate
        else:
            eligible.append(doc)

    return eligible, review, excluded
