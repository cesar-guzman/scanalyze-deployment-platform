"""PII masking utilities for employee profiles.

Centralised masking functions so that CURP/RFC/claveElector are never exposed
in list endpoints or logs.  Every function is pure & deterministic so it is
easily testable.
"""
from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import re
from typing import Any, Optional


_REDACTED_PROFILE_NAME = "[REDACTED]"
_PROFILE_STATUS_VALUES = frozenset({"COMPLETE", "PARTIAL", "NEEDS_REVIEW"})
_SAFE_OBJECT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_IDENTIFIER_NAMES = ("curp", "rfc", "claveElector")


def mask_curp(value: Optional[str]) -> str:
    """Mask CURP keeping first 4 and last 2 chars visible.

    GARC850101HDFRRL09 → GARC**********09
    """
    if not value:
        return ""
    v = value.strip()
    if len(v) <= 6:
        return "*" * len(v)
    return v[:4] + "*" * (len(v) - 6) + v[-2:]


def mask_rfc(value: Optional[str]) -> str:
    """Mask RFC keeping first 4 and last 3 chars visible.

    GARC8501019A8 → GARC******9A8
    """
    if not value:
        return ""
    v = value.strip()
    if len(v) <= 7:
        return "*" * len(v)
    return v[:4] + "*" * (len(v) - 7) + v[-3:]


def mask_clave_elector(value: Optional[str]) -> str:
    """Mask clave de elector keeping first 4 and last 2 chars visible."""
    if not value:
        return ""
    v = value.strip()
    if len(v) <= 6:
        return "*" * len(v)
    return v[:4] + "*" * (len(v) - 6) + v[-2:]


def mask_identifier(value: Optional[str], id_type: str) -> str:
    """Dispatch masking by identifier type."""
    dispatch = {
        "curp": mask_curp,
        "rfc": mask_rfc,
        "claveElector": mask_clave_elector,
        "clave_elector": mask_clave_elector,
    }
    fn = dispatch.get(id_type, mask_curp)  # conservative default
    return fn(value)


def _safe_object_id(value: Any) -> str | None:
    if isinstance(value, str) and _SAFE_OBJECT_ID_PATTERN.fullmatch(value):
        return value
    return None


def _safe_profile_timestamp(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return value


def _safe_count(value: Any) -> int:
    return len(value) if isinstance(value, (list, tuple)) else 0


def project_masked_profile(profile: Mapping[str, Any]) -> dict[str, Any]:
    """Build the only supported masked profile representation.

    Stored ``maskedIdentifiers`` and all other free-form fields are ignored.
    Identifiers are deterministically remasked from scalar canonical values.
    """
    identifiers = profile.get("identifiers")
    masked_identifiers: dict[str, str] = {}
    if isinstance(identifiers, Mapping):
        for identifier_name in _IDENTIFIER_NAMES:
            value = identifiers.get(identifier_name)
            if isinstance(value, str) and value:
                masked_identifiers[identifier_name] = mask_identifier(
                    value,
                    identifier_name,
                )

    status = profile.get("status")
    safe_status = (
        status
        if isinstance(status, str) and status in _PROFILE_STATUS_VALUES
        else None
    )
    score = profile.get("completenessScore")
    safe_score = (
        float(score)
        if isinstance(score, (int, float))
        and not isinstance(score, bool)
        and 0 <= score <= 1
        else None
    )
    return {
        "profileId": _safe_object_id(profile.get("profileId")),
        "batchId": _safe_object_id(profile.get("batchId")),
        "fullName": _REDACTED_PROFILE_NAME,
        "status": safe_status,
        "completenessScore": safe_score,
        "identifiers": masked_identifiers,
        "maskedIdentifiers": masked_identifiers,
        "sourceDocumentCount": _safe_count(profile.get("sourceDocuments")),
        "missingFieldCount": _safe_count(profile.get("missingFields")),
        "warningCount": _safe_count(profile.get("warnings")),
        "generatedAt": _safe_profile_timestamp(profile.get("generatedAt")),
    }
