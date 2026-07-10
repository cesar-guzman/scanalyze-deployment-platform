"""PII masking utilities for employee profiles.

Centralised masking functions so that CURP/RFC/claveElector are never exposed
in list endpoints or logs.  Every function is pure & deterministic so it is
easily testable.
"""
from __future__ import annotations

from typing import Optional


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
