"""Canonical, provider-neutral document metadata contracts."""
from __future__ import annotations

from typing import Any


SUPPORTED_DOCUMENT_CONTENT_TYPES = frozenset(
    {
        "application/pdf",
        "image/jpeg",
        "image/png",
        "image/tiff",
    }
)


def canonical_document_content_type(value: Any) -> str | None:
    """Return a reviewed MIME value or ``None`` for legacy/poisoned input."""
    return (
        value
        if isinstance(value, str) and value in SUPPORTED_DOCUMENT_CONTENT_TYPES
        else None
    )


def public_document_content_type(value: Any) -> str:
    """Normalize unreviewed stored metadata before any response or aggregate."""
    return canonical_document_content_type(value) or "Unknown"
