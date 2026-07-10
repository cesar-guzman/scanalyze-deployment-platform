"""Pure utility functions for Employee Profiles — no AWS dependencies.

These functions are extracted from the service module so they can be
tested without boto3/botocore installed.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, List


# Sanitise tenant key for S3 — only allow alphanumeric, hyphens, underscores
_SAFE_KEY_RE = re.compile(r"[^a-zA-Z0-9_-]")


def sanitise_key(value: str) -> str:
    """Sanitise a value for safe use in S3 keys."""
    return _SAFE_KEY_RE.sub("_", value.strip())[:128]


def compute_source_fingerprint(
    tenant: str,
    batch_id: str,
    options: Dict[str, Any],
    eligible_docs: List[Dict[str, Any]],
) -> str:
    """P0.7: Deterministic fingerprint of the source data set.

    Includes documentId, classification, status, updatedAt, and artifact keys
    so that if new documents arrive or change, the fingerprint changes.
    """
    parts = [tenant, batch_id, json.dumps(options, sort_keys=True, default=str)]
    for doc in sorted(eligible_docs, key=lambda d: d.get("documentId", "")):
        doc_sig = "|".join([
            doc.get("documentId", ""),
            doc.get("classificationRoute", "") or doc.get("docType", ""),
            doc.get("status", ""),
            doc.get("updatedAt", "") or doc.get("createdAt", ""),
        ])
        # Include artifact key if available
        stages = doc.get("stages") or {}
        persist = stages.get("persist") or {}
        art_ref = persist.get("artifactRef") or {}
        if art_ref.get("key"):
            doc_sig += f"|{art_ref['key']}"
        parts.append(doc_sig)
    raw = "\n".join(parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def strip_internal_paths(field_sources: Dict[str, Any]) -> Dict[str, Any]:
    """P1.3: Remove any S3 bucket/key info from field sources before sending to frontend."""
    cleaned: Dict[str, Any] = {}
    for field, info in field_sources.items():
        if isinstance(info, dict):
            cleaned[field] = {
                k: v for k, v in info.items()
                if k not in ("bucket", "key", "s3Key", "s3Bucket")
            }
        else:
            cleaned[field] = info
    return cleaned


def options_hash(options: Dict[str, Any]) -> str:
    """Deterministic hash of generation options."""
    raw = json.dumps(options, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]
