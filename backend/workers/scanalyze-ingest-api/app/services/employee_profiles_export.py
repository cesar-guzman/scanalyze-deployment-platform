"""Export utilities for Employee Profiles — JSON and CSV."""
from __future__ import annotations

import csv
import io
import json
from typing import Any, Dict, List

from .employee_profiles_masking import mask_identifier


def export_profile_json(profile: Dict[str, Any]) -> str:
    """Export a single profile as a pretty-printed JSON string."""
    return json.dumps(profile, indent=2, ensure_ascii=False, default=str)


def export_profiles_csv(profiles: List[Dict[str, Any]], mask_pii: bool = False) -> str:
    """Export a list of profiles as a CSV string.

    P0.8: By default exports FULL (unmasked) PII for authenticated users.
    Set mask_pii=True to mask CURP/RFC/claveElector in output.
    """
    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        "profileId",
        "fullName",
        "firstNames",
        "lastNames",
        "birthDate",
        "sex",
        "nationality",
        "address",
        "curp",
        "rfc",
        "claveElector",
        "status",
        "completenessScore",
        "sourceDocumentCount",
        "missingFields",
        "warningCount",
        "generatedAt",
    ])

    for p in profiles:
        ids = p.get("identifiers") or {}
        curp_val = ids.get("curp", "")
        rfc_val = ids.get("rfc", "")
        clave_val = ids.get("claveElector", "")

        if mask_pii:
            curp_val = mask_identifier(curp_val, "curp")
            rfc_val = mask_identifier(rfc_val, "rfc")
            clave_val = mask_identifier(clave_val, "claveElector")

        writer.writerow([
            p.get("profileId", ""),
            p.get("fullName", ""),
            p.get("firstNames", ""),
            p.get("lastNames", ""),
            p.get("birthDate", ""),
            p.get("sex", ""),
            p.get("nationality", ""),
            (p.get("address") or "")[:100],  # truncate long addresses
            curp_val,
            rfc_val,
            clave_val,
            p.get("status", ""),
            p.get("completenessScore", 0),
            len(p.get("sourceDocuments") or []),
            "; ".join(p.get("missingFields") or []),
            len(p.get("warnings") or []),
            p.get("generatedAt", ""),
        ])

    return output.getvalue()
