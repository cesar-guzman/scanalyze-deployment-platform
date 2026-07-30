"""Export utilities for Employee Profiles — JSON and CSV."""
from __future__ import annotations

import csv
import io
import json
from typing import Any, Dict, List

from ..csv_safety import neutralize_csv_cell
from .employee_profiles_masking import project_masked_profile


def export_profile_json(profile: Dict[str, Any], mask_pii: bool = False) -> str:
    """Export a single profile as a pretty-printed JSON string."""
    if mask_pii:
        profile = project_masked_profile(profile)
    return json.dumps(profile, indent=2, ensure_ascii=False, default=str)


def export_profiles_csv(profiles: List[Dict[str, Any]], mask_pii: bool = False) -> str:
    """Export a list of profiles as a CSV string.

    P0.8: By default exports FULL (unmasked) PII for authenticated users.
    Set mask_pii=True to use the closed non-identifying profile projection.
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
        if mask_pii:
            p = project_masked_profile(p)
        ids = p.get("identifiers") or {}
        curp_val = ids.get("curp", "")
        rfc_val = ids.get("rfc", "")
        clave_val = ids.get("claveElector", "")

        writer.writerow(
            neutralize_csv_cell(value)
            for value in [
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
            ]
        )

    return output.getvalue()
