"""Employee Profiles add-on API routes.

Namespace: /api/v1/addons/employee-profiles

P0.1: Route ordering — static routes BEFORE dynamic /{profileId}.
Order:
  1. GET  /status
  2. GET  /export/csv
  3. POST /generate
  4. GET  /jobs/{job_id}
  5. GET  /                        (list)
  6. GET  /{profile_id}/export/json
  7. GET  /{profile_id}/export/csv
  8. GET  /{profile_id}            (detail — LAST)
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Path, Query
from fastapi.responses import JSONResponse, Response

from ....auth import AuthContext
from ....authorization import (
    require_export_access,
    require_read_access,
    require_write_access,
)
from ....logging import bind_context, get_logger
from ....services.employee_profiles import EmployeeProfileService
from ....services.employee_profiles_export import export_profile_json, export_profiles_csv

router = APIRouter()
logger = get_logger()


def _svc() -> EmployeeProfileService:
    return EmployeeProfileService()


# ─────────────────────────────────────────────────
# 1. GET /status  (static — must be before /{profile_id})
# ─────────────────────────────────────────────────
@router.get("/status")
def get_feature_status(
    auth: AuthContext = Depends(require_read_access),
    svc: EmployeeProfileService = Depends(_svc),
) -> dict:
    """P0.4: Check if employee profiles feature is enabled for this tenant.

    Requires JWT. Does not expose tenant list.
    """
    return svc.get_status(auth.tenant)


# ─────────────────────────────────────────────────
# 2. GET /export/csv  (static — must be before /{profile_id})
# ─────────────────────────────────────────────────
@router.get("/export/csv")
def export_csv_batch(
    batchId: Optional[str] = Query(default=None),
    masked: bool = Query(default=False),
    auth: AuthContext = Depends(require_export_access),
    svc: EmployeeProfileService = Depends(_svc),
) -> Response:
    """P0.8: Export all profiles for a batch as downloadable CSV.

    By default exports full (unmasked) PII for authenticated users.
    Use ?masked=true to get masked output.
    """
    bind_context(tenant=auth.tenant)

    if not batchId:
        return JSONResponse(
            status_code=400,
            content={"code": "VALIDATION_ERROR", "message": "batchId query param is required", "details": {}},
        )

    # Load full profiles from batch manifest
    bucket = svc._structured_bucket()
    profiles_key = svc._batch_profiles_key(auth.tenant, batchId)
    data = svc._read_s3_json(bucket, profiles_key)
    profiles = data if isinstance(data, list) else []

    # Tenant guard
    profiles = [p for p in profiles if p.get("tenantId") == auth.tenant]

    csv_str = export_profiles_csv(profiles, mask_pii=masked)
    safe_batch = batchId[:24].replace("/", "_")
    return Response(
        content=csv_str,
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="employee_profiles_{safe_batch}.csv"',
        },
    )


# ─────────────────────────────────────────────────
# 3. POST /generate
# ─────────────────────────────────────────────────
@router.post("/generate", status_code=202)
def generate_profiles(
    body: dict,
    auth: AuthContext = Depends(require_write_access),
    svc: EmployeeProfileService = Depends(_svc),
) -> dict:
    """Generate employee profiles for a batch.

    Body:
      {
        "batchId": "string",
        "options": {"force": false, "includeIncomplete": false}
      }
    """
    bind_context(tenant=auth.tenant)

    batch_id = body.get("batchId")
    if not batch_id or not isinstance(batch_id, str) or len(batch_id) < 8:
        return JSONResponse(
            status_code=400,
            content={"code": "VALIDATION_ERROR", "message": "Valid batchId is required", "details": {}},
        )

    options = body.get("options") or {}
    result = svc.generate_profiles(
        tenant=auth.tenant,
        batch_id=batch_id,
        requested_by=auth.subject,
        options=options,
    )

    # 200 if existing/stale, 202 if new generation
    status_code = 200 if result.get("existing") else 202
    return JSONResponse(status_code=status_code, content=result)


# ─────────────────────────────────────────────────
# 4. GET /jobs/{job_id}
# ─────────────────────────────────────────────────
@router.get("/jobs/{job_id}")
def get_job_status(
    job_id: str = Path(..., min_length=8, max_length=128),
    batchId: Optional[str] = Query(default=None),
    auth: AuthContext = Depends(require_read_access),
    svc: EmployeeProfileService = Depends(_svc),
) -> dict:
    """Get generation job status."""
    bind_context(tenant=auth.tenant)
    return svc.get_job(tenant=auth.tenant, job_id=job_id, batch_id=batchId)


# ─────────────────────────────────────────────────
# 5. GET /  (list)
# ─────────────────────────────────────────────────
@router.get("")
def list_profiles(
    batchId: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    q: Optional[str] = Query(default=None, description="Search by name only"),
    limit: int = Query(default=50, ge=1, le=200),
    auth: AuthContext = Depends(require_export_access),
    svc: EmployeeProfileService = Depends(_svc),
) -> dict:
    """List employee profiles, filtered by batch/status/name.

    P0.5: q searches by name ONLY. Do not use for CURP/RFC lookups.
    """
    bind_context(tenant=auth.tenant)
    return svc.list_profiles(
        tenant=auth.tenant,
        batch_id=batchId,
        status_filter=status,
        q=q,
        limit=limit,
    )


# ─────────────────────────────────────────────────
# 6. GET /{profile_id}/export/json
# ─────────────────────────────────────────────────
@router.get("/{profile_id}/export/json")
def export_json(
    profile_id: str = Path(..., min_length=8, max_length=128),
    batchId: Optional[str] = Query(default=None),
    masked: bool = Query(default=False),
    auth: AuthContext = Depends(require_export_access),
    svc: EmployeeProfileService = Depends(_svc),
) -> Response:
    """P0.8: Export a single profile as downloadable JSON.

    Full PII by default for authenticated users. Use ?masked=true for masked.
    """
    bind_context(tenant=auth.tenant)
    profile = svc.get_profile(
        tenant=auth.tenant,
        profile_id=profile_id,
        batch_id=batchId,
    )
    if masked:
        # Replace raw identifiers with masked versions
        profile = {**profile, "identifiers": profile.get("maskedIdentifiers", {})}

    json_str = export_profile_json(profile)
    safe_id = profile_id[:24].replace("/", "_")
    return Response(
        content=json_str,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="profile_{safe_id}.json"',
        },
    )


# ─────────────────────────────────────────────────
# 7. GET /{profile_id}/export/csv  (P1.4: individual CSV)
# ─────────────────────────────────────────────────
@router.get("/{profile_id}/export/csv")
def export_csv_individual(
    profile_id: str = Path(..., min_length=8, max_length=128),
    batchId: Optional[str] = Query(default=None),
    masked: bool = Query(default=False),
    auth: AuthContext = Depends(require_export_access),
    svc: EmployeeProfileService = Depends(_svc),
) -> Response:
    """P1.4: Export a single profile as downloadable CSV."""
    bind_context(tenant=auth.tenant)
    profile = svc.get_profile(
        tenant=auth.tenant,
        profile_id=profile_id,
        batch_id=batchId,
    )
    csv_str = export_profiles_csv([profile], mask_pii=masked)
    safe_id = profile_id[:24].replace("/", "_")
    return Response(
        content=csv_str,
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="profile_{safe_id}.csv"',
        },
    )


# ─────────────────────────────────────────────────
# 8. GET /{profile_id}  (detail — MUST be LAST)
# ─────────────────────────────────────────────────
@router.get("/{profile_id}")
def get_profile(
    profile_id: str = Path(..., min_length=8, max_length=128),
    batchId: Optional[str] = Query(default=None),
    auth: AuthContext = Depends(require_export_access),
    svc: EmployeeProfileService = Depends(_svc),
) -> dict:
    """Get full profile detail. P0.2: No batchId required (direct S3 lookup)."""
    bind_context(tenant=auth.tenant)
    return svc.get_profile(
        tenant=auth.tenant,
        profile_id=profile_id,
        batch_id=batchId,
    )
