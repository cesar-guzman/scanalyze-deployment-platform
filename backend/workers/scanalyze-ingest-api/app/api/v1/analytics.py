from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter, Depends, Query, status

from ...auth import AuthContext
from ...authorization import require_export_access, require_read_access
from ...logging import bind_context
from ...services.analytics import AnalyticsService

router = APIRouter()

def _svc() -> AnalyticsService:
    return AnalyticsService()

@router.get(
    "/dashboard",
    response_model=Dict[str, Any]
)
def get_dashboard(
    startDate: str = Query(None, alias="startDate"),
    endDate: str = Query(None, alias="endDate"),
    docType: str = Query(None, alias="docType"),
    batchId: str = Query(None, alias="batchId"),
    status: str = Query(None, alias="status"),
    auth: AuthContext = Depends(require_read_access),
    svc: AnalyticsService = Depends(_svc),
) -> dict:
    bind_context(tenant=auth.tenant)
    return svc.get_dashboard(
        auth=auth,
        start_date=startDate,
        end_date=endDate,
        doc_type=docType,
        batch_id=batchId,
        status=status
    )

@router.get(
    "/overview",
    response_model=Dict[str, Any],
)
def get_overview(
    auth: AuthContext = Depends(require_read_access),
    svc: AnalyticsService = Depends(_svc),
) -> dict:
    bind_context(tenant=auth.tenant)
    return svc.get_overview(auth=auth)

@router.get(
    "/pages-by-user",
    response_model=List[Dict[str, Any]],
)
def get_by_user(
    auth: AuthContext = Depends(require_read_access),
    svc: AnalyticsService = Depends(_svc),
) -> List[Dict[str, Any]]:
    bind_context(tenant=auth.tenant)
    return svc.get_by_user(auth=auth)

@router.get(
    "/by-day",
    response_model=List[Dict[str, Any]],
)
def get_by_day(
    auth: AuthContext = Depends(require_read_access),
    svc: AnalyticsService = Depends(_svc),
) -> List[Dict[str, Any]]:
    bind_context(tenant=auth.tenant)
    return svc.get_by_day(auth=auth)

@router.get(
    "/by-batch",
    response_model=List[Dict[str, Any]],
)
def get_by_batch(
    auth: AuthContext = Depends(require_read_access),
    svc: AnalyticsService = Depends(_svc),
) -> List[Dict[str, Any]]:
    bind_context(tenant=auth.tenant)
    return svc.get_by_batch(auth=auth)

@router.get(
    "/by-doc-type",
    response_model=List[Dict[str, Any]],
)
def get_by_doc_type(
    auth: AuthContext = Depends(require_read_access),
    svc: AnalyticsService = Depends(_svc),
) -> List[Dict[str, Any]]:
    bind_context(tenant=auth.tenant)
    return svc.get_by_doc_type(auth=auth)

@router.get(
    "/costs",
    response_model=Dict[str, Any],
)
def get_costs_dashboard(
    auth: AuthContext = Depends(require_read_access),
    svc: AnalyticsService = Depends(_svc),
) -> dict:
    bind_context(tenant=auth.tenant)
    return svc.get_costs_dashboard(auth=auth)

@router.get(
    "/export-ine",
    responses={
        200: {
            "content": {"text/csv": {}},
            "description": "Returns a CSV file containing INE data extracts."
        }
    }
)
def export_ine(
    startDate: str = Query(None, alias="startDate"),
    endDate: str = Query(None, alias="endDate"),
    userId: str = Query(None, alias="userId"),
    auth: AuthContext = Depends(require_export_access),
    svc: AnalyticsService = Depends(_svc),
):
    bind_context(tenant=auth.tenant)
    return svc.export_ine_data(
        auth=auth,
        start_date=startDate,
        end_date=endDate,
        user_id=userId
    )
