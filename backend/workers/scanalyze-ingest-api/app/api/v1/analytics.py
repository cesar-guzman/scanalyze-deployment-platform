from __future__ import annotations

from typing import Any, Dict, List, Literal

from fastapi import APIRouter, Depends, Query, Request, Response, status

from ...auth import AuthContext
from ...authorization import require_operation
from ...enterprise_authorization import OperationId
from ...errors import AppError
from ...logging import bind_context
from ...services.analytics import AnalyticsService

router = APIRouter()

_READ_IDENTIFIED_METRICS_ACCESS = require_operation(
    OperationId.METRICS_READ_IDENTIFIED
)
_READ_METRICS_ACCESS = require_operation(OperationId.METRICS_READ)
_EXECUTE_EXPORT_ACCESS = require_operation(OperationId.EXPORTS_EXECUTE)
_READ_DOCUMENT_ACCESS = require_operation(OperationId.DOCUMENTS_READ_METADATA)

def _svc() -> AnalyticsService:
    return AnalyticsService()


def _closed_query(request: Request, allowed: set[str]) -> None:
    if any(key not in allowed or len(request.query_params.getlist(key)) != 1 for key in request.query_params):
        raise AppError(code="VALIDATION_ERROR", message="Invalid bank query.", status_code=422, details={})


@router.get("/docs", response_model=Dict[str, Any])
def get_bank_documents(
    request: Request,
    response: Response,
    classRoute: Literal["bank-extract"] = Query("bank-extract"),
    limit: int = Query(50, ge=1, le=100),
    cursor: str | None = Query(None, pattern=r"^v1:[0-9a-f]{32}:[0-9a-f]{64}$", max_length=100),
    auth: AuthContext = Depends(_READ_DOCUMENT_ACCESS),
    svc: AnalyticsService = Depends(_svc),
) -> dict:
    _closed_query(request, {"classRoute", "limit", "cursor"})
    response.headers["Cache-Control"] = "no-store"
    return svc.get_bank_documents(auth=auth, limit=limit, cursor=cursor)


@router.get("/export-bank", responses={200: {"content": {"text/csv": {}}}})
def export_bank(
    request: Request,
    documentIds: str = Query(..., min_length=32, max_length=329),
    auth: AuthContext = Depends(_EXECUTE_EXPORT_ACCESS),
    svc: AnalyticsService = Depends(_svc),
) -> Response:
    _closed_query(request, {"documentIds"})
    return svc.export_bank_data(auth=auth, document_ids=documentIds)

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
    auth: AuthContext = Depends(_READ_IDENTIFIED_METRICS_ACCESS),
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
    auth: AuthContext = Depends(_READ_METRICS_ACCESS),
    svc: AnalyticsService = Depends(_svc),
) -> dict:
    bind_context(tenant=auth.tenant)
    return svc.get_overview(auth=auth)

@router.get(
    "/pages-by-user",
    response_model=List[Dict[str, Any]],
)
def get_by_user(
    auth: AuthContext = Depends(_READ_IDENTIFIED_METRICS_ACCESS),
    svc: AnalyticsService = Depends(_svc),
) -> List[Dict[str, Any]]:
    bind_context(tenant=auth.tenant)
    return svc.get_by_user(auth=auth)

@router.get(
    "/by-day",
    response_model=List[Dict[str, Any]],
)
def get_by_day(
    auth: AuthContext = Depends(_READ_METRICS_ACCESS),
    svc: AnalyticsService = Depends(_svc),
) -> List[Dict[str, Any]]:
    bind_context(tenant=auth.tenant)
    return svc.get_by_day(auth=auth)

@router.get(
    "/by-batch",
    response_model=List[Dict[str, Any]],
)
def get_by_batch(
    auth: AuthContext = Depends(_READ_METRICS_ACCESS),
    svc: AnalyticsService = Depends(_svc),
) -> List[Dict[str, Any]]:
    bind_context(tenant=auth.tenant)
    return svc.get_by_batch(auth=auth)

@router.get(
    "/by-doc-type",
    response_model=List[Dict[str, Any]],
)
def get_by_doc_type(
    auth: AuthContext = Depends(_READ_METRICS_ACCESS),
    svc: AnalyticsService = Depends(_svc),
) -> List[Dict[str, Any]]:
    bind_context(tenant=auth.tenant)
    return svc.get_by_doc_type(auth=auth)

@router.get(
    "/costs",
    response_model=Dict[str, Any],
)
def get_costs_dashboard(
    auth: AuthContext = Depends(_READ_METRICS_ACCESS),
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
    auth: AuthContext = Depends(_EXECUTE_EXPORT_ACCESS),
    svc: AnalyticsService = Depends(_svc),
):
    bind_context(tenant=auth.tenant)
    return svc.export_ine_data(
        auth=auth,
        start_date=startDate,
        end_date=endDate,
        user_id=userId
    )
