from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter, Depends, Path, status
from fastapi.responses import StreamingResponse, FileResponse

from ...auth import AuthContext
from ...authorization import require_operation
from ...enterprise_authorization import OperationId
from ...logging import bind_context
from ...services.batches import BatchesService
from .models import (
    BatchCreateRequest,
    BatchResponse,
    BatchManifestResponse
)

router = APIRouter()

_CREATE_BATCH_ACCESS = require_operation(OperationId.BATCHES_CREATE)
_READ_BATCH_ACCESS = require_operation(OperationId.BATCHES_READ_METADATA)
_EXECUTE_EXPORT_ACCESS = require_operation(OperationId.EXPORTS_EXECUTE)

def _svc() -> BatchesService:
    return BatchesService()

@router.post(
    "",
    response_model=BatchResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_batch(
    req: BatchCreateRequest,
    auth: AuthContext = Depends(_CREATE_BATCH_ACCESS),
    svc: BatchesService = Depends(_svc),
) -> dict:
    bind_context(tenant=auth.tenant)
    return svc.create_batch(
        auth=auth,
        subject=auth.subject,
        email=auth.email,
        name=auth.name,
        metadata=req.metadata,
    )

@router.get(
    "/{batch_id}",
    response_model=BatchResponse,
)
def get_batch(
    auth: AuthContext = Depends(_READ_BATCH_ACCESS),
    svc: BatchesService = Depends(_svc),
    batch_id: str = Path(..., min_length=8, max_length=128),
) -> dict:
    bind_context(tenant=auth.tenant, batchId=batch_id)
    return svc.get_batch(auth=auth, batch_id=batch_id)

@router.get(
    "/{batch_id}/documents",
    response_model=List[Dict[str, Any]],
)
def get_batch_documents(
    auth: AuthContext = Depends(_READ_BATCH_ACCESS),
    svc: BatchesService = Depends(_svc),
    batch_id: str = Path(..., min_length=8, max_length=128),
) -> List[Dict[str, Any]]:
    bind_context(tenant=auth.tenant, batchId=batch_id)
    return svc.get_batch_documents(auth=auth, batch_id=batch_id)

@router.get(
    "/{batch_id}/manifest",
    response_model=BatchManifestResponse,
)
def export_manifest(
    auth: AuthContext = Depends(_EXECUTE_EXPORT_ACCESS),
    svc: BatchesService = Depends(_svc),
    batch_id: str = Path(..., min_length=8, max_length=128),
) -> dict:
    bind_context(tenant=auth.tenant, batchId=batch_id)
    return svc.export_manifest(auth=auth, batch_id=batch_id)

@router.get(
    "/{batch_id}/exports/json",
    response_class=StreamingResponse,
)
def export_json(
    auth: AuthContext = Depends(_EXECUTE_EXPORT_ACCESS),
    svc: BatchesService = Depends(_svc),
    batch_id: str = Path(..., min_length=8, max_length=128),
) -> StreamingResponse:
    bind_context(tenant=auth.tenant, batchId=batch_id)
    return svc.export_json(auth=auth, batch_id=batch_id)

@router.get(
    "/{batch_id}/exports/csv",
    response_class=StreamingResponse,
)
def export_csv(
    auth: AuthContext = Depends(_EXECUTE_EXPORT_ACCESS),
    svc: BatchesService = Depends(_svc),
    batch_id: str = Path(..., min_length=8, max_length=128),
) -> StreamingResponse:
    bind_context(tenant=auth.tenant, batchId=batch_id)
    return svc.export_csv(auth=auth, batch_id=batch_id)

@router.get(
    "/{batch_id}/exports/zip",
    response_class=FileResponse,
)
def export_zip(
    auth: AuthContext = Depends(_EXECUTE_EXPORT_ACCESS),
    svc: BatchesService = Depends(_svc),
    batch_id: str = Path(..., min_length=8, max_length=128),
) -> FileResponse:
    bind_context(tenant=auth.tenant, batchId=batch_id)
    return svc.export_zip(auth=auth, batch_id=batch_id)
