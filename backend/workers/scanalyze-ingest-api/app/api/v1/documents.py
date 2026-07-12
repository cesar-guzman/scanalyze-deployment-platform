from __future__ import annotations

from fastapi import APIRouter, Depends, Path, status

from ...auth import AuthContext
from ...authorization import (
    require_export_access,
    require_read_access,
    require_write_access,
)
from ...logging import bind_context
from ...services.documents import DocumentsService
from .models import (
    CreateDocumentRequest,
    CreateDocumentResponse,
    DocumentStatusResponse,
    ListArtifactsResponse,
    PresignDownloadResponse,
    ResultResponse,
    SubmitDocumentRequest,
    SubmitDocumentResponse,
)

router = APIRouter()

def _svc() -> DocumentsService:
    return DocumentsService()

@router.post(
    "",
    response_model=CreateDocumentResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_document(
    req: CreateDocumentRequest,
    auth: AuthContext = Depends(require_write_access),
    svc: DocumentsService = Depends(_svc),
) -> dict:
    # bind tenant en logs
    bind_context(tenant=auth.tenant)

    return svc.create_document(
        auth=auth,
        subject=auth.subject,
        email=auth.email,
        name=auth.name,
        filename=req.filename,
        content_type=req.contentType,
        content_length=req.contentLength,
        batch_id=req.batchId,
    )

@router.post(
    "/{document_id}/submit",
    response_model=SubmitDocumentResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def submit_document(
    req: SubmitDocumentRequest,
    auth: AuthContext = Depends(require_write_access),
    svc: DocumentsService = Depends(_svc),
    document_id: str = Path(..., min_length=8, max_length=128),
) -> dict:
    bind_context(tenant=auth.tenant, documentId=document_id, stage=req.stage or None)
    return svc.submit_document(auth=auth, document_id=document_id, stage=req.stage)

@router.get(
    "/{document_id}",
    response_model=DocumentStatusResponse,
)
def get_document(
    auth: AuthContext = Depends(require_read_access),
    svc: DocumentsService = Depends(_svc),
    document_id: str = Path(..., min_length=8, max_length=128),
) -> dict:
    bind_context(tenant=auth.tenant, documentId=document_id)
    return svc.get_document_status(auth=auth, document_id=document_id)

@router.get(
    "/{document_id}/result",
    response_model=ResultResponse,
)
def get_result(
    auth: AuthContext = Depends(require_export_access),
    svc: DocumentsService = Depends(_svc),
    document_id: str = Path(..., min_length=8, max_length=128),
) -> dict:
    bind_context(tenant=auth.tenant, documentId=document_id)
    return svc.get_result(auth=auth, document_id=document_id)

@router.get(
    "/{document_id}/artifacts",
    response_model=ListArtifactsResponse,
)
def list_artifacts(
    auth: AuthContext = Depends(require_read_access),
    svc: DocumentsService = Depends(_svc),
    document_id: str = Path(..., min_length=8, max_length=128),
) -> dict:
    bind_context(tenant=auth.tenant, documentId=document_id)
    return svc.list_artifacts(auth=auth, document_id=document_id)

@router.get(
    "/{document_id}/download",
    response_model=PresignDownloadResponse,
)
def download_generic(
    artifactId: str,
    auth: AuthContext = Depends(require_export_access),
    svc: DocumentsService = Depends(_svc),
    document_id: str = Path(..., min_length=8, max_length=128),
) -> dict:
    bind_context(tenant=auth.tenant, documentId=document_id)
    return svc.presign_artifact_download(auth=auth, document_id=document_id, artifact_id=artifactId)


@router.get(
    "/{document_id}/artifacts/{artifact_id}/download",
    response_model=PresignDownloadResponse,
)
def presign_download(
    auth: AuthContext = Depends(require_export_access),
    svc: DocumentsService = Depends(_svc),
    document_id: str = Path(..., min_length=8, max_length=128),
    artifact_id: str = Path(..., min_length=2, max_length=2048),
) -> dict:
    bind_context(tenant=auth.tenant, documentId=document_id)
    return svc.presign_artifact_download(auth=auth, document_id=document_id, artifact_id=artifact_id)
