from __future__ import annotations

from fastapi import APIRouter, Depends, Path, status

from ...auth import AuthContext
from ...authorization import require_operation
from ...enterprise_authorization import OperationId
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

_CREATE_DOCUMENT_ACCESS = require_operation(OperationId.DOCUMENTS_CREATE)
_SUBMIT_DOCUMENT_ACCESS = require_operation(OperationId.DOCUMENTS_SUBMIT)
_READ_DOCUMENT_ACCESS = require_operation(OperationId.DOCUMENTS_READ_METADATA)
_READ_FULL_RESULT_ACCESS = require_operation(OperationId.RESULTS_READ_FULL)
_LIST_ARTIFACTS_ACCESS = require_operation(OperationId.ARTIFACTS_LIST_METADATA)
_DOWNLOAD_ARTIFACT_ACCESS = require_operation(OperationId.ARTIFACTS_DOWNLOAD)

def _svc() -> DocumentsService:
    return DocumentsService()

@router.post(
    "",
    response_model=CreateDocumentResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_document(
    req: CreateDocumentRequest,
    auth: AuthContext = Depends(_CREATE_DOCUMENT_ACCESS),
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
    auth: AuthContext = Depends(_SUBMIT_DOCUMENT_ACCESS),
    svc: DocumentsService = Depends(_svc),
    document_id: str = Path(..., min_length=8, max_length=128),
) -> dict:
    # Request input never enters logging context. The service binds only the
    # reviewed canonical stage after validating this optional confirmation.
    bind_context(tenant=auth.tenant, documentId=document_id)
    return svc.submit_document(auth=auth, document_id=document_id, stage=req.stage)

@router.get(
    "/{document_id}",
    response_model=DocumentStatusResponse,
)
def get_document(
    auth: AuthContext = Depends(_READ_DOCUMENT_ACCESS),
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
    auth: AuthContext = Depends(_READ_FULL_RESULT_ACCESS),
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
    auth: AuthContext = Depends(_LIST_ARTIFACTS_ACCESS),
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
    auth: AuthContext = Depends(_DOWNLOAD_ARTIFACT_ACCESS),
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
    auth: AuthContext = Depends(_DOWNLOAD_ARTIFACT_ACCESS),
    svc: DocumentsService = Depends(_svc),
    document_id: str = Path(..., min_length=8, max_length=128),
    artifact_id: str = Path(..., min_length=2, max_length=2048),
) -> dict:
    bind_context(tenant=auth.tenant, documentId=document_id)
    return svc.presign_artifact_download(auth=auth, document_id=document_id, artifact_id=artifact_id)
