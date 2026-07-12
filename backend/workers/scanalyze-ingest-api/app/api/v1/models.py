from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, model_validator


_NORMALIZED_IDENTITY_AUTHORITY_FIELDS = frozenset({
    "customerid",
    "deploymentid",
    "tenantid",
    "xtenantid",
})


class _IdentitySafeRequestModel(BaseModel):
    """Reject identity authority while preserving unrelated extension fields."""

    @model_validator(mode="before")
    @classmethod
    def _reject_identity_authority(cls, value: Any) -> Any:
        if isinstance(value, Mapping):
            normalized_keys = {
                key.replace("_", "").replace("-", "").lower()
                for key in value
                if isinstance(key, str)
            }
            if _NORMALIZED_IDENTITY_AUTHORITY_FIELDS.intersection(normalized_keys):
                raise ValueError("Request payload must not contain identity authority fields")
        return value


class ErrorEnvelope(BaseModel):
    code: str
    message: str
    details: Dict[str, Any] = Field(default_factory=dict)

class CreateDocumentRequest(_IdentitySafeRequestModel):
    filename: Optional[str] = Field(default=None, description="Original filename (optional)")
    contentType: str = Field(..., description="MIME type, e.g. application/pdf")
    contentLength: Optional[int] = Field(default=None, ge=0, description="Bytes (optional)")
    batchId: Optional[str] = Field(default=None, description="Batch ID (optional)")

class CreateDocumentResponse(BaseModel):
    documentId: str
    uploadUrl: str
    expiresAt: str
    uploadMethod: str = "PUT"
    requiredHeaders: Dict[str, str] = Field(default_factory=dict)

class SubmitDocumentRequest(_IdentitySafeRequestModel):
    stage: Optional[str] = Field(default=None, description="Override FIRST_STAGE (optional)")

class SubmitDocumentResponse(BaseModel):
    documentId: str
    stage: str
    enqueued: bool
    sqsMessageId: Optional[str] = None
    message: Optional[str] = None

class DocumentStatusResponse(BaseModel):
    documentId: str
    tenantId: Optional[str] = None
    batchId: Optional[str] = None
    status: Optional[str] = None
    createdAt: Optional[str] = None
    updatedAt: Optional[str] = None
    uploaderUserId: Optional[str] = None
    correlationId: Optional[str] = None
    input: Dict[str, Any] = Field(default_factory=dict)
    stages: Dict[str, Any] = Field(default_factory=dict)

class BatchCreateRequest(_IdentitySafeRequestModel):
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Custom metadata for the batch")

class BatchResponse(BaseModel):
    batchId: str
    tenantId: str
    createdAt: str
    createdBy: Optional[str] = None
    status: str
    metadata: Dict[str, Any] = Field(default_factory=dict)

class ArtifactItem(BaseModel):
    artifactId: str
    bucketAlias: str
    uri: str

class ListArtifactsResponse(BaseModel):
    documentId: str
    prefix: str
    artifacts: List[ArtifactItem]

class PresignDownloadResponse(BaseModel):
    documentId: str
    artifactId: str
    downloadUrl: str
    expiresAt: str

class ResultResponse(PresignDownloadResponse):
    pass

class BatchManifestDocument(BaseModel):
    batchId: str
    documentId: str
    docType: Optional[str] = None
    status: str
    generatedAt: Optional[str] = None
    artifactReferences: List[Dict[str, Any]] = Field(default_factory=list)
    errorCode: Optional[str] = None
    errorMessage: Optional[str] = None

class BatchManifestSummary(BaseModel):
    total: int = 0
    completed: int = 0
    failed: int = 0
    pending: int = 0

class BatchManifestResponse(BaseModel):
    manifestVersion: str = "1.0"
    batchId: str
    generatedAt: str
    summary: BatchManifestSummary
    documents: List[BatchManifestDocument]
