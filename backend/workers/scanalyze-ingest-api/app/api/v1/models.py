from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator


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
    stage: Optional[str] = Field(
        default=None,
        description="Optional confirmation of the configured canonical FIRST_STAGE",
    )

class SubmitDocumentResponse(BaseModel):
    documentId: str
    stage: str
    enqueued: bool
    sqsMessageId: Optional[str] = None
    message: Optional[str] = None


class StoredObjectLocatorV2(BaseModel):
    """Stored, already-authorized locator carried as a non-authoritative hint."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    bucket: str = Field(min_length=1)
    key: str = Field(min_length=1)


class IngestEnvelopeMetadataV2(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    correlationId: str = Field(min_length=1)
    traceId: Optional[str] = Field(default=None, min_length=1)


class IngestEnvelopeV2(BaseModel):
    """Strict producer contract for the canonical async ingress boundary."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    schemaVersion: Literal["scanalyze.ingest.v2"] = "scanalyze.ingest.v2"
    documentId: str = Field(min_length=1, max_length=128)
    customer_id: str = Field(pattern=r"^cust_[0-9A-HJKMNP-TV-Z]{26}$")
    deployment_id: str = Field(pattern=r"^dep_[0-9A-HJKMNP-TV-Z]{26}$")
    ownership_schema_version: Literal[1] = 1
    pipeline_stage: Literal["ingest"] = "ingest"
    processing_domain: Optional[Literal["bank", "personal", "gov"]] = None
    enqueue_id: str = Field(min_length=1, max_length=128)
    raw: StoredObjectLocatorV2
    contentType: Optional[str] = None
    metadata: IngestEnvelopeMetadataV2 = Field(
        validation_alias="_metadata",
        serialization_alias="_metadata",
    )

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
