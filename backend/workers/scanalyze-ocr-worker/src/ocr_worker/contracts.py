from typing import Annotated, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, StringConstraints


OWNERSHIP_SCHEMA_VERSION = 1

NonEmptyString = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
CustomerId = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        pattern=r"^cust_[0-9A-HJKMNP-TV-Z]{26}$",
    ),
]
DeploymentId = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        pattern=r"^dep_[0-9A-HJKMNP-TV-Z]{26}$",
    ),
]
DocumentId = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$",
    ),
]


class StrictContract(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class MessageMetadata(StrictContract):
    """Non-authoritative trace metadata allowed to cross the OCR boundary."""

    correlationId: Optional[NonEmptyString] = None
    traceId: Optional[NonEmptyString] = None


class S3Location(StrictContract):
    bucket: NonEmptyString
    key: NonEmptyString


class IngestMessage(StrictContract):
    """Strict ownership-bound message consumed from the ingest queue."""

    schemaVersion: Literal["scanalyze.ingest.v2"]
    customer_id: CustomerId
    deployment_id: DeploymentId
    ownership_schema_version: Literal[1]
    pipeline_stage: Literal["ingest"]
    processing_domain: Optional[Literal["bank", "personal", "gov"]] = None
    enqueue_id: NonEmptyString
    documentId: DocumentId
    raw: S3Location
    contentType: Optional[NonEmptyString] = None
    uploadedAt: Optional[NonEmptyString] = None
    metadata: MessageMetadata = Field(default_factory=MessageMetadata, alias="_metadata")


class TextractInfo(StrictContract):
    jobId: NonEmptyString
    api: Literal["StartDocumentTextDetection"] = "StartDocumentTextDetection"


class OcrPollMessage(StrictContract):
    """Strict ownership-bound message consumed from the OCR poll queue."""

    schemaVersion: Literal["scanalyze.ocr-poll.v2"]
    customer_id: CustomerId
    deployment_id: DeploymentId
    ownership_schema_version: Literal[1]
    pipeline_stage: Literal["ocr"]
    documentId: DocumentId
    textractJobId: NonEmptyString
    sourceBucket: NonEmptyString
    sourceKey: NonEmptyString
    sourceEtag: Optional[NonEmptyString] = None
    documentRoute: Literal["platform", "bank", "personal", "gov", "default"]
    requestedNextStage: Optional[NonEmptyString] = None
    artifactBucket: NonEmptyString
    artifactKey: NonEmptyString
    correlationId: Optional[NonEmptyString] = None
    submittedAt: NonEmptyString
    timeoutAt: Optional[NonEmptyString] = None
    attempt: int = Field(default=0, ge=0)
    metadata: MessageMetadata = Field(default_factory=MessageMetadata, alias="_metadata")


class ClassifyMeta(StrictContract):
    pages: Optional[int] = Field(default=None, ge=0)
    env: NonEmptyString
    tenant: Literal["platform", "bank", "personal", "gov", "default"]


class ClassifyMessage(StrictContract):
    """Ownership-bound message emitted after OCR to the classifier."""

    schemaVersion: Literal["scanalyze.classify.v2"]
    customer_id: CustomerId
    deployment_id: DeploymentId
    ownership_schema_version: Literal[1]
    pipeline_stage: Literal["classify"]
    documentId: DocumentId
    ocr: S3Location
    raw: S3Location
    textract: TextractInfo
    meta: ClassifyMeta
    metadata: MessageMetadata = Field(default_factory=MessageMetadata, alias="_metadata")


class ExtractMessage(StrictContract):
    """Ownership-bound message emitted directly to a domain extract worker."""

    schemaVersion: Literal["scanalyze.extract.v2"] = "scanalyze.extract.v2"
    customer_id: CustomerId
    deployment_id: DeploymentId
    ownership_schema_version: Literal[1]
    pipeline_stage: Literal["bank-extract", "personal-extract", "gov-extract"]
    processing_domain: Literal["bank", "personal", "gov"]
    documentId: DocumentId
    ocr: S3Location
    raw: S3Location
    correlationId: Optional[NonEmptyString] = None
    attempt: int = Field(default=0, ge=0)
    metadata: MessageMetadata = Field(default_factory=MessageMetadata, alias="_metadata")
