from typing import Annotated, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

NonEmptyString = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
CustomerId = Annotated[
    str,
    StringConstraints(strip_whitespace=True, pattern=r"^cust_[0-9A-HJKMNP-TV-Z]{26}$"),
]
DeploymentId = Annotated[
    str,
    StringConstraints(strip_whitespace=True, pattern=r"^dep_[0-9A-HJKMNP-TV-Z]{26}$"),
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


class S3Location(BaseModel):
    model_config = ConfigDict(extra="forbid")
    bucket: NonEmptyString
    key: NonEmptyString


class TextractInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")
    jobId: NonEmptyString
    api: Literal["StartDocumentTextDetection"] = "StartDocumentTextDetection"


class ClassifyMeta(BaseModel):
    model_config = ConfigDict(extra="forbid")
    pages: Optional[int] = Field(default=None, ge=0)
    env: NonEmptyString
    tenant: Literal["platform", "bank", "personal", "gov", "default"]


class ClassifyMessage(BaseModel):
    """
    Ingest format from SQS `classify` queue.
    Produced by the OCR worker.
    """
    model_config = ConfigDict(extra="forbid")
    schemaVersion: Literal["scanalyze.classify.v2"] = "scanalyze.classify.v2"
    documentId: DocumentId
    customer_id: CustomerId
    deployment_id: DeploymentId
    ownership_schema_version: Literal[1]
    pipeline_stage: Literal["classify"]
    processing_domain: None = None
    ocr: S3Location
    raw: S3Location
    textract: Optional[TextractInfo] = None
    meta: ClassifyMeta


class ExtractMessage(BaseModel):
    """
    Output format sent to SQS `bank-extract_url` or `personal-extract_url`.
    """
    model_config = ConfigDict(extra="forbid")
    schemaVersion: Literal["scanalyze.extract.v2"] = "scanalyze.extract.v2"
    documentId: DocumentId
    customer_id: CustomerId
    deployment_id: DeploymentId
    ownership_schema_version: Literal[1]
    pipeline_stage: Literal["bank-extract", "personal-extract", "gov-extract"]
    processing_domain: Literal["bank", "personal", "gov"]
    ocr: S3Location
    raw: S3Location
    correlationId: Optional[NonEmptyString] = None
    attempt: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def require_stage_to_match_domain(self):
        expected_stage = {
            "bank": "bank-extract",
            "personal": "personal-extract",
            "gov": "gov-extract",
        }[self.processing_domain]
        if self.pipeline_stage != expected_stage:
            raise ValueError("pipeline stage does not match processing domain")
        return self

    def model_dump(self, *args, **kwargs):
        """Serialize optional trace fields by omission, matching the v2 schema."""

        kwargs.setdefault("exclude_none", True)
        return super().model_dump(*args, **kwargs)
