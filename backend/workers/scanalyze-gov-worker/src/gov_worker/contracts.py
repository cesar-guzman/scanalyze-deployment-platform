from pydantic import BaseModel, Field, ConfigDict, StringConstraints
from typing import Annotated, Optional, Any, Dict, List, Literal

NonEmptyString = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
CustomerId = Annotated[str, StringConstraints(pattern=r"^cust_[0-9A-HJKMNP-TV-Z]{26}$")]
DeploymentId = Annotated[str, StringConstraints(pattern=r"^dep_[0-9A-HJKMNP-TV-Z]{26}$")]

class S3Location(BaseModel):
    model_config = ConfigDict(extra="forbid")
    bucket: NonEmptyString
    key: NonEmptyString

class GovExtractMessage(BaseModel):
    """Strict, ownership-bound input from the government extract queue."""
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["scanalyze.extract.v2"]
    documentId: NonEmptyString
    customer_id: CustomerId
    deployment_id: DeploymentId
    ownership_schema_version: Literal[1]
    pipeline_stage: Literal["gov-extract"]
    processing_domain: Literal["gov"]
    ocr: S3Location
    raw: S3Location
    correlationId: Optional[str] = None
    attempt: int = Field(default=0, ge=0)

class ValidateMeta(BaseModel):
    model_config = ConfigDict(extra="forbid")
    env: NonEmptyString
    tenant: Literal["gov"]
    schema_version: str
    prompt_version: str

class ValidateMessage(BaseModel):
    """
    Output message sent to the validate queue
    """
    model_config = ConfigDict(extra="forbid")
    schemaVersion: Literal["scanalyze.validate.v2"] = "scanalyze.validate.v2"
    documentId: NonEmptyString
    customer_id: CustomerId
    deployment_id: DeploymentId
    ownership_schema_version: Literal[1]
    pipeline_stage: Literal["validate"]
    processing_domain: Literal["gov"]
    structured: S3Location
    meta: ValidateMeta
    correlationId: Optional[str] = None

class ModelUsageSchema(BaseModel):
    provider: str = "bedrock"
    modelId: str
    usage: Optional[Any] = None

class DocumentDetailsSchema(BaseModel):
    type: Optional[str] = None
    title: Optional[str] = None
    number: Optional[str] = None
    folio: Optional[str] = None
    country: Optional[str] = None
    language: Optional[str] = None

class IssuerSchema(BaseModel):
    name: Optional[str] = None
    agency: Optional[str] = None
    department: Optional[str] = None
    address: Optional[str] = None

class RecipientSchema(BaseModel):
    name: Optional[str] = None
    entity: Optional[str] = None
    address: Optional[str] = None

class DatesSchema(BaseModel):
    issueDate: Optional[str] = None
    effectiveDate: Optional[str] = None
    expiryDate: Optional[str] = None

class AmountsSchema(BaseModel):
    currency: Optional[str] = None
    subtotal: Optional[float] = None
    tax: Optional[float] = None
    total: Optional[float] = None

class SignatorySchema(BaseModel):
    name: Optional[str] = None
    role: Optional[str] = None

class GovDocSchema(BaseModel):
    """
    Strict schema for government documents.
    Does not allow extra fields.
    """
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0"
    prompt_version: str
    tenant: str = "gov"
    documentId: str
    docType: str = "gov_document"
    generatedAt: Optional[str] = None
    model: ModelUsageSchema
    document: DocumentDetailsSchema
    issuer: IssuerSchema
    recipient: RecipientSchema
    dates: DatesSchema
    amounts: AmountsSchema
    references: List[Any] = Field(default_factory=list)
    signatories: List[SignatorySchema] = Field(default_factory=list)
    summaryText: Optional[str] = None
