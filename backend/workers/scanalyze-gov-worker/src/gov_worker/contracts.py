from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, Any, Dict, List

class S3Location(BaseModel):
    bucket: Optional[str] = None
    key: Optional[str] = None

class GovExtractMessage(BaseModel):
    """
    Input message from the extract queue.
    Tolerates extra fields (like those from classifier).
    """
    model_config = ConfigDict(extra="ignore")

    documentId: str
    ocr: Optional[S3Location] = None
    raw: Optional[S3Location] = None
    correlationId: Optional[str] = None
    attempt: int = 0

class ValidateMeta(BaseModel):
    env: str
    tenant: str
    schema_version: str
    prompt_version: str

class ValidateMessage(BaseModel):
    """
    Output message sent to the validate queue
    """
    schemaVersion: str = Field(default="scanalyze.validate.v1")
    documentId: str
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
