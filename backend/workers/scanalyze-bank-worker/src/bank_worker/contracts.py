from pydantic import BaseModel, Field, ConfigDict, StringConstraints
from typing import Annotated, Optional, List, Any, Dict, Literal

NonEmptyString = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
CustomerId = Annotated[str, StringConstraints(pattern=r"^cust_[0-9A-HJKMNP-TV-Z]{26}$")]
DeploymentId = Annotated[str, StringConstraints(pattern=r"^dep_[0-9A-HJKMNP-TV-Z]{26}$")]

class S3Location(BaseModel):
    model_config = ConfigDict(extra="forbid")
    bucket: NonEmptyString
    key: NonEmptyString

class BankExtractMessage(BaseModel):
    """Strict, ownership-bound input from the bank extract queue."""
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["scanalyze.extract.v2"]
    documentId: NonEmptyString
    customer_id: CustomerId
    deployment_id: DeploymentId
    ownership_schema_version: Literal[1]
    pipeline_stage: Literal["bank-extract"]
    processing_domain: Literal["bank"]
    ocr: S3Location
    raw: S3Location
    correlationId: Optional[str] = None
    attempt: int = Field(default=0, ge=0)

class ValidateMeta(BaseModel):
    model_config = ConfigDict(extra="forbid")
    env: NonEmptyString
    tenant: Literal["bank"]
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
    processing_domain: Literal["bank"]
    structured: S3Location
    meta: ValidateMeta
    correlationId: Optional[str] = None

class BaseBankTransaction(BaseModel):
    date: Optional[str] = None
    description: Optional[str] = None
    reference: Optional[str] = None
    direction: Optional[str] = Field(default=None, pattern="^(credit|debit)$")
    amount: Optional[float] = None
    balanceAfter: Optional[float] = None
    category: Optional[str] = None  # nómina, transferencia, comisión, retiro, compra, interés, etc.

class BankFees(BaseModel):
    """Comisiones acumuladas del periodo"""
    totalFees: Optional[float] = None
    ivaOnFees: Optional[float] = None

class ModelUsageSchema(BaseModel):
    provider: str = "bedrock"
    modelId: str
    usage: Optional[Any] = None

class FieldValidation(BaseModel):
    """Validation result for a single extracted field."""
    valid: Optional[bool] = None
    present: Optional[bool] = None
    score: float = 0.0
    issue: Optional[str] = None

class BankFieldConfidence(BaseModel):
    """Granular per-field confidence scores for bank statement extraction."""
    bankName: Optional[FieldValidation] = None
    accountHolder: Optional[FieldValidation] = None
    balanceReconciliation: Optional[FieldValidation] = None
    transactionCount: Optional[FieldValidation] = None
    periodDetected: Optional[FieldValidation] = None

class BankStatementSchema(BaseModel):
    """
    Strict schema for bank statement documents.
    Uses extra='ignore' to allow additive fields without breaking compatibility.
    """
    model_config = ConfigDict(extra="ignore")

    schema_version: str = "1.0"
    prompt_version: str
    tenant: str = "bank"
    documentId: str
    docType: str = "bank_statement"
    generatedAt: str
    model: Dict[str, Any]
    bank: Optional[Dict[str, Optional[str]]] = Field(default_factory=dict)
    account: Optional[Dict[str, Optional[str]]] = Field(default_factory=dict)
    statement: Optional[Dict[str, Optional[str]]] = Field(default_factory=dict)
    balances: Optional[Dict[str, Optional[float]]] = Field(default_factory=dict)
    transactions: List[BaseBankTransaction] = Field(default_factory=list)
    accountType: Optional[str] = None       # cheques, ahorro, crédito, inversión
    bankCountry: Optional[str] = None       # ISO 3166-1 alpha-2: MX, US, etc.
    fees: Optional[Dict[str, Optional[float]]] = None
    interestEarned: Optional[float] = None
    interestCharged: Optional[float] = None
    summaryText: Optional[str] = None
    overallConfidence: Optional[float] = None
    fieldConfidence: Optional[BankFieldConfidence] = None
