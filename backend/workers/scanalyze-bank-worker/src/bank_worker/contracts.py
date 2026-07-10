from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List, Any, Dict

class S3Location(BaseModel):
    bucket: Optional[str] = None
    key: Optional[str] = None

class BankExtractMessage(BaseModel):
    """
    Input message from the extract queue.
    Tolerates extra fields (like those from classifier).
    """
    model_config = ConfigDict(extra="ignore")

    schemaVersion: str = Field(default="scanalyze.bank-extract.v1")
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
