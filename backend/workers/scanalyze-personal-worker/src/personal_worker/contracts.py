from pydantic import BaseModel, Field, ConfigDict, StringConstraints
from typing import Annotated, Optional, Any, Dict, List, Literal

NonEmptyString = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
CustomerId = Annotated[str, StringConstraints(pattern=r"^cust_[0-9A-HJKMNP-TV-Z]{26}$")]
DeploymentId = Annotated[str, StringConstraints(pattern=r"^dep_[0-9A-HJKMNP-TV-Z]{26}$")]
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

class PersonalExtractMessage(BaseModel):
    """Strict, ownership-bound input from the personal extract queue."""
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["scanalyze.extract.v2"]
    documentId: DocumentId
    customer_id: CustomerId
    deployment_id: DeploymentId
    ownership_schema_version: Literal[1]
    pipeline_stage: Literal["personal-extract"]
    processing_domain: Literal["personal"]
    ocr: S3Location
    raw: S3Location
    correlationId: Optional[NonEmptyString] = None
    attempt: int = Field(default=0, ge=0)

class ValidateMeta(BaseModel):
    model_config = ConfigDict(extra="forbid")
    env: NonEmptyString
    tenant: Literal["personal"]
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
    processing_domain: Literal["personal"]
    structured: S3Location
    meta: ValidateMeta
    correlationId: Optional[str] = None

class ModelUsageSchema(BaseModel):
    provider: str = "bedrock"
    modelId: str
    usage: Optional[Any] = None

class PersonSchema(BaseModel):
    fullName: Optional[str] = None
    givenNames: Optional[str] = None
    surnames: Optional[str] = None
    dob: Optional[str] = None
    sex: Optional[str] = None
    nationality: Optional[str] = None
    address: Optional[str] = None

class ContactSchema(BaseModel):
    """Contact information extracted from documents (canonical location)."""
    email: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[str] = None

class DocumentDetailsSchema(BaseModel):
    number: Optional[str] = None         # Full document number if visible
    numberMasked: Optional[str] = None
    type: Optional[str] = None           # CFDI, constancia, cédula, etc.
    uuid: Optional[str] = None           # UUID fiscal (CFDI)
    issueDate: Optional[str] = None
    expiryDate: Optional[str] = None
    countryOfIssue: Optional[str] = None

class IdentifiersSchema(BaseModel):
    curp: Optional[str] = None
    rfc: Optional[str] = None
    claveElector: Optional[str] = None
    cic: Optional[str] = None
    ocr: Optional[str] = None
    mrz: Optional[str] = None
    nss: Optional[str] = None            # NSS IMSS (11 dígitos)

class EmployerSchema(BaseModel):
    """Employer/patron data from payroll, IMSS, or labor docs."""
    name: Optional[str] = None
    rfc: Optional[str] = None
    registrationNumber: Optional[str] = None  # Registro patronal IMSS

class PayrollSchema(BaseModel):
    """Payroll/nómina data — only for subType=payroll_cfdi_mx."""
    position: Optional[str] = None
    department: Optional[str] = None
    payPeriod: Optional[str] = None       # ISO interval or date range
    paymentDate: Optional[str] = None     # ISO date
    grossPay: Optional[float] = None
    deductions: Optional[float] = None
    taxWithheld: Optional[float] = None
    netPay: Optional[float] = None

class ImssSchema(BaseModel):
    """IMSS-specific data — only for nss_imss / imss_weeks_certificate."""
    weeksContributed: Optional[int] = None
    employers: Optional[List[Dict[str, Any]]] = None  # [{name, registrationNumber, weeks}]

class FieldValidation(BaseModel):
    """Validation result for a single extracted field."""
    valid: Optional[bool] = None
    present: Optional[bool] = None
    matchesDob: Optional[bool] = None
    matchesName: Optional[bool] = None
    score: float = 0.0
    issue: Optional[str] = None

class FieldConfidenceSchema(BaseModel):
    """Granular per-field confidence scores with validation details."""
    curp: Optional[FieldValidation] = None
    fullName: Optional[FieldValidation] = None
    dob: Optional[FieldValidation] = None

# SubTypes aligned with classifier taxonomy v1.1
VALID_SUBTYPES = frozenset({
    "ine_mx", "ine_front_mx", "ine_back_mx",
    "curp_mx", "rfc_sat", "nss_imss",
    "imss_weeks_certificate", "birth_certificate",
    "passport", "mx_driver_license",
    "cv_resume", "personal_doc_generic",
    "payroll_cfdi_mx",
    "recommendation_letter", "labor_certificate",
    "unknown",
})

_SUBTYPE_PATTERN = "^(" + "|".join(sorted(VALID_SUBTYPES)) + ")$"


class PersonalDocSchema(BaseModel):
    """
    Strict schema for personal documents.
    SubType enum aligned with classifier taxonomy v1.1.
    Uses extra='ignore' to allow additive fields without breaking compatibility.
    """
    model_config = ConfigDict(extra="ignore")

    schema_version: str = "1.0"
    prompt_version: str
    tenant: str = "personal"
    documentId: str
    docType: str = "personal_doc"
    subType: str = Field(pattern=_SUBTYPE_PATTERN)
    variant: Optional[str] = None  # e.g., "curp_certificate" for curp_mx
    generatedAt: Optional[str] = None
    model: ModelUsageSchema
    person: PersonSchema
    document: DocumentDetailsSchema
    identifiers: IdentifiersSchema
    contact: Optional[ContactSchema] = None        # Contact info (canonical)
    employer: Optional[EmployerSchema] = None       # Employer/patron data
    payroll: Optional[PayrollSchema] = None         # Payroll data (payroll_cfdi_mx only)
    imss: Optional[ImssSchema] = None               # IMSS data (nss_imss/imss_weeks only)
    overallConfidence: Optional[float] = None
    summaryText: Optional[str] = None
    fieldConfidence: Optional[FieldConfidenceSchema] = None
    extractionReasonCodes: Optional[List[str]] = None  # post-processing reason codes
