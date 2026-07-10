from pydantic import BaseModel, Field
from typing import Optional

# ----------------------------------------------------
# Contrato de Esquemas (V1)
# ----------------------------------------------------

class S3Location(BaseModel):
    bucket: Optional[str] = None
    key: Optional[str] = None

class IngestMessage(BaseModel):
    """
    Formato del mensaje recibido en la cola `ingest`
    """
    schemaVersion: str = Field(default="scanalyze.ingest.v1")
    documentId: str
    raw: Optional[S3Location] = None
    s3: Optional[S3Location] = None
    contentType: Optional[str] = None
    uploadedAt: Optional[str] = None

class TextractInfo(BaseModel):
    jobId: str
    api: str = "StartDocumentTextDetection"

class OcrPollMessage(BaseModel):
    """
    Formato del mensaje recibido en la cola `ocr` para hacer polling
    Contrato estricto entre ingest y poll.
    """
    schemaVersion: str = Field(default="scanalyze.ocr-poll.v1")
    documentId: str
    textractJobId: str
    sourceBucket: str
    sourceKey: str
    sourceEtag: Optional[str] = None
    serviceTenant: str
    documentRoute: str
    requestedNextStage: Optional[str] = None
    artifactBucket: str
    artifactKey: str
    correlationId: Optional[str] = None
    submittedAt: str
    timeoutAt: Optional[str] = None
    attempt: int = 0

class ClassifyMeta(BaseModel):
    pages: Optional[int] = None
    env: str
    tenant: str

class ClassifyMessage(BaseModel):
    """
    Formato del mensaje enviado a la cola `classify` tras completar OCR
    """
    schemaVersion: str = Field(default="scanalyze.classify.v1")
    documentId: str
    ocr: S3Location
    raw: S3Location
    textract: TextractInfo
    meta: ClassifyMeta
