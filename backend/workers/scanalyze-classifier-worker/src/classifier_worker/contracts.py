from pydantic import BaseModel, Field
from typing import Optional

class S3Location(BaseModel):
    bucket: Optional[str] = None
    key: Optional[str] = None

class TextractInfo(BaseModel):
    jobId: str
    api: str = "StartDocumentTextDetection"

class ClassifyMeta(BaseModel):
    pages: Optional[int] = None
    env: str
    tenant: str

class ClassifyMessage(BaseModel):
    """
    Ingest format from SQS `classify` queue.
    Produced by the OCR worker.
    """
    schemaVersion: str = Field(default="scanalyze.classify.v1")
    documentId: str
    ocr: S3Location
    raw: S3Location
    textract: Optional[TextractInfo] = None
    meta: ClassifyMeta

class ExtractMeta(BaseModel):
    pages: Optional[int] = None
    env: str
    tenant: str
    classifierStrategy: str

class ExtractMessage(BaseModel):
    """
    Output format sent to SQS `bank-extract_url` or `personal-extract_url`.
    """
    schemaVersion: str = Field(default="scanalyze.extract.v1")
    documentId: str
    docType: str
    confidence: float
    ocr: S3Location
    raw: S3Location
    textract: Optional[TextractInfo] = None
    meta: ExtractMeta
