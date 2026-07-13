import hashlib
import json
import logging
from typing import Dict, Any, Tuple
from botocore.exceptions import ClientError
from .aws import s3_client

logger = logging.getLogger(__name__)

MAX_STRUCTURED_ARTIFACT_BYTES = 10 * 1024 * 1024


def _structured_body(data: Dict[str, Any]) -> bytes:
    return json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")


def _structured_metadata(
    *,
    customer_id: str,
    deployment_id: str,
    document_id: str,
    processing_domain: str,
    ownership_schema_version: int,
    pipeline_stage: str,
    writer: str,
    artifact_schema_version: str,
    checkpoint_id: str,
    content_sha256: str,
) -> Dict[str, str]:
    return {
        "customer-id": customer_id,
        "deployment-id": deployment_id,
        "document-id": document_id,
        "processing-domain": processing_domain,
        "ownership-schema-version": str(ownership_schema_version),
        "pipeline-stage": pipeline_stage,
        "writer": writer,
        "artifact-schema-version": artifact_schema_version,
        "checkpoint-id": checkpoint_id,
        "content-sha256": content_sha256,
    }

def get_ocr_text(bucket: str, key: str, char_limit: int = 150000) -> Tuple[str, Dict[str, Any]]:
    """
    Downloads OCR artifact from S3. Supports JSON wrapping, Textract style, or raw txt.
    Truncates text to prevent huge Claude requests.
    Returns (text_content, stats_dict)
    """
    try:
        response = s3_client.get_object(Bucket=bucket, Key=key)
        raw_body = response['Body'].read().decode('utf-8')
    except Exception as e:
        logger.error("Failed to read OCR artifact", extra={"errorType": type(e).__name__})
        raise

    extracted_text = ""
    
    # Try parsing as JSON first
    try:
        data = json.loads(raw_body)
        if isinstance(data, dict):
            # Bank format {"data": {"text": "..."}}
            if 'data' in data and 'text' in data['data']:
                extracted_text = data['data']['text']
            # Textract format
            elif 'Blocks' in data or 'blocks' in data:
                blocks = data.get('Blocks', data.get('blocks', []))
                lines = [b.get('Text', '') for b in blocks if b.get('BlockType') == 'LINE']
                extracted_text = "\n".join(lines)
            else:
                extracted_text = str(data)
        else:
            extracted_text = str(data)
    except json.JSONDecodeError:
        # It's plain text
        extracted_text = raw_body

    chars_len = len(extracted_text)
    truncated = False
    
    if chars_len > char_limit:
        logger.warning(f"OCR text length ({chars_len}) exceeds char_limit ({char_limit}). Truncating.")
        extracted_text = extracted_text[:char_limit] + "\n\n...[TRUNCATED_BY_PERSONAL_WORKER]"
        truncated = True
        chars_len = len(extracted_text)

    stats = {
        "chars": chars_len,
        "truncated": truncated
    }

    return extracted_text.strip(), stats

def save_structured_artifact(
    bucket: str,
    key: str,
    data: Dict[str, Any],
    *,
    customer_id: str,
    deployment_id: str,
    document_id: str,
    processing_domain: str,
    ownership_schema_version: int,
    pipeline_stage: str,
    writer: str,
    artifact_schema_version: str,
    checkpoint_id: str,
) -> Tuple[bool, str]:
    """
    Saves the final structured JSON output to S3.
    Returns whether this call created the object and the digest of the attempted
    body. A collision is recoverable only after an exact proof readback.
    """
    body = _structured_body(data)
    if len(body) > MAX_STRUCTURED_ARTIFACT_BYTES:
        raise ValueError("Structured artifact is unavailable")
    content_sha256 = hashlib.sha256(body).hexdigest()
    metadata = _structured_metadata(
        customer_id=customer_id,
        deployment_id=deployment_id,
        document_id=document_id,
        processing_domain=processing_domain,
        ownership_schema_version=ownership_schema_version,
        pipeline_stage=pipeline_stage,
        writer=writer,
        artifact_schema_version=artifact_schema_version,
        checkpoint_id=checkpoint_id,
        content_sha256=content_sha256,
    )
    try:
        s3_client.put_object(
            Bucket=bucket,
            Key=key,
            Body=body,
            ContentType="application/json",
            Metadata=metadata,
            IfNoneMatch="*",
        )
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code")
        status = error.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        if code in {"PreconditionFailed", "ConditionalRequestConflict"} or status in {409, 412}:
            return False, content_sha256
        raise
    return True, content_sha256


def require_structured_artifact_proof(
    bucket: str,
    key: str,
    *,
    customer_id: str,
    deployment_id: str,
    document_id: str,
    processing_domain: str,
    ownership_schema_version: int,
    pipeline_stage: str,
    writer: str,
    artifact_schema_version: str,
    checkpoint_id: str,
    expected_digest: str | None = None,
) -> str:
    """Return the verified digest for one exactly bound structured artifact."""
    response = s3_client.get_object(Bucket=bucket, Key=key)
    content_length = response.get("ContentLength")
    if isinstance(content_length, int) and content_length > MAX_STRUCTURED_ARTIFACT_BYTES:
        raise ValueError("Structured artifact is unavailable")

    body_stream = response.get("Body")
    if body_stream is None:
        raise ValueError("Structured artifact is unavailable")
    body = body_stream.read(MAX_STRUCTURED_ARTIFACT_BYTES + 1)
    if not isinstance(body, bytes) or len(body) > MAX_STRUCTURED_ARTIFACT_BYTES:
        raise ValueError("Structured artifact is unavailable")

    content_sha256 = hashlib.sha256(body).hexdigest()
    if expected_digest is not None and content_sha256 != expected_digest:
        raise ValueError("Structured artifact is unavailable")

    expected_metadata = _structured_metadata(
        customer_id=customer_id,
        deployment_id=deployment_id,
        document_id=document_id,
        processing_domain=processing_domain,
        ownership_schema_version=ownership_schema_version,
        pipeline_stage=pipeline_stage,
        writer=writer,
        artifact_schema_version=artifact_schema_version,
        checkpoint_id=checkpoint_id,
        content_sha256=content_sha256,
    )
    if response.get("Metadata") != expected_metadata:
        raise ValueError("Structured artifact is unavailable")
    return content_sha256
