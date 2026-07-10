import json
import logging
from typing import Dict, Any, Tuple
from .aws import s3_client

logger = logging.getLogger(__name__)

def get_ocr_text(bucket: str, key: str, char_limit: int = 150000) -> Tuple[str, Dict[str, Any]]:
    """
    Downloads OCR artifact from S3. Supports JSON wrapping or raw txt.
    Extracts only LINE blocks to prevent bloat.
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
        if isinstance(data, dict) and 'blocks' in data:
            # Textract format from ocr_worker
            lines = [b.get('Text', '') for b in data['blocks'] if b.get('BlockType') == 'LINE']
            extracted_text = "\n".join(lines)
        elif isinstance(data, dict) and 'data' in data and 'text' in data['data']:
            extracted_text = data['data']['text']
        else:
            # Maybe it's raw JSON text wrapper not matching standard, just dump it
            extracted_text = str(data)
    except json.JSONDecodeError:
        # It's plain text
        extracted_text = raw_body

    chars_len = len(extracted_text)
    
    # We remove the blind truncation because we will chunk the text in the caller (extract.py).
    # Leaving stats as they are expected by callers, but returning the full clean text.
    stats = {
        "chars": chars_len,
        "truncated": False
    }

    return extracted_text.strip(), stats

def save_structured_artifact(bucket: str, key: str, data: Dict[str, Any]) -> str:
    """
    Saves the final structured JSON output to S3.
    Returns the key.
    """
    s3_client.put_object(
        Bucket=bucket,
        Key=key,
        Body=json.dumps(data, indent=2, ensure_ascii=False).encode('utf-8'),
        ContentType="application/json"
    )
    return key
