import json
import logging
from typing import Dict, Any, Tuple
from .aws import s3_client

logger = logging.getLogger(__name__)

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
