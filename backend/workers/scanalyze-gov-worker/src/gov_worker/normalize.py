import json
import json_repair
from typing import Dict, Any
from datetime import datetime, timezone
from .contracts import GovDocSchema
from .logger import log_event, safe_error_details
from pydantic import ValidationError

def clean_json_string(raw_text: str) -> str:
    """
    Strips markdown code fences and extracts the first balanced JSON object.
    Because sometimes Claude ignores strict system prompts.
    """
    text = raw_text.strip()
    
    if text.startswith("```"):
        lines = text.split("\n")
        if lines[0].startswith("```"):
            lines.pop(0)
        if lines and lines[-1].strip().startswith("```"):
            lines.pop(-1)
        text = "\n".join(lines).strip()
        
    start_idx = text.find("{")
    end_idx = text.rfind("}")
    
    if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
        text = text[start_idx:end_idx+1]
        
    return text

def parse_and_normalize(raw_json: str, document_id: str, prompt_version: str, model_id: str) -> Dict[str, Any]:
    """
    Validates against strict Pydantic Gov schema and applies normalizations.
    """
    cleaned = clean_json_string(raw_json)
    
    try:
        data = json_repair.loads(cleaned)
        if not isinstance(data, dict):
            raise ValueError(f"Parsed JSON is not a dictionary. Got: {type(data)}")
    except Exception as e:
        log_event(
            "bedrock_json_parse_failed",
            documentId=document_id,
            **safe_error_details(e),
        )
        raise ValueError("Bedrock returned invalid JSON dictionary") from None
        
    # Enforce static schema requirements for Gov
    data["schema_version"] = "1.0"
    data["prompt_version"] = prompt_version
    data["tenant"] = "gov"
    data["documentId"] = document_id
    data["docType"] = "gov_document"
    data["generatedAt"] = datetime.now(timezone.utc).isoformat()
    
    data["model"] = {
        "provider": "bedrock",
        "modelId": model_id,
        "usage": None # Populated later
    }
    
    # Normalizer fixes for gov: currency ISO
    if "amounts" in data and isinstance(data["amounts"], dict):
        if data["amounts"].get("currency") and isinstance(data["amounts"]["currency"], str):
            data["amounts"]["currency"] = data["amounts"]["currency"].upper()

    # Normalizer fixes for gov: array fallbacks
    if "references" not in data or not isinstance(data.get("references"), list):
        data["references"] = []
    
    if "signatories" not in data or not isinstance(data.get("signatories"), list):
        data["signatories"] = []

    try:
        # Pydantic schema will coerce floats correctly if they are strings.
        validated_obj = GovDocSchema(**data)
        return validated_obj.model_dump(exclude_none=False)
    except ValidationError as ve:
        log_event(
            "bedrock_schema_validation_failed",
            documentId=document_id,
            **safe_error_details(ve),
        )
        raise ValueError("Schema violation") from None
