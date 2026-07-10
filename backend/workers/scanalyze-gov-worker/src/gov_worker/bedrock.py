import json
import logging
from typing import Dict, Any, Tuple
from .aws import bedrock_client

logger = logging.getLogger(__name__)

PROMPT_VERSION = "1.0.0"

SYSTEM_PROMPT = """Eres un extractor determinista de información de documentos gubernamentales (docType=gov_document). 
Debes extraer únicamente la información presente en el OCR. Si un dato no está presente, usa null. 
No inventes datos ni asumas valores. 
Extrae fechas en formato ISO-8601 (YYYY-MM-DD); si no puedes parsear, null.
Transforma la moneda (currency) a formato ISO 4217 en mayúsculas (ej. MXN, USD).
Transforma las cantidades a número/float o déjalas nulas.
Devuelve SOLO JSON válido (sin markdown, sin comentarios). NO agregues campos fuera del esquema."""

def get_user_prompt(document_id: str, model_id: str, ocr_text: str) -> str:
    return f"""Extrae los detalles del documento gubernamental desde el texto OCR entre <<DOC>> y </DOC>.
Devuelve un único objeto JSON que cumpla este esquema EXACTO (schema_version=1.0).

ESQUEMA JSON EXACTO:
{{
  "schema_version": "1.0",
  "prompt_version": "{PROMPT_VERSION}",
  "tenant": "gov",
  "documentId": "{document_id}",
  "docType": "gov_document",
  "generatedAt": "<AQUI_COLOCA_ISO8601_UTC_O_NULL>",
  "model": {{
    "provider": "bedrock",
    "modelId": "{model_id}",
    "usage": null
  }},
  "document": {{
    "type": null,
    "title": null,
    "number": null,
    "folio": null,
    "country": null,
    "language": null
  }},
  "issuer": {{
    "name": null,
    "agency": null,
    "department": null,
    "address": null
  }},
  "recipient": {{
    "name": null,
    "entity": null,
    "address": null
  }},
  "dates": {{
    "issueDate": null,
    "effectiveDate": null,
    "expiryDate": null
  }},
  "amounts": {{
    "currency": null,
    "subtotal": null,
    "tax": null,
    "total": null
  }},
  "references": [],
  "signatories": [
    {{ "name": null, "role": null }}
  ],
  "summaryText": "<AQUI_COLOCA_UN_RESUMEN_HIPER_BREVE_DE_1_LINEA>"
}}

<<DOC>>
{ocr_text}
</DOC>"""

def invoke_bedrock_gov_doc(document_id: str, ocr_text: str, model_id: str) -> Tuple[str, Dict[str, Any]]:
    """
    Invokes Amazon Bedrock Converse API with the strict Prompt for government documents.
    Returns (raw_json_string, metrics_dict)
    """
    
    system = [{"text": SYSTEM_PROMPT}]
    messages = [
        {
            "role": "user",
            "content": [{"text": get_user_prompt(document_id, model_id, ocr_text)}]
        }
    ]
    
    # Optional inference parameters
    # High restrictiveness
    inf_params = {"temperature": 0.0, "topP": 0.1, "maxTokens": 4000}
    
    try:
        response = bedrock_client.converse(
            modelId=model_id,
            messages=messages,
            system=system,
            inferenceConfig=inf_params
        )
        
        output_message = response['output']['message']
        raw_text = output_message['content'][0]['text']
        
        usage = response.get('usage', {})
        metrics = {
            "inputTokens": usage.get("inputTokens", 0),
            "outputTokens": usage.get("outputTokens", 0),
            "totalTokens": usage.get("totalTokens", 0),
            "latencyMs": response['metrics'].get('latencyMs', 0)
        }
        
        return raw_text, metrics

    except Exception as e:
        logger.error("Bedrock invocation failed", extra={"errorType": type(e).__name__})
        # Could be throttling, service limits, etc. Bubbling up to trigger SQS retry.
        raise
