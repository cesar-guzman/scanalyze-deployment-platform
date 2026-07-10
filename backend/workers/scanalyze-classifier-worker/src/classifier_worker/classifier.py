import json
from typing import Tuple, Dict, Any
from .logger import get_logger, safe_error_details
from .aws import bedrock_client
from .config import config

log = get_logger(__name__)

def heuristic_classify(text: str) -> Tuple[str, float, str]:
    """
    Deterministic rule-based classification based on keyword presence.
    Returns: (docType, confidence, route)
    Routes correspond to suffixes for target queues: "bank-extract", "personal-extract", or "gov-extract"
    """
    text_lower = text.lower()
    
    bank_keywords = ["bank", "statement", "balance", "account number", "deposit", "withdrawal", "routing number"]
    personal_keywords = ["id", "identify", "passport", "driver license", "driver's license", "birth certificate", "dob", "date of birth", "ine"]
    gov_keywords = ["oficio", "gobierno", "dependencia", "secretaria", "acta", "official", "gob", "ley"]
    
    bank_score = sum(1 for kw in bank_keywords if kw in text_lower)
    personal_score = sum(1 for kw in personal_keywords if kw in text_lower)
    gov_score = sum(1 for kw in gov_keywords if kw in text_lower)
    
    total = bank_score + personal_score + gov_score
    if total == 0:
        return ("unknown", 0.1, "gov-extract")
        
    bank_confidence = bank_score / total
    personal_confidence = personal_score / total
    gov_confidence = gov_score / total
    
    if bank_score > personal_score and bank_score > gov_score:
        return ("bank_statement", round(bank_confidence, 2), "bank-extract")
    elif personal_score > bank_score and personal_score > gov_score:
        return ("id_document", round(personal_confidence, 2), "personal-extract")
    elif gov_score > bank_score and gov_score > personal_score:
        return ("gov_document", round(gov_confidence, 2), "gov-extract")
    else:
        # Tie
        return ("unknown_ambiguous", 0.3, "personal-extract")

def parse_bedrock_json(text: str) -> Dict[str, Any]:
    """Finds the first JSON object in a string that might contain markdown or extra text."""
    start_idx = text.find('{')
    if start_idx == -1:
        raise ValueError("No JSON object found")
    
    brace_count = 0
    end_idx = start_idx
    for i in range(start_idx, len(text)):
        if text[i] == '{':
            brace_count += 1
        elif text[i] == '}':
            brace_count -= 1
        
        if brace_count == 0:
            end_idx = i
            break
            
    if brace_count != 0:
        raise ValueError("Unbalanced JSON braces")
        
    json_str = text[start_idx:end_idx+1]
    return json.loads(json_str)

def bedrock_classify(text: str, model_id: str) -> Tuple[str, float, str]:
    """
    Calls Bedrock Converse API to classify the document text.
    Returns: (docType, confidence, route)
    """
    # Truncate text to a safe length for prompt (e.g. 5000 chars)
    truncated_text = text[:5000]
    
    prompt = f"""You are a document classifier. Only return a valid JSON object. No markdown, no explanations.
Analyze the following document text and classify it into a docType.
Also assign a confidence score between 0.0 and 1.0.
Decide a route, which must be strictly "bank-extract" if the document relates to banking or finances, "gov-extract" for official government documents, acts, or laws, or "personal-extract" for identity or personal documents.

Document Text:
{truncated_text}

Required Output JSON Format:
{{ "docType": "string", "confidence": float, "route": "bank-extract" | "personal-extract" | "gov-extract" }}
"""
    
    system = [{"text": "Devuelve SOLO JSON válido, sin markdown, sin comentarios."}]
    messages = [
        {"role": "user", "content": [{"text": prompt}]}
    ]
    inf_params = {"temperature": 0.0, "maxTokens": 200}
    
    try:
        response = bedrock_client.converse(
            modelId=model_id,
            messages=messages,
            system=system,
            inferenceConfig=inf_params
        )
        content_text = response['output']['message']['content'][0]['text']
        
        parsed = parse_bedrock_json(content_text)
        
        docType = str(parsed.get('docType', 'unknown'))
        confidence = float(parsed.get('confidence', 0.1))
        route = str(parsed.get('route', 'personal-extract'))
        
        if route not in ['bank-extract', 'personal-extract', 'gov-extract']:
            route = 'personal-extract'
            
        return (docType, confidence, route)
    except Exception as e:
        log.error(
            "bedrock_classification_failed",
            modelId=model_id,
            **safe_error_details(e),
        )
        raise

def classify_document(text: str, enable_bedrock: bool) -> Tuple[str, float, str, str]:
    """
    Performs classification. Falls back to heuristic if bedrock fails.
    Returns (docType, confidence, route, strategy_used)
    """
    if enable_bedrock:
        try:
            model_id = config.get("BEDROCK_MODEL_ID", default="amazon.nova-lite-v1:0")
            docType, conf, route = bedrock_classify(text, model_id)
            return (docType, conf, route, "bedrock")
        except Exception as filter_e:
            log.warning(
                "bedrock_fallback_triggered",
                **safe_error_details(filter_e),
            )
            # Fallback
            docType, conf, route = heuristic_classify(text)
            return (docType, conf, route, "bedrock_fallback")
            
    docType, conf, route = heuristic_classify(text)
    return (docType, conf, route, "heuristic")
