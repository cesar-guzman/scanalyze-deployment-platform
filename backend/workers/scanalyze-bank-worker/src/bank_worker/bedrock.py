import json
import logging
from typing import Dict, Any, Tuple
from .aws import bedrock_client

logger = logging.getLogger(__name__)

PROMPT_VERSION = "2.1.0"

SYSTEM_PROMPT = """Actúas como un extractor determinista de datos financieros especializado en estados de cuenta bancarios de cualquier banco del mundo (México, Estados Unidos, Europa, etc).

Reglas estrictas:
1. Extrae únicamente información presente en el texto OCR. Si un dato no está, usa null.
2. NO inventes transacciones, montos ni saldos.
3. Devuelve SOLO JSON válido via la herramienta proporcionada. Sin markdown, sin comentarios.
4. Usa formato numérico con punto decimal (ej: 15000.50, no 15,000.50).
5. Fechas en formato ISO-8601 (YYYY-MM-DD). Si el formato original es DD/MM/YYYY o MMM-DD-YYYY, conviértelo.
6. El campo direction debe ser 'credit' para depósitos/abonos y 'debit' para cargos/retiros.
7. Categoriza cada transacción según su naturaleza: nómina, transferencia, spei, comisión, retiro_atm, compra_pos, pago_servicio, interés, dividendo, cheque, domiciliación, otro.
8. Si detectas comisiones bancarias o IVA sobre comisiones, extráelos tanto como transacciones individuales (con category='comisión' o 'iva') como en el objeto fees agregado.
9. Detecta automáticamente el banco emisor (BBVA, Banorte, Santander, Banamex/Citibanamex, Scotiabank, HSBC, Banregio, BanCoppel, Bank of America, Chase, Wells Fargo, Citi, etc.).
10. Detecta el país del banco (MX, US, GB, ES, etc.) usando ISO 3166-1 alpha-2.
11. Detecta la moneda (MXN, USD, EUR, GBP, etc.) usando ISO 4217.
12. Detecta el tipo de cuenta: cheques, ahorro, crédito, inversión, nómina.
13. Extrae intereses generados (interestEarned) e intereses cobrados (interestCharged) si aparecen en el estado.
14. Si la CLABE interbancaria completa (18 dígitos) está visible en el documento, extráela en account.clabe SIN espacios. Si está parcialmente visible o enmascarada, usa account.clabeMasked.
15. Si el número de cuenta completo está visible, extráelo en account.number. Para versiones parciales usa account.numberMasked."""

def get_user_prompt(document_id: str, model_id: str, ocr_text: str) -> str:
    return f"""Extrae un estado de cuenta bancario (bank_statement) del texto OCR entre <<DOC>> y </DOC>.
Usa la herramienta `extract_bank_statement` para devolver los datos.

Reglas de extracción:
- Si no existe el campo, usa null.
- amounts: número positivo con punto decimal; direction indica credit/debit.
- currency: ISO 4217 (MXN/USD/EUR...) detectado del documento; si no se detecta, null.
- periodStart/periodEnd: YYYY-MM-DD si se detectan; convierte de DD/MM/YYYY si es necesario.
- transactions: lista completa de todas las transacciones del periodo. Cada una incluye date, description, amount, direction, category. reference y balanceAfter son opcionales.
- category: clasifica cada transacción como: nómina, transferencia, spei, comisión, retiro_atm, compra_pos, pago_servicio, interés, dividendo, cheque, domiciliación, otro.
- summaryText: un resumen breve de 1 línea (banco, tipo cuenta, periodo, titular).
- accountType: tipo de cuenta detectado (cheques, ahorro, crédito, inversión, nómina).
- bankCountry: país del banco en ISO 3166-1 alpha-2 (MX, US, etc.).
- fees: comisiones totales y IVA sobre comisiones del periodo, si aparecen.
- interestEarned: intereses ganados en el periodo (si aparecen).
- interestCharged: intereses cobrados en el periodo (si aparecen).
- overallConfidence: Evalúa de 0 a 100 según qué tan legible es el texto OCR y qué tan completa es la información extraída. Si faltan campos clave (banco, titular, saldos) o el texto es muy corto/ilegible, baja la confianza.

<<DOC>>
{ocr_text}
</DOC>
"""

def get_tool_config() -> Dict[str, Any]:
    return {
        "tools": [
            {
                "toolSpec": {
                    "name": "extract_bank_statement",
                    "description": "Extrae los datos requeridos de un estado de cuenta bancario de cualquier banco nacional o internacional",
                    "inputSchema": {
                        "json": {
                            "type": "object",
                            "properties": {
                                "bank": {
                                    "type": "object",
                                    "properties": {"name": {"type": "string"}}
                                },
                                "account": {
                                    "type": "object",
                                    "properties": {
                                        "holder": {"type": "string"},
                                        "number": {"type": "string", "description": "Número de cuenta completo si visible."},
                                        "numberMasked": {"type": "string", "description": "Número de cuenta enmascarado."},
                                        "clabe": {"type": "string", "description": "CLABE interbancaria completa (18 dígitos, sin espacios) si visible."},
                                        "clabeMasked": {"type": "string", "description": "CLABE parcial o enmascarada."},
                                        "currency": {"type": "string"}
                                    }
                                },
                                "statement": {
                                    "type": "object",
                                    "properties": {
                                        "periodStart": {"type": "string"},
                                        "periodEnd": {"type": "string"}
                                    }
                                },
                                "balances": {
                                    "type": "object",
                                    "properties": {
                                        "opening": {"type": "number"},
                                        "closing": {"type": "number"},
                                        "totalCredits": {"type": "number"},
                                        "totalDebits": {"type": "number"}
                                    }
                                },
                                "transactions": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "properties": {
                                            "date": {"type": "string"},
                                            "description": {"type": "string"},
                                            "reference": {"type": "string"},
                                            "direction": {"type": "string", "enum": ["credit", "debit"]},
                                            "amount": {"type": "number"},
                                            "balanceAfter": {"type": "number"},
                                            "category": {
                                                "type": "string",
                                                "enum": ["nómina", "transferencia", "spei", "comisión", "retiro_atm", "compra_pos", "pago_servicio", "interés", "dividendo", "cheque", "domiciliación", "otro"]
                                            }
                                        },
                                        "required": ["direction"]
                                    }
                                },
                                "accountType": {
                                    "type": "string",
                                    "enum": ["cheques", "ahorro", "crédito", "inversión", "nómina"]
                                },
                                "bankCountry": {
                                    "type": "string",
                                    "description": "ISO 3166-1 alpha-2 country code of the bank"
                                },
                                "fees": {
                                    "type": "object",
                                    "properties": {
                                        "totalFees": {"type": "number"},
                                        "ivaOnFees": {"type": "number"}
                                    }
                                },
                                "interestEarned": {"type": "number"},
                                "interestCharged": {"type": "number"},
                                "summaryText": {"type": "string"},
                                "overallConfidence": {
                                    "type": "number",
                                    "description": "Nivel de confiabilidad general de la extracción del estado de cuenta. Usar un valor de 0 a 100."
                                }
                            }
                        }
                    }
                }
            }
        ],
        "toolChoice": {
            "tool": {"name": "extract_bank_statement"}
        }
    }

def invoke_bedrock_bank_statement(document_id: str, ocr_text: str, model_id: str) -> Tuple[str, Dict[str, Any]]:
    """
    Invokes Amazon Bedrock Converse API with the strict Prompt and ToolConfig.
    Returns (raw_json_string, metrics_dict)
    """
    
    system = [{"text": SYSTEM_PROMPT}]
    messages = [
        {
            "role": "user",
            "content": [{"text": get_user_prompt(document_id, model_id, ocr_text)}]
        }
    ]
    
    # High restrictiveness with increased maxTokens for statements with many transactions
    inf_params = {"temperature": 0.0, "topP": 0.1, "maxTokens": 8000}
    
    try:
        response = bedrock_client.converse(
            modelId=model_id,
            messages=messages,
            system=system,
            inferenceConfig=inf_params,
            toolConfig=get_tool_config()
        )
        
        output_message = response['output']['message']
        raw_text = "{}"
        
        # Bedrock Converse ToolUse
        for content in output_message.get('content', []):
            if 'toolUse' in content:
                # The tool was used, get its input arguments which forms our structured JSON
                tool_input = content['toolUse']['input']
                raw_text = json.dumps(tool_input)
                break
            elif 'text' in content and raw_text == "{}":
                # Fallback in case tool was not used
                raw_text = content['text']
        
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
