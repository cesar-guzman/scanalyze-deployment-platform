import json
import logging
from typing import Dict, Any, Optional, Tuple, List
from .aws import bedrock_client

logger = logging.getLogger(__name__)

PROMPT_VERSION = "1.3.0"

SYSTEM_PROMPT = """Eres un extractor determinista de información de documentos personales (docType=personal_doc). 
Debes extraer únicamente la información presente en el OCR. Si un dato no está presente, usa null. 
No inventes datos ni asumas valores. 
El campo "document.numberMasked" debe venir ENMASCARADO (ejemplo: terminación visible y lo demás con X).
Extrae fechas en formato ISO-8601 (YYYY-MM-DD); si no puedes parsear, null.
Devuelve SOLO JSON válido (sin markdown, sin comentarios). NO agregues campos fuera del esquema.

REGLAS CRÍTICAS PARA INE MEXICANA:
- El CURP tiene EXACTAMENTE 18 caracteres alfanuméricos (letras y números, SIN guiones, SIN "<").
  Formato: 4 letras + 6 dígitos + 1 letra (H/M) + 5 letras + 1 alfanumérico + 1 dígito.
  Ejemplo válido: LOOS790918HDFPRR03
- El MRZ (Machine Readable Zone) del reverso contiene "<" y/o "MEX" — esto NO es el CURP.
  Ejemplo de MRZ: 9212118M3212312MEX<03<<23021<9
- Si no puedes identificar un CURP con formato correcto, usa null.
- La Clave de Elector tiene 18 caracteres alfanuméricos.
- Coloca datos del MRZ en el campo "mrz", NUNCA en el campo "curp".

REGLAS PARA CONSTANCIA CURP (subType=curp_mx):
- Si el documento dice "Constancia de la Clave Única de Registro de Población", "CURP Certificada", RENAPO, SEGOB o TELCURP, usar subType="curp_mx".
- El CURP del TITULAR es el valor principal que aparece junto a "Clave:" o en el bloque principal de la constancia.
- Si hay múltiples CURPs en el documento, elegir SOLO el del TITULAR (persona principal del documento), NO usar CURPs secundarios de familiares, referencias, texto legal o documentos adjuntos.
- Una constancia CURP NUNCA tiene "claveElector". Para subType="curp_mx", claveElector SIEMPRE debe ser null.
- Si encuentras un valor con formato CURP que podrías poner en claveElector para una constancia CURP, eso es un ERROR: debe ir en identifiers.curp.

REGLA claveElector:
- claveElector SOLO aplica para credencial INE (subType="ine_mx") cuando el OCR dice "CLAVE DE ELECTOR".
- Para CUALQUIER otro subType (curp_mx, rfc_sat, nss_imss, passport, etc.), claveElector SIEMPRE debe ser null.

REGLAS PARA NÓMINA/CFDI (subType=payroll_cfdi_mx):
- Si el documento es un Comprobante Fiscal Digital (CFDI) de nómina, recibo de nómina, recibo de pago de salarios, timbrado de nómina, o XML de nómina, usar subType="payroll_cfdi_mx".
- Extraer employer.name (razón social del emisor/patrón) y employer.rfc si visibles.
- Extraer payroll.netPay (percepciones netas/pago neto) y payroll.grossPay (total de percepciones) como NÚMEROS, no strings.
- Extraer payroll.deductions (total deducciones) y payroll.taxWithheld (ISR retenido) como números si visibles.
- Extraer payroll.position (puesto/cargo) y payroll.department si visibles.
- Extraer payroll.payPeriod (período de pago) y payroll.paymentDate (fecha de pago) en ISO-8601.
- Extraer document.uuid (UUID/folio fiscal del CFDI) si visible.
- No fabricar montos ni puestos si no están en el OCR.
- El objeto payroll SOLO debe existir para documentos de nómina (subType=payroll_cfdi_mx).

REGLAS PARA IMSS (subType=nss_imss / imss_weeks_certificate):
- Extraer identifiers.nss con el NSS COMPLETO (11 dígitos) si está visible en el documento.
- Extraer document.number si el número de documento completo está visible.
- Si solo hay NSS parcial visible, usar document.numberMasked.
- NO confundir NSS (11 dígitos numéricos) con CURP (18 alfanuméricos).
- Extraer imss.weeksContributed (semanas cotizadas) si visible.
- Extraer imss.employers (lista de patrones con nombre y registro patronal) si visible.
- Extraer employer.name y employer.registrationNumber (registro patronal) si visibles.

REGLAS PARA CV/CURRÍCULUM (subType=cv_resume):
- Extraer contact.email, contact.phone y contact.address si visibles.
- No confundir datos de contacto del titular con datos de referencias o empresas previas.

REGLA SubType:
- Respetar el subType indicado por el clasificador salvo contradicción OCR fuerte.
- No degradar a personal_doc_generic si el clasificador indica un subType específico soportado.
- Si el documento no encaja en ningún subType específico, usar personal_doc_generic.

REGLA employer:
- El objeto employer puede existir para payroll_cfdi_mx, nss_imss, imss_weeks_certificate y labor_certificate.
- Para otros subTypes, employer debe ser null."""

def get_user_prompt(document_id: str, model_id: str, ocr_text: str, classifier_hints: Optional[Dict[str, Any]] = None) -> str:
    # Build classifier context section if hints are available
    classifier_context = ""
    if classifier_hints:
        hint_sub = classifier_hints.get("subType")
        hint_doc = classifier_hints.get("canonicalDocType")
        hint_reasons = classifier_hints.get("reasonCodes", [])
        if hint_sub or hint_doc:
            parts = []
            if hint_doc:
                parts.append(f"canonicalDocType={hint_doc}")
            if hint_sub:
                parts.append(f"subType={hint_sub}")
            if hint_reasons:
                parts.append(f"reasonCodes={','.join(hint_reasons)}")
            classifier_context = f"""
CONTEXTO DEL CLASIFICADOR (respeta estos hints salvo evidencia OCR fuertemente contradictoria):
- {'; '.join(parts)}
- Si el clasificador indica subType=curp_mx, este documento ES una constancia CURP. No devuelvas subType=ine_mx.
- Si el clasificador indica subType=curp_mx, claveElector DEBE ser null.
- Si el clasificador indica subType=payroll_cfdi_mx, extraer campos de payroll y employer. No degradar a personal_doc_generic.
- Si el clasificador indica subType=nss_imss o imss_weeks_certificate, extraer identifiers.nss completo si visible y campos de imss.
"""

    return f"""Extrae los detalles del documento personal desde el texto OCR entre <<DOC>> y </DOC>.
Usa la herramienta `extract_personal_document` para devolver los datos.
Reglas:
- Si un dato no está presente en el OCR, usa null.
- subType debe ser uno de: "ine_mx", "curp_mx", "rfc_sat", "nss_imss", "imss_weeks_certificate", "birth_certificate", "passport", "mx_driver_license", "cv_resume", "payroll_cfdi_mx", "recommendation_letter", "labor_certificate", "personal_doc_generic", "unknown".
- Extrae fechas en formato ISO-8601 (YYYY-MM-DD); si no puedes parsear, null.
- El campo "numberMasked" debe venir ENMASCARADO (ejemplo: terminación visible y lo demás con X).
- El campo "summaryText" debe contener un resumen hiper breve de 1 linea del documento identificado en formato texto.
- CURP: Debe tener EXACTAMENTE 18 caracteres alfanuméricos (sin "<", sin "MEX"). Si el texto contiene "<" o "MEX" es MRZ, NO CURP. Si no encuentras un CURP válido, usa null.
- MRZ: Las líneas con "<" y/o "MEX" del reverso van en el campo "mrz".
- NSS: Debe tener EXACTAMENTE 11 dígitos numéricos. No confundir con CURP.
- overallConfidence: Evalúa de 0 a 100 según qué tan legible es el texto OCR y qué tan completa es la información. Si faltan campos clave o el texto es muy corto/ilegible, baja la confianza.
- claveElector: SOLO para INE (subType=ine_mx) cuando el OCR dice "CLAVE DE ELECTOR". Para cualquier otro subType, SIEMPRE usar null.
- contact: Si el documento tiene email, teléfono o dirección del titular, colocarlos en el objeto contact (NO en person).
- payroll: SOLO incluir el objeto payroll si subType=payroll_cfdi_mx. netPay y grossPay deben ser NÚMEROS.
- employer: Incluir si el documento es nómina, IMSS o constancia laboral y los datos del patrón son visibles.
{classifier_context}
<<DOC>>
{ocr_text}
</DOC>"""

def get_tool_config() -> Dict[str, Any]:
    return {
        "tools": [
            {
                "toolSpec": {
                    "name": "extract_personal_document",
                    "description": "Extrae datos estructurados de un documento personal",
                    "inputSchema": {
                        "json": {
                            "type": "object",
                            "properties": {
                                "subType": {
                                    "type": "string",
                                    "enum": [
                                        "ine_mx", "curp_mx", "rfc_sat", "nss_imss",
                                        "imss_weeks_certificate", "birth_certificate",
                                        "passport", "mx_driver_license",
                                        "cv_resume", "payroll_cfdi_mx",
                                        "recommendation_letter", "labor_certificate",
                                        "personal_doc_generic", "unknown"
                                    ]
                                },
                                "person": {
                                    "type": "object",
                                    "properties": {
                                        "fullName": {"type": "string"},
                                        "givenNames": {"type": "string"},
                                        "surnames": {"type": "string"},
                                        "dob": {"type": "string"},
                                        "sex": {"type": "string"},
                                        "nationality": {"type": "string"},
                                        "address": {"type": "string"}
                                    }
                                },
                                "contact": {
                                    "type": "object",
                                    "description": "Datos de contacto del titular. Usar este objeto en vez de poner email/phone en person.",
                                    "properties": {
                                        "email": {"type": "string", "description": "Email del titular si visible en el documento."},
                                        "phone": {"type": "string", "description": "Teléfono del titular si visible en el documento."},
                                        "address": {"type": "string", "description": "Dirección de contacto si diferente a person.address."}
                                    }
                                },
                                "document": {
                                    "type": "object",
                                    "properties": {
                                        "number": {"type": "string", "description": "Número completo del documento si visible (no enmascarado)."},
                                        "numberMasked": {"type": "string", "description": "Número enmascarado del documento."},
                                        "type": {"type": "string", "description": "Tipo de documento: CFDI, constancia, cédula, título, certificado, etc."},
                                        "uuid": {"type": "string", "description": "UUID/folio fiscal del CFDI si visible."},
                                        "issueDate": {"type": "string"},
                                        "expiryDate": {"type": "string"},
                                        "countryOfIssue": {"type": "string"}
                                    }
                                },
                                "identifiers": {
                                    "type": "object",
                                    "properties": {
                                        "curp": {
                                            "type": "string",
                                            "description": "CURP mexicana del TITULAR del documento (18 caracteres). Formato: 4 letras + 6 dígitos + H/M + 5 letras + 2 alfanuméricos. SIEMPRE colocar el CURP aquí, NUNCA en claveElector. Si hay múltiples CURPs, elegir el del titular (persona principal del documento), no el de familiares o registrantes."
                                        },
                                        "rfc": {"type": "string", "description": "RFC mexicano de 12-13 caracteres."},
                                        "claveElector": {
                                            "type": "string",
                                            "description": "Clave de Elector de una credencial INE mexicana (18 caracteres). SOLO extraer si subType='ine_mx' Y el OCR dice 'CLAVE DE ELECTOR'. Para cualquier otro subType, SIEMPRE usar null."
                                        },
                                        "cic": {"type": "string", "description": "Código de identificación CIC del INE."},
                                        "ocr": {"type": "string", "description": "Código OCR del INE."},
                                        "mrz": {"type": "string", "description": "Machine Readable Zone. Contiene '<' y/o 'MEX'. NO es CURP."},
                                        "nss": {"type": "string", "description": "Número de Seguridad Social IMSS. EXACTAMENTE 11 dígitos numéricos. Extraer SOLO si el NSS completo está visible. No confundir con CURP."}
                                    }
                                },
                                "employer": {
                                    "type": "object",
                                    "description": "Datos del patrón/empleador. Solo para nómina, IMSS o constancia laboral.",
                                    "properties": {
                                        "name": {"type": "string", "description": "Razón social del patrón/emisor."},
                                        "rfc": {"type": "string", "description": "RFC del patrón (12-13 caracteres)."},
                                        "registrationNumber": {"type": "string", "description": "Registro patronal IMSS si visible."}
                                    }
                                },
                                "payroll": {
                                    "type": "object",
                                    "description": "Datos de nómina. SOLO incluir si subType=payroll_cfdi_mx.",
                                    "properties": {
                                        "position": {"type": "string", "description": "Puesto o cargo del trabajador."},
                                        "department": {"type": "string", "description": "Departamento del trabajador."},
                                        "payPeriod": {"type": "string", "description": "Período de pago (ej: 2026-04-16/2026-04-30)."},
                                        "paymentDate": {"type": "string", "description": "Fecha de pago en ISO-8601."},
                                        "grossPay": {"type": "number", "description": "Total de percepciones (número)."},
                                        "deductions": {"type": "number", "description": "Total de deducciones (número)."},
                                        "taxWithheld": {"type": "number", "description": "ISR retenido (número)."},
                                        "netPay": {"type": "number", "description": "Neto a pagar (número)."}
                                    }
                                },
                                "imss": {
                                    "type": "object",
                                    "description": "Datos específicos IMSS. Solo para nss_imss o imss_weeks_certificate.",
                                    "properties": {
                                        "weeksContributed": {"type": "integer", "description": "Semanas cotizadas si visible."},
                                        "employers": {
                                            "type": "array",
                                            "description": "Lista de patrones registrados. Cada uno con name y registrationNumber.",
                                            "items": {
                                                "type": "object",
                                                "properties": {
                                                    "name": {"type": "string"},
                                                    "registrationNumber": {"type": "string"},
                                                    "weeks": {"type": "integer"}
                                                }
                                            }
                                        }
                                    }
                                },
                                "overallConfidence": {
                                    "type": "number", 
                                    "description": "Nivel de confiabilidad general de la lectura del documento. Usar un valor de 0 a 100."
                                },
                                "summaryText": {"type": "string"}
                            },
                            "required": ["subType", "person", "document", "identifiers", "overallConfidence"]
                        }
                    }
                }
            }
        ],
        "toolChoice": {
            "tool": {"name": "extract_personal_document"}
        }
    }

def invoke_bedrock_personal_doc(
    document_id: str, ocr_text: str, model_id: str,
    classifier_hints: Optional[Dict[str, Any]] = None,
) -> Tuple[str, Dict[str, Any]]:
    """
    Invokes Amazon Bedrock Converse API with the strict Prompt for personal documents utilizing toolConfig.
    Returns (raw_json_string, metrics_dict)
    """
    system = [{"text": SYSTEM_PROMPT}]
    messages = [
        {
            "role": "user",
            "content": [{"text": get_user_prompt(document_id, model_id, ocr_text, classifier_hints)}]
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
            inferenceConfig=inf_params,
            toolConfig=get_tool_config()
        )
        
        output_message = response['output']['message']
        raw_text = "{}"
        
        # Bedrock Converse ToolUse extraction
        for content in output_message.get('content', []):
            if 'toolUse' in content:
                # The tool was used, get its input arguments which forms our structured JSON
                tool_input = content['toolUse']['input']
                raw_text = json.dumps(tool_input)
                break
            elif 'text' in content and raw_text == "{}":
                # Fallback in case tool was not used but text was generated
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
        raise
