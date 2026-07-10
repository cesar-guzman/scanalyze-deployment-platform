# Scanalyze Personal Worker

Microservicio (ECS/Fargate) diseñado para consumir mensajes de Amazon SQS, recuperar artifacts de OCR correspondientes desde S3 (producidos previamente en el pipeline), e invocar Amazon Bedrock utilizando Claude 3 Haiku para extraer y estructurar el texto original estrictamente en formato JSON adherido al esquema `personal_doc` (INE, Pasaportes, Licencias Mexicanas).

Al finalizar, sube el esquema resultante a S3, actualiza el estado en DynamoDB y redirige el flujo mediante un mensaje de validación de SQS hacia el siguiente paso en la etapa (`validate worker`).

## Arquitectura

1.  **SQS (Extract Queue):** El microservicio se suscribe mediante *Long Polling* a una cola de SQS para reaccionar a la etapa de "extracción" del tenant `personal`.
2.  **S3 (OCR Payload):** Ubica en S3 el JSON o texto resultante dictado por textract u ocr normalizado.
3.  **Bedrock (LLM):** Invoca el modelo Claude respetando *Converse API* con un context limit estricto y un `system prompt` sin alucinación.
4.  **S3 (Structured Bucket):** Almacena el resultado validado estructuralmente por `Pydantic` bajo formato JSON determinista.
5.  **DynamoDB:** Añade metadata, logs de trazabilidad en las etapas, metricas de tokens y cambia el estatus principal a `PERSONAL_EXTRACTED`.
6.  **SQS (Validate Queue):** Envía el artifact resultante pre-validado para confirmar que está disponible a clientes front-end.

## Entorno Local (Desarrollo)

Usa un perfil AWS no productivo aprobado y autenticado mediante SSO.

```bash
export SCANALYZE_ENV="<ENVIRONMENT>"
export SCANALYZE_TENANT="personal"
export AWS_REGION="<AWS_REGION>"
export BEDROCK_MODEL_ID="anthropic.claude-3-haiku-20240307-v1:0"
export LOG_LEVEL="INFO"
```

El worker obtiene de forma automática y asume rutas críticas en SSM `System Manager Parameter Store`.
Para `SCANALYZE_ENV`=`<ENVIRONMENT>` y tenant `personal`:

* `/scanalyze/<ENVIRONMENT>/tenants/personal/queues/personal-extract_url`
* `/scanalyze/<ENVIRONMENT>/tenants/personal/queues/validate_url`
* `/scanalyze/<ENVIRONMENT>/tenants/personal/data-foundation/ocr_bucket_name`
* `/scanalyze/<ENVIRONMENT>/tenants/personal/data-foundation/structured_bucket_name`
* `/scanalyze/<ENVIRONMENT>/tenants/personal/data-foundation/documents_table_name`

### Ejecución

```bash
# Entorno virtual y dependencias
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Ejecución del worker
PYTHONPATH=src python -m personal_worker.main
```

### Pruebas (Tests Unitarios)

Aseguran contratos Pydantic, normalización JSON contra caracteres rebeldes y validaciones deterministas:

```bash
pip install pytest pydantic
PYTHONPATH=src pytest tests/
```
