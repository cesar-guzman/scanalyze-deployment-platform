# Scanalyze Bank Worker

Este worker procesa tareas de extracción de datos bancarios para el tenant `bank`.
Se encarga de leer el resultado de OCR de S3, enviarlo a Amazon Bedrock (Claude 3 Haiku por defecto) mediante un prompt estricto y un schema JSON (1.0), normalizar el resultado de vuelta, guardarlo en S3 (structured bucket) y actualizar DynamoDB.

## Arquitectura

- **Trigger**: SQS Long Polling (`bank-extract_url`)
- **Inputs**: S3 OCR Artifact (bucket/key)
- **AI**: Amazon Bedrock Converse API
- **Outputs**: 
  - `result.json` guardado en el Structured Bucket de S3.
  - Item actualizado en la tabla de DynamoDB (status `BANK_EXTRACTED` + metadata y metrics).
  - Mensaje hacia la SQS `validate_url` para seguir el pipeline.

## Configuración y Variables de Entorno

El worker utiliza `Boto3` y SSM Parameter Store para inyectar su configuración dinámicamente.

- `AWS_REGION`: Región explícita del deployment.
- `SCANALYZE_ENV`: Identificador de entorno inyectado por el deployment.
- `SCANALYZE_TENANT`: Para este worker debe ser **obligatoriamente** `bank`.
- `LOG_LEVEL`: `INFO` (por defecto) o `DEBUG`.
- `BEDROCK_MODEL_ID`: Configurable si se desea cambiar de modelo en el futuro. Default: `anthropic.claude-3-haiku-20240307-v1:0`

### Rutas SSM Esperadas
Basado en `SCANALYZE_ENV`=`<ENVIRONMENT>` y `SCANALYZE_TENANT`=`bank`:
- `/scanalyze/<ENVIRONMENT>/tenants/bank/queues/bank-extract_url`
- `/scanalyze/<ENVIRONMENT>/tenants/bank/queues/validate_url`
- `/scanalyze/<ENVIRONMENT>/tenants/bank/data-foundation/ocr_bucket_name`
- `/scanalyze/<ENVIRONMENT>/tenants/bank/data-foundation/structured_bucket_name`
- `/scanalyze/<ENVIRONMENT>/tenants/bank/data-foundation/documents_table_name`

## Idempotencia y Reintentos
- **Retryable Errors**: Throttling, timeouts de AWS, fallos de red. SQS se encarga de reintentar luego de que expira el Visibility Timeout.
- **Non-retryable Errors**: Archivos de OCR faltantes (`NoSuchKey`), validaciones de schema insalvables (`Pydantic ValidationError`). En estos casos se actualiza DynamoDB marcando el stage como `FAILED` y se hace acknowledge (borrado) del mensaje original para evitar bucles.
- **Idempotencia**: Antes de llamar a Bedrock, el worker hace un `HeadObject` en S3 comprobando si el `result.json` ya existe. Si existe, no vuelve a procesar y emite un log de skip_idempotent.

## Ejecución Local

1. Usa un `AWS_PROFILE` no productivo aprobado y autentícate con `aws sso login`.
2. Crea un entorno virtual e instala dependencias:
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
3. Exporta variables obligatorias:
```bash
export SCANALYZE_ENV="<ENVIRONMENT>"
export SCANALYZE_TENANT="bank"
export AWS_REGION="<AWS_REGION>"
export PYTHONPATH=src
```
4. Ejecuta:
```bash
python -m bank_worker.main
```
