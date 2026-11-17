# Scanalyze Bank Worker

Este worker procesa tareas de extracción de datos bancarios para el tenant `bank`.
Se encarga de leer el resultado de OCR de S3, enviarlo a Amazon Bedrock (Claude Haiku 4.5 por defecto) mediante un prompt estricto y un schema JSON (1.0), normalizar el resultado de vuelta, guardarlo en S3 (structured bucket) y actualizar DynamoDB.

## Extracción por páginas y conciliación (GUG-542)

- El texto OCR conserva sus páginas y se envía en bloques de hasta 3 páginas (`PAGES_PER_CHUNK`).
- Si la salida del modelo se corta en `maxTokens` (`stopReason = max_tokens`) o no pasa el esquema dos veces, el bloque se reintenta página por página. Si una página sigue fallando, el documento no se escribe y el mensaje vuelve a la cola (reintento y DLQ); ninguna página se descarta en silencio.
- Al unir: el saldo inicial viene del primer bloque que lo reporta y el final del último; totales, intereses y comisiones del documento nunca se suman entre bloques.
- La conciliación es al centavo (redondeo half-up, tolerancia de 0.01): saldo inicial + abonos − cargos = saldo final, y los totales impresos deben coincidir con las transacciones.
- La confianza propia del modelo (`overallConfidence`) es obligatoria; si falta, el bloque se trata como violación de esquema. Un 0 explícito se conserva.
- Los parámetros de muestreo dependen del modelo (`model_profile.py`): Claude 3 acepta `temperature` y `topP`; Claude 4 hasta 4.6 solo `temperature`; Claude 4.7 y 5.x ninguno.

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
- `BEDROCK_MODEL_ID`: Configurable si se desea cambiar de modelo. Default: `us.anthropic.claude-haiku-4-5-20251001-v1:0` (perfil de inferencia US; Bedrock no admite el ID base de Haiku 4.5 bajo demanda). Debe coincidir con `bedrock_extractor_model_ids` de la capa `global`, que fija el IAM.

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
