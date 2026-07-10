# Scanalyze OCR Worker

Worker ECS multi-tenant "production-grade" para procesar documentos a través de AWS Textract.

## Arquitectura y Flujo

Este worker soporta dos modos de ejecución inyectados vía la variable de entorno `WORKER_MODE` o mediante el command entrypoint en el contenedor:
1. **INGEST Mode**: Consume URLs desde la cola `ingest`, valida, inicia la detección en Textract (async) y encola un mensaje hacia `ocr` para polling.
2. **OCR_POLL Mode**: Consume desde la cola `ocr`, revisa el estado de Textract y transiciona entre error o exito. Si está listo (SUCCEEDED), genera artifacts JSON en S3 y avisa a la cola `classify` bajo el contrato v1.

## Cómo correr local (Sin AWS)

El worker cuenta con un smoke test que usa `unittest.mock` para emular completamente los servicios de AWS, incluyendo SSM para config y DynamoDB/SQS/S3 para el procesamiento.

### Prerrequisitos
- Python 3.11
- pip install -r requirements.txt

### Ejecutar Smoke Test
```sh
export PYTHONPATH=src/
python tests/smoke_test.py
```
> El Output debe de mostrar `¡Smoke Test Pasó Correctamente!` demostrando el flujo de ingest -> poll (backoff) -> poll (succeded) -> guardado a s3 -> encolado classify.

## Cómo correr en ECS

La Task Definition en ECS requiere los siguientes permisos IAM:
- leectura recursiva (GetParametersByPath) hacia el root SSM configurado.
- permisos sobre las SQS (Receive, Delete, ChangeMessageVisibility, SendMessage)
- permisos KMS / S3 PutObject para en `ocr_bucket_name`.
- DynamoDB `GetItem`, `UpdateItem` sobre `documents_table_name`.
- Textract `StartDocumentTextDetection` y `GetDocumentTextDetection`.

### Variables de Entorno Requeridas:
- `SCANALYZE_ENV` (identificador inyectado del entorno)
- `SCANALYZE_TENANT` (identificador de tenant del contrato)
- `SCANALYZE_PARAM_ROOT` (ej. `/scanalyze/<ENVIRONMENT>/tenants`)
- `WORKER_MODE` (`INGEST` o `OCR_POLL`)
- `LOG_LEVEL` (opcional, default `INFO`)

### Ejemplo Básico Task Definition "Conceptual" (ECS):
```json
{
  "family": "scanalyze-ocr-worker-ingest",
  "containerDefinitions": [
    {
      "name": "worker",
      "image": "<AWS_ACCOUNT_ID>.dkr.ecr.<AWS_REGION>.amazonaws.com/<ECR_PREFIX>/ocr-worker@sha256:<DIGEST>",
      "environment": [
        {"name": "SCANALYZE_ENV", "value": "<ENVIRONMENT>"},
        {"name": "SCANALYZE_TENANT", "value": "<TENANT>"},
        {"name": "SCANALYZE_PARAM_ROOT", "value": "/scanalyze/<ENVIRONMENT>/tenants"},
        {"name": "WORKER_MODE", "value": "INGEST"}
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/scanalyze-ocr-worker",
          "awslogs-region": "<AWS_REGION>",
          "awslogs-stream-prefix": "worker"
        }
      }
    }
  ]
}
```
*Se recomienda tener un servicio para la task definitions de Ingest, y otro para OCR_POLL para escalar independientemente las colas.*

## Cómo hacer smoke test real en AWS CLI

1. **Obtener las colas desde SSM**
```bash
TENANT="<TENANT>"
ENVIRONMENT="<ENVIRONMENT>"
export INGEST_URL=$(aws ssm get-parameter --name "/scanalyze/${ENVIRONMENT}/tenants/$TENANT/queues/ingest_url" --query "Parameter.Value" --output text)
export OCR_URL=$(aws ssm get-parameter --name "/scanalyze/${ENVIRONMENT}/tenants/$TENANT/queues/ocr_url" --query "Parameter.Value" --output text)
export CLASSIFY_URL=$(aws ssm get-parameter --name "/scanalyze/${ENVIRONMENT}/tenants/$TENANT/queues/classify_url" --query "Parameter.Value" --output text)
```

2. **Mandar mensaje a INGEST**
```bash
aws sqs send-message \
  --queue-url $INGEST_URL \
  --message-body '{
    "schemaVersion": "scanalyze.ingest.v1",
    "documentId": "test-doc-001",
    "raw": {"bucket": "mi-raw-bucket-existente", "key": "inbound/test.pdf"}
  }'
```
> El servicio (si esta corriendo) agarrará el mensaje, activará textract, y mandará un mensaje a la URL OCR.

3. **Revisar si llegó el msg a Classify (Tras que el OCR_POLL lo procesó y Textract terminó)**
```bash
aws sqs receive-message \
  --queue-url $CLASSIFY_URL \
  --max-number-of-messages 1 \
  --wait-time-seconds 10
```

¡Listo!
