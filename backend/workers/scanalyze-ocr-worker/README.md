# Scanalyze OCR Worker

Worker ECS multi-tenant "production-grade" para procesar documentos a través de AWS Textract.

## Arquitectura y Flujo

Este worker soporta dos modos de ejecución inyectados vía la variable de entorno `WORKER_MODE` o mediante el command entrypoint en el contenedor:
1. **INGEST Mode**: Consume URLs desde la cola `ingest`, valida, inicia la detección en Textract (async) y encola un mensaje hacia `ocr` para polling.
2. **OCR_POLL Mode**: Consume desde la cola `ocr`, revisa el estado de Textract y transiciona entre error o exito. Si está listo (SUCCEEDED), genera artifacts JSON en S3 y avisa a la cola `classify` bajo el contrato v1.

## Cómo correr local (Sin AWS)

El worker cuenta con un smoke test que usa `unittest.mock` para emular completamente los servicios de AWS, incluyendo SSM para config y DynamoDB/SQS/S3 para el procesamiento.

### Prerrequisitos
- Python 3.11.14 (pinned in `.tool-versions`)
- `pip install -r requirements.txt`
- `pip install 'pytest==9.1.1'`

### Package Layout

The worker uses relative imports internally. Both layouts resolve the same
production modules:

| Context | PYTHONPATH | Import prefix | Example |
|---------|-----------|---------------|---------|
| **Source** (host tests/CI) | `<service>/src` | `ocr_worker.…` | `from ocr_worker.logger import get_logger` |
| **Container** (Docker) | `/app` | `src.ocr_worker.…` | `python -m src.ocr_worker.main` |

The canonical owner of `get_logger` is `ocr_worker.logger` (one definition,
no fallback, no duplicate).

### Ejecutar Tests Offline (sin AWS)

```sh
# Variables sintéticas requeridas
export SCANALYZE_ENV=test
export SCANALYZE_TENANT=platform
export SCANALYZE_DEPLOYMENT_CUSTOMER_ID=cust_01ARZ3NDEKTSV4RRFFQ69G5FAW
export SCANALYZE_DEPLOYMENT_ID=dep_01ARZ3NDEKTSV4RRFFQ69G5FAV
export SCANALYZE_PARAM_ROOT=/scanalyze/test/tenants
export AWS_EC2_METADATA_DISABLED=true
export AWS_REGION=us-east-1

# Suite completa del worker
PYTHONPATH=backend/workers/scanalyze-ocr-worker/src:backend/workers/scanalyze-ocr-worker \
  python -m pytest backend/workers/scanalyze-ocr-worker/tests -q

# Smoke test legacy
PYTHONPATH=backend/workers/scanalyze-ocr-worker/src \
  python backend/workers/scanalyze-ocr-worker/tests/smoke_test.py
```

### Docker Build

> **Blocker:** The current Dockerfile runs `pip install` during the build,
> which requires network access.  An offline build with `--network=none` will
> fail because the pip dependencies are not pre-cached in the base image.
> CI builds succeed because runners have network access.

The following static contract tests validate the Dockerfile without building:

- `test_dockerfile_entrypoint_references_src_module` — ENTRYPOINT references
  `src.ocr_worker.main`.
- `test_dockerfile_copies_src_into_app` — `COPY src/ ./src/` is present.

**What is not validated offline:**
- Actual Docker image build
- Container import (`src.ocr_worker.*` inside image)
- Container startup (`WORKER_MODE=INVALID` entrypoint)
- Synthetic processing inside the container
- Container log-redaction

### Log-Redaction Invariant

The structured JSON logger uses a **centralised fail-closed allowlist** to
control which metadata fields are emitted.  The canonical sanitiser
`_sanitize_log_fields()` is the single owner of these rules and is called by
every entry path:

1. `bind_context()` — context fields bound to the async scope.
2. `log_event()` — structured event keyword arguments.
3. `JSONFormatter.format()` — `LogRecord` extra fields and context replay.

**Behaviour:**

- Only fields in `_ALLOWED_FIELDS` are emitted; unknown fields are dropped.
- Nested dicts, lists (except bounded `invalidFields`), and custom objects
  are dropped.
- String values are bounded to 1024 characters and control characters are
  stripped.
- Exception logging emits `errorType` but never the raw exception message
  or traceback.
- Correlation IDs and approved operational metadata are preserved.


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

> **Nota:** Esta sección requiere un entorno AWS en vivo con credenciales
> configuradas. No forma parte de la validación offline (GUG-105).

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
