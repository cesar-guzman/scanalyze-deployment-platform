# Scanalyze OCR Worker

Worker ECS multi-tenant "production-grade" para procesar documentos a través de AWS Textract.

## Arquitectura y Flujo

Este worker soporta dos modos de ejecución inyectados vía la variable de entorno `WORKER_MODE` o mediante el command entrypoint en el contenedor:
1. **INGEST Mode**: Consume mensajes `scanalyze.ingest.v2` desde la cola `ingest`, valida, inicia la detección en Textract (async) y encola un mensaje `scanalyze.ocr-poll.v2` hacia `ocr` para polling.
2. **OCR_POLL Mode**: Consume `scanalyze.ocr-poll.v2` desde la cola `ocr`, revisa el estado de Textract y transiciona entre error o éxito. Si está listo (`SUCCEEDED`), genera artefactos JSON en S3 y emite `scanalyze.classify.v2` o el contrato `scanalyze.extract.v2` correspondiente a la ruta del documento.

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
> CI builds the image only when the repository variable `CI_BASE_IMAGE` is
> configured; otherwise it explicitly skips Docker after compile-and-test.

The following static contract tests validate the Dockerfile without building:

- `test_dockerfile_entrypoint_references_src_module` — requires the exact
  `ENTRYPOINT ["python", "-m", "src.ocr_worker.main"]` instruction.
- `test_dockerfile_copies_src_into_app` — requires the exact
  `COPY --chown=app:app src/ ./src/` instruction.

**What is not validated offline:**
- Actual Docker image build
- Container import (`src.ocr_worker.*` inside image)
- Container startup (`WORKER_MODE=INVALID` entrypoint)
- Synthetic processing inside the container
- Container log-redaction

### Log-Redaction Invariant

The structured JSON logger uses strict validation and a field contract matrix to control metadata emission. The canonical sanitizer `_sanitize_log_fields()` enforces these rules across different context scopes:

1. `bind_context()` — context fields bound to the async scope.
2. `log_event()` — structured event keyword arguments.
3. `JSONFormatter.format()` — `LogRecord` extra fields and precedence.

**Field Contract and Precedence (highest to lowest):**

1. **Core**: `timestamp`, `level`, `env`, `tenant`, `customerId`, `deploymentId`, `message`. Unconditionally overrides any other fields. The message is bounded to 1024 characters.
2. **Context**: Context-scoped fields (`stage`, `documentId`, `correlationId`, `traceId`). Bounded size, strictly validated, and overrides event or extra metadata.
3. **Event**: Validated event metadata. Must be explicitly permitted in `_SOURCE_PERMISSIONS`. Includes `event`, `errorType` and cannot replace context/core ownership.
4. **Extra**: Only the narrow `_SOURCE_PERMISSIONS["extra"]` allowlist is accepted. Field validators bound type and size; unknown or nested values are dropped.

**Behaviour:**

- Nested dicts, lists (except bounded `invalidFields`), and custom objects are dropped.
- Sanitized metadata containing control characters or surrounding whitespace is rejected as a complete field; characters are not stripped.
- Canonical formats are enforced for IDs (e.g. `correlationId` and `traceId` reject angle-bracket sentinels and PII).
- Exception logging emits `errorType` but never the raw exception message or traceback to prevent sensitive leaks.


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
- `SCANALYZE_DEPLOYMENT_CUSTOMER_ID` (identificador canónico `cust_<ULID>`)
- `SCANALYZE_DEPLOYMENT_ID` (identificador canónico `dep_<ULID>`)
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
        {"name": "SCANALYZE_DEPLOYMENT_CUSTOMER_ID", "value": "<CUSTOMER_ID>"},
        {"name": "SCANALYZE_DEPLOYMENT_ID", "value": "<DEPLOYMENT_ID>"},
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
    "schemaVersion": "scanalyze.ingest.v2",
    "customer_id": "cust_01ARZ3NDEKTSV4RRFFQ69G5FAW",
    "deployment_id": "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV",
    "ownership_schema_version": 1,
    "pipeline_stage": "ingest",
    "enqueue_id": "enqueue-test-001",
    "documentId": "test-doc-001",
    "raw": {
      "bucket": "mi-raw-bucket-existente",
      "key": "customers/cust_01ARZ3NDEKTSV4RRFFQ69G5FAW/deployments/dep_01ARZ3NDEKTSV4RRFFQ69G5FAV/documents/test-doc-001/source.pdf"
    },
    "_metadata": {
      "correlationId": "ref_f07165b64216ae9a4988fc779b08f0db",
      "traceId": "ref_8d49ce52b2f423b5306c54091fa2fb54"
    }
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
