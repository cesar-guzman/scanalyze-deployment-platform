# scanalyze-ingest-api

Microservicio de ingestión para Scanalyze (ECS Fargate) basado en FastAPI.

## Endpoints mínimos
Public:
- `GET /health`
- `GET /v1/health`

Auth (protegidos por API Gateway JWT Authorizer en `/v1/*`):
- `POST /v1/documents`
- `POST /v1/documents/{id}/submit`
- `GET /v1/documents/{id}`
- `GET /v1/documents/{id}/result`
- `GET /v1/documents/{id}/artifacts`
- `POST /v1/documents/{id}/artifacts/{artifactId}/download`

## Configuración (ENV)
Soporta:
- Variables directas: `DOCUMENTS_TABLE_NAME`, `RAW_BUCKET`, `STRUCTURED_BUCKET`, `OCR_BUCKET`, `ERRORS_BUCKET`, `OCR_QUEUE_URL`, etc.
- Variables JSON opcionales:
  - `BUCKETS_JSON`: e.g. `{"raw":"raw-bucket","structured":"structured-bucket","ocr":"ocr-bucket","errors":"errors-bucket"}`
  - `SQS_QUEUE_URLS_JSON`: e.g. `{"ocr":"https://sqs.../ocr-queue","classify":"https://sqs.../classify-queue"}`

Otros:
- `UPLOAD_URL_TTL_SECONDS` (default 900)
- `DOWNLOAD_URL_TTL_SECONDS` (default 600)
- `FIRST_STAGE` (default `ocr`)
- `S3_KEY_PREFIX_TEMPLATE` (default `{tenant}/{document_id}/`)

### Identidad y autenticación

Las rutas protegidas usan `AUTH_MODE=cognito_jwt`. La API verifica firma,
issuer, token type y client/audience; nunca toma customer o deployment de un
header, query parameter o payload. `ENFORCE_AUTH_HEADER` y `X-Tenant-Id` son
interfaces legacy rechazadas y no deben configurarse.

Toda configuración remota requiere dos identidades distintas:

- `SCANALYZE_DEPLOYMENT_CUSTOMER_ID`
- `SCANALYZE_DEPLOYMENT_ID`

Un cliente M2M nuevo sólo se habilita mediante:

- `M2M_TENANT_RESOLUTION=client_identity_bindings_v1`
- `M2M_CLIENT_IDENTITY_BINDINGS_V1`, un objeto versionado que vincula cada
  client ID con customer, deployment y scopes requeridos.
- `M2M_ACTION_SCOPE_SETS_V1`, un objeto versionado con conjuntos exactos,
  no vacíos y disjuntos para `read`, `write` y `admin`.

Las acciones se derivan únicamente de los scopes del binding revisado; scopes
adicionales presentes sólo en el token no elevan permisos. Cada ruta protegida
declara una política M2M explícita de lectura, escritura o exportación
(`read+admin`). Los nombres concretos de scopes proceden de la configuración
aprobada, no de constantes hardcodeadas.

`M2M_CLIENT_TENANT_MAP` no constituye autorización y no es un fallback. Los
identificadores y bindings reales deben permanecer fuera de Git, logs y
evidencia general. Consulte `ADR/ADR-020-versioned-m2m-identity-binding.md` y
`docs/deployment/identity-contract.md`.

`AUTH_MODE=local_mock` sólo es válido para `APP_ENV=local|test|ci` y usa
fixtures explícitamente sintéticos.

## Local run
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
PORT=8080 DOCUMENTS_TABLE_NAME=... RAW_BUCKET=... uvicorn app.main:app --host 0.0.0.0 --port 8080
```
