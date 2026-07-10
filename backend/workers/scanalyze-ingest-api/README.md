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
- `ENFORCE_AUTH_HEADER` (default false) para exigir Authorization incluso si el auth lo hace APIGW.

## Local run
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
PORT=8080 DOCUMENTS_TABLE_NAME=... RAW_BUCKET=... uvicorn app.main:app --host 0.0.0.0 --port 8080
```
