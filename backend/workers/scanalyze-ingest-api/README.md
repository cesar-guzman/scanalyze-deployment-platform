# scanalyze-ingest-api

Microservicio de ingestión para Scanalyze (ECS Fargate) basado en FastAPI.

## Endpoints mínimos
Public:
- `GET /health`
- `GET /api/v1/health`

Auth (protegidos en `/api/v1/*`):
- `POST /api/v1/documents`
- `POST /api/v1/documents/{id}/submit`
- `GET /api/v1/documents/{id}`
- `GET /api/v1/documents/{id}/result`
- `GET /api/v1/documents/{id}/artifacts`
- `GET /api/v1/documents/{id}/download`
- `GET /api/v1/documents/{id}/artifacts/{artifactId}/download`
- `POST /api/v1/batches`
- `GET /api/v1/batches/{id}`
- `GET /api/v1/batches/{id}/documents`
- `GET /api/v1/batches/{id}/manifest`
- `GET /api/v1/batches/{id}/exports/{json|csv|zip}`

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

### Autorización de objetos

Autenticación y policy de ruta no prueban por sí solas acceso a un documento o
batch concreto. Cada operación protegida conserva el `AuthContext` completo y
debe autorizar el objeto mediante igualdad exacta de los campos canónicos:

```text
record.customer_id == auth.customer_id
record.deployment_id == auth.deployment_id
```

Para registros nuevos, ambos campos son obligatorios, provienen exclusivamente
del `AuthContext` validado y son inmutables. `tenantId` es una interfaz legacy y
no prueba ownership. Ownership ausente, parcial, malformado, contradictorio o
legacy-only se rechaza; nunca se completa desde headers, query parameters,
payload, metadata, un batch accesible, un mapa tenant o un prefijo S3.

`AUTH_MODE=local_mock` también requiere un `SCANALYZE_DEPLOYMENT_ID` sintético,
explícito y válido. No existe un deployment local compartido o inferido.

El batch y cada documento miembro se autorizan por separado. Una membresía mixta
o inconsistente bloquea la operación completa, incluidos manifest y exports. Las
consultas de lista o membresía deben vincular customer y deployment en el patrón
de acceso DynamoDB; un scan o fetch-then-filter no es un control aceptable.

Bucket y key de un artifact se obtienen sólo de metadata almacenada del documento
ya autorizado. La API autoriza antes de generar una URL prefirmada y nunca acepta
bucket, key o prefix desde la solicitud. Result, exports y downloads protegidos
conservan la policy M2M `read+admin` de GUG-102.

Mientras GUG-89 migra los producers asíncronos, se admite únicamente su contrato
exacto y revisado: `platform|bank|personal|gov/<documentId>/ocr.json` en el bucket
OCR configurado y `bank|personal|gov/<documentId>/result.json` en el bucket
structured configurado. Route, document id, filename y bucket deben coincidir;
no se aceptan prefijos legacy arbitrarios ni valores enviados por el request.
El worker OCR todavía no valida el tuple de ownership del mensaje contra DynamoDB
y por ello esa frontera asíncrona permanece **Blocked** para GUG-89.

Los jobs, manifests y perfiles del add-on Employee Profiles autorizan cualquier
objeto preexistente incluso con `force=true`. Creación usa `If-None-Match: *` y
reemplazo usa `If-Match` sobre la versión leída, por lo que ownership legacy,
conflictivo o una actualización concurrente fallan cerrados.

Objeto inexistente, extranjero o sin ownership usa una respuesta externa
sanitizada que no revela existencia. Los fallos no registran contenido, PII,
JWTs, S3 keys, URLs prefirmadas ni payloads.

Consulte `ADR/ADR-021-object-level-authorization.md` y
`docs/deployment/object-ownership-migration-quarantine.md`. La presencia de esos
documentos no demuestra implementación ni validación: **Implemented**, **Locally
validated**, **CI validated** y **Live validated** requieren evidencia separada
para la revisión exacta. La migración y validación live continúan **Blocked** y
producción permanece **NO-GO**.

## Local run
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
PORT=8080 DOCUMENTS_TABLE_NAME=... RAW_BUCKET=... uvicorn app.main:app --host 0.0.0.0 --port 8080
```
