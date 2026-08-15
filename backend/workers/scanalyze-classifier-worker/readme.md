# Scanalyze Classifier Worker

Worker Python ECS (single-tenant) que consume mensajes de la cola de clasificación (`classify`), descarga el texto extraído (vía OCR Textract) desde S3, clasifica el documento (usando reglas heurísticas o AWS Bedrock si el flag está habilitado) y enruta el resultado a los workers de extracción específicos (`bank-extract_url` o `personal-extract_url`). 
Además, persiste la evidencia de la clasificación en DynamoDB.

## Variables de Entorno (Requeridas)
- `SCANALYZE_ENV`: Identificador de entorno inyectado por el deployment.
- `SCANALYZE_TENANT`: Nombre del tenant (aislamiento en entorno de ejecución).
- `SCANALYZE_DEPLOYMENT_CUSTOMER_ID`: Identificador canónico del customer (`cust_<ULID>`).
- `SCANALYZE_DEPLOYMENT_ID`: Identificador canónico del deployment (`dep_<ULID>`).
- `AWS_REGION`: Región AWS explícita del deployment (sin default).
- `SCANALYZE_PARAM_ROOT`: Opcional, root param (por defecto `/scanalyze/{env}/tenants/{tenant}`).

## Parámetros de SSM Esperados
Este worker lee su configuración de AWS Systems Manager Parameter Store usando el prefijo `${SCANALYZE_PARAM_ROOT}`.
Todos los valores deben existir bajo ese prefix:
- `queues/classify_url`: URL de la cola de entrada (de la que se hace polling).
- `queues/bank-extract_url`: URL de la cola destino para documentos bancarios.
- `queues/personal-extract_url`: URL de la cola destino para documentos personales.
- `data-foundation/ocr_bucket_name`: Bucket S3 de donde sacar el resultado OCR.
- `data-foundation/documents_table_name`: Tabla DynamoDB donde guardar la evidencia de clasificación.
- `features/bedrock_classification_enabled`: (Opcional) flag "true" / "false" para habilitar la Fase 2 (Bedrock). Por defecto "false".

## Ejecución Local
Para pruebas con un perfil AWS no productivo aprobado y autenticado mediante SSO:

```bash
export SCANALYZE_ENV="<ENVIRONMENT>"
export SCANALYZE_TENANT="<TENANT>"
export SCANALYZE_DEPLOYMENT_CUSTOMER_ID="<CUSTOMER_ID>"
export SCANALYZE_DEPLOYMENT_ID="<DEPLOYMENT_ID>"
export AWS_REGION="<AWS_REGION>"
export PYTHONPATH=./src
python -m classifier_worker.main
```

La suite usa Python 3.11 y `pytest`. Desde la raíz del repositorio, crea un
entorno limpio e instala el closure bloqueado del worker y la misma versión de
`pytest` usada por CI:

```bash
service_dir="backend/workers/scanalyze-classifier-worker"

python3.11 -m venv .venv
.venv/bin/python -m pip install \
  -r "${service_dir}/requirements.txt" \
  "pytest==9.1.1"
```

Ejecuta la colección completa con configuración sintética y sin cargar perfiles
AWS locales. Las pruebas no realizan llamadas AWS:

```bash
env -i \
  PATH="/usr/bin:/bin:/usr/sbin:/sbin" \
  AWS_SHARED_CREDENTIALS_FILE=/dev/null \
  AWS_CONFIG_FILE=/dev/null \
  AWS_EC2_METADATA_DISABLED=true \
  AWS_REGION=us-east-1 \
  AWS_DEFAULT_REGION=us-east-1 \
  SCANALYZE_ENV=test \
  SCANALYZE_TENANT=tenant-test \
  SCANALYZE_DEPLOYMENT_CUSTOMER_ID=cust_01ARZ3NDEKTSV4RRFFQ69G5FAW \
  SCANALYZE_DEPLOYMENT_ID=dep_01ARZ3NDEKTSV4RRFFQ69G5FAV \
  PYTHONPATH="${service_dir}/src:${service_dir}" \
  .venv/bin/python -m pytest "${service_dir}/tests" -q
```

## Evidencia hermética del contenedor

El cierre de dependencias conserva exactamente las versiones aprobadas en
`requirements.lock` y añade un hash SHA-256 para cada wheel de CPython 3.11.14
en `linux/amd64`. La preparación descarga esos wheels antes del build en el
directorio generado e ignorado `.wheelhouse/`; el Dockerfile instala después
con `--no-index --find-links=/wheelhouse --require-hashes`.

Desde un commit limpio y con la base pública aprobada fijada por digest:

```bash
revision="$(git rev-parse HEAD)"
created="$(git show -s --format=%cI "$revision")"
base_image="docker.io/library/python:3.11.14-slim-bookworm@sha256:83f339c1be6340ae1096010fdccf6552ac932d8f410d45d206014916bdf37e48"
image="scanalyze-ci/classifier-worker:sha-${revision:0:12}"

docker pull --platform linux/amd64 "$base_image"
scripts/microservices/prepare-classifier-wheelhouse.sh
docker build \
  --platform linux/amd64 \
  --pull=false \
  --network=none \
  --build-arg "BASE_IMAGE=${base_image}" \
  --label "org.opencontainers.image.source=https://github.com/cesar-guzman/scanalyze-deployment-platform" \
  --label "org.opencontainers.image.revision=${revision}" \
  --label "org.opencontainers.image.created=${created}" \
  --tag "$image" \
  backend/workers/scanalyze-classifier-worker
scripts/microservices/verify-classifier-container.sh \
  --image "$image" \
  --revision "$revision"
```

El verificador exige la imagen local exacta y no hace pull. Ejecuta como el
usuario no-root `app`, con red deshabilitada, filesystem de solo lectura,
metadata de AWS deshabilitada, archivos de configuración apuntando a
`/dev/null`, sin variables de credenciales, sin mounts y sin Docker socket.
Comprueba Python y dependencias, importa `classifier_worker.main`,
`classifier_worker.classifier` y `classifier_worker.contracts`, inicia el
entrypoint real con un deployment ID controladamente inválido y observa el
fallo antes de crear un cliente AWS. Después procesa un fixture sintético con
adaptadores en memoria y verifica el contrato existente
`scanalyze.classify.v2` → `scanalyze.extract.v2`, FIFO/deduplicación y la
clasificación heurística determinista.

La salida se rechaza si contiene sentinels sintéticos de contenido documental,
token, credencial, account ID o payload de proveedor. Un resultado verde prueba
únicamente la imagen local y el SHA indicado: no prueba AWS, Bedrock, ECR, ECS,
colas/objetos reales, despliegue, staging ni producción.

Rollback: revertir el commit revisado y reconstruir el SHA anterior. Este flujo
no publica imágenes ni escribe estado remoto, por lo que no existe rollback de
registry, AWS o deployment dentro de este alcance. Producción permanece
**NO-GO**.
