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
