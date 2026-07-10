# Monorepo, microservicios y cadena de suministro

Scanalyze consolida infraestructura y código de microservicios en un único
repositorio versionado. La decisión completa está en
[`ADR-011`](../ADR/ADR-011-monorepo-microservices-source.md); la cadena de
suministro objetivo está en
[`ADR-007`](../ADR/ADR-007-artifact-supply-chain.md).

## Fuente única, despliegues aislados

Los siete servicios viven bajo `backend/workers/scanalyze-*`:

- ingest-api;
- ocr-worker;
- postprocess-worker;
- classifier-worker;
- bank-worker;
- personal-worker;
- gov-worker.

Todos los clientes consumen el mismo commit. Las diferencias se inyectan por
contratos, variables protegidas y SSM. No se crean forks, branches permanentes
por cliente ni valores específicos dentro de código o Dockerfiles.

El monorepo no significa que el código fuente se copie a la cuenta cliente. El
boundary de entrega es una imagen OCI inmutable. Cada cuenta conserva sus
propios ECR, KMS, scan results y metadatos, en coherencia con
account-per-deployment.

## Cadena de identidad del artefacto

La trazabilidad esperada es:

`commit aprobado → build reproducible → base image por digest → imagen OCI → digest ECR → metadata SSM → input Terraform → task definition ECS`

Cada eslabón tiene una función distinta:

- Git identifica fuente y revisión;
- el workflow y el script definen el build;
- ECR almacena bytes inmutables y devuelve el digest;
- SSM registra metadata de release, pero no despliega;
- Terraform es dueño de task definitions y servicios;
- ECS ejecuta sólo las imágenes aprobadas.

Un tag no sustituye al digest. `latest` no forma parte del flujo enterprise.

## Base images

Los Dockerfiles aceptan `BASE_IMAGE` como argumento. En el flujo enterprise,
CI lo proporciona explícitamente y apunta a una imagen aprobada por digest en
el ECR correspondiente. El runtime no depende de Docker Hub ni de una cuenta
AWS ajena.

La promoción de base images y servicios debe preservar proveniencia, scan,
SBOM, firma y attestation según la madurez descrita en ADR-007. Cuando un
control aún sea roadmap, la documentación debe decirlo; no se presume que está
implementado.

## GitHub OIDC y mínimo privilegio

El workflow global declara sólo lectura de contenido. El permiso para solicitar
un token OIDC aparece únicamente en el job de publicación. Ese job se asocia a
un Environment protegido y asume un rol específico de la cuenta objetivo.

El trust policy debe limitar repositorio, branch o environment y audiencia. El
rol de publicación sólo necesita acceso a los repos ECR, lectura de la base
image y escritura en el prefijo SSM del deployment. No requiere administrar
ECS ni Terraform.

## Comportamiento por evento

- **Pull request:** lint, tests, validaciones y build sin push ni SSM.
- **Push a main:** validación path-aware; no publica si el environment y el rol
  no están configurados explícitamente.
- **Dispatch aprobado:** puede publicar y registrar metadata cuando los inputs,
  aprobaciones y guardas de cuenta pasan.

La matriz permite construir por servicio. El script aplica la misma allowlist
en ejecución local y CI, evitando que el YAML mantenga una segunda
implementación del proceso.

## Compatibilidad legacy

CodeCommit, CodeBuild y CodePipeline pueden permanecer detrás de flags
conservadores durante una transición. No son la fuente canónica del monorepo y
no deben destruirse por sorpresa. Cualquier retiro se revisa mediante plan
Terraform y una decisión explícita de migración.

## Controles fail-closed

La publicación se detiene ante cuenta incorrecta, servicio no allowlisted,
base image no verificable, tag existente con bytes distintos, digest ausente o
error al registrar metadata. Un fallo parcial se reconcilia contra el digest
real; no se sobreescribe una etiqueta ni se fuerza un deployment ECS.

Los servicios preservan semántica at-least-once, idempotencia y DLQs. El
handoff OCR se confirma antes de completion y postprocess valida claves,
identidad y transición DynamoDB antes de mutar estado.

## Rollback

El rollback de aplicación selecciona el último conjunto de digests aprobado,
genera un nuevo plan de `services` y aplica ese plan tras revisión. No se
reescriben tags, no se hace state surgery y no se fuerza ECS fuera de Terraform.
El rollback de fuente es un revert revisado en Git.

## Fuentes relacionadas

- [`backend/workers/README.md`](../backend/workers/README.md)
- [`docs/migration/monorepo-microservices-migration.md`](../docs/migration/monorepo-microservices-migration.md)
- [`modules/cicd/README.md`](../modules/cicd/README.md)
- [`roots/cicd/README.md`](../roots/cicd/README.md)

## Exclusiones para NotebookLM

No se carga código fuente completo, imágenes, SBOMs, reportes de scanners,
manifests con identificadores reales, salidas ECR/SSM, credenciales ni logs.
NotebookLM recibe la decisión y el modelo de control; los artefactos y la
evidencia permanecen en sus sistemas autorizados.
