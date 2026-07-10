# Seguridad, identidad y cadena de suministro

> **Fuentes:** [ADR-004](../ADR/ADR-004-cross-account-identity.md),
> [ADR-007](../ADR/ADR-007-artifact-supply-chain.md),
> [ADR-009](../ADR/ADR-009-threat-model.md) y
> [ADR-011](../ADR/ADR-011-monorepo-microservices-source.md)

## Frontera de seguridad

La cuenta AWS dedicada es el límite de cada deployment. Documentos, PII,
resultados de extracción, cómputo, storage, identidad, cifrado y observabilidad
de un cliente deben permanecer dentro de ese límite.

El repositorio contiene source y configuración declarativa segura. Las cuentas
cliente reciben artefactos inmutables; no deben recibir clones del source.

## Identidad: decisión, implementación y evidencia

ADR-004 describe un modelo objetivo de roles terminales separados para plan,
apply, promotion, validation y operaciones break-glass. Su estado es
**DRAFT rev3**. No se debe afirmar que los seis roles, session policies,
SourceIdentity, boundaries y trust conditions están desplegados en todas las
cuentas sin revisar IaC y evidencia live.

Los invariantes son:

- identidad y región se proporcionan explícitamente;
- caller account se verifica antes de cualquier mutación;
- least privilege por operación y layer;
- una sesión de deployment no puede escapar a otro deployment;
- trust policies evitan confused deputy;
- break-glass es humano, excepcional, auditable y no automatizado;
- producción es read-only por defecto.

## GitHub Actions y OIDC

El flujo monorepo implementa GitHub OIDC como mecanismo de automatización. Las
reglas son:

- pull requests no reciben credenciales AWS ni permiso id-token;
- el job de publicación recibe id-token únicamente cuando publica;
- el trust debe bindear repositorio, branch/Environment y rol exactos;
- el Environment protegido contiene account, región, deployment, ECR prefix y
  base image aprobados;
- el workflow y el script comparan identidad esperada con caller account;
- ninguna AWS access key estática pertenece en secrets, variables o archivos.

Este diseño está **Implemented** y **Locally validated**. El nuevo flujo
monorepo no está **Live validated** hasta ejecutar y leer de vuelta una
publicación autorizada en non-production.

## Datos sensibles

Nunca versionar, imprimir ni usar como fixture:

- documentos o uploads de clientes;
- PII real, datos bancarios, personales o gubernamentales;
- tokens, passwords, cookies o credenciales;
- private keys, certificados privados o archivos de entorno;
- Terraform state, planes o backups;
- logs de producción, dumps o extracted payloads;
- generated config con identificadores reales.

Los tests usan datos sintéticos mínimos. Un valor con forma de identidad sólo
es aceptable cuando está documentado como sintético y cubierto por una
allowlist estrecha. Una allowlist no convierte datos reales en seguros.

La observabilidad registra IDs técnicos, estados y errores sanitizados; no
registra documentos, texto extraído, JWT ni secretos.

## Cadena de suministro implementada

| Control | Estado |
|---|---|
| Source canónico único en GitHub | **Implemented** en la branch, pendiente de merge |
| Dockerfiles con BASE_IMAGE explícita | **Implemented**, **Locally validated** |
| Base image enterprise en ECR objetivo por digest | **Implemented** como requisito del flujo |
| ECR customer-local con tags inmutables | **Implemented** en IaC; validar cada deployment |
| Lectura de digest después del push | **Implemented**, **Locally validated** |
| Escritura de image_digest al final | **Implemented**, **Locally validated** |
| ECS actualizado sólo por Terraform | **Implemented** como separación de ownership |
| Build/push real del monorepo | No **Live validated** |

## Cadena de suministro objetivo

ADR-007 describe capacidades adicionales:

- SBOM por artefacto;
- signing y verificación;
- provenance/attestation;
- vulnerability scan gate con política definida;
- dependencias lockeadas y verificadas;
- builder y egress controlados;
- build central firmado y promoción verificable.

Estas capacidades son **Target** salvo evidencia específica. ADR-011 registra
que el flujo actual hace builds customer-scoped, mantiene dependencias no
completamente deterministas y aún no implementa todas las etapas de ADR-007.

## Controles fail-closed

Una operación se detiene cuando:

- la cuenta o región no coincide;
- falta BASE_IMAGE o no está identificada por digest para publicación;
- se intenta usar latest;
- el repositorio ECR no existe o el tag inmutable ya representa bytes distintos;
- el contract deployment/account/route no coincide;
- falta una precondición de estado o identidad;
- el payload productivo está degradado o ambiguo;
- un security gate encuentra secretos, PII no autorizada, state o planes;
- se solicita write-ssm sin una publicación verificada;
- un cambio CI legado produciría destrucción no revisada.

Los errores no se silencian para continuar una release.

## Identidad de aplicación

La plataforma todavía no tiene evidencia de un contrato canónico completo que
alinee customer identity entre Cognito, token claims, Terraform, configuración
ECS, ingest y onboarding.

Estado: **Blocked**.

Hasta cerrarlo:

- no crear ni entregar usuarios;
- no debilitar validación tenant/customer;
- no derivar identidad de campos no confiables;
- no afirmar login, API protegida o pipeline E2E como listos para producción.

El frontend también está **Blocked** hasta que una capa Terraform tenga
ownership único de config.json y bindings exactos de CloudFront, API y S3.

## Rollback y respuesta

- Una release se revierte seleccionando digests previamente aprobados mediante
  un nuevo plan Terraform.
- State no es rollback.
- Un tag inmutable no se sobreescribe ni se borra para “reparar” metadata.
- Reconciliación usa lectura de digest y comparación exacta.
- Break-glass y destrucción siguen procesos separados y aprobados.

## Preguntas de revisión

1. ¿La acción cruza una frontera de cuenta o datos?
2. ¿La identidad proviene de una fuente confiable y está vinculada al deployment?
3. ¿Los permisos son mínimos para esa fase?
4. ¿La imagen, base image y release están identificadas de forma inmutable?
5. ¿Hay evidencia local o live, y para qué ambiente?
6. ¿La operación revela PII o secretos en logs?
7. ¿Existe un blocker que se está intentando eludir?

Si alguna respuesta es desconocida, no autorizar la mutación.
