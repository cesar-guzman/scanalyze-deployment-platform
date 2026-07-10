# Scanalyze Platform v2 — Guía de despliegue enterprise

| Campo | Valor |
|---|---|
| Versión | 4.0 |
| Fecha | 2026-07-10 |
| Estado | **DRAFT — NON-EXECUTABLE — NO-GO** |
| Clasificación | Uso interno; no contiene secretos ni datos de clientes |
| Audiencia | Platform Engineering, SRE, DevSecOps, Security, Release Management |
| Fuente canónica | Este archivo Markdown |
| Artefactos derivados | DOCX/PDF para distribución; no son fuente de verdad |
| Owner propuesto | Scanalyze Platform Engineering |
| Aprobadores requeridos | Platform, Security, SRE y owner de producto |

> [!CAUTION]
> **NO EJECUTAR ESTE DOCUMENTO CONTRA AWS.** El repositorio contiene controles
> locales y una ruta target-state, pero todavía no implementa ni ha validado
> todos los componentes necesarios para un despliegue enterprise end-to-end.
> Ningún texto de esta guía autoriza un `terraform apply`, un push a ECR, una
> escritura en SSM, un cambio en ECS o cualquier otra mutación.

> [!IMPORTANT]
> Esta versión reemplaza las afirmaciones históricas de “production-ready”.
> La evidencia de despliegues anteriores no demuestra la ruta actual de
> monorepo, GitHub OIDC, promoción de artefactos, contratos, runtime config ni
> onboarding. La producción permanece en **NO-GO** hasta cerrar todos los
> bloqueantes definidos en esta guía y completar una validación non-production
> aprobada.

---

## Tabla de contenido

1. [Propósito, alcance y no objetivos](#1-propósito-alcance-y-no-objetivos)
2. [Evidence boundary y estado real](#2-evidence-boundary-y-estado-real)
3. [Principios obligatorios](#3-principios-obligatorios)
4. [Gobierno, RACI y change record](#4-gobierno-raci-y-change-record)
5. [Arquitectura y secuencia target-state](#5-arquitectura-y-secuencia-target-state)
6. [Fuentes de verdad e inventario de inputs](#6-fuentes-de-verdad-e-inventario-de-inputs)
7. [Stop conditions y preflight](#7-stop-conditions-y-preflight)
8. [Account baseline y backend de Terraform](#8-account-baseline-y-backend-de-terraform)
9. [Patrón Plan → Approve → Apply](#9-patrón-plan--approve--apply)
10. [GitHub OIDC, ECR y supply chain](#10-github-oidc-ecr-y-supply-chain)
11. [Runtime configuration y contratos SSM](#11-runtime-configuration-y-contratos-ssm)
12. [Rollout de servicios por waves](#12-rollout-de-servicios-por-waves)
13. [Edge, identidad, frontend y onboarding](#13-edge-identidad-frontend-y-onboarding)
14. [Readiness y validación end-to-end](#14-readiness-y-validación-end-to-end)
15. [Observabilidad y activación operativa](#15-observabilidad-y-activación-operativa)
16. [Abort criteria y manejo de incidentes](#16-abort-criteria-y-manejo-de-incidentes)
17. [Rollback y reconciliación](#17-rollback-y-reconciliación)
18. [Evidence package, handoff y aceptación](#18-evidence-package-handoff-y-aceptación)
19. [Troubleshooting seguro](#19-troubleshooting-seguro)
20. [Publicación documental y NotebookLM](#20-publicación-documental-y-notebooklm)
21. [Fuentes oficiales](#21-fuentes-oficiales)
22. [Apéndices](#22-apéndices)

---

## 1. Propósito, alcance y no objetivos

Esta guía define el procedimiento objetivo para desplegar Scanalyze en una
cuenta AWS dedicada por cliente, conservando aislamiento, reproducibilidad,
trazabilidad y control declarativo. También define explícitamente qué controles
existen, qué capacidades faltan y cuándo debe abortarse el proceso.

Incluye:

- account binding y separación de roles;
- estados, contratos e inputs de Terraform;
- release y promoción de imágenes por digest;
- GitHub Actions con OIDC;
- despliegue progresivo de servicios;
- identidad, frontend y onboarding;
- readiness, observabilidad, incidentes, rollback y handoff;
- evidencia sanitizada y distribución documental.

No incluye ni autoriza:

- creación manual del account baseline;
- uso de credenciales AWS estáticas;
- `terraform apply` o `destroy` sin aprobación y tooling implementado;
- state surgery, importaciones ad hoc o selección del “primer” recurso AWS;
- publicación de imágenes sin un release aprobado;
- pruebas con documentos reales, PII o datos de clientes;
- creación o entrega de contraseñas fuera del flujo de identidad aprobado;
- bypass de CI, contratos, IAM, escaneo, firmas o revisión humana.

---

## 2. Evidence boundary y estado real

### 2.1 Clasificación del estado

| Capacidad | Estado | Evidencia | Decisión |
|---|---|---|---|
| Siete microservicios en el monorepo | Implementada localmente | Código, Dockerfiles y tests del repositorio | Apta para revisión |
| Build sin push | Implementada localmente | `build-push.sh --no-push` y workflow de PR | Apta para CI |
| Account/deployment binding en publish script | Implementada | Validaciones en el script | Conservar |
| GitHub workflow con OIDC | Implementado parcialmente | Workflow con permisos mínimos y variables protegidas | Falta provisionar/validar el rol |
| ECR immutable, KMS y scan-on-push | Declarado en Terraform | `modules/cicd` | Falta plan/live validation |
| Terraform roots principales | Provider-validated localmente | Gates M2/M2B | No constituyen evidencia live |
| Account baseline enterprise | Target-state | ADRs | No está implementado por este repo |
| Backend/orchestrator de apply | Target-state incompleto | Templates y ADRs | Bloqueante |
| Contratos SSM entre todas las capas | Target-state incompleto | Outputs sin publisher completo | Bloqueante |
| Runtime config SSM de workers | Sin owner completo | No existe implementación declarativa completa | Bloqueante |
| Full OCI artifact graph y release firmado | Target-state | ADR-007 | Bloqueante |
| Service rollout por waves | Diseño | ADR-010 | Falta orquestación segura |
| Frontend config declarativo | No implementado | Gap confirmado | Bloqueante |
| Contrato canónico de identidad cliente | No implementado | Gap confirmado | Bloqueante |
| Synthetic E2E non-production | No ejecutado para esta ruta | Sin evidencia | Bloqueante |

### 2.2 Bloqueantes conocidos

| ID | Bloqueante | Severidad | Criterio de cierre |
|---|---|---:|---|
| B-01 | No existe un orchestrator aprobado que renderice backend e inputs y separe Plan/Apply | P0 | Tooling revisado, probado y fail-closed |
| B-02 | Los providers de roots principales están configurados para validación local, no para apply con account binding | P0 | `allowed_account_ids`/assume-role y tests por root |
| B-03 | Publicación y consumo de contratos/runtime config SSM incompletos | P0 | Ownership único, schema y preconditions probados |
| B-04 | Supply chain no genera/promueve el full OCI artifact graph | P0 | Imagen, SBOM, firma y provenance verificados |
| B-05 | Log groups de ECS se crean después de los servicios | P0 | Ownership previo al arranque de tasks |
| B-06 | Config frontend e identidad de cliente no tienen contrato declarativo completo | P0 | ADR, Terraform, backend y E2E aprobados |
| B-07 | No existe validación live non-production de la ruta actual | P0 | Deploy, validate, rollback y evidence aprobados |
| B-08 | Rol GitHub OIDC deployment-scoped no está provisionado por un owner declarado | P1 | IaC/trust policy y Environment revisados |
| B-09 | Digests de `service_definitions` no están vinculados fail-closed al release manifest | P1 | Validación Terraform y tests negativos |
| B-10 | SNS/observabilidad no tiene receptor operativo confirmado | P1 | Suscripción, escalamiento y prueba de alarma |

Mientras cualquier bloqueante P0 esté abierto, el resultado obligatorio es:
**NO-GO**.

---

## 3. Principios obligatorios

1. **Account-per-Deployment.** Una cuenta AWS por cliente/ambiente; sin mezcla de
   identidad, cómputo, datos, estado, artefactos ni observabilidad.
2. **No customer forks.** Un solo source; diferencias por deployment record,
   contratos, variables declarativas y SSM.
3. **Evidence before claims.** Una gate local no prueba un despliegue live; un
   estado `ACTIVE` no prueba un pipeline end-to-end.
4. **Fail-closed.** Identidad, contrato, firma, digest, plan o evidence ausente
   bloquea la siguiente fase.
5. **Least privilege.** Plan, Apply, Promotion, Validation, Diagnostic y
   StateRecovery son funciones separadas.
6. **Terraform owns infrastructure.** No ClickOps, no `update-service` como
   mecanismo normal y no state surgery.
7. **State is not rollback.** El rollback se expresa como configuración anterior
   revisada y un nuevo plan.
8. **Immutable artifact delivery.** ECS consume imágenes por digest. Tags son
   metadata, nunca identidad de release.
9. **Customer-local data.** Documentos, PII y resultados no abandonan la cuenta
   del cliente.
10. **Sanitized evidence.** Nunca guardar planes raw, state, tfvars reales,
    tokens, logs sensibles ni documentos de clientes en Git o NotebookLM.

---

## 4. Gobierno, RACI y change record

### 4.1 RACI

| Actividad | Platform | Security | SRE | Release Manager | Product/Customer Owner |
|---|---|---|---|---|---|
| Aprobar arquitectura y contracts | R | A/C | C | I | I |
| Aprobar IAM/OIDC y supply chain | C | A/R | C | I | I |
| Preparar release y manifest | C | C | I | A/R | I |
| Revisar Terraform plan | R | C para IAM/KMS/network | A/R | I | I |
| Autorizar apply | R | C | A | C | I |
| Validar salud y observabilidad | C | C | A/R | I | I |
| Autorizar onboarding/go-live | C | C | R | C | A |
| Declarar incidente/rollback | C | C | A/R | C | I |
| Aceptar handoff | C | I | R | I | A |

`A` debe ser una sola función por decisión. Los nombres, turnos y sustitutos se
registran en el change record; nunca se hardcodean en este repositorio.

### 4.2 Change record obligatorio

Antes de cualquier acción live, el sistema de change management debe contener:

- `change_id`, deployment ID, cuenta, región y ambiente;
- commit/tag/release version aprobados;
- digest del release manifest y attestation;
- ventana, owner, aprobadores y on-call;
- alcance por roots y waves;
- plan de validación;
- last-known-good release y criterio de rollback;
- riesgos/waivers con owner y expiración;
- enlaces a evidence sanitizada.

Un ticket abierto no equivale a aprobación.

---

## 5. Arquitectura y secuencia target-state

### 5.1 Servicios

| Servicio | Tipo | Función |
|---|---|---|
| `ingest-api` | API | Entrada y control de documentos |
| `ocr-worker` | Worker | OCR/Textract y handoff durable |
| `classifier-worker` | Worker | Clasificación y routing |
| `bank-worker` | Worker | Extracción de documentos bancarios |
| `personal-worker` | Worker | Extracción de documentos personales |
| `gov-worker` | Worker | Extracción de documentos gubernamentales |
| `postprocess-worker` | Worker | Validación y persistencia final |

### 5.2 Contract graph canónico

```text
ACCOUNT_READY
    │
    ▼
global → network → platform → data-foundation → services
                                             │
                                             ▼
                                      edge-identity → edge
                                             │          │
                                             └────┬─────┘
                                                  ▼
                                               addons
```

`cicd` es una fase operacional para ECR/release metadata. No debe alterar el
contract graph ni desplegar ECS.

### 5.3 Secuencia target-state

1. Crear y aprobar un release central firmado.
2. Provisionar la cuenta mediante AccountVendingProvider.
3. Validar deployment record y `ACCOUNT_READY`.
4. Ejecutar `account-ready-gate`.
5. Plan/aprobar/aplicar `global`.
6. Plan/aprobar/aplicar `network`.
7. Plan/aprobar/aplicar `platform`.
8. Plan/aprobar/aplicar `data-foundation`.
9. Plan/aprobar/aplicar `cicd` para ECR y metadata, sin legacy pipeline salvo
   decisión explícita.
10. Promover y verificar el full OCI artifact graph en la cuenta cliente.
11. Plan/aprobar/aplicar `services` por waves.
12. Plan/aprobar/aplicar `edge-identity`.
13. Plan/aprobar/aplicar `edge`.
14. Plan/aprobar/aplicar `addons`.
15. Realizar cutover declarativo de frontend/identidad.
16. Ejecutar validación sintética, activar observabilidad y entregar handoff.

> [!WARNING]
> Esta secuencia es target-state. No es ejecutable mientras B-01 a B-07 sigan
> abiertos.

---

## 6. Fuentes de verdad e inventario de inputs

### 6.1 Fuentes de verdad

| Dato | Fuente autoritativa | No usar |
|---|---|---|
| Deployment/account/region | Deployment registry aprobado | Variables copiadas de otro cliente |
| Account readiness | `ACCOUNT_READY` firmado/digerido | Existencia aislada de un bucket |
| Release | Manifest y attestation firmados | Tag OCI o branch |
| Infra outputs | Contrato versionado de la capa productora | `Items[0]`, listados o nombres inferidos |
| Imagen ECS | Digest aprobado en release manifest | `:latest` o tag mutable |
| Runtime config | Terraform/contrato con ownership único | Parámetros manuales |
| Frontend config | Artefacto declarativo versionado | Upload/invalidation ad hoc |
| Identidad cliente | Claim canónico definido por ADR | Tenant derivado de input no verificado |

### 6.2 Inputs mínimos por root

| Root | Inputs de identidad/release | Inputs upstream/propios |
|---|---|---|
| `account-ready-gate` | deployment/account | digest real y esperado de ACCOUNT_READY |
| `global` | account, region, release version/manifest | ACCOUNT_READY y schema |
| `network` | identidad/release | contrato global |
| `platform` | identidad/release | contrato network, VPC/subnets/certificate |
| `data-foundation` | identidad/release | contrato platform |
| `cicd` | deployment/account/region | cluster contract, microservices y flags legacy |
| `services` | identidad/release | cluster, roles, VPC, ALB y siete definiciones por digest |
| `edge-identity` | identidad/release | contratos platform/services y dominio |
| `edge` | identidad/release | contrato edge-identity, DNS/API/frontend |
| `addons` | identidad/release | contratos finales y destinos de alertamiento |

Los inputs deben generarse desde deployment record + contratos validados. No
deben reconstruirse manualmente en múltiples tfvars.

### 6.3 Reglas para tfvars y generated config

- `*.local.tfvars`, `*.auto.tfvars`, backend generado y config local son
  secretos operativos o material deployment-specific; permanecen ignorados.
- Sólo se versionan templates `*.example` sintéticos.
- No incluir account IDs, ARNs, dominios ni valores reales en documentación.
- El canal de entrega debe ser aprobado, cifrado, auditable y con retención.
- Un input ausente o no vinculable al deployment record produce **ABORT**.

---

## 7. Stop conditions y preflight

### 7.1 Stop conditions globales

Abortar antes de mutar si ocurre cualquiera:

- branch/revision no aprobada o working tree sucio;
- toolchain diferente de las versiones fijadas;
- gates locales, tests o CI incompletos/fallidos;
- cuenta, región, deployment o role session no coinciden;
- `ACCOUNT_READY`, contrato, schema, firma, attestation o digest inválido;
- backend/state key/KMS/lock no coincide con deployment record;
- plan contiene delete/replace/IAM/network/KMS no aprobado;
- full OCI graph incompleto, scan pendiente/fallido o waiver inválido;
- faltan los siete digests o el last-known-good release;
- runtime config/log groups/alert receiver no están listos;
- frontend o identidad permanecen bloqueados;
- no existe on-call o ventana de cambio activa;
- no puede escribirse evidence sanitizada;
- cualquier operador propone state surgery o ClickOps.

### 7.2 Preflight local permitido

Estos comandos son locales y no autorizan AWS:

```bash
git status --short --branch
git diff --check
make git-safety
make security-check
make microservices-check
make preflight-m2b
```

Requisitos:

- Python `3.11.14`;
- Terraform `1.14.6`;
- lock files revisados;
- cero secretos/state/plans/tfvars reales;
- tests de los siete servicios y tooling en CI;
- commit aprobado y clean worktree antes de publish.

`make preflight-m2b` demuestra validación local de providers, no permisos,
estado ni comportamiento de AWS.

### 7.3 Identidad live target-state

Antes de cada fase, no sólo al inicio:

1. seleccionar explícitamente profile/role y región;
2. obtener caller identity sin imprimir credenciales;
3. comparar cuenta contra deployment record;
4. validar role ARN, SourceIdentity/session tags y expiración;
5. validar backend bucket/key/KMS;
6. abortar ante cualquier mismatch.

No usar el default profile ni variables de credenciales estáticas.

---

## 8. Account baseline y backend de Terraform

### 8.1 Ownership

AccountVendingProvider, no este runbook, debe crear:

- roles terminales Plan, Apply, Promotion, Validation, Diagnostic y
  StateRecovery;
- permissions boundaries y trust policies;
- state, evidence y contract stores;
- KMS keys, tags y políticas;
- deployment record y `ACCOUNT_READY`.

Esta guía sólo debe verificar esos objetos con una identidad read-only/aprobada.

### 8.2 Backend target-state

El orchestrator debe renderizar un backend por root desde el deployment record:

- bucket de state de la cuenta cliente;
- key global o regional correcta;
- customer-managed KMS;
- versioning;
- S3 native lockfile cuando corresponda;
- sin Terraform workspaces;
- sin backend identifiers hardcodeados.

Los roots globales no deben recibir una key regional accidental. Los planes,
state y locks no se guardan dentro del repositorio.

### 8.3 Gap actual

Los roots principales están configurados para provider validation local y
esperan un backend renderizado. El repositorio no contiene todavía un
orchestrator aprobado que realice ese flujo. `roots/cicd` no debe usarse como
prueba de que los demás roots están listos.

Resultado: **B-01/B-02 abiertos; apply prohibido.**

---

## 9. Patrón Plan → Approve → Apply

> [!CAUTION]
> La siguiente secuencia es una especificación de control, no un script ni una
> autorización para ejecutar Terraform.

### 9.1 Plan

Con rol Plan acotado a una capa:

1. leer deployment record y contratos;
2. renderizar backend e inputs efímeros;
3. verificar provider lock;
4. ejecutar validate;
5. crear saved plan en una zona efímera externa al repo;
6. generar plan JSON sólo en esa zona;
7. calcular digest del plan;
8. aplicar policy gates a create/update/delete/replace;
9. producir un resumen sanitizado;
10. registrar state serial/version observado.

Nunca guardar plan binario/JSON raw en Git, Word o NotebookLM.

### 9.2 Approve

La aprobación debe vincular:

- `change_id`;
- root/wave;
- commit y release manifest digest;
- plan digest;
- resource action counts;
- deletes/replaces explícitamente aceptados;
- aprobador y timestamp;
- expiración del plan;
- last-known-good release.

Un cambio del state serial, contrato, release o identidad invalida el plan.

### 9.3 Apply

Con un rol Apply distinto y session policy de la capa:

1. revalidar identidad y ventana;
2. recuperar el saved plan aprobado;
3. comparar digest;
4. registrar state version pre-apply;
5. aplicar exactamente el saved plan;
6. registrar exit status y state version post-apply;
7. verificar contrato producido;
8. ejecutar health check de capa;
9. exigir un nuevo plan sin drift;
10. cerrar o abortar antes de avanzar.

La implementación debe rechazar:

- apply sin aprobación;
- re-plan dentro de la fase Apply;
- plan expirado;
- cambio de cuenta/role/region;
- contrato o state serial distinto;
- state commands manuales.

### 9.4 Evidence

Evidence persistente contiene sólo:

- plan/apply IDs y digests;
- resumen de acciones sanitizado;
- state version IDs, no state content;
- contract/release digests;
- resultados de gates y health checks;
- aprobaciones y timestamps;
- incident/rollback decision.

---

## 10. GitHub OIDC, ECR y supply chain

### 10.1 Controles implementados que deben conservarse

`.github/workflows/microservices-build.yml`:

- usa permisos globales `contents: read`;
- concede `id-token: write` sólo al job de publish;
- fija GitHub Actions por commit SHA;
- no persiste credenciales del checkout;
- restringe publish a `main`;
- compara inputs contra variables de un GitHub Environment;
- usa `allowed-account-ids`;
- ejecuta PR builds sin push/SSM.

`scripts/microservices/build-push.sh`:

- usa Bash estricto y allowlist de siete servicios;
- rechaza `latest`;
- exige base image por digest para publish;
- exige base image ECR de la cuenta objetivo;
- vincula account, region, deployment y ECR prefix;
- requiere clean Git worktree y revision=HEAD;
- verifica tag immutability y digest después del push;
- no actualiza ECS;
- SSM write requiere push explícito.

### 10.2 Requisitos OIDC pendientes

El rol OIDC debe ser propiedad declarativa de AccountVendingProvider o un módulo
aprobado y debe:

- confiar sólo en el issuer/audience oficial de GitHub;
- restringir `sub` al repositorio y Environment exactos;
- aceptar únicamente `main` mediante Environment deployment rules;
- tener session duration mínima;
- permitir pull de la base image aprobada;
- permitir push sólo a repos ECR del deployment;
- permitir SSM sólo bajo
  `/<deployment_id>/cicd/images/<service>/{image_tag,image_digest}`;
- no tener permisos ECS, IAM, Terraform state o customer data;
- generar CloudTrail auditable.

El GitHub Environment debe tener:

- required reviewers y no-bypass;
- branch policy `main`;
- `AWS_ROLE_ARN`, `AWS_ACCOUNT_ID`, `AWS_REGION`,
  `DEPLOYMENT_ID`, `ECR_PREFIX` y `BASE_IMAGE_URI`;
- `MAIN_PUBLISH_ENABLED=false` por defecto;
- variables, no static AWS secrets.

### 10.3 Supply chain target-state

Un release production debe incluir por servicio:

1. imagen reproducible desde commit aprobado;
2. dependencies locked y hash-verified;
3. base image customer-approved por digest;
4. SBOM;
5. dependency, license y container scan;
6. firma;
7. provenance/attestation;
8. asociación en un release manifest firmado.

La promoción a la cuenta cliente debe copiar y verificar:

```text
image digest + signature + SBOM + provenance
```

Después:

- comparar source/destination digests;
- esperar el scan en ECR cliente;
- evaluar la scan gate;
- registrar los siete digests en una sola decisión de release;
- mantener el last-known-good full graph disponible.

### 10.4 Gaps actuales

El workflow actual construye/pushea por servicio y SSM puede quedar parcialmente
actualizado si una matrix job falla. No genera el full OCI graph ni un release
manifest transaccional. Algunos requirements tampoco están hash-locked.

Por tanto:

- build sin push: permitido para CI;
- build/push en sandbox aprobado: sólo después de autorización específica;
- producción: **prohibida** hasta cerrar B-04/B-09.

SSM image metadata es tracking; no es una acción de deploy ni una fuente
autoritativa equivalente al release manifest.

---

## 11. Runtime configuration y contratos SSM

### 11.1 Ownership objetivo

Cada parámetro/contrato tiene exactamente un writer Terraform. Consumers sólo
leen. Los contratos deben incluir:

- schema version;
- deployment/account/region binding;
- producer release/module;
- state version/serial;
- content digest;
- outputs mínimos;
- clasificación/sensitivity.

Los consumers validan digest esperado, schema y binding mediante preconditions
fail-closed.

### 11.2 Runtime config

La configuración de workers debe declarar, por deployment/tenant:

- queues y DLQs;
- bucket y table names;
- document key schema/templates;
- route/docType contracts;
- region/environment;
- feature flags aprobados;
- timeouts/retries/idempotency settings;
- log level sin activar datos sensibles.

No colocar secretos en plain String ni en ECS environment. Secretos legítimos,
si existen, usan el mecanismo aprobado y un task role acotado.

### 11.3 Gap actual

`services` no implementa por sí solo todos los parámetros runtime descritos por
versiones anteriores del playbook. Los módulos exponen contract payloads, pero no
existe un publisher completo de contratos para todas las capas.

No iniciar ECS hasta:

- tener owner declarativo por parámetro;
- validar rutas y document keys;
- crear log groups;
- probar IAM de lectura;
- confirmar que no se imprime configuración sensible.

---

## 12. Rollout de servicios por waves

### 12.1 Reglas

- Terraform es el único owner de task definitions/services.
- ECS usa `repository@sha256:digest`.
- No usar `aws ecs update-service --force-new-deployment` como ruta normal.
- Mantener circuit breaker habilitado.
- No habilitar tráfico externo hasta completar todas las waves en un deployment
  nuevo.
- Preservar idempotencia, retries, FIFO semantics y DLQs.

### 12.2 Waves target-state

| Wave | Servicios | Gate de salida |
|---|---|---|
| 1 | `ingest-api` | Task estable y target healthy; tráfico aún cerrado |
| 2 | `classifier-worker` | Task estable y config/queue verificadas |
| 3 | `bank-worker`, `personal-worker`, `gov-worker` | Tasks estables; rutas y DLQs correctas |
| 4 | `ocr-worker`, `postprocess-worker` | Tasks estables; handoffs y transitions verificadas |

Por wave:

1. plan con sólo cambios esperados;
2. approve por digest;
3. apply exacto;
4. wait steady state;
5. verificar stopped tasks, logs sanitizados, queue bindings y alarms;
6. plan sin drift;
7. avanzar o abortar.

> [!WARNING]
> El root actual no demuestra que una lista truncada de
> `service_definitions` preserve servicios fuera de la wave. No ejecutar waves
> pasando subsets hasta implementar y probar esa semántica.

### 12.3 Log groups

Los log groups deben existir antes de que una task con `awslogs` arranque. Su
ownership, KMS/retention y nombre deben estar en la misma fase o en una fase
upstream. Crear log groups en `addons` después de esperar estabilidad es un
bloqueante de secuencia.

---

## 13. Edge, identidad, frontend y onboarding

### 13.1 Edge e identidad

`edge-identity` se despliega después de `services` y consume sus contratos.
`edge` consume outputs exactos de identidad/API. Ninguna capa debe buscar
recursos por posición o nombre aproximado.

### 13.2 Frontend config

El repositorio aún no tiene un owner declarativo completo para un
`config.json` versionado y deployment-bound.

Requisitos de cierre:

- owner Terraform único;
- bucket/distribution/API exactos desde contratos;
- object version/release binding;
- no secretos;
- cache policy adecuada;
- cutover y rollback declarativos;
- test de campos contra schema.

No hacer upload manual ni CloudFront invalidation seleccionando recursos de un
listado.

### 13.3 Identidad cliente

Debe existir un claim canónico, emitido/verificado por Cognito y consistente con:

- schema del user pool;
- token/authorizer;
- backend validation;
- Terraform/ECS configuration;
- deployment/customer record;
- onboarding y revocación.

No debilitar tenant validation para “hacer funcionar” login.

### 13.4 Onboarding

Permanece bloqueado hasta cerrar config e identidad. Nunca entregar passwords,
tokens o client secrets en correo, ticket, Word o NotebookLM. El handoff de
usuarios debe usar el flujo de invitación/primer login aprobado.

---

## 14. Readiness y validación end-to-end

### 14.1 Infra readiness

| Check | Expected |
|---|---|
| Account/deployment binding | Coincidencia exacta |
| Terraform state | Backend/key/KMS/lock correctos |
| Post-apply plan | Sin drift |
| Contracts | Legibles, schema/digest/binding válidos |
| ECR | Siete repos, immutable/KMS/scan |
| Task definitions | Siete digests coinciden con manifest |
| ECS | Running=desired, deployments estables |
| ALB | Targets healthy |
| Stopped tasks | Sin fallos no explicados |
| SQS/DLQ | Config correcta; DLQ vacía antes de go-live |
| Dynamo/S3/KMS | Acceso sólo por roles esperados |
| Alarms | Existentes, OK y con receiver confirmado |

### 14.2 Security readiness

- firmas, SBOM, provenance y attestation verificadas;
- no waivers expirados;
- OIDC trust y IAM analizados;
- no static credentials;
- CloudTrail/evidence activos;
- WAF/auth/CORS/headers revisados;
- no raw documents, PII, tokens ni secretos en logs;
- pruebas negativas de tenant/deployment isolation aprobadas.

### 14.3 Synthetic E2E

Sólo en non-production y después de cerrar B-01 a B-06:

1. usar un documento sintético aprobado, sin PII real;
2. autenticar por el flujo oficial;
3. crear una unidad de trabajo con correlation ID;
4. verificar, sin imprimir contenido, cada transición durable;
5. confirmar estado final;
6. confirmar queues/DLQs, alarms y logs;
7. validar que datos/artefactos permanecieron en la cuenta;
8. registrar resultado sanitizado;
9. ejecutar la limpieza conforme al policy aprobado.

Flujo esperado:

```text
Upload → ingest-api → OCR → classifier → domain worker → postprocess → COMPLETED
```

No declarar E2E por ver únicamente `Running=desired`.

### 14.4 Go-live gate

Go-live requiere:

- cero P0/P1 sin waiver aprobado;
- synthetic E2E exitoso;
- rollback ensayado en non-production;
- on-call y alerts activos;
- evidence package completo;
- aceptación conjunta Platform/Security/SRE/Product.

Estado actual: **NO-GO**.

---

## 15. Observabilidad y activación operativa

### 15.1 Cobertura mínima

- ECS desired/running, deployment failure y stopped reasons;
- ALB target health, latency y 4xx/5xx;
- SQS visible/in-flight/oldest age y DLQ depth;
- Dynamo throttles/conditional failures;
- S3/KMS access failures;
- Textract/Bedrock throttling, error rate y costo;
- API Gateway/Cognito/WAF;
- application error rate por servicio y release;
- release/deployment correlation IDs.

### 15.2 Alerting

Un SNS topic sin subscription confirmada no es alerting operativo. Antes de
go-live:

- declarar receiver/escalation owner;
- confirmar suscripción;
- probar una alarma sintética no sensible;
- medir delivery y acknowledgement;
- documentar fallback;
- asegurar que mensajes no incluyan PII.

### 15.3 Logs

- log groups existen antes de las tasks;
- KMS/retention/ownership declarativos;
- logs estructurados con deployment, service, release y correlation ID;
- nunca raw document text, bank data, PII, JWT, credentials o config secrets;
- troubleshooting usa métricas y metadata antes de consultar logs.

---

## 16. Abort criteria y manejo de incidentes

### 16.1 Abort matrix

| Fase | Condición | Acción |
|---|---|---|
| Preflight | Gate/CI/toolchain falla | No iniciar |
| Identity | Account/region/role/deployment mismatch | Cerrar sesión y abortar |
| Contracts | Digest/schema/binding inválido | Bloquear plan |
| Plan | Delete/replace/IAM/KMS/network no aprobado | Rechazar plan |
| Approval | Digest/serial/release cambió | Invalidar aprobación |
| Supply chain | Graph/scan/signature incompleto | No promover/desplegar |
| Apply | Error o state version inesperada | Detener capas posteriores |
| Services | Circuit breaker/stopped tasks/health falla | Detener wave |
| Data plane | DLQ/alarms/error rate excede threshold | Cerrar tráfico y evaluar rollback |
| Edge/auth | Login/authorizer/config falla | No hacer cutover |
| Evidence | No puede persistirse evidencia sanitizada | No declarar éxito |
| E2E | Transición incompleta/aislamiento falla | NO-GO |

### 16.2 Incidente

Al abortar:

1. marcar el deployment/change como `FAILED` o `ROLLBACK_PENDING`;
2. detener fases posteriores y tráfico nuevo cuando aplique;
3. preservar evidence sanitizada y referencias de state versions;
4. notificar on-call/Security según impacto;
5. no ejecutar comandos improvisados;
6. decidir roll-forward, rollback o hold;
7. documentar timeline, impacto, decisión y owner;
8. abrir problem record para root cause.

No copiar logs, documents, state o plan raw al ticket.

---

## 17. Rollback y reconciliación

### 17.1 Principios

- rollback es un nuevo cambio declarativo;
- Terraform state no es rollback;
- preferir roll-forward si existe riesgo de schema/queue incompatibility;
- no usar `terraform state`, import ni edición manual;
- no asumir que una imagen antigua sigue retenida: verificar antes del cambio;
- preservar compatibilidad con mensajes/in-flight jobs.

### 17.2 Predeployment rollback readiness

Antes del rollout:

- identificar manifest/digests last-known-good;
- verificar full OCI graph y scan/signature;
- registrar task definitions y state versions actuales;
- confirmar retención ECR;
- revisar cambios de schema/config/message contracts;
- medir in-flight, queue depth y DLQs;
- definir timeout, decision owner y traffic control.

### 17.3 Application rollback target-state

1. detener nuevas waves/tráfico;
2. confirmar si los mensajes producidos son compatibles;
3. restaurar los digests anteriores en inputs declarativos;
4. crear y aprobar un nuevo plan;
5. aplicar por wave;
6. verificar circuit breaker, queues, DLQs y estado;
7. ejecutar smoke sintético;
8. actualizar deployment record/evidence.

### 17.4 Infrastructure rollback

- revertir source/config mediante PR revisado;
- planear el revert;
- revisar deletes/replaces;
- aplicar sólo el saved plan aprobado;
- validar contratos/state/health;
- usar StateRecovery exclusivamente para corrupción/recuperación autorizada, no
  como rollback ordinario.

### 17.5 Reconciliación de metadata

`--reconcile-existing` sólo reconcilia metadata de una imagen existente cuando
tag y digest coinciden exactamente. No construye, pushea ni despliega ECS. No
convierte un release parcial en aprobado: el release manifest completo sigue
siendo obligatorio.

---

## 18. Evidence package, handoff y aceptación

### 18.1 Evidence package sanitizado

- change/deployment/release IDs;
- commit y manifest/attestation digests;
- resultados CI/gates;
- plan digests y summaries;
- approvals;
- state version IDs;
- contract digests;
- siete destination image digests;
- scan/signature/SBOM/provenance results;
- per-wave health;
- synthetic E2E result;
- final no-drift result;
- alarms/on-call validation;
- incident/rollback record, si aplica.

Nunca incluir state, plan JSON/binario, tfvars reales, logs raw, tokens,
credenciales, documentos o PII.

### 18.2 Handoff

| Entregable | Receptor | Acceptance |
|---|---|---|
| Deployment/release summary | Operations/Product | IDs y alcance correctos |
| Runbook y rollback | SRE/on-call | Ejercicio nonprod aprobado |
| Observability links | SRE | Alarms y receiver probados |
| Security evidence | Security | Sin gaps/waivers desconocidos |
| Identity/onboarding | Product/Support | Flujo oficial validado |
| Known risks | Todos | Owner y fecha de cierre |

### 18.3 Cierre

El deployment sólo pasa a `ACTIVE` cuando:

- todos los criterios de readiness son verdes;
- evidence está completa;
- no hay alertas no explicadas;
- handoff fue aceptado;
- los aprobadores firman el go-live.

---

## 19. Troubleshooting seguro

Reglas:

1. confirmar deployment/account/region antes de consultar;
2. usar APIs read-only y nombres derivados de contratos;
3. no imprimir tokens, payloads, documentos ni contenido extraído;
4. registrar sólo error type, service, correlation ID y timestamps;
5. no editar código/config live;
6. no replay de DLQ sin runbook, aprobación e idempotency review;
7. cualquier fix requiere branch, tests, PR, release y rollout normal.

| Síntoma | Diagnóstico seguro | Escalamiento |
|---|---|---|
| ECS no estable | Desired/running, deployment status, stopped reason, target health | Platform/SRE |
| Worker sin progreso | Queue depth/age, DLQ, task status, alarm state | SRE/service owner |
| ECR tag existe | Verificar immutable tag y digest | Release Manager |
| Metadata incompleta | Comparar contra manifest, no contra tag | Release/Platform |
| Auth 403 | Revisar claim/authorizer contract sin imprimir JWT | Identity/Security |
| Frontend config inválido | Comparar artifact/schema/contract | Edge/Frontend |
| Contract mismatch | Detener y comparar producer/state/release digests | Platform/Security |
| Plan inesperado | No aplicar; revisar ownership/drift | Platform/Security |

Decommissioning requiere un runbook separado, actual y aprobado. Los reportes
históricos de destroy no son instrucciones ejecutables.

---

## 20. Publicación documental y NotebookLM

### 20.1 Single source of truth

Este Markdown es la fuente canónica. DOCX/PDF deben generarse de forma
reproducible y registrar:

- versión/fecha;
- commit source;
- checksum del Markdown;
- fecha de generación;
- clasificación;
- aviso de que el Markdown prevalece.

Los cambios se realizan primero aquí y pasan por PR/revisión.

### 20.2 NotebookLM Brain

Contenido permitido:

- este runbook sanitizado;
- ADRs;
- READMEs;
- schemas y templates sintéticos;
- reportes de validación sanitizados;
- glosario y RACI sin datos personales innecesarios.

Contenido prohibido:

- tfvars/backend reales;
- Terraform state, plan binario o plan JSON;
- account IDs, ARNs/domains deployment-specific no públicos;
- tokens, cookies, credentials, keys o screenshots de sesiones;
- documentos, PII, bank/gov/personal data;
- logs raw o incident evidence sensible;
- customer contracts no autorizados.

Cada source en NotebookLM debe incluir versión, commit, owner y fecha. Al
publicar una revisión, retirar o marcar como superseded la anterior para evitar
respuestas basadas en runbooks obsoletos.

---

## 21. Fuentes oficiales

### 21.1 Fuentes normativas del repositorio

- `ADR/ADR-001-tenancy-model.md`
- `ADR/ADR-003-state-backend.md`
- `ADR/ADR-004-cross-account-identity.md`
- `ADR/ADR-005-deployment-schemas.md`
- `ADR/ADR-006-modules-contracts.md`
- `ADR/ADR-007-artifact-supply-chain.md`
- `ADR/ADR-009-threat-model.md`
- `ADR/ADR-010-testing-rollout.md`
- `ADR/ADR-011-monorepo-microservices-source.md`
- `ADR/ARCHITECTURE_OWNERSHIP_MATRIX.md`
- `backend/workers/README.md`
- `modules/cicd/README.md`
- `roots/cicd/README.md`
- `.github/workflows/microservices-build.yml`
- `scripts/microservices/build-push.sh`

Ante contradicción, debe resolverse mediante ADR/PR; no elegir silenciosamente
la instrucción más conveniente.

### 21.2 Documentación oficial externa

- [Terraform S3 backend](https://developer.hashicorp.com/terraform/language/backend/s3)
- [GitHub Actions: OIDC en AWS](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-aws)
- [GitHub Environments](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments)
- [AWS CLI: get-caller-identity](https://docs.aws.amazon.com/cli/latest/reference/sts/get-caller-identity.html)
- [Amazon ECR tag immutability](https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-tag-mutability.html)
- [Amazon ECR image scanning](https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html)
- [Amazon ECS deployment circuit breaker](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/deployment-circuit-breaker.html)

Las fuentes externas explican mecanismos del proveedor; las decisiones
arquitectónicas de Scanalyze viven en los ADRs.

---

## 22. Apéndices

### Apéndice A — Comandos y acciones

| Clase | Estado |
|---|---|
| Git status/diff y local tests | Permitido |
| Terraform fmt/init backend=false/validate local | Permitido |
| AWS describe/get/list bajo rol read-only aprobado | Requiere autorización de assessment |
| Docker build no-push | Permitido en CI/local aprobado |
| Terraform plan live | Bloqueado hasta M3/approval/tooling |
| Terraform apply/destroy | Bloqueado |
| Docker/ECR push | Bloqueado salvo release/sandbox aprobado |
| SSM put, ECS update, CloudFront invalidation | Bloqueado |
| State commands/manual editing | Prohibido |

### Apéndice B — Release acceptance

- [ ] Commit/release aprobado y clean.
- [ ] Toolchain exacto.
- [ ] Tests/gates verdes.
- [ ] ACCOUNT_READY válido.
- [ ] OIDC/roles/account binding válidos.
- [ ] Backend/state/evidence stores válidos.
- [ ] Full OCI graph de siete servicios.
- [ ] Scans/signatures/attestation verdes.
- [ ] Runtime config/contracts completos.
- [ ] Log groups y alert receiver listos.
- [ ] Saved plans aprobados.
- [ ] Waves estables y sin drift.
- [ ] Frontend/auth gates cerradas.
- [ ] Synthetic E2E verde.
- [ ] Rollback verificado.
- [ ] Evidence/handoff aceptados.

### Apéndice C — Decisión actual

```text
Decision: NO-GO
Reason: B-01 through B-07 remain open
Allowed next step: implement and validate blockers in non-production
Production authorization: none
```
