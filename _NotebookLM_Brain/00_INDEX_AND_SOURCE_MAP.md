# Scanalyze Knowledge Brain — índice y mapa de fuentes

> **Última revisión editorial:** 2026-07-12
>
> **Ámbito:** plataforma de despliegue dedicada y monorepo de microservicios
>
> **Audiencia:** Platform Engineering, DevSecOps, SRE, arquitectura y revisores
>
> **Línea de trabajo:** programa de production readiness; cada work package usa
> branch y PR aislados, sin merge ni autoridad live implícita

## Propósito

Esta carpeta contiene explicaciones curadas para NotebookLM y otros asistentes.
No reemplaza el código, los ADR ni los playbooks operativos. Su función es
explicar el sistema sin exponer secretos, datos de clientes ni artefactos
operativos, y ayudar a encontrar la fuente canónica de cada afirmación.

La regla editorial es **evidence before claims**: una decisión aprobada, una
implementación local y una validación live son evidencias diferentes.

## Vocabulario obligatorio de estado

| Estado | Significado |
|---|---|
| **Implemented** | El comportamiento está representado en código o configuración del repositorio. No implica que esté desplegado. |
| **Locally validated** | Existen pruebas o gates locales exitosas sobre la implementación. No implica acceso ni ejecución en AWS. |
| **CI validated** | Existen checks exitosos para un commit y workflow identificados. No implica AWS salvo evidencia live explícita y autorizada. |
| **Live validated** | Existe evidencia revisable de ejecución en una cuenta y ambiente explícitos. No equivale automáticamente a aprobación de producción. |
| **Target** | Es el estado arquitectónico deseado, normalmente descrito por un ADR. Puede estar parcial o totalmente pendiente. |
| **Blocked** | No debe continuarse con la operación dependiente hasta cerrar la condición indicada y producir evidencia. |

No se debe convertir **Accepted**, **Draft** o **Proposed** de un ADR en
**Implemented** sin revisar el código, ni convertir **Locally validated** o
**CI validated** en **Live validated**.

## Jerarquía de fuentes

Cuando dos documentos difieran, usar este orden:

1. Código y tests del commit revisado.
2. ADR aceptado aplicable y matriz de ownership vigente.
3. Playbook operativo canónico.
4. Documento de migración y evidencia de gates.
5. README específicos del componente.
6. Este Brain como explicación derivada.
7. Reports históricos únicamente como evidencia fechada, nunca como instrucción
   operativa vigente.

## Mapa de fuentes canónicas

| Pregunta | Fuente canónica |
|---|---|
| ¿Qué contiene el monorepo? | [README principal](../README.md) |
| ¿Dónde vive el código de servicios? | [README de microservicios](../backend/workers/README.md) |
| ¿Cómo se construyen y publican imágenes? | [README de microservicios](../backend/workers/README.md), [script de build/push](../scripts/microservices/build-push.sh) y [workflow de GitHub](../.github/workflows/microservices-build.yml) |
| ¿Cómo se despliega una cuenta enterprise? | [Playbook enterprise](../playbooks/enterprise-client-deployment.md) |
| ¿Cuál es el DAG y límite de ejecución del orquestador GitOps? | [ADR-017](../ADR/ADR-017-github-actions-release-orchestrator.md), [GitOps orchestrator](../docs/deployment/gitops-orchestrator.md) y `deployment/layers.yaml` |
| ¿Por qué existe account-per-deployment? | [ADR-001](../ADR/ADR-001-tenancy-model.md) |
| ¿Cuál es la fuente de los microservicios? | [ADR-011](../ADR/ADR-011-monorepo-microservices-source.md) |
| ¿Quién es dueño de cada recurso? | [Architecture Ownership Matrix](../ADR/ARCHITECTURE_OWNERSHIP_MATRIX.md) |
| ¿Qué se migró y qué quedó pendiente? | [Registro de migración](../docs/migration/monorepo-microservices-migration.md) |
| ¿Qué gates existen realmente? | [Makefile](../Makefile) y sus tests |
| ¿Qué políticas de seguridad aplican? | ADR-004, ADR-007, ADR-009, código, policies y session-policies |
| ¿Cuál es la foundation y secuencia de Production Readiness? | [ADR-019](../ADR/ADR-019-production-readiness-foundation.md) y [índice de Fase 0](../docs/production-readiness/README.md) |
| ¿Cómo se vincula un cliente M2M con customer y deployment? | [ADR-020](../ADR/ADR-020-versioned-m2m-identity-binding.md), [Identity Contract Reference](../docs/deployment/identity-contract.md) y tests GUG-102 |
| ¿Cómo se migra un deployment al binding M2M v2? | [Runbook M2M v2](../docs/deployment/m2m-identity-v2-migration.md); el inventario live permanece fuera de Git y NotebookLM |
| ¿Cómo se autoriza un documento, batch o artifact concreto? | [ADR-021](../ADR/ADR-021-object-level-authorization.md), código y tests GUG-114 del commit revisado |
| ¿Cómo se clasifican registros sin ownership canónico? | [Runbook de ownership y cuarentena](../docs/deployment/object-ownership-migration-quarantine.md); el inventario live y referencias reales permanecen fuera de Git y NotebookLM |

## Estado de evidencia al 2026-07-12

| Capacidad | Estado | Límite de la evidencia |
|---|---|---|
| Fuente única para infraestructura y siete microservicios | **Implemented**, **Locally validated** | Está en el worktree de la branch; aún requiere PR, CI y merge. |
| Safety gates para secretos, PII y artefactos prohibidos | **Implemented**, **Locally validated** | El resultado local no sustituye los required checks del PR. |
| Build parametrizado con base image explícita | **Implemented**, **Locally validated** | No hubo build real contra una base ECR aprobada durante la migración. |
| Publicación por GitHub OIDC a ECR del deployment | **Implemented**, **Locally validated** | El workflow y script existen; el flujo monorepo no está **Live validated**. |
| Metadatos de tag y digest en SSM | **Implemented**, **Locally validated** | Es metadata de release; no despliega ECS por sí sola. |
| DAG GitOps y workflow non-production reusable | **Implemented** como dry-run | Requiere CI verde; no solicita OIDC, no ejecuta apply y no constituye evidencia live. |
| Consumo de imagen inmutable por digest | **Implemented** como contrato de despliegue | Requiere plan y validación non-production antes de una promoción real. |
| Build central firmado y promoción verificable cross-account | **Target** | No es el flujo implementado actual. |
| SBOM, firma, provenance y vulnerability gate completos | **Target** | ADR-007 describe el objetivo; ADR-011 registra los gaps. |
| Configuración declarativa final del frontend | **Blocked** | Falta un dueño declarativo único y bindings exactos. |
| Binding M2M customer/deployment v2 en repositorio | **Implemented** cuando existe en el commit revisado; **Locally validated** sólo con gates verdes | No es evidencia Cognito/AWS. La habilitación live sigue **Blocked** por GUG-93/GUG-117. |
| Autorización de objetos customer/deployment | **Implemented** sólo cuando el commit revisado contiene enforcement central, rutas y storage protegidos; **Locally validated** sólo con gates verdes identificados | ADR-021 y el runbook por sí solos son decisiones. CI, inventario legacy, migración y aislamiento live requieren evidencia separada; producción sigue **NO-GO**. |
| Contrato completo de identidad y onboarding | **Blocked** | Claims, scope taxonomy, control-plane handoff, object authorization y evidencia live siguen pendientes. |
| Despliegue productivo del flujo monorepo | **Blocked** | Requiere CI verde, revisión humana y evidencia live non-production. |
| Foundation de Production Readiness / GUG-116 | **Implemented**, **Locally validated** | El validator y tests locales pasan; el cuaderno existente conserva una fuente sanitizada y respondió correctamente las seis preguntas fail-closed. No es evidencia AWS y producción sigue **NO-GO**. |

## Inventario del Brain

| Documento | Enfoque |
|---|---|
| [01 — Platform Overview](01_Scanalyze_Platform_Overview.md) | Propósito, límites y modelo de operación |
| [02 — Architecture and ADRs](02_Architecture_and_ADRs.md) | Decisiones y madurez de cada ADR |
| [03 — Infrastructure as Code Contracts](03_Infrastructure_as_Code_Contracts.md) | Roots, modules, ownership y contratos |
| [04 — Security and Identity](04_Security_and_Identity.md) | Aislamiento, identidad, datos y supply chain |
| [05 — Enterprise Deployment Playbook](05_Enterprise_Deployment_Playbook.md) | Resumen operativo derivado del playbook canónico |
| [06 — Testing and Acceptance Gates](06_Testing_and_Acceptance_Gates.md) | Gates reales y límites de evidencia |
| [07 — AI Agents and Automation Tooling](07_AI_Agents_and_Automation_Tooling.md) | Operación segura de agentes |
| [08 — Monorepo and Supply Chain](08_Monorepo_Microservices_and_Supply_Chain.md) | Código, imágenes, ECR, SSM, ECS y gaps de supply chain |
| [09 — Production Readiness and Handoff](09_Production_Readiness_and_Operational_Handoff.md) | Readiness, stop gates y operación |
| [10 — Production Readiness Foundation](10_Production_Readiness_Foundation.md) | Fase 0, arquitectura GitOps, evidencia, gates, riesgos y respuestas fail-closed |

## Reglas de ingestión y mantenimiento

- Ingerir Markdown, ADR y playbooks revisados; no ingerir tfvars operativos,
  state, planes, dumps, logs, documentos de clientes ni archivos de credenciales.
- No usar customer IDs, account IDs, ARNs, dominios, correos o regiones reales
  en ejemplos.
- Mantener placeholders sintéticos y no secretos.
- Actualizar primero la fuente canónica y después este resumen.
- Registrar fecha, commit y ambiente para cualquier afirmación **Live validated**.
- No inferir que un archivo en esta carpeta fue cargado correctamente a
  NotebookLM; la ingestión requiere verificación separada.

## Preguntas que este Brain debe responder de forma fail-closed

1. ¿La operación mantiene aislamiento account-per-deployment?
2. ¿El recurso tiene un solo dueño declarativo?
3. ¿Se usa source común sin forks de cliente?
4. ¿La imagen y la base image están identificadas por digest?
5. ¿La acción requiere una aprobación o credencial que no fue proporcionada?
6. ¿La evidencia es local, live o solamente un target?
7. ¿Existe un blocker de identidad, frontend o supply chain?
8. ¿Producción continúa NO-GO y GUG-128 bloqueado?
9. ¿La afirmación confunde Fase 0, CI o dry-run con evidencia AWS?
10. ¿La promoción intenta reconstruir en vez de reutilizar el release inmutable?
11. ¿Falta algún binding de cliente, deployment, cuenta, región o ambiente?
12. ¿Se está tratando state restore como rollback rutinario?
13. ¿El documento, batch y cada membership prueban customer y deployment exactos
    sin fallback legacy, scan ni filtrado posterior?

Si una respuesta depende de datos ausentes, el Brain debe indicarlo como
**Blocked** o **Unknown**, nunca completar el dato por inferencia.
