# Scanalyze Knowledge Brain — índice y mapa de fuentes

> **Última revisión editorial:** 2026-07-21
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
| ¿Qué roles, acciones, scopes y lifecycle enterprise aplican? | [ADR-023](../ADR/ADR-023-enterprise-authorization-and-user-lifecycle.md), [Enterprise Authorization Reference](../docs/deployment/enterprise-authorization.md) y [fuente sanitizada GUG-92](12_GUG92_Enterprise_Authorization.md) |
| ¿Cómo se implementa el control plane de identidad sin convertir grupos, Terraform o secretos en autoridad? | [ADR-024](../ADR/ADR-024-identity-control-plane-and-provider-boundary.md), [Identity Control Plane Reference](../docs/deployment/identity-control-plane.md), [runbook de bootstrap/retiro](../docs/operations/identity-bootstrap-retirement.md) y [fuente sanitizada GUG-93](13_GUG93_Identity_Control_Plane.md) |
| ¿Cómo se aplica autorización humana fail-closed en cada ruta backend? | [ADR-025](../ADR/ADR-025-human-authorization-enforcement.md), [Human Authorization Enforcement Reference](../docs/deployment/human-authorization-enforcement.md), [delta de threat model GUG-153](../docs/security/gug-153-threat-model-delta.md) y [fuente sanitizada GUG-153](14_GUG153_Human_Authorization_Enforcement.md) |
| ¿Cómo se administran usuarios, membresías, sesiones y bootstrap de forma recuperable? | [ADR-026](../ADR/ADR-026-enterprise-user-lifecycle-and-recoverable-bootstrap.md), [Enterprise User Lifecycle API](../docs/deployment/enterprise-user-lifecycle-api.md), [runbook de recuperación](../docs/operations/user-lifecycle-recovery.md), [delta de threat model GUG-94](../docs/security/gug-94-threat-model-delta.md) y [fuente sanitizada GUG-94](15_GUG94_Enterprise_User_Lifecycle.md) |
| ¿Cómo opera la consola enterprise sin convertir claims o UI en autoridad? | [ADR-028](../ADR/ADR-028-portable-enterprise-user-console.md), [Enterprise User Console](../docs/deployment/enterprise-user-console.md), [delta de threat model GUG-95](../docs/security/gug-95-enterprise-user-console-threat-model-delta.md) y [fuente sanitizada GUG-95](17_GUG95_Enterprise_User_Console.md) |
| ¿Cómo se autoriza un documento, batch o artifact concreto? | [ADR-021](../ADR/ADR-021-object-level-authorization.md), código y tests GUG-114 del commit revisado |
| ¿Cómo se clasifican registros sin ownership canónico? | [Runbook de ownership y cuarentena](../docs/deployment/object-ownership-migration-quarantine.md); el inventario live y referencias reales permanecen fuera de Git y NotebookLM |
| ¿Cómo se resuelven contratos tipados en el DAG canónico? | [ADR-029](../ADR/ADR-029-strict-contracts-and-canonical-dag.md), [resolución estricta](../docs/deployment/strict-contract-resolution.md) y [fuente sanitizada GUG-121](18_GUG121_Strict_Contracts_and_DAG.md) |
| ¿Cómo se autoriza un target y se deriva su backend sin confiar en el request? | [ADR-030](../ADR/ADR-030-registry-account-baseline-backend-locking.md), [backend y locking](../docs/deployment/registry-account-baseline-backend-locking.md), [runbook de recuperación](../docs/operations/terraform-backend-migration-and-recovery.md) y [fuente sanitizada GUG-122](19_GUG122_Registry_Backend_Locking.md) |
| ¿Qué ejecución GitHub puede obtener identidad y entrar a cada rol terminal? | [ADR-031](../ADR/ADR-031-github-oidc-terminal-identity.md), [referencia GUG-123](../docs/deployment/github-oidc-terminal-identity.md), [runbook de rollout](../docs/operations/github-oidc-terminal-identity-rollout.md) y [fuente sanitizada GUG-123](20_GUG123_GitHub_OIDC_Terminal_Identity.md) |
| ¿Cómo se aplica una sola vez el plan exacto revisado, cómo se crea la autoridad portable y cómo se reconcilia un resultado incierto? | [ADR-033](../ADR/ADR-033-nonproduction-live-engine-and-saved-plans.md), [referencia GUG-125](../docs/deployment/nonproduction-live-engine.md), [bootstrap de platform authority](../docs/deployment/platform-authority-bootstrap.md), [runbook de reconciliación](../docs/operations/nonproduction-live-engine-reconciliation.md) y [fuente sanitizada GUG-125](22_GUG125_Nonproduction_Live_Engine.md) |
| ¿Cómo se crea de forma recuperable el backend de la cuenta dedicada de autoridad? | [ADR-034](../ADR/ADR-034-dedicated-platform-authority-account-bootstrap.md), [bootstrap GUG-206](../docs/deployment/platform-authority-account-bootstrap.md), [runbook de recuperación](../docs/operations/platform-authority-bootstrap-recovery.md), [delta de threat model](../docs/security/gug-206-threat-model-delta.md) y [fuente sanitizada GUG-206](23_GUG206_Platform_Authority_Account_Bootstrap.md) |
| ¿Qué nombres de permission set son portables y autoritativos para el bootstrap? | [ADR-036](../ADR/ADR-036-identity-center-permission-set-name-contract.md), [bootstrap GUG-206](../docs/deployment/platform-authority-account-bootstrap.md), [delta de threat model GUG-208](../docs/security/gug-208-identity-center-name-contract-threat-model-delta.md) y [fuente sanitizada GUG-208](25_GUG208_Identity_Center_Name_Contract.md) |
| ¿Cómo se maneja una excepción de founder con un solo operador sin degradar la aprobación independiente normal? | [ADR-037](../ADR/ADR-037-founder-bootstrap-single-operator-exception.md), [runbook de excepción](../docs/operations/founder-bootstrap-single-operator-exception.md), [delta de threat model GUG-209](../docs/security/gug-209-founder-bootstrap-exception-threat-model-delta.md) y [fuente sanitizada GUG-209](26_GUG209_Founder_Bootstrap_Exception.md) |
| ¿Cómo se impide durablemente repetir el seed founder y cómo se prueba el backend antes de éxito? | [ADR-039](../ADR/ADR-039-durable-founder-bootstrap-pep.md), [referencia GUG-211](../docs/deployment/durable-founder-bootstrap-pep.md), [runbook PEP](../docs/operations/durable-founder-bootstrap-pep.md), [delta de threat model](../docs/security/gug-211-durable-founder-bootstrap-pep-threat-model-delta.md) y [fuente sanitizada GUG-211](28_GUG211_Durable_Founder_Bootstrap_PEP.md) |
| ¿Cómo se recupera un shell de autoridad sin inferir recursos ni omitir Change Sets? | [ADR-040](../ADR/ADR-040-authority-recovery-preflight.md), [runbook de recuperación](../docs/operations/platform-authority-bootstrap-recovery.md), [delta GUG-214](../docs/security/gug-214-authority-recovery-preflight-threat-model-delta.md) y [fuente sanitizada GUG-214](29_GUG214_Authority_Recovery_Preflight.md) |
| ¿Cómo se retira exactamente un Change Set retenido cuando falta la evidencia Plan original? | [ADR-041](../ADR/ADR-041-retained-change-set-retirement.md), [contrato GUG-215](../docs/deployment/platform-authority-change-set-retirement.md), [runbook de retiro](../docs/operations/platform-authority-retained-change-set-retirement.md), [delta GUG-215](../docs/security/gug-215-retained-change-set-retirement-threat-model-delta.md) y [fuente sanitizada GUG-215](30_GUG215_Retained_Change_Set_Retirement.md) |
| ¿Cómo se obtiene una sesión identity-enhanced sin exponer secretos y cómo se comprueba que el servicio destino la soporta? | [ADR-042](../ADR/ADR-042-identity-enhanced-operator-session-compatibility.md), [contrato GUG-216](../docs/deployment/platform-authority-identity-enhanced-session.md), [runbook de sesión](../docs/operations/platform-authority-identity-enhanced-session.md), [delta GUG-216](../docs/security/gug-216-identity-enhanced-session-threat-model-delta.md) y [fuente sanitizada GUG-216](31_GUG216_Identity_Enhanced_Operator_Session.md) |
| ¿Cómo se conserva la prueba inmutable de usuario cuando la sesión identity-enhanced no puede invocar Lambda? | [ADR-043](../ADR/ADR-043-identity-context-compatible-retirement-pep.md), [contrato GUG-217](../docs/deployment/platform-authority-identity-context-pep.md), [runbook GUG-217](../docs/operations/platform-authority-identity-context-pep.md), [delta GUG-217](../docs/security/gug-217-identity-context-pep-threat-model-delta.md) y [fuente sanitizada GUG-217](32_GUG217_Identity_Context_Compatible_Retirement_PEP.md) |
| ¿Cómo se prueba que no existe autoridad Lambda aditiva antes de habilitar el PEP? | [ADR-044](../ADR/ADR-044-account-wide-lambda-invocation-authority.md), [contrato GUG-218](../docs/deployment/platform-authority-lambda-invocation-authority.md), [runbook GUG-218](../docs/operations/platform-authority-lambda-invocation-authority.md), [delta GUG-218](../docs/security/gug-218-lambda-invocation-authority-threat-model-delta.md) y [fuente sanitizada GUG-218](33_GUG218_Lambda_Invocation_Authority.md) |
| ¿Cómo se produce la allowlist GUG-218 sin copiar evidencia sintética ni confiar en un perfil AWS? | [ADR-045](../ADR/ADR-045-reviewed-lambda-authority-allowlist-and-collector.md), [contrato GUG-219](../docs/deployment/platform-authority-lambda-invocation-materialization.md), [runbook GUG-219](../docs/operations/platform-authority-lambda-invocation-materialization.md), [delta GUG-219](../docs/security/gug-219-lambda-authority-materialization-threat-model-delta.md) y [fuente sanitizada GUG-219](34_GUG219_Lambda_Authority_Allowlist_and_Collector.md) |
| ¿Cómo se provisiona y verifica el collector Lambda mínimo sin confiar en nombres locales, intents stale ni respuestas asíncronas ambiguas? | [ADR-046](../ADR/ADR-046-lambda-audit-permission-set-provisioning.md), [contrato GUG-220](../docs/deployment/platform-authority-lambda-audit-permission-set.md), [runbook GUG-220](../docs/operations/platform-authority-lambda-audit-permission-set.md), [delta GUG-220](../docs/security/gug-220-lambda-audit-permission-set-threat-model-delta.md) y [fuente sanitizada GUG-220](35_GUG220_Lambda_Audit_Permission_Set.md) |
| ¿Cómo se repara el estado parcial exacto del collector sin reintentar GUG-220 ni usar autoridad administrativa amplia? | [ADR-047](../ADR/ADR-047-lambda-audit-provisioning-repair.md), [contrato GUG-221](../docs/deployment/platform-authority-lambda-audit-provisioning-repair.md), [runbook GUG-221](../docs/operations/platform-authority-lambda-audit-provisioning-repair.md), [delta GUG-221](../docs/security/gug-221-lambda-audit-provisioning-repair-threat-model-delta.md) y [fuente sanitizada GUG-221](36_GUG221_Lambda_Audit_Provisioning_Repair.md) |

## Estado de evidencia al 2026-07-22

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
| Contrato enterprise RBAC+ABAC y lifecycle v1 | **Implemented** sólo cuando el commit revisado contiene policy/schema, validator, fixtures, ADR-023 y referencia; **Locally validated** sólo con gates verdes identificados | No implica enforcement humano, Cognito, APIs administrativas ni revocación live. GUG-93, GUG-94 y GUG-117 conservan sus propios gates. |
| Control plane de identidad GUG-93 | **Implemented** sólo para una revisión que contenga layer/root, contratos, runtime fail-closed, tests, ADR-024 y runbooks; **Locally validated** sólo con resultados nombrados | CI permanece pendiente hasta los checks del commit exacto. AWS/Cognito, bootstrap, credenciales M2M, adopción/migración, retiro, aislamiento de dos deployments y producción siguen **Blocked / NO-GO**. |
| Enforcement humano PDP/PEP GUG-153 | **Implemented** sólo cuando el commit revisado contiene el snapshot tipado, PDP central, PEP en las 30 rutas, contratos, auditoría y pruebas negativas; **Locally validated** sólo con resultados nombrados | No habilita el flag humano ni prueba provider/AWS. CI, merge/main, GUG-94/GUG-95, aislamiento de dos deployments y validación live conservan evidencia separada; producción sigue **NO-GO**. |
| Consola enterprise GUG-95 | **Implemented** sólo cuando el commit revisado contiene UI fail-closed, cliente tipado, contratos lifecycle/CORS, ADR, threat model y pruebas; **Locally validated** sólo con gates nombrados | Claims son UX, no autoridad. CI, merge/main, proveedor/browser live, activación y prueba autorizada de dos deployments siguen **Blocked / NO-GO**. |
| Autorización de objetos customer/deployment | **Implemented** sólo cuando el commit revisado contiene enforcement central, rutas y storage protegidos; **Locally validated** sólo con gates verdes identificados | ADR-021 y el runbook por sí solos son decisiones. CI, inventario legacy, migración y aislamiento live requieren evidencia separada; producción sigue **NO-GO**. |
| Contrato completo de identidad y onboarding | **Blocked** | Los catálogos y contratos repositorio están definidos; siguen pendientes su realización en provider/control plane, enforcement GUG-153, APIs/UI GUG-94/GUG-95 y evidencia live. |
| Despliegue productivo del flujo monorepo | **Blocked** | Requiere CI verde, revisión humana y evidencia live non-production. |
| Foundation de Production Readiness / GUG-116 | **Implemented**, **Locally validated** | El validator y tests locales pasan; el cuaderno existente conserva una fuente sanitizada y respondió correctamente las seis preguntas fail-closed. No es evidencia AWS y producción sigue **NO-GO**. |
| Motor live non-production GUG-125 | **Implemented** como contratos, core, adapters y fábrica Terraform portable de platform authority; **Locally validated** sólo con gates nombrados | El workflow sigue dry-run. Tercera cuenta/backend autorizados, Environments/revisores independientes, ACCOUNT_READY, plans/applies, health, reconciliación, no-change, aislamiento y cleanup live siguen **Blocked / NO-GO**. |
| Bootstrap de cuenta platform-authority GUG-206 | **Implemented** sólo cuando el commit revisado contiene plantilla S3/KMS, plan/aprobación/verificación tipados, CLI fail-closed, policy mínima, tests, ADR-034 y runbooks; **Locally validated** sólo con gates nombrados | El inventario AWS read-only no equivale a bootstrap. Permission set mínimo, segundo principal SSO, Change Set autorizado, apply, verificación, root Terraform y aislamiento de dos clientes siguen **Blocked / NO-GO**. |
| Reparación de autorización KMS alias GUG-207 | **Implemented** en worktree y **Locally validated** con gates nombrados; commit, revisión y CI pendientes | `kms:RequestAlias` no es válido para operaciones de alias. CI previa no es evidencia live; AWS y producción siguen **Blocked / NO-GO**. |
| Contrato de nombres Identity Center GUG-208 | **Implemented** sólo en el worktree hasta commit, revisión y merge; **Locally validated** sólo con gates nombrados | La primera creación Plan fue rechazada antes de crear recursos. Los nombres corregidos, assignments, Change Set y bootstrap live siguen **Blocked / NO-GO**. |
| Excepción founder de un solo operador GUG-209 | **Target OFFLINE-ONLY — LIVE EXECUTION BLOCKED** hasta que el commit revisado contenga contratos, políticas temporales, ledger/revocación, tests, ADR, runbook y delta de threat model; **Locally validated** sólo con gates nombrados | JSON/digests locales no son autorización ni CAS durable. La excepción declara explícitamente ausencia de aprobación independiente; no autoriza AWS, Change Set execution, Terraform apply, despliegue, producción ni cleanup live. Un PEP futuro requiere CAS durable, evidencia confiable y readback exacto; revocación estructural sigue **Blocked / NO-GO**. |
| Binding IAM de Change Set GUG-210 | **Implemented** sólo cuando el commit revisado contiene stack ARN + `cloudformation:ChangeSetName`, tags exactos, tests, ADR-038 y threat-model delta; **Locally validated** sólo con gates nombrados | El ARN/UUID completo sigue siendo evidencia PEP, no selector IAM para Create/Delete/Execute. CI, AWS, bootstrap live y producción siguen **Blocked / NO-GO**. |
| PEP durable founder GUG-211 | **Implemented** sólo cuando el commit revisado contiene seed Organizations/StackSets exacto, ledger DynamoDB protegido, intent/ledger tipados, CAS antes de efectos, políticas Plan/Apply disjuntas, readback S3/KMS completo, tests, ADR/runbooks/threat model y fuente sanitizada; **Locally validated** sólo con gates nombrados | No es evidencia live ni autorización AWS. Seed, Identity Center, Plan, Apply, revocación, GUG-206, GUG-125, aislamiento de dos deployments y producción siguen **Blocked / NO-GO** hasta su evidencia separada. |
| Reparación de lectura de tags founder GUG-213 | **Implemented** sólo cuando el commit revisado separa `ListTagsForResource` en el ARN family S3 exacto y conserva reads posteriores tag-gated; **Locally validated** sólo con gates nombrados | El intento live creó la política exacta con cero targets y falló cerrado antes de StackSets/ledger. No se permite retry hasta CI, merge, main verification y reconciliación del permission set; producción sigue **NO-GO**. |
| Preflight de recuperación de autoridad GUG-214 | **Implemented** sólo cuando el commit revisado contiene `preflight-recovery`, `ListChangeSets` exact-stack paginado, doble inventario founder, reads exactos de tabla/PITR, tests, ADR/runbooks/threat model y fuente sanitizada; **Locally validated** sólo con gates nombrados | ReadOnly es evidencia independiente, no autoridad. PAB ausente, Change Set activo/ambiguo o recurso inferido bloquean. La validación live requiere policy provisionada y rol Plan exacto; producción sigue **NO-GO**. |
| Retiro exacto de Change Set retenido GUG-215 | **Implemented** sólo cuando el commit revisado contiene Lambda PEP versionada, aliases `classify`/`retire`/`reconcile`, dos Identity Store UserIds inmutables distintos, roles humanos invoke-only, ledger DynamoDB con resource policy y `CLASSIFIED -> APPROVED -> ATTEMPTED -> RETIRED_RECONCILED`, PEP target por UUID/contenido, un solo delete sin retry, CLI broker-only, tests, ADR/runbooks/threat model y fuente sanitizada; **Locally validated** sólo con gates nombrados | La inspección sanitizada observó un shell `REVIEW_IN_PROGRESS`, cero recursos y un Change Set `CREATE_COMPLETE` / `AVAILABLE` con cuatro cambios esperados. El broker/ledger y los bindings identity-enhanced de dos operadores independientes no fueron desplegados ni invocados. Clasificación y retiro live permanecen **Blocked**; ningún delete live fue ejecutado, CI está pendiente y producción sigue **NO-GO**. |
| Sesión identity-enhanced y compatibilidad GUG-216 | **Implemented** en el worktree sólo cuando el commit revisado contiene guard de policy administrada, adapter one-shot capability-bound, bindings/receipts estrictos, policies exactas, tests, ADR/runbook/threat model y fuente sanitizada; **Locally validated** sólo con gates nombrados | El snapshot público `v12` es reproducibilidad offline, no evidencia live. Su `Deny` / `NotAction` excluye `lambda:InvokeFunction`, así que no se emite token, sesión STS ni invocación. César es el único operador actual y no satisface classifier+approver. CI, AWS live, segundo humano, GUG-215 y producción siguen **Blocked / NO-GO**. |
| PEP compatible con identity context GUG-217 | **Implemented** sólo cuando el commit revisado contiene Function URLs `AWS_IAM` por alias, invocadores ordinarios exactos, proof roles deny-all, exchange OAuth/STS en broker, receipt digest en ledger antes del efecto, attribution explícita, schemas/tests/ADR/runbook/threat model y fuente sanitizada; **Locally validated** sólo con gates nombrados | `v12` se usa sólo para `sts:SetContext`, nunca como autoridad Lambda/CloudFormation. No hubo provisioning, token, sesión STS, invocación ni retiro live. César sigue siendo el único humano; falta approver independiente y producción sigue **Blocked / NO-GO**. |
| Inventario account-wide de autoridad Lambda GUG-218 | **Implemented** sólo cuando el commit revisado contiene snapshot tipado, procedencia sellada, paginación estricta, grafo cerrado de 14 edges, cero mutadores, analizador puro, adapter read-only, receipt sanitizado, policy mínima, tests, ADR/runbook/threat model y fuente sanitizada; **Locally validated** sólo con gates nombrados | Sólo una captura autenticada puede producir `REVIEW_SAFE_REPORT_ONLY`; `OFFLINE_UNVERIFIED` siempre bloquea. Ningún receipt autoriza efectos. No hubo lectura AWS, invoke, token, STS, provisioning ni despliegue. Falta guardrail preventivo, inventario live repetido y segundo humano; producción sigue **Blocked / NO-GO**. |
| Materialización de allowlist y collector GUG-219 | **Implemented** sólo cuando el commit revisado contiene contrato de permission set dedicado, renderer determinista, release anchor de cinco minutos, dos capturas distintas, almacenamiento privado create-only, schemas, tests, ADR/runbook/threat model y fuente sanitizada; **Locally validated** sólo con gates nombrados | Este paquete no crea ni provisiona el permission set, no despliega GUG-217 y no realiza AWS calls. Una sola persona puede producir evidencia report-only, pero no satisface la aprobación independiente de GUG-215. Live validation y producción siguen **Blocked / NO-GO**. |
| Provisioning del collector Lambda GUG-220 | **Implemented** sólo cuando el commit revisado contiene contrato exacto `ScanalyzeAuthorityLambdaAudit`, policy exclusiva, `PT1H`, intent máximo 15 minutos ligado por digest al Instance/Identity Store live y al directorio privado `0700`, ledger one-shot `O_EXCL` por `intent_digest`, receipt reservado antes del write, asignación directa bootstrap, provisioning o reprovisioning explícito a un único target, reconciliación sin retry, paginación IAM completa, una sola instancia Identity Center `ACTIVE`, readback con ambos ARN digests y tres gates positivos, custodia `O_NOFOLLOW`/owner/`0600`, schemas de intent/ledger/receipt, tests, ADR/runbook/threat model y fuente sanitizada; **Locally validated** sólo con gates nombrados | Replay falla `EXECUTION_LEDGER_ALREADY_CONSUMED`; timeout, `OSError` o falla post-write queda `UNCERTAIN_RECONCILE_ONLY`. Intents v1 anteriores al hardening son obsoletos. Los IDs/ARNs/evidencia live permanecen privados. Una asignación a un único operador no es aprobación independiente; Candidate A/B son read-only y GUG-215 sigue bloqueado hasta dos humanos. Producción sigue **NO-GO**. |
| Reparación del provisioning Lambda GUG-221 | **Implemented** sólo cuando el commit revisado contiene el invocador exacto `ScanalyzeLambdaAuditRepair` sin APIs crudas, funciones/aliases privados y versionados para Plan/repair/reconcile, seis roles separados incluido el inspector exacto, grafo account-wide verificado en cada snapshot, Plan durable create-only obligatorio, repair update-only, policy de sólo tres mutaciones detrás del PEP, intent corto, ledger DynamoDB CAS provider-backed, receipt sanitizado, reconciliación sin retry, lineage exacto de Phase A con `ClientRequestToken`/CloudTrail/StackEvents, readback SSO+IAM completo, schemas, tests, ADR/runbook/threat model y fuente sanitizada | El ledger GUG-220 permanece consumido: sólo puede leerse para sellar su digest y jamás mutarse o reutilizarse. Los dos stacks requieren bootstrap y readback separados; cualquier ambigüedad queda reconcile-only. No hay validación live. Candidate A/B, aprobación independiente y producción siguen **Blocked / NO-GO**. |

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
| [12 — GUG-92 Enterprise Authorization](12_GUG92_Enterprise_Authorization.md) | RBAC+ABAC portable, scopes, lifecycle, bootstrap, soporte JIT, break-glass, migración y límites de evidencia |
| [13 — GUG-93 Identity Control Plane](13_GUG93_Identity_Control_Plane.md) | Cognito como adapter no autoritativo, access tokens, bootstrap one-use, M2M runtime sin secretos en Terraform, contratos, migración/retiro y límites de evidencia |
| [14 — GUG-153 Human Authorization Enforcement](14_GUG153_Human_Authorization_Enforcement.md) | Snapshot humano bounded, PDP/PEP tipado, 30 rutas, role/data-class checks, step-up, audit, ownership y límites de evidencia |
| [16 — GUG-95 Frontend Source Consolidation](16_GUG95_Frontend_Source_Consolidation.md) | Fuente SPA canónica, procedencia cerrada, config v2 fail-closed, CI reproducible y límites NO-GO |
| [17 — GUG-95 Enterprise User Console](17_GUG95_Enterprise_User_Console.md) | UI de privilegios fail-closed, lifecycle recuperable, privacidad, CORS y E2E sintético |
| [18 — GUG-121 Strict Contracts and DAG](18_GUG121_Strict_Contracts_and_DAG.md) | Catálogo de contratos, productores únicos, resolución content-addressed, DAG canónico y límites live |
| [19 — GUG-122 Registry and Backend Locking](19_GUG122_Registry_Backend_Locking.md) | Registry anclado, ACCOUNT_READY v2, backend derivado, lockfile nativo, ejecución exclusiva y recuperación revisada |
| [20 — GUG-123 GitHub OIDC and Terminal Identity](20_GUG123_GitHub_OIDC_Terminal_Identity.md) | IDs inmutables, Environment anclado, subject exacto, roles terminales y separación break-glass |
| [21 — GUG-124 Build Once and Supply Chain](21_GUG124_Build_Once_Supply_Chain.md) | Grafo completo, evidencia por digest, VSA firmada, gate central, promoción y rollback sin rebuild |
| [22 — GUG-125 Non-Production Live Engine](22_GUG125_Nonproduction_Live_Engine.md) | Plan exacto versionado, fábrica portable de platform authority, aprobación independiente, ledger CAS, health, reconciliación y límites live |
| [23 — GUG-206 Platform Authority Account Bootstrap](23_GUG206_Platform_Authority_Account_Bootstrap.md) | Cuenta dedicada, backend S3/KMS, locking nativo, Change Set exacto, SSO independiente, recuperación y límites live |
| [24 — GUG-207 KMS Alias Authorization](24_GUG207_KMS_Alias_Authorization.md) | Autorización exacta alias/key, condiciones KMS válidas, CloudFormation forward access y límites live |
| [25 — GUG-208 Identity Center Name Contract](25_GUG208_Identity_Center_Name_Contract.md) | Nombres portables exactos, validación del rol SSO, separación Plan/Apply y límites live |
| [26 — GUG-209 Founder Bootstrap Exception](26_GUG209_Founder_Bootstrap_Exception.md) | Excepción single-operator offline-only, deny temporal AWS-side, PEP/CAS futuro, revocación y límites NO-GO |
| [27 — GUG-210 Change Set IAM Binding](27_GUG210_ChangeSet_IAM_Binding.md) | Stack ARN, condición ChangeSetName, tags de creación, verificación PEP y límites live |
| [28 — GUG-211 Durable Founder Bootstrap PEP](28_GUG211_Durable_Founder_Bootstrap_PEP.md) | Seed exacto, ledger CAS durable, Plan/Apply de un intento, incertidumbre terminal, readback de backend, revocación y límites live |
| [29 — GUG-214 Authority Recovery Preflight](29_GUG214_Authority_Recovery_Preflight.md) | Shell exacto, inventario paginado de Change Sets, PAB fail-closed, tabla/PITR exactos y límites live |
| [30 — GUG-215 Retained Change Set Retirement](30_GUG215_Retained_Change_Set_Retirement.md) | Inspección target read-only, ledger CAS durable, identidad temporal exacta, policy digest, PEP por UUID, un delete sin retry, separación SSO honesta, reconciliación y límites live |
| [31 — GUG-216 Identity-Enhanced Operator Session](31_GUG216_Identity_Enhanced_Operator_Session.md) | CreateTokenWithIAM/ProvidedContexts one-shot, guard de compatibilidad de policy administrada, secretos in-memory, separación humana y bloqueo Lambda live |
| [32 — GUG-217 Identity-Context-Compatible Retirement PEP](32_GUG217_Identity_Context_Compatible_Retirement_PEP.md) | Function URLs AWS_IAM por alias, proof roles deny-all, secretos one-shot, proof digest durable antes del efecto, attribution broker y bloqueo por segundo humano |
| [33 — GUG-218 Lambda Invocation Authority](33_GUG218_Lambda_Invocation_Authority.md) | Inventario IAM/Lambda account-wide, grafo exacto, paginación estricta, receipt report-only y límites live |
| [34 — GUG-219 Lambda Authority Allowlist and Collector](34_GUG219_Lambda_Authority_Allowlist_and_Collector.md) | Renderer determinista desde evidencia privada, collector Identity Center mínimo, release anchor y segunda captura obligatoria |
| [35 — GUG-220 Lambda Audit Permission Set](35_GUG220_Lambda_Audit_Permission_Set.md) | Permission set exacto, intent live-bound de máximo 15 minutos, ledger one-shot y receipt reservado, asignación bootstrap de un operador, provisioning/reprovisioning de un target, custodia privada descriptor-safe, reconciliación sin retry, paginación completa, readback completo y handoff report-only |
| [36 — GUG-221 Lambda Audit Provisioning Repair](36_GUG221_Lambda_Audit_Provisioning_Repair.md) | Estado parcial exacto, invocador humano Lambda-only, funciones Plan/repair/reconcile, inspector account-wide, Plan durable obligatorio, tres mutaciones ordenadas, ledger DynamoDB CAS, lineage exacto Phase A, ambigüedad terminal, readback Identity Center/IAM y NO-GO |

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
14. ¿El usuario tiene membership activo y versiones vigentes de policy, rol,
    scopes y grant, además del ownership y assurance requeridos?
15. ¿Bootstrap, soporte o break-glass son one-use/JIT, aprobados, expiran y se
    revocan sin crear una autoridad standing?
16. ¿Los grupos del provider se están tratando sólo como mapping no autoritativo
    y el membership store sigue siendo la autoridad?
17. ¿Un valor de credencial M2M intenta entrar a Terraform, state, output,
    contrato, log o evidencia general?
18. ¿La adopción, migración o eliminación de identidad legacy está intentando
    inferir bindings o saltar el procedimiento retain-first?
19. ¿El backend proviene del registry anclado, ACCOUNT_READY v2, lock vigente y
    DAG canónico, o de un manifest, prefijo, perfil o convención no autoritativa?
20. ¿Un lock expirado está siendo tratado incorrectamente como permiso para
    takeover o force-unlock automático?
21. ¿La identidad cloud proviene de un subject OIDC exacto y de evidencia fresca
    del Environment, o de nombres, inputs, variables, defaults o wildcards?
22. ¿Apply descargó la versión exacta aprobada, revalidó state/contratos/release,
    consumió un solo intento y obtuvo health, o intenta re-planear/reintentar?
23. ¿Un Change Set retenido sin receipt Plan original usa la Lambda PEP
    versionada GUG-215, dos UserIds inmutables distintos, roles humanos
    invoke-only, aliases calificados, ledger con resource policy y PEP por UUID,
    o intenta reconstruir el Plan, mutar directamente, borrar el stack o
    reintentar?
24. ¿Una sesión identity-enhanced valida primero la policy administrada de STS,
    conserva tokens/contexto sólo en memoria y exige dos personas/UserIds
    distintos, o intenta invocar Lambda pese al deny, omitir ProvidedContexts o
    convertir al único operador actual en classifier y approver?
25. ¿El PEP compatible usa una sesión ordinaria sólo para el Function URL
    exacto, limita `v12` a la prueba deny-all de `sts:SetContext`, persiste el
    proof digest antes del efecto y atribuye honestamente CloudFormation al
    broker, o intenta convertir la prueba en credencial de efecto?
26. ¿La reparación del collector acepta exclusivamente el estado parcial
    GUG-220 observado, limita al humano `ScanalyzeLambdaAuditRepair` a aliases
    privados exactos, reclama un ledger DynamoDB CAS provider-backed antes del
    primer efecto y limita el service role a policy, asignación y provisioning,
    o intenta reusar el ledger anterior, ampliar la autoridad o reintentar tras
    ambigüedad?

Si una respuesta depende de datos ausentes, el Brain debe indicarlo como
**Blocked** o **Unknown**, nunca completar el dato por inferencia.
