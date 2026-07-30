# Arquitectura y decisiones de Scanalyze

> **Fuentes canónicas:** [directorio ADR](../ADR) y
> [Architecture Ownership Matrix](../ADR/ARCHITECTURE_OWNERSHIP_MATRIX.md)

## Cómo leer un ADR

Un ADR expresa una decisión, una propuesta o un objetivo. Su estado documental
no prueba que la implementación exista ni que haya sido validada en AWS.

Para responder una pregunta arquitectónica:

1. Identificar el ADR aplicable y su estado literal.
2. Confirmar el owner en la matriz de ownership.
3. Inspeccionar código y tests del commit relevante.
4. Separar evidencia local de evidencia live.
5. Si falta uno de estos elementos, declarar el límite.

## Registro de decisiones

| ADR | Tema | Estado documental en el repositorio | Lectura correcta |
|---|---|---|---|
| ADR-001 | Tenancy model | **ACCEPTED** | Account-per-deployment es la decisión vigente. |
| ADR-002 | Organizations y Control Tower | **PROPOSED / BLOCKED** | No afirmar que account vending completo está implementado. |
| ADR-003 | State backend e isolation | **DRAFT rev3** | Es diseño en evolución; verificar roots y backend reales. |
| ADR-004 | Identidad cross-account | **DRAFT rev3** | Los roles y controles descritos son target hasta probar implementación/live. |
| ADR-005 | Deployment schemas | **ACCEPTED** | Los contratos estrictos son la decisión vigente; verificar cada schema y gate. |
| ADR-006 | Modules y contracts | **DRAFT rev3** | Canonicalización y contracts requieren evidencia por componente. |
| ADR-007 | Artifact supply chain | **DRAFT rev3** | SBOM, signing, provenance y promotion completa siguen parcialmente pendientes. |
| ADR-008 | Region, HA y DR | **DRAFT rev3** | No prometer multi-region o DR sin ejercicio live. |
| ADR-009 | Threat model | **DRAFT rev3** | Es una amenaza/base de control, no una certificación. |
| ADR-010 | Testing y rollout | **DRAFT rev3** | Las gates implementadas son las del código y Makefile actuales. |
| ADR-011 | Fuente monorepo | **Accepted** | GitHub monorepo es source canónico; ECR recibe imágenes, no source. |
| ADR-015 | Identity contract v1 | **Accepted / legacy** | Conserva semántica v1; no reinterpretar slugs como IDs v2. |
| ADR-019 | Production-readiness foundation | **Accepted** | Define gates y evidencia; no constituye aprobación productiva. |
| ADR-020 | Binding M2M versionado | **Accepted** | Customer, deployment, client y scopes se vinculan en v2; live enablement sigue bloqueado. |

## Decisiones que gobiernan el cambio de monorepo

### Una fuente común

ADR-011 establece que infraestructura, contratos, tooling y los siete servicios
se revisan en una sola línea de source. Los cambios específicos de deployment
se inyectan mediante configuración declarativa; un fork por cliente viola esta
decisión.

### Artifact boundary

El source permanece en Git. La cuenta del deployment recibe una imagen OCI en
su ECR. El flujo implementado hoy construye contra una base image por digest de
la cuenta objetivo. Un modelo central de build firmado y promoción cross-account
continúa como **Target** de ADR-007.

### Ownership declarativo

Cada recurso debe tener un único owner:

- roots instancian capas desplegables;
- modules encapsulan recursos reutilizables;
- Terraform es owner de ECR, SSM de metadata, task definitions y ECS services
  según la capa;
- el script de imágenes construye, publica y registra metadata sólo cuando se
  autoriza explícitamente;
- el script no debe hacer deployment de ECS.

### Compatibilidad de CI legado

La migración conserva defaults compatibles para evitar destrucciones
sorpresivas. Desactivar CodePipeline o CodeCommit es una transición Terraform
independiente que requiere un plan live revisado. Retener temporalmente source
legado no lo convierte en canónico.

## Invariantes arquitectónicos

1. Una cuenta dedicada por deployment.
2. Ningún dato de cliente cruza la frontera de su cuenta.
3. Ningún ID de cliente, account ID, ARN, dominio o región se hardcodea en
   código productivo.
4. No existe dependencia directa de state entre capas.
5. Los contratos son explícitos, versionados y fail-closed.
6. Las imágenes productivas son inmutables y se consumen por digest.
7. Los cambios live pasan por plan, revisión y aprobación.
8. Terraform state no es mecanismo de rollback.
9. GitHub OIDC sustituye llaves AWS estáticas para automatización.
10. Ninguna promesa de supply chain, HA o DR excede la evidencia.

## Madurez de la arquitectura

| Área | Clasificación |
|---|---|
| Account-per-deployment como decisión | **Accepted** |
| Monorepo como fuente canónica | **Implemented**, **Locally validated**, pendiente de merge |
| Gates de seguridad y portabilidad | **Implemented**, **Locally validated** |
| Build/publish customer-scoped | **Implemented**, **Locally validated**, no **Live validated** |
| Account vending automatizado | **Proposed / Blocked** según ADR-002 |
| Modelo completo de seis roles terminales | **Target** según ADR-004 Draft |
| Supply chain SLSA/signing/SBOM/provenance completa | **Target** |
| Multi-region y DR probados | **Target** |
| Frontend config e identidad para onboarding | **Blocked** |
| Binding M2M v2 en repositorio | **Implemented** sólo en el commit revisado; requiere gates locales y no es evidencia live |

## Reglas para propuestas nuevas

Una propuesta debe rechazarse o marcarse **Blocked** cuando:

- mezcle datos o recursos entre clientes;
- introduzca forks o constantes específicas de cliente;
- tenga dos owners declarativos;
- requiera ClickOps como estado permanente;
- use tags mutables como identidad de release;
- dependa de llaves AWS estáticas;
- trate state o edición manual de state como rollback;
- declare como implementado un control que sólo aparece en un ADR Draft;
- omita precondiciones de identidad, cuenta, región o transición.

## Referencias

- [ADR-001: tenancy](../ADR/ADR-001-tenancy-model.md)
- [ADR-004: cross-account identity](../ADR/ADR-004-cross-account-identity.md)
- [ADR-005: deployment schemas](../ADR/ADR-005-deployment-schemas.md)
- [ADR-007: artifact supply chain](../ADR/ADR-007-artifact-supply-chain.md)
- [ADR-009: threat model](../ADR/ADR-009-threat-model.md)
- [ADR-010: testing and rollout](../ADR/ADR-010-testing-rollout.md)
- [ADR-011: monorepo source](../ADR/ADR-011-monorepo-microservices-source.md)
- [ADR-020: versioned M2M identity binding](../ADR/ADR-020-versioned-m2m-identity-binding.md)
