# Scanalyze Deployment Platform — visión general

> **Fuente principal:** [README del monorepo](../README.md)
>
> **Decisiones relacionadas:** [ADR-001](../ADR/ADR-001-tenancy-model.md) y [ADR-011](../ADR/ADR-011-monorepo-microservices-source.md)

## Qué es Scanalyze

Scanalyze es una plataforma enterprise de Intelligent Document Processing. Su
arquitectura procesa documentos y datos sensibles mediante servicios
event-driven en AWS. El diseño debe conservar la confidencialidad, integridad,
trazabilidad y separación física entre deployments.

El repositorio reúne:

- infraestructura y contratos declarativos;
- políticas y gates de seguridad;
- tooling de validación;
- playbooks de operación;
- el código de los siete microservicios.

## Modelo de aislamiento

La decisión aceptada es **account-per-deployment**. Cada deployment de cliente
vive en una cuenta AWS dedicada. Datos, cómputo, identidad, storage, cifrado y
observabilidad no deben compartirse entre clientes.

Las diferencias de deployment se expresan mediante contratos, inputs Terraform
revisados, parámetros SSM y configuración declarativa. No se admiten forks de
código por cliente ni identificadores de cliente hardcodeados.

### Identificadores conceptuales

| Concepto | Función |
|---|---|
| customer identity | Identidad comercial; requiere un contrato canónico antes de onboarding. |
| deployment identity | Identifica técnicamente un ambiente desplegado. |
| AWS account | Límite físico del deployment. |
| region | Región explícita donde opera una capa regional. |
| processing domain | Ruta funcional declarada, por ejemplo bank, personal o gov. |

Estos conceptos no son intercambiables. En especial, no se debe derivar la
identidad comercial de un payload no confiable ni asumir que deployment y
customer usan el mismo valor.

## Monorepo

La fuente canónica está en este repositorio:

| Servicio | Ruta |
|---|---|
| ingest-api | backend/workers/scanalyze-ingest-api |
| ocr-worker | backend/workers/scanalyze-ocr-worker |
| postprocess-worker | backend/workers/scanalyze-postprocess-worker |
| classifier-worker | backend/workers/scanalyze-classifier-worker |
| bank-worker | backend/workers/scanalyze-bank-worker |
| personal-worker | backend/workers/scanalyze-personal-worker |
| gov-worker | backend/workers/scanalyze-gov-worker |

GitHub es la fuente primaria del monorepo. Un CodeCommit legado puede existir
temporalmente sólo como excepción de migración no canónica; no debe volver a
ser la fuente de verdad ni eliminarse sin un plan Terraform revisado.

## Flujo de artefactos implementado

El flujo actual no envía source code a una cuenta cliente:

1. El source se revisa en el monorepo.
2. Cada Dockerfile recibe una base image explícita.
3. La publicación enterprise usa una base image por digest en el ECR de la
   cuenta objetivo.
4. El build produce una imagen OCI para el ECR local del deployment.
5. El digest leído de ECR se registra como metadata de release en SSM.
6. Terraform sigue siendo dueño de task definitions y ECS services.
7. Una actualización de SSM no equivale a desplegar ECS.

El build central, la firma completa y la promoción verificable entre cuentas
son **Target**, no estado actual. No se debe afirmar “build once, deploy many”
como capacidad probada hasta implementar y validar esa cadena.

## Principios operativos

1. Evidence before claims.
2. Un dueño declarativo por recurso.
3. Sin forks de cliente.
4. PII y documentos permanecen dentro de la cuenta del deployment.
5. Imágenes y base images inmutables por digest.
6. Terraform state no es rollback.
7. Sin ClickOps como fuente de verdad.
8. Sin llaves AWS estáticas en CI.
9. Fail-closed ante identidad, contrato o transición inválida.
10. Sin afirmaciones de producción, HA o supply chain sin evidencia.

## Estado actual

| Área | Estado |
|---|---|
| Estructura monorepo y siete servicios | **Implemented**, **Locally validated** |
| Tests y gates locales del cambio | **Locally validated** |
| Workflow OIDC y script de publicación | **Implemented**, **Locally validated** |
| Ejecución live del nuevo flujo de imágenes | No **Live validated** |
| Fuente GitHub y retiro gradual de CI legado | **Implemented** como decisión y compatibilidad |
| Supply chain completa de ADR-007 | **Target** |
| Configuración declarativa de frontend | **Blocked** |
| Contrato de identidad y onboarding | **Blocked** |
| Producción con el nuevo flujo | **Blocked** hasta evidencia non-production |

## Qué significa “listo”

- **Listo localmente**: el código y los tests existen en un worktree.
- **Listo para PR**: el diff está acotado, seguro y reproducible.
- **Listo para merge**: required checks y revisión humana aprobaron el PR.
- **Listo para non-production**: roles, Environment, base image y plan fueron
  revisados para una cuenta explícita.
- **Listo para producción**: existe evidencia live non-production, se cerraron
  los blockers y se aprobó la promoción.

Estas etapas no deben colapsarse en una sola afirmación.

## Fuentes de detalle

- [Playbook de deployment enterprise](../playbooks/enterprise-client-deployment.md)
- [README de microservicios](../backend/workers/README.md)
- [Registro de migración](../docs/migration/monorepo-microservices-migration.md)
- [ADR-007: supply chain](../ADR/ADR-007-artifact-supply-chain.md)
- [ADR-011: monorepo](../ADR/ADR-011-monorepo-microservices-source.md)
