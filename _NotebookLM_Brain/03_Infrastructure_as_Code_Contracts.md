# Infraestructura como código y contratos

> **Fuentes:** [roots](../roots), [modules](../modules),
> [ownership matrix](../ADR/ARCHITECTURE_OWNERSHIP_MATRIX.md) y
> [playbook enterprise](../playbooks/enterprise-client-deployment.md)

## Modelo de IaC

Scanalyze divide el deployment en roots Terraform pequeños. Cada root instancia
modules y conserva ownership declarativo de su capa. Esta separación reduce el
blast radius, permite planes revisables y evita que un único state controle toda
la plataforma.

Los README antiguos de roots o modules pueden describir un scaffold histórico.
La existencia de código y tests actuales tiene prioridad sobre esa etiqueta,
pero tampoco demuestra por sí sola una ejecución live.

## Orden operativo

El orden vigente para operadores está en el playbook canónico. De forma
resumida:

1. Validar account baseline y account-ready gate.
2. global.
3. network.
4. platform.
5. data-foundation.
6. edge-identity.
7. edge.
8. cicd, para ECR y metadata de imágenes.
9. construir y publicar las siete imágenes.
10. services, consumiendo digests revisados.
11. addons, después de estabilidad.

No aplicar services antes de que existan referencias de imagen inmutables.
Frontend e identity tienen blockers adicionales documentados en el playbook;
su posición en el DAG no autoriza onboarding.

## Roots y responsabilidad

| Root | Responsabilidad principal |
|---|---|
| account-ready-gate | Validar precondiciones del baseline; no sustituye account vending. |
| global | Recursos IAM de workloads definidos por la plataforma. |
| network | VPC, subnets, rutas y endpoints. |
| platform | ECS cluster, ALB y componentes base de cómputo. |
| data-foundation | S3, DynamoDB, SQS, KMS y datos fundacionales. |
| edge-identity | Cognito y superficie de identidad/API correspondiente. |
| edge | CloudFront, WAF, DNS/ACM y distribución. |
| cicd | ECR, metadata SSM y compatibilidad CI/CD legada. |
| services | Task definitions, ECS services y runtime config. |
| addons | Observabilidad y capacidades opcionales posteriores. |

La tabla es una guía. La
[Architecture Ownership Matrix](../ADR/ARCHITECTURE_OWNERSHIP_MATRIX.md) es la
fuente para resolver ownership detallado; su estado es Draft y debe
contrastarse con el código.

## Contratos entre capas

La arquitectura evita que una capa lea directamente el state de otra. Los
outputs necesarios se publican mediante contratos explícitos, normalmente en
SSM. Un consumidor debe comprobar:

- versión y schema;
- deployment y account esperados;
- región y layer;
- identidad del productor;
- digest o integridad cuando aplique;
- precondiciones antes de mutar recursos.

Un contrato ausente, ambiguo, de otro deployment o con digest inconsistente
debe detener la operación. Un warning no es suficiente para un requisito de
seguridad.

ADR-003 y ADR-006 continúan como Draft. Por ello, no debe afirmarse que todos los
roots y todos los ambientes live cumplen íntegramente el modelo sin evidencia
por root y deployment.

## Contrato de imágenes

Hay tres responsabilidades distintas:

1. **ECR** conserva la imagen inmutable.
2. **SSM de CI/CD** conserva metadata de tag y digest.
3. **services Terraform** decide qué digest usa ECS.

Escribir metadata en SSM no actualiza ECS. Un release requiere que services
consuma una referencia repository@sha256 revisada y que el plan Terraform sea
aprobado.

## Inputs de deployment

- Los valores reales de un deployment no pertenecen a Git.
- Los archivos locales usan convenciones ignoradas, como local.tfvars.
- Sólo se versionan templates o examples sintéticos y redacted.
- Nunca incluir passwords, tokens, documentos, account IDs reales, ARNs reales
  o configuración generada.
- Un tfvars existente y trackeado no se debe borrar silenciosamente; requiere
  inventario, revisión de historia y remediación separada.

## Flujo Terraform seguro

Cada mutación debe seguir esta secuencia:

1. Identidad AWS y región proporcionadas explícitamente.
2. Verificación fail-closed de caller account.
3. Backend y state key específicos de layer/deployment.
4. Init y validate.
5. Plan guardado fuera de Git.
6. Revisión humana del plan, incluyendo deletes y replacements.
7. Apply del plan exacto con aprobación.
8. Validación read-only y nuevo plan sin drift.

Ninguna gate local autoriza apply. Terraform init con backend deshabilitado y
terraform validate son validaciones locales, no evidencia live.

## Patrones prohibidos

- terraform_remote_state entre capas.
- Manipulación manual de state como rollback.
- tfstate, tfplan, generated config o tfvars reales en Git.
- Recursos duplicados en dos roots.
- Seleccionar el “primer” recurso encontrado en una cuenta.
- Defaults de account, región, cliente o ARN.
- apply o destroy sin plan y aprobación.
- ClickOps que contradiga Terraform.
- Marcar un contract check informativo como precondición bloqueante.

## Rollback

Rollback significa restaurar inputs o digests previamente aprobados mediante un
nuevo plan revisado. No significa editar, copiar o restaurar state para revertir
una release. La destrucción o decommissioning usa un runbook separado.

## Estado de evidencia

| Capacidad | Estado |
|---|---|
| Roots/modules y ownership por capas | **Implemented** en el repositorio |
| Gates locales de interfaces y ownership | **Locally validated** |
| Validación provider de roots seleccionados | Evidencia local fechada; revisar antes de reutilizar |
| Nuevo flujo monorepo en una cuenta non-production | No **Live validated** |
| Cambios live de flags legacy | **Blocked** hasta plan revisado |
| Contratos perfectos en todos los deployments existentes | No demostrado |
