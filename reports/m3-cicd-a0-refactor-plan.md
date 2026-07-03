# M3-CICD-A0 — Refactor Plan

## Objetivo

Convertir CI/CD en un layer reproducible del deployment platform con ownership claro,
release manifest, ECR local, build-only pipelines, y cero mutación directa de ECS.

## Cambios Realizados (Local Only)

### Nuevos Archivos

| Archivo | Propósito |
|---------|-----------|
| `schemas/cicd-contract.v1.schema.json` | Contrato JSON Schema para outputs del layer cicd |
| `roots/cicd/main.tf` | Root skeleton que invoca modules/cicd |
| `roots/cicd/variables.tf` | Variables sin hardcoding, validaciones estrictas |
| `roots/cicd/providers.tf` | Provider + backend S3 |
| `roots/cicd/outputs.tf` | Contract-aligned outputs |
| `modules/cicd/main.tf` | Módulo completo: build-only pipelines, ECR, CodeCommit, S3/KMS, IAM, SSM |
| `modules/cicd/variables.tf` | Variables del módulo |
| `modules/cicd/outputs.tf` | Outputs del módulo para contrato |
| `modules/container-platform/ssm_contracts.tf` | SSM outputs del platform layer para consumo downstream |
| `tooling/lint_cicd_safety.py` | Linter estático que bloquea violaciones Platform v2 |
| `reports/m3-cicd-a0-refactor-plan.md` | Este archivo |
| `reports/m3-cicd-ownership-matrix.md` | Matriz de ownership |
| `reports/m3-cicd-security-findings.md` | Hallazgos de seguridad |

### Qué se migró de ci-cd-micros brownfield

| Componente | Acción |
|------------|--------|
| CodeBuild projects | ✅ Migrado a modules/cicd |
| S3 artifact bucket + KMS | ✅ Migrado a modules/cicd |
| CodePipeline Source + Build | ✅ Migrado a modules/cicd |
| ECR repo lifecycle | ✅ Migrado a modules/cicd |
| SSM metadata output | ✅ Migrado a modules/cicd |
| IAM roles/policies | ✅ Migrado + tightened (sin ecs:*, sin PassRole *) |
| ECR repositories | ✅ **Nuevo** — ahora cicd los crea (gap cerrado) |
| CodeCommit repositories | ✅ **Nuevo** — ahora cicd los crea (gap cerrado) |
| ECS Deploy stage | ❌ **Eliminado** — Terraform owns ECS |
| CodeDeployToECS stage | ❌ **Eliminado** — Terraform owns ECS |
| imagedefinitions.json deploy | ❌ **Eliminado** — no como deploy artifact |
| ecs:* IAM | ❌ **Eliminado** |
| iam:PassRole "*" | ❌ **Eliminado** |
| codedeploy IAM role | ❌ **Eliminado** |
| CloudFront invalidation in CodeBuild | ❌ **Eliminado** (frontend deploy es separado) |

### Qué NO se tocó

- No se modificó ci-cd-micros brownfield directamente
- No se hizo AWS write
- No se hizo terraform plan/apply
- No se cambió Permission Set
- No se pusheó a CodeCommit

## Orden de Despliegue Actualizado

```
 1. account-ready-gate
 2. global
 3. network
 4. platform          ← ahora publica SSM contracts
 5. data-foundation
 6. edge-identity
 7. edge
 8. cicd              ← NUEVO: build-only pipelines, ECR, CodeCommit
 9. build/promote     ← push código → pipeline ejecuta → build → ECR + digest
10. release manifest  ← SSM parameters con digests aprobados
11. services          ← Terraform consume digests, actualiza task definitions
12. addons
13. synthetic validation
```

## Próximos Pasos (Requieren Aprobación PM)

1. `terraform validate` del nuevo módulo cicd
2. `terraform plan` en sandbox
3. Integrar platform SSM contracts al platform root
4. Crear runbook de destroy/redeploy
5. Apply CI/CD layer
6. Push código a CodeCommit
7. Services layer consume digests
