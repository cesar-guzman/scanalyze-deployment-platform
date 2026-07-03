# M3-CICD Post-Apply Reconciliation Report

**Status: POST-APPLY GOVERNANCE REVIEW**
**Date: 2026-07-03T23:14Z**
**Author: Antigravity agent**
**Reviewed by: PM (pending)**

---

## P0-1: Evidencia Completa del Cambio AWS

### 1. Cuenta y Sesión (masked)

| Campo | Valor |
|-------|-------|
| Account | `9054****3887` |
| Region | `us-east-1` |
| Role | `AWSReservedSSO_ScanalyzeSandboxDeploy_672521c451425b62` |
| Session | `cesar.guzman@***` |
| Tipo de credencial | STS session token (temporal) |

### 2. Commit Aplicado

```
cb2ff88 feat(cicd): apply Phase 2+3 — ECR + SSM + S3/KMS deployed to sandbox
```

### 3. Root Aplicado

```
roots/cicd
```

### 4. Backend y State

| Campo | Valor |
|-------|-------|
| Backend | **local** (no remote) |
| State file | `roots/cicd/terraform.tfstate` |
| State size | 67,294 bytes |
| Gitignored | ✅ `.gitignore:17:*.tfstate` |
| Committed | ❌ No — protegido por gitignore |

> [!WARNING]
> El state es local. Si se pierde el archivo, Terraform no puede reconciliar los recursos. Migrar a S3 backend es un paso pendiente antes de producción.

### 5. Plan Summary (antes del apply final exitoso)

El plan real ejecutado fue el segundo intento (después de corregir ECR names y deshabilitar CodeCommit):

```
Plan: 2 to add, 0 to change, 0 to destroy.
```

Ese plan era sólo `codepipeline_policy + codepipeline_attachment`, pero falló por `MalformedPolicyDocument` (Resources vacíos cuando CodeBuild es condicional).

Historial completo de applies:

| Intento | Plan | Resultado | Recursos creados | Errores |
|---------|------|-----------|------------------|---------|
| 1 (pre-fix) | 69 to add | PARCIAL (exit 1) | 25 creados | ECR name inválido (7), CodeCommit access denied (7) |
| 2 (post-fix, ECR-only) | 19 to add | SUCCESS | 19 nuevos | IAM role already exists (2) |
| 3 (convergence) | 2 to add | FAILED | 0 | MalformedPolicyDocument |
| 4 (final) | 0 | NO CHANGES | 0 | — |

### 6. Apply Output Sanitizado

#### Intento 1 (parcial — errores)
- **Creó**: 25 recursos (CW logs 7, IAM roles 2, KMS 2, SSM 14)
- **Falló**: ECR repos (nombre con `_`), CodeCommit (access denied)
- **Acción correctiva**: Se corrigió `sanitized_deployment_id`, se agregó `enable_codecommit = false`

#### Intento 2 (post-fix)
- **Creó**: 19 recursos (ECR 7, ECR lifecycle 7, S3 bucket + config 5)
- **Falló**: IAM roles already exist (creados en intento 1, removidos del state)
- **Acción correctiva**: `terraform import` de 2 IAM roles

#### Estado final
- **terraform plan**: `No changes. Your infrastructure matches the configuration.`

### 7. terraform state list Actual

```
41 entries (2 data sources + 39 managed resources)

Data sources:
  module.cicd.data.aws_caller_identity.current
  module.cicd.data.aws_partition.current

Managed resources (39):
  ECR repos:            7  (scanalyze/{service})
  ECR lifecycle:        7
  IAM role:             2  (codepipeline-role, codebuild-role)
  IAM policy:           1  (codebuild-policy)
  IAM attachment:       1  (codebuild)
  KMS key:              1
  KMS alias:            1
  S3 bucket:            1
  S3 config:            4  (versioning, encryption, lifecycle, PAB)
  SSM digest params:    7
  SSM tag params:       7
```

### 8. terraform plan Actual

```
No changes. Your infrastructure matches the configuration.
Terraform has compared your real infrastructure against your configuration
and found no differences, so no changes are needed.
```

### 9. Inventario de Recursos (ARNs masked)

#### ECR Repositories (7)

| Repo | Mutability | ScanOnPush | Images |
|------|-----------|------------|--------|
| dep-01kwm****/scanalyze/ingest-api | IMMUTABLE | ✅ | 0 |
| dep-01kwm****/scanalyze/ocr-worker | IMMUTABLE | ✅ | 0 |
| dep-01kwm****/scanalyze/postprocess-worker | IMMUTABLE | ✅ | 0 |
| dep-01kwm****/scanalyze/classifier-worker | IMMUTABLE | ✅ | 0 |
| dep-01kwm****/scanalyze/bank-worker | IMMUTABLE | ✅ | 0 |
| dep-01kwm****/scanalyze/personal-worker | IMMUTABLE | ✅ | 0 |
| dep-01kwm****/scanalyze/gov-worker | IMMUTABLE | ✅ | 0 |

#### S3 Artifact Bucket

| Campo | Valor |
|-------|-------|
| Name | `dep-01kwm****-cicd-artifacts` |
| Versioning | Enabled |
| PublicAccessBlock | All blocked (4/4) |
| Encryption | KMS (customer managed) |
| Objects | **0** |

#### KMS Key

| Campo | Valor |
|-------|-------|
| Alias | `alias/dep_01KWM****-cicd-artifacts` |
| KeyId | `a5bf8129****` |
| KeyState | Enabled |
| KeyManager | CUSTOMER |

#### IAM Roles

| Role | Created | In State |
|------|---------|----------|
| `dep_01KWM****-codepipeline-role` | 2026-07-03T22:49:11Z | ✅ |
| `dep_01KWM****-codebuild-role` | 2026-07-03T22:49:11Z | ✅ |

#### IAM Policies

| Policy | In State | Attached To |
|--------|----------|-------------|
| `dep_01KWM****-codebuild-policy` | ✅ | codebuild-role |
| `dep_01KWM****-codepipeline-policy` | ❌ **NOT CREATED** | — |

> [!IMPORTANT]
> `codepipeline-policy` no existe en AWS. La resource es `count = 0` porque `enable_codecommit = false`. Esto es correcto y esperado — no hay pipelines, no se necesita la policy.

#### SSM Parameters (14)

Todos en valor `"UNSET"` — placeholder hasta que un build real escriba digests:

| Parameter | Value |
|-----------|-------|
| `/.../images/ingest-api/image_digest` | UNSET |
| `/.../images/ingest-api/image_tag` | UNSET |
| `/.../images/ocr-worker/image_digest` | UNSET |
| `/.../images/ocr-worker/image_tag` | UNSET |
| `/.../images/postprocess-worker/image_digest` | UNSET |
| `/.../images/postprocess-worker/image_tag` | UNSET |
| `/.../images/classifier-worker/image_digest` | UNSET |
| `/.../images/classifier-worker/image_tag` | UNSET |
| `/.../images/bank-worker/image_digest` | UNSET |
| `/.../images/bank-worker/image_tag` | UNSET |
| `/.../images/personal-worker/image_digest` | UNSET |
| `/.../images/personal-worker/image_tag` | UNSET |
| `/.../images/gov-worker/image_digest` | UNSET |
| `/.../images/gov-worker/image_tag` | UNSET |

### 10. Confirmación: No ECS Deploy / CodeDeployToECS

| Check | Resultado |
|-------|-----------|
| CodePipeline pipelines en AWS | **0** (ninguno creado) |
| CodeDeploy applications | **0** |
| ECS task definitions mutadas hoy por cicd | **No** — todas en `:1` (revision original de platform) |
| Deploy stage en código Terraform | **No existe** — `enable_codecommit = false` impide creación de pipelines |
| `ecs:*` en IAM policies | **No** — verificado por `lint_cicd_safety.py` |
| `iam:PassRole "*"` | **No** — verificado por linter |

### 11. No raw state/plan/credentials committed

| Check | Resultado |
|-------|-----------|
| `*.tfstate` en commits | ❌ No — gitignored |
| `*.tfplan` en commits | ❌ No |
| `.env` en commits | ❌ No — gitignored |
| `credentials` en commits | ❌ No — gitignored |
| `git diff --name-only HEAD~5` con patrones sensibles | **Ningún match** |

### 12. Reconciliación de AWS Writes

> [!CAUTION]
> El tracker anterior decía "0 AWS writes except Cognito delete". Esto era **incorrecto** después de Phase 3.

**Estado honesto de AWS writes ejecutados:**

| Timestamp (UTC) | Operación | Scope | Detalle |
|-----------------|-----------|-------|---------|
| 2026-07-03T19:53:04Z | Cognito AdminDeleteUser | 1 user | `sandbox-test@scanalyze.cloud` eliminado |
| 2026-07-03T22:49:08Z | Terraform apply #1 (parcial) | 25 resources | CW logs, IAM roles, KMS, SSM |
| 2026-07-03T22:53:02Z | Terraform destroy (parcial, falló) | 0 destroyed | Permission denied en CW logs y IAM |
| 2026-07-03T22:53:32Z | Terraform state rm | 9 entries | 7 CW logs + 2 IAM roles removidos de state |
| 2026-07-03T22:54:35Z | Terraform apply #2 | 19 resources | ECR, S3, lifecycle, IAM policy |
| 2026-07-03T22:56:47Z | Terraform import | 2 resources | IAM roles re-importados |
| 2026-07-03T23:00:11Z | Terraform apply #3 (falló) | 0 resources | MalformedPolicyDocument |

---

## P0-2: CloudWatch Log Groups Huérfanos

### Inventario Exacto

| # | Log Group Name | StoredBytes | Retention | In State |
|---|---------------|-------------|-----------|----------|
| 1 | `/aws/codebuild/dep_01KWM783E0S1FZVAM8FRDV1HR2-bank-worker` | 0 | 14 days | ❌ |
| 2 | `/aws/codebuild/dep_01KWM783E0S1FZVAM8FRDV1HR2-classifier-worker` | 0 | 14 days | ❌ |
| 3 | `/aws/codebuild/dep_01KWM783E0S1FZVAM8FRDV1HR2-gov-worker` | 0 | 14 days | ❌ |
| 4 | `/aws/codebuild/dep_01KWM783E0S1FZVAM8FRDV1HR2-ingest-api` | 0 | 14 days | ❌ |
| 5 | `/aws/codebuild/dep_01KWM783E0S1FZVAM8FRDV1HR2-ocr-worker` | 0 | 14 days | ❌ |
| 6 | `/aws/codebuild/dep_01KWM783E0S1FZVAM8FRDV1HR2-personal-worker` | 0 | 14 days | ❌ |
| 7 | `/aws/codebuild/dep_01KWM783E0S1FZVAM8FRDV1HR2-postprocess-worker` | 0 | 14 days | ❌ |

**Características:**
- **0 bytes** de logs almacenados (nunca se escribió nada)
- **14 días** de retention (se aplicó la config de Terraform antes de `state rm`)
- **No gestionados** — removidos del state con `terraform state rm`

### Análisis de Propiedad

Estos log groups **deberían pertenecer al módulo cicd** cuando `enable_codecommit = true`. El recurso `aws_cloudwatch_log_group.codebuild` existe en el módulo pero está condicionado a `enable_codecommit`. Cuando se habiliten los pipelines completos, estos log groups se volverán necesarios.

### Opciones

Se detallan en el runbook separado: `reports/m3-cicd-orphan-loggroups-runbook.md`

---

## P0-3: State Hygiene

### Estado Actual

| Métrica | Valor | Aceptable |
|---------|-------|-----------|
| Managed resources | 39 | ✅ |
| Data sources | 2 | ✅ |
| Unmanaged resources (orphans) | 7 CW log groups + codepipeline-policy absence | ⚠️ Bloqueador |
| terraform plan | No changes | ✅ |
| State backend | local | ⚠️ Riesgo (no backup remoto) |

### Discrepancia: State vs AWS

| Recurso AWS | En State | En Config | Notas |
|-------------|----------|-----------|-------|
| 7 ECR repos | ✅ | ✅ | Converged |
| 7 ECR lifecycle | ✅ | ✅ | Converged |
| S3 bucket + 4 configs | ✅ | ✅ | Converged |
| KMS key + alias | ✅ | ✅ | Converged |
| 14 SSM params | ✅ | ✅ | Converged |
| codebuild-role | ✅ | ✅ | Importado |
| codepipeline-role | ✅ | ✅ | Importado |
| codebuild-policy | ✅ | ✅ | Creado apply #2 |
| codebuild-attachment | ✅ | ✅ | Creado apply #1 |
| codepipeline-policy | ❌ No existe en AWS | ❌ count=0 | **Correcto** — no pipelines |
| codepipeline-attachment | ❌ No existe en AWS | ❌ count=0 | **Correcto** — no pipelines |
| **7 CW log groups** | **❌ No en state** | **❌ count=0** | **ORPHAN — bloqueador** |

---

## P0-5: Reconciliación de Terminología

### Antes (incorrecto)
> "0 AWS writes except Cognito delete"

### Después (correcto)
> "AWS writes ejecutados: Cognito AdminDeleteUser + Terraform apply roots/cicd (3 intentos, 2 exitosos parcialmente, 1 fallido) + 2 terraform imports + 9 state rm operations. Resultado final: 39 recursos managed + 7 orphans."

### Descripción Precisa del Estado Actual
> "CICD foundation desplegada parcialmente: ECR repos, artifact bucket, KMS, SSM metadata y IAM roles creados. Pipelines (CodePipeline, CodeBuild, CodeCommit) **no creados** porque `enable_codecommit = false` por falta de permisos en el permission set."

---

## Resumen de Estado

```
┌─────────────────────────────────────────────────────┐
│ CICD LAYER — ESTADO POST-APPLY                      │
├─────────────────────────────────────────────────────┤
│ Managed by Terraform:  39 resources    ✅            │
│ terraform plan:        No changes      ✅            │
│ Orphan CW log groups:  7               ⚠️ BLOCKER   │
│ State backend:         local           ⚠️ RISK      │
│ CodePipelines:         0 (disabled)    ℹ️ By design  │
│ CodeBuild projects:    0 (disabled)    ℹ️ By design  │
│ CodeCommit repos:      0 (disabled)    ℹ️ By design  │
│ ECR images:            0               ℹ️ Expected   │
│ SSM values:            14x "UNSET"     ℹ️ Expected   │
│ S3 objects:            0               ℹ️ Expected   │
│ ECS mutations:         0               ✅            │
│ Credentials committed: 0               ✅            │
│ State committed:       0               ✅            │
└─────────────────────────────────────────────────────┘
```
