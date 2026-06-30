# Rev3 Correction Cycle — Cerrar bloqueadores P0 para ACCEPTED

## Estado de entrada

Las 12 correcciones conceptuales de rev2 fueron incorporadas, pero el veredicto final identificó que **varias no son ejecutables ni consistentes**. Este plan cierra esos defectos con cambios focalizados.

> [!CAUTION]
> **No se requiere rediseño.** La dirección arquitectónica está validada. Lo pendiente es cerrar correctamente IAM, bootstrap, state evidence, contract enforcement, migration semantics y multi-region ownership.

---

## Mapa de bloqueadores → entregas

| ID | Bloqueador | Impacto si no se corrige | ADR afectado |
|---|---|---|---|
| **P0-1** | Trust policies con JSON inválido, tags sin binding, SourceIdentity estática | Acceso cross-account más amplio del previsto | ADR-004 |
| **P0-2** | Ciclo bootstrap imposible (global crea roles que necesita para ejecutarse) | Imposibilidad de bootstrap en cuenta nueva | ADR-004 + Matrix |
| **P0-3** | `check` blocks no bloquean (solo warning) | Contratos fail-open | ADR-006 |
| **P0-4** | Bucket policies con principals incorrectos, `s3:CopyObject` inválido, Plan role demasiado amplio | Políticas S3 inválidas o permisivas | ADR-003 |
| **P0-5** | Saved plans con secrets en Object Lock 90 días | Datos sensibles imposibles de eliminar | ADR-003 |
| **P0-6** | Migración acepta perder writes, DDB ImportTable incompatible con TF | Pérdida de documentos financieros | ADR-010 |
| **P0-7** | ECS circuit breaker crea drift TF sin reconciliación | Divergencia Terraform ↔ ECS runtime | ADR-010 |

---

## Entrega 1 — ADR-004 rev3: Identity & Bootstrap

Cierra **P0-1** y **P0-2**.

### Cambios específicos

#### 1.1 Trust policies — JSON válido
- **Eliminar `StringEquals` duplicado.** Fusionar todas las condiciones `StringEquals` en un solo objeto JSON.
- **Eliminar `sts:TransitiveTagKeys`** — los customer roles son terminales (no hacen role chaining adicional).
- **Agregar `aws:TagKeys` restriction** con `ForAllValues:StringEquals` para evitar tags inesperados.

#### 1.2 SourceIdentity dinámica
- Cambiar de `scanalyze-orchestrator` (estática) a `exec_{pipeline_execution_id}` o `chg_{change_ulid}`.
- Documentar que SourceIdentity es inmutable durante role chaining y no puede reemplazarse.
- Trust policy: `StringLike: {"sts:SourceIdentity": ["exec_*", "chg_*"]}`.

#### 1.3 Tags vinculados al deployment destino
- El customer role tiene un resource tag `deployment_id`.
- Trust condition: `StringEquals: {"aws:RequestTag/deployment_id": "${aws:ResourceTag/deployment_id}"}`.
- Esto garantiza que el orchestrator solo puede asumir el role con el deployment_id correcto.

#### 1.4 Session names compactos
- Formato: `{op}-{hash8}-{ulid8}` (max ~24 chars, bien dentro de 64).
- Valor completo en session tags y deployment registry.

#### 1.5 Diagnostic exige operation=diagnostic
- Agregar `StringEquals: {"aws:RequestTag/operation": "diagnostic"}` a trust policy Diagnostic.

#### 1.6 Bootstrap — account baseline vs golden workload
- **Mover los 6 control-plane roles a account baseline** (provisioned por AccountVendingProvider).
- Account baseline crea: Plan, Apply, Promotion, Validation, Diagnostic, StateRecovery, trust policies, permissions boundaries, state/evidence/contracts buckets, infra KMS keys.
- **Layer global ahora gestiona solo**: ECS task execution role, ECS task role, application-level IAM policies, application permissions boundaries.
- Documentar secuencia: `AccountVending → ACCOUNT_READY → Orchestrator → global layer → workload layers`.

#### 1.7 Policies exactas por role/layer
- Tabla de permisos IAM por role × layer (no genéricas).
- Plan role: lectura de infraestructura + state read + lock write/delete.
- Apply role: escritura de infraestructura + state read/write + lock write/delete + SSM contract write.
- Promotion role: ECR push + S3 frontend write + CloudFront invalidation.
- Etc.

---

## Entrega 2 — ADR-003 rev3: State, Evidence & Bucket Policies

Cierra **P0-4** y **P0-5**.

### Cambios específicos

#### 2.1 Principals correctos en bucket policies
- Reemplazar `ScanalyzeBreakGlass` (shared services) por `ScanalyzeCustomer-Diagnostic` y `ScanalyzeCustomer-StateRecovery` (customer account).
- Después de AssumeRole, las llamadas S3 las hace la sesión del role destino, no el role origen.

#### 2.2 Eliminar `s3:CopyObject`
- No es una acción IAM válida.
- StateRecovery necesita: `s3:GetObject` + `s3:GetObjectVersion` (source) + `s3:PutObject` (destination).

#### 2.3 Lock permissions exactas por clave
- **Plan role**:
  - `{dep_id}/{layer}/terraform.tfstate` → `s3:GetObject` solamente.
  - `{dep_id}/{layer}/terraform.tfstate.tflock` → `s3:GetObject`, `s3:PutObject`, `s3:DeleteObject`.
- **Apply role**:
  - `{dep_id}/{layer}/terraform.tfstate` → `s3:GetObject`, `s3:PutObject`.
  - `{dep_id}/{layer}/terraform.tfstate.tflock` → `s3:GetObject`, `s3:PutObject`, `s3:DeleteObject`.
- Policies scoped por prefix de layer, no bucket-wide.

#### 2.4 Reemplazar DenyAllOthers por deny patterns específicos
- `Deny` non-TLS (`aws:SecureTransport: false`).
- `Deny` unencrypted puts (`s3:x-amz-server-side-encryption` != `aws:kms`).
- `Deny` wrong KMS key.
- Block Public Access a nivel de cuenta + bucket.
- No deny global que bloquee replicación, backup, lifecycle, security tooling.

#### 2.5 Plan evidence model: efímero + sanitizado

**Plan execution store** (efímero):
- Prefix: `plan-execution/`
- TTL: 24–72 horas, Object Lock: ninguno.
- Contiene: plan binary, plan JSON, SHA-256 del binario, state lineage/serial.
- Acceso: Plan role (write), Apply role (read), Diagnostic (sin acceso por defecto).
- Eliminado automáticamente por lifecycle rule.

**Evidence store inmutable** (permanente):
- Contiene SOLO: plan digest, plan summary sanitizado, resource action counts, policy evaluation, approval record, apply execution ID, state version IDs, release manifest digest, logs sanitizados.
- **NO contiene**: plan binario, state completo, raw plan JSON, secrets, variables sensibles.
- Object Lock: COMPLIANCE 90 días (summaries), 365 días (apply logs).

**Recovery store** (altamente restringido):
- Pre-apply state snapshots para disaster recovery.
- Acceso: solo StateRecovery role.
- No accesible por Diagnostic.

#### 2.6 Matriz KMS coherente

| Role | State KMS | Evidence KMS | Contracts KMS |
|---|---|---|---|
| Plan | Decrypt | — | Decrypt |
| Apply | Encrypt, Decrypt, GenerateDataKey | Encrypt, GenerateDataKey | Encrypt, Decrypt, GenerateDataKey |
| Promotion | — | — | — |
| Validation | — | Decrypt | Decrypt |
| Diagnostic | Decrypt | Decrypt | Decrypt |
| StateRecovery | Encrypt, Decrypt, GenerateDataKey | — | — |

#### 2.7 Regional state keys
- Global: `{dep_id}/global/terraform.tfstate`
- Edge: `{dep_id}/edge/terraform.tfstate`
- Regional: `{dep_id}/{region}/{layer}/terraform.tfstate`
- Aplica a evidence, contract payloads, ownership manifest.

---

## Entrega 3 — ADR-006 rev3: Contract Enforcement

Cierra **P0-3**.

### Cambios específicos

#### 3.1 Preconditions bloqueantes (no check blocks)
- Reemplazar `check` blocks por `terraform_data` con `lifecycle { precondition {} }`.
- Las preconditions generan error y detienen `terraform plan`.
- CI test: wrong account/deployment/digest → exit code 1.

#### 3.2 Content-addressed contracts
- Contract SSM parameter name incluye contract version hash prefix para detectar replay.
- O: verificar `last_modified_date` del SSM parameter contra ventana esperada.

#### 3.3 Edge/identity separado de addons
- `addons` se divide en:
  - **edge-identity** (layer 5a): Cognito, API Gateway, CloudFront, WAF, ACM, Route53.
  - **addons** (layer 5b): extensiones opcionales, features empresariales.
- Cada uno con su propio root, state key y contrato.

#### 3.4 Contract IAM enforcement por layer
- Apply role solo puede escribir SSM parameters con prefix matching su layer.
- Ejemplo: Apply ejecutando `roots/network` solo puede escribir `/scanalyze/deployments/{dep}/contracts/network/*`.

---

## Entrega 4 — ADR-007 rev3: Supply Chain

Cierra P1 supply chain.

### Cambios específicos

#### 4.1 Builder/egress model realista
- Cambiar de "no internet egress" a **"controlled egress through allowlisted proxy"** hasta que existan mirrors locales.
- Roadmap: ECR mirror para base images, CodeArtifact para Python/npm, builder image propia (`scanalyze/build-environment@sha256:...`).

#### 4.2 Manifest signing mecanismo explícito
- AWS Signer firma container images (OCI). Para JSON arbitrario (release manifest, attestation): **KMS asymmetric Sign (ECDSA_SHA_256) + DSSE/in-toto envelope**.
- Documentar: firma central = identidad de release, nunca reemplazada por firma local.

#### 4.3 Promotion graph: copy + verify
- Decisión de diseño: **copy del grafo OCI completo** (no re-sign).
- Verificación en destino contra trust roots centrales.
- Firma local adicional opcional como evidence de promotion.

#### 4.4 Referrer validation flexible
- Cambiar de "exactly 3 referrers" a: **"al menos un referrer aprobado por cada tipo obligatorio (signature, SBOM, provenance) + digest registrado en manifest + sin referrers prohibidos"**.

#### 4.5 Retention basada en releases
- Retener: active release, previous supported, last known-good, rollback release, security/legal hold.
- No `last N` genérico.
- Documentar: ECR elimina reference artifacts al borrar subject image.

---

## Entrega 5 — ADR-008 rev3: Multi-Region & DR

Cierra P1 multi-region.

### Cambios específicos

#### 5.1 Regional state model
- State keys incluyen región para layers regionales.
- Ownership manifest registra qué región produce cada contrato.
- SSM es regional nativamente; el deployment record registra `{region}/{layer}` explícitamente.

#### 5.2 Write fencing durante failover
- Primary active → recovery read-only.
- Failover: fence primary → confirmar → activar recovery → cambiar routing → validar.
- Sin fencing, DynamoDB Global Tables recibe escrituras concurrentes.

#### 5.3 Cognito token/issuer strategy
- Tokens existentes contienen issuer del pool primario.
- Opciones: aceptar temporalmente ambos issuers en authorizer, forzar re-auth, cambiar authorizer config en failover.
- Documentar impacto en auth RTO.

#### 5.4 API routing simplificado
- Decisión: **CloudFront → solo frontend estático. Regional API domain + Route53 failover → todos los métodos API** (no split read/write por hostname).

#### 5.5 Cost model fuera del ADR
- Mover estimaciones de costo a documento separado.
- ADR referencia el documento pero no contiene tablas de pricing.

---

## Entrega 6 — ADR-010 rev3: Migration & ECS Reconciliation

Cierra **P0-6** y **P0-7**.

### Cambios específicos

#### 6.1 Cero pérdida de writes aceptados
- Eliminar "60-min write loss window".
- Modelo: greenfield en validation mode (solo sintéticos) → maintenance window → brownfield rechaza writes (503 maintenance) → drain completo → data sync → integrity validation → cutover → greenfield habilita writes.
- Después del primer write aceptado: **forward-only**.

#### 6.2 DynamoDB migration utility (no ImportTable)
- ImportTable crea tabla nueva → conflicto con TF owner.
- Migration utility:
  1. Lee full export de brownfield.
  2. Convierte DynamoDB JSON.
  3. Escribe vía BatchWrite/TransactWrite en tabla existente (creada por TF).
  4. Verifica keys e integridad.
  5. Incremental exports con delta applier.
  6. Conditional writes + version attributes para idempotencia.
  7. Checkpoints para resume.
- Documentar: incremental exports no son transaccionalmente consistentes.

#### 6.3 Full async drain criteria
- No solo "SQS depth == 0" ni "no running worker tasks".
- Verificar:
  - Queues estables en cero durante ≥ visibility timeout.
  - DLQs en cero.
  - No in-flight messages.
  - No workflow records en estado no-terminal.
  - No active Textract jobs.
  - No unresolved Bedrock invocation states.
  - No postprocess work pending.
  - No stale metering events.
  - No scheduled retries pending.

#### 6.4 ECS rollback → TF reconciliation
- Cuando circuit breaker revierte ECS:
  1. Orchestrator detecta DEPLOYMENT_FAILED.
  2. Detiene el release.
  3. Confirma revision/digest activo de ECS.
  4. Selecciona release N.
  5. Genera nuevo plan con config N.
  6. Forward apply para reconciliar TF state con ECS runtime.
  7. Ejecuta validación.
  8. Marca release N+1 bloqueado.

#### 6.5 Wave-based rollout
- No un solo `terraform apply` para 7 servicios simultáneamente.
- Estrategia por waves:
  - Wave 1: ingest-api (entry point).
  - Wave 2: classifier-worker.
  - Wave 3: bank-worker + personal-worker + gov-worker.
  - Wave 4: ocr-worker + postprocess-worker.
- Implementación: roots separados por service group, o orchestration con plan parcial por grupo.
- No `terraform -target` rutinario.

---

## Entrega 7 — ADR-009 rev3 + Ownership Matrix rev2

Cierra P1 threat model y matrix.

### ADR-009 rev3 cambios

- Agregar Domain 9 faltante o renumerar (actualmente dice 9 pero tiene 8).
- T6.3 residual target: LOW (no NONE).
- JWKS es público — la amenaza es issuer/JWKS misvalidation, no leakage.
- Prompt injection: controles específicos (input length limits, output schema validation, Bedrock guardrails config).
- Private subnets + NAT = egress exists; no presentar como "sin internet".
- Agregar threats faltantes:
  - T9.1: Economic DoS por Textract/Bedrock.
  - T9.2: Deployment registry tampering.
  - T9.3: SSM contract tampering/replay.
  - T9.4: Saved-plan substitution.
- T6.2: reconciliar "no terraform show en CI" con ADR-006 que usa plan JSON.
- T4.3: reconciliar "state no en artifacts" con evidence snapshots.

### Ownership Matrix rev2 cambios

1. 6 control-plane roles → account baseline (no global).
2. SSM contract params owned por producer layer.
3. edge-identity separado de addons.
4. "per-tenant" → processing_domain.
5. Diagnostic/StateRecovery como principals en bucket policies.
6. Plan artifact writer explícito.
7. Apply reads upstream contracts (documented).
8. Regional states incluyen región.
9. Frontend release owner explícito.
10. Account baseline state/owner identificado.

---

## Orden de ejecución

```
Entrega 1: ADR-004 rev3 (fundacional — identidad, bootstrap)
    ↓
Entrega 2: ADR-003 rev3 (depende de roles correctos de E1)
    ↓
Entrega 3: ADR-006 rev3 (depende de roles y buckets de E1+E2)
    ↓
Entrega 4: ADR-007 rev3 (independiente, pero referencia roles de E1)
    ↓
Entrega 5: ADR-008 rev3 (depende de state keys regionales de E2)
    ↓
Entrega 6: ADR-010 rev3 (depende de wave strategy y reconciliation)
    ↓
Entrega 7: ADR-009 rev3 + Ownership Matrix rev2 (reconciliación final)
```

---

## Constraints

- No AWS writes.
- No Terraform apply/import/state mutation.
- No account creation, role creation.
- No pipeline deployment ni golden-stack implementation.
- Todos los cambios son documentación y diseño.

## Trabajo paralelo autorizado

- Track A freeze y evidencia read-only.
- Retiro del IAM user humano (IAM Identity Center).
- Request formal al Organization Team.
- Repository proposal documental.
- JSON Schemas y golden fixtures sin infraestructura activa.
