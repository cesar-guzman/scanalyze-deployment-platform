# ADR-001: Tenancy Model — Account-per-Deployment

> **Status**: `ACCEPTED`  
> **Date**: 2026-06-23  
> **Revised**: 2026-06-23 (incorporates mandatory review changes)  
> **Decision makers**: César Guzmán  
> **Scope**: Scanalyze Dedicated Deployment Platform

---

## Context

Scanalyze es un producto SaaS de procesamiento inteligente de documentos (IDP). Cada cliente envía documentos financieros, personales y gubernamentales que contienen PII y datos regulados. La plataforma actual opera en una sola cuenta AWS con aislamiento lógico mediante prefijos de nombres y claims de JWT.

Este enfoque tiene limitaciones fundamentales:
- Un blast radius que afecta a todos los clientes
- Complejidad creciente en IAM policies
- Sin boundaries de red entre clientes
- Dificultad para cumplir requisitos regulatorios por cliente
- No escalable para clientes con requisitos de data residency

---

## Decision

### Modelo de Tenancy: Account-per-Deployment

Cada deployment de Scanalyze (una instancia operativa para un cliente en un ambiente y región) vive en una cuenta AWS dedicada.

```
customer_id: acme-corp
  └── deployments:
        ├── acme-corp-prod-us-east-1      (cuenta AWS dedicada)
        ├── acme-corp-uat-us-east-1       (cuenta AWS dedicada)
        └── acme-corp-dr-us-west-2        (cuenta AWS dedicada, futuro)
```

### Jerarquía de Identidad

| Nivel | Identificador | Propósito | Fuente |
|---|---|---|---|
| **Customer** | `customer_id` | Identidad comercial, metering, facturación | JWT `custom:customerId` + deployment contract |
| **Deployment** | `deployment_id` | Frontera técnica de aislamiento | Deployment contract |
| **Account** | AWS Account ID | Boundary físico | AWS Organizations |
| **Processing Domain** | `processing_domain` | Routing de procesamiento interno | `bank`, `personal`, `gov` |

> [!IMPORTANT]
> `platform` no es un processing domain opcional. Es un componente obligatorio de cada deployment. Los processing domains son particiones de routing de documentos: `bank`, `personal`, `gov`.

---

## Lifecycle Invariants

Estas propiedades son inmutables y no admiten excepciones:

| Invariante | Regla |
|---|---|
| Single-deployment accounts | Una cuenta **nunca** aloja más de un deployment de customer |
| No account reuse | Una cuenta offboarded **nunca** se reutiliza para otro customer |
| Immutable customer_id | `customer_id` no cambia una vez asignado |
| Immutable deployment_id | `deployment_id` no cambia una vez asignado |
| Account migration | `account_id` solo puede cambiar mediante una migración formal documentada |
| Environment isolation | Un deployment `prod` y uno `uat` **nunca** comparten cuenta |
| Deletion requires formal process | Ningún dato se destruye sin el workflow de offboarding contractual |

---

## JWT Verification Chain

La validación de identidad en cada request sigue una cadena estricta y ordenada. **Cada paso debe pasar antes de evaluar el siguiente.**

```
Step 1: Verify JWT signature
         └── JWKS fetched from Cognito issuer URL
         └── Algorithm must be in allowlist (RS256)
         └── Reject unsigned, none-algorithm, or HMAC tokens

Step 2: Validate issuer (iss)
         └── Must match the Cognito User Pool URL for this deployment

Step 3: Validate audience (aud) / client ID
         └── Must match the registered app client for this deployment

Step 4: Validate expiration (exp)
         └── Token must not be expired

Step 5: Validate token_use
         └── Must be "id" or "access" depending on context

Step 6: Extract custom:customerId

Step 7: Compare
         custom:customerId == SCANALYZE_DEPLOYMENT_CUSTOMER_ID
```

`SCANALYZE_DEPLOYMENT_CUSTOMER_ID` proviene del deployment contract validado y se inyecta en la task definition declarativa. **Nunca proviene del request, header o mensaje SQS.**

> [!CAUTION]
> La igualdad de una claim no convierte un token no verificado en confiable. Steps 1–5 son prerrequisitos obligatorios.

### `custom:customerId` como Claim Canónica

| Atributo | Valor |
|---|---|
| Claim Cognito | `custom:customerId` |
| Editable por usuario | **No** |
| Emitido por | Administración del pool, federación o pre-token trigger |
| Validado contra | `SCANALYZE_DEPLOYMENT_CUSTOMER_ID` |
| Usado para autorización | **Sí** — es la fuente de identidad del customer |
| Mutable en runtime | **No** — requiere cambio administrativo controlado |

---

## Legacy: `tenantId` Inventory and Deprecation

`custom:tenantId` **no determina identidad de customer** y **no es fuente de autorización**.

### Representaciones conocidas

| Representación | Ubicación | Owner actual | Schema version | Acción |
|---|---|---|---|---|
| JWT `custom:tenantId` | Cognito claims | Auth config | Legacy | **Deprecar**: no usar para autorización; mantener temporalmente para backward compat |
| Message field `tenantId` | SQS messages | Worker producers | v1 | **Migrar** a `customer_id` + `processing_domain` en schema v2 |
| DynamoDB attribute `tenantId` | batches, documents tables | data-foundation | v1 | **Migrar** con versionado; no borrar datos existentes |
| Env var `SCANALYZE_TENANT` | Task definitions | cicd/services layers | Legacy | **Reemplazar** por `SCANALYZE_DEPLOYMENT_CUSTOMER_ID` + `SCANALYZE_PROCESSING_DOMAIN` |
| S3 prefix `{tenantId}/` | Document buckets | data-foundation | v1 | **Evaluar** durante migración; puede requerir copy + redirect |

### Migration schema

```
message/record schema v1:  tenantId              → legacy, routing only
message/record schema v2:  customer_id            → authoritative identity
                           processing_domain      → processing partition (bank|personal|gov)
```

### Deprecation criteria

- Métrica de consumo legacy por endpoint/consumer
- Zero legacy-only consumers durante 30 días → eligible para eliminación
- Cada representación tiene un owner y una fecha de deprecación
- No hay eliminación masiva sin evidencia de zero-usage

---

## Data Plane Isolation Invariants

Estas propiedades aplican a recursos del **customer data plane**:

> Customer document data, application state, runtime queues, encryption keys,
> authentication stores and workload networks are **never shared** across
> customer deployments.

Específicamente:

| Recurso | Compartido | Dedicado |
|---|---|---|
| S3 document buckets | ❌ | ✅ Per deployment |
| DynamoDB tables | ❌ | ✅ Per deployment |
| SQS queues | ❌ | ✅ Per deployment |
| KMS application keys | ❌ | ✅ Per deployment |
| Cognito User Pool | ❌ | ✅ Per deployment |
| VPC / subnets | ❌ | ✅ Per deployment |
| ECS cluster | ❌ | ✅ Per deployment |

Recursos del **control plane** que **sí** pueden centralizarse:

| Recurso | Justificación |
|---|---|
| ECR central (artifact factory) | Build once, promote digest |
| Signed release manifests | Immutable, no customer data |
| Deployment registry | Metadata operacional, sin PII |
| Allowlisted operational metrics | Sanitized, schema-controlled |
| Build pipeline artifacts | Pre-customer, generic |

---

## Deployment Trust Policy (Provider-Managed)

El `ScanalyzeDeploymentRole` en cada customer account NO confía en toda la Organization genéricamente.

### Trust conditions (todas requeridas simultáneamente)

| Condition | Propósito |
|---|---|
| **Principal ARN exacto** del orchestrator role en Shared Services | Identidad precisa |
| `aws:PrincipalOrgID` | Defensa en profundidad: confirma membership |
| `sts:SourceIdentity` requerido | Trazabilidad del actor |
| Session tags requeridas | `deployment_id`, `release_version`, `change_id` |
| Permissions boundary | Limita el máximo alcanzable |

```json
{
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::SHARED_SERVICES_ACCOUNT:role/ScanalyzeDeploymentOrchestrator"
  },
  "Action": "sts:AssumeRole",
  "Condition": {
    "StringEquals": {
      "aws:PrincipalOrgID": "o-rpnh6nbjnt",
      "sts:SourceIdentity": "scanalyze-orchestrator"
    },
    "StringLike": {
      "aws:RequestTag/deployment_id": "*",
      "aws:RequestTag/release_version": "*",
      "aws:RequestTag/change_id": "*"
    }
  }
}
```

> [!IMPORTANT]
> `aws:PrincipalOrgID` es una defensa adicional, **no el principal completo**. El principal debe ser el ARN exacto del orchestrator.

### Customer-Managed Trust (deferred)

Para cuentas fuera de la Organization (customer-managed), se requiere:
- Principal exacto de la cuenta Shared Services
- `sts:ExternalId` único por deployment
- Session duration limitada
- Permissions boundary
- IAM Access Analyzer
- AssumeRole test positivo y negativo

**No implementado en la primera versión.**

---

## Modalidades Comerciales

### Provider-Managed (default, primera implementación)

| Propiedad | Valor |
|---|---|
| Cuenta AWS | En la Organization de TDSynnex/BCM Corp |
| OU | Scanalyze Workloads / NonProd |
| Trust | Principal exacto + OrgID + session conditions |
| State backend | En la customer account |
| Lifecycle | Managed by Scanalyze |

### Customer-Managed (schema-compatible, implementation deferred)

| Propiedad | Valor |
|---|---|
| Cuenta AWS | Propiedad del cliente |
| Trust | Principal exacto + `sts:ExternalId` + session duration |
| State backend | Decisión contractual |
| Lifecycle | Contractual |
| **Primera versión** | **Rechazado explícitamente**: `FEATURE_NOT_IMPLEMENTED` |

---

## Customer Registry

Vive en Shared Services account (o Operations account). **No en la management account.**

### Campos Mínimos

| Campo | Tipo | Descripción |
|---|---|---|
| `customer_id` | string | Identidad comercial estable (immutable) |
| `deployment_id` | string | Identidad técnica de deployment (immutable) |
| `account_id` | string | AWS account ID |
| `account_ownership` | enum | `scanalyze-managed` \| `customer-managed` |
| `ou_id` | string | OU assignment |
| `primary_region` | string | Región principal |
| `environment` | enum | `prod` \| `uat` \| `staging` \| `demo` |
| `release_version` | string | Release activo |
| `desired_release_version` | string | Release target |
| `deployment_status` | enum | Ver state machine |
| `security_baseline_status` | enum | Ver security assessment |
| `record_version` | integer | Optimistic concurrency |
| `etag` | string | Conditional update token |
| `created_at` | timestamp | Fecha de creación (immutable) |
| `updated_at` | timestamp | Última modificación |
| `updated_by` | string | Identity que realizó la última actualización |

### Evidence References

| Campo | Tipo | Descripción |
|---|---|---|
| `request_digest` | string | SHA-256 del deployment request |
| `release_manifest_digest` | string | SHA-256 del release manifest activo |
| `last_plan_digest` | string | SHA-256 del saved plan |
| `last_plan_artifact_uri` | string | S3 URI del plan artifact |
| `last_apply_execution_id` | string | ID de la ejecución de apply |
| `last_runtime_validation_id` | string | ID de la validación runtime |
| `security_assessment_id` | string | ID del último security assessment |

### Status State Machine

Transiciones válidas (todo lo demás está prohibido):

```
REQUESTED → PROVISIONING
PROVISIONING → READY | PROVISIONING_FAILED
PROVISIONING_FAILED → PROVISIONING (retry)
READY → DEPLOYING
DEPLOYING → ACTIVE | DEPLOYMENT_FAILED
DEPLOYMENT_FAILED → DEPLOYING (retry) | SUSPENDING
ACTIVE → UPGRADING | SUSPENDING | OFFBOARDING
UPGRADING → ACTIVE | ROLLBACK_REQUIRED
ROLLBACK_REQUIRED → UPGRADING (rollback) | SUSPENDING
SUSPENDING → SUSPENDED
SUSPENDED → DEPLOYING (reactivation) | OFFBOARDING
OFFBOARDING → ARCHIVED
```

Las actualizaciones de estado usan **conditional writes** (DynamoDB `ConditionExpression` o equivalente). Un proceso no puede saltar de `ACTIVE` a `ARCHIVED` directamente.

El historial de transiciones es **append-only**: cada cambio de estado genera un registro de auditoría con timestamp, actor, evidencia y estado anterior/nuevo.

### Qué NO contiene el registry

- Documentos o resultados de OCR
- Datos extraídos de documentos
- Credenciales o secrets
- JWT tokens
- PII de empleados o usuarios finales
- State files o fragmentos de state

---

## Consequences

### Positivas
- Aislamiento total por boundary nativo de AWS
- Blast radius limitado a un deployment
- Cumplimiento regulatorio simplificado
- Offboarding limpio (desactivar cuenta)
- Auditoría clara por CloudTrail de Organization

### Negativas
- Complejidad operacional: más cuentas que administrar
- Costo de NAT/endpoints por cuenta
- Cross-account orchestration necesario
- Management account access requerido para account vending

### Riesgos
- Si la management account no es accesible, el account vending no funciona
- ECR local requiere promotion pipeline confiable
- Customer-managed accounts requieren trust modelo diferente

---

## Alternatives Considered

| Alternativa | Razón de rechazo |
|---|---|
| Single-account multi-tenant | Blast radius total, IAM complexity O(n²), PII co-mingled |
| VPC-per-customer same account | Límites de VPC, shared IAM, shared KMS |
| Namespace-per-customer (prefixes) | Estado actual — insuficiente para enterprise |
| Account-per-customer (not deployment) | No permite UAT + Prod + DR separados |

---

## References

- AWS Well-Architected SaaS Lens: Tenant Isolation
- AWS Multi-Account Strategy Whitepaper
- P0-001: Customer identity via `custom:customerId`
- P1-002: Task definitions completas y declarativas
- Scanalyze Platform Plan v3
