# ADR-002: AWS Organization, Control Tower, OUs and AFT/Workload Boundary

> **Status**: `PROPOSED / BLOCKED`  
> **Blocked by**: Organization Team evidence required  
> **Date**: 2026-06-23  
> **Revised**: 2026-06-23 (incorporates mandatory review changes)  
> **Decision makers**: César Guzmán  
> **Scope**: Scanalyze Dedicated Deployment Platform  
> **Depends on**: ADR-001

---

## Context

El discovery B0.0A (2026-06-23) desde la member account reveló:

| Hallazgo | Detalle |
|---|---|
| Organization | `o-rpnh6nbjnt`, feature set ALL |
| Management Account | `8393****1433` (TDSynnex/BCM Corp) |
| Scanalyze Account | `5334****8743` (member account) |
| Control Tower | ✅ Evidencia de baselines (CloudTrail, Config, roles) |
| IAM Identity Center | ✅ Activo (`ssoins-7223feaee61e2475`) |
| GuardDuty | Estado organizacional desconocido; no habilitado localmente en us-east-1 |
| Security Hub | Estado organizacional desconocido; no suscrito localmente en us-east-1 |
| AWS Backup | Estado organizacional desconocido; sin vaults locales en us-east-1 |
| AFT | Estado desconocido |

> [!WARNING]
> **B0.0B — Organization Management Discovery permanece BLOCKED.** Los hallazgos desde la member account son evidencia fuerte de enrollment en Control Tower, pero no confirman: landing zone health/version, home region, OUs, controls efectivos, delegated administrators, AFT presence, Log Archive/Audit accounts.

### Restricción clave

Scanalyze **no controla la management account**. Toda acción a nivel de Organization, OUs, SCPs y account vending requiere coordinación con el equipo que administra la Organization.

### Security finding

> `SEC-PLATFORM-001`: La auditoría se ejecutó mediante un IAM user de larga duración (`cesar-codecommit`). La plataforma objetivo debe migrar operaciones a IAM Identity Center permission sets y sesiones de corta duración. No bloquea ADRs; **sí bloquea operación productiva** del customer factory.

---

## Decision

### 1. No crear una nueva Organization

La Organization ya existe. Scanalyze se integra como un conjunto de OUs y cuentas dentro de la Organization existente.

### 2. Respetar el Control Tower existente

No debe:
- Crearse otra landing zone
- Deshabilitarse el Control Tower existente
- Conflictar con los controls ya configurados

### 3. Boundary AFT / Workload

| Responsabilidad | Owner | Sistema |
|---|---|---|
| Crear cuentas AWS | Organization Team | AFT / Account Factory / Corporate Process |
| Asignar cuentas a OUs | Organization Team | Control Tower / Organizations |
| Account security baseline | Organization Team + AFT | Customizations |
| GuardDuty / Security Hub | Organization Team | Delegated admin |
| Backup policies organizacionales | Organization Team | Organization policies |
| Deployment role bootstrap | AFT customization | Account baseline |
| State backend bootstrap | AFT customization | Account baseline |
| `account_ready` contract | AFT customization | SSM parameter |
| **VPC / network** | **Scanalyze orchestrator** | **Deployment platform** |
| **ECR local repos** | **Scanalyze orchestrator** | **Deployment platform** |
| **ECS / ALB / API GW** | **Scanalyze orchestrator** | **Deployment platform** |
| **DDB / S3 / SQS / KMS** | **Scanalyze orchestrator** | **Deployment platform** |
| **Task definitions** | **Scanalyze orchestrator** | **Deployment platform** |
| **Cognito** | **Scanalyze orchestrator** | **Deployment platform** |
| **Addons** | **Scanalyze orchestrator** | **Deployment platform** |

> [!IMPORTANT]
> **AFT provisiona y customiza cuentas. El deployment orchestrator de Scanalyze despliega la aplicación.** ECR repos, workload networking y compute son responsabilidad del orchestrator, no del account baseline.

---

## 4. Account Vending Interface

AFT **no es una dependencia rígida**. La plataforma define una interfaz de account vending con adaptadores:

### Interface: `AccountVendingProvider`

```
request_account(deployment_request) → account_request_id
get_request_status(account_request_id) → status
get_account_record(deployment_id) → resolved_account
retry_customization(account_id) → execution_id
decommission_account(account_id, reason) → decommission_id
```

### Adaptadores posibles

| Adaptador | Cuándo usarlo |
|---|---|
| **Corporate AFT** | Organization Team tiene AFT instalado y expone account request repos |
| **Control Tower Account Factory** | No hay AFT pero Account Factory está habilitado |
| **Corporate Service Catalog** | TDSynnex tiene un workflow propio de Service Catalog |
| **Approved manual process** | Proceso documentado con checklist y evidencia |
| **Future customer-managed enrollment** | Cliente proporciona cuenta y delegation |

> [!IMPORTANT]
> Si TDSynnex no permite instalar AFT ni proporciona un mecanismo compatible de account vending, el customer factory **no debe quedar inutilizable**. Debe existir al menos un adaptador viable.

### Account Baseline (lo que hace el provider, no Scanalyze)

```
Account Baseline Checklist (AFT customization or equivalent)
├── Default VPC removal
├── ScanalyzeDeploymentRole
│   ├── Trust: exact orchestrator principal in Shared Services
│   ├── Condition: aws:PrincipalOrgID + sts:SourceIdentity + session tags
│   └── Permissions boundary attached
├── Terraform state backend
│   ├── S3 bucket (versioning, KMS, lockfile)
│   └── Bucket policy (deployment role + break-glass only)
├── Logging prerequisites (CloudWatch Logs group, SNS topic)
├── Security enrollment verification
│   ├── GuardDuty membership confirmed
│   ├── Security Hub membership confirmed
│   ├── CloudTrail organizational coverage confirmed
│   └── Config recorder confirmed
├── Budget and cost anomaly detection
└── account_ready SSM parameter
    └── Only set when ALL checks pass
```

> [!IMPORTANT]
> El baseline **verifica** que los servicios de seguridad están habilitados (por el delegated admin organizacional). No los habilita localmente de forma unilateral, ya que esto crearía un modelo de administración paralelo.

---

## 5. Estructura de OUs Propuesta

```
Root
├── ... (OUs existentes de TDSynnex/BCM Corp)
│
├── Scanalyze OU (nuevo — requiere aprobación corporativa)
│   ├── Scanalyze-Workloads OU
│   │   ├── customer-acme-prod
│   │   ├── customer-globex-prod
│   │   └── scanalyze-reference-prod
│   │
│   ├── Scanalyze-NonProd OU
│   │   ├── scanalyze-demo-v2
│   │   ├── integration-test
│   │   └── 5334****8743 (demo actual)
│   │
│   ├── Scanalyze-SharedServices OU
│   │   └── scanalyze-shared-services (control plane)
│   │
│   └── Scanalyze-Suspended OU
│       └── (offboarded accounts)
│
└── ...
```

---

## 6. Control Objectives (not SCP implementations)

Las SCPs concretas requieren revisión corporativa. Lo que Scanalyze propone son **control objectives**:

### Scanalyze-Workloads OU

| Control Objective | Candidate Implementation | Corporate Dependency | Test Cases | Exception Process |
|---|---|---|---|---|
| Restrict to approved regions | SCP deny on unapproved regions + CT region deny control | Exceptions for global services (IAM, CloudFront, R53, STS, WAF Global) | Deploy in approved region ✅; deploy in unapproved region ❌ | Documented exception request |
| Prevent root user operational use | SCP deny on root actions except break-glass | CT root activity control | Root login triggers alert; root action denied | Break-glass procedure |
| Prevent S3 public access | SCP + S3 Block Public Access at account level + CT control | Coordination with corporate S3 policy | Create public bucket ❌; public ACL ❌ | None — no exceptions |
| Restrict KMS key deletion authority | SCP limit `kms:ScheduleKeyDeletion` to break-glass role | KMS already enforces waiting period; SCP controls who can invoke | Non-authorized role tries ScheduleKeyDeletion ❌ | Security review + dual approval |
| Prevent IAM user creation | SCP deny `iam:CreateUser` | CT IAM user control | Create IAM user ❌; create role ✅ | None |
| Protect CloudTrail | SCP deny CloudTrail modification | CT cloudtrail integrity control | Stop/delete trail ❌ | None |
| Prevent Organization leave | SCP deny `organizations:LeaveOrganization` | Standard corporate control | Leave attempt ❌ | None |

### Scanalyze-Suspended OU

| Control Objective | Implementation |
|---|---|
| Default deny for workload identities | SCP deny * with exceptions for recovery |
| Compute stopped | SCP deny ECS/EC2/Lambda run actions |
| Ingress disabled | SCP deny network ingestion |
| Dedicated recovery/export role | Role requires approval, short-lived session, session recording |
| CloudTrail mandatory | Cannot be disabled (organizational) |
| KMS decrypt restricted | Only recovery workflow role |
| No routine human browsing | No SSO permission set for casual access |

> [!WARNING]
> SCPs no conceden permisos; solo limitan el máximo permitido. `Allow S3/DDB read` en una SCP no funciona — el role debe tener grants explícitos y la SCP simplemente no debe denegarlos.

---

## 7. Security Services Integration

### GuardDuty

| Aspecto | Modelo |
|---|---|
| Administration | Organization delegated administrator |
| Enablement | Administrator auto-enables for OU |
| Account baseline role | **Verify** membership and detector status |
| Local unilateral enablement | **Prohibited** without confirming delegated admin status |
| Regional scope | Per region — must verify all regions donde opera Scanalyze |

### Security Hub

| Aspecto | Modelo |
|---|---|
| Administration | Central configuration via delegated administrator |
| Configuration policies | Applied to Scanalyze OU |
| Standards | Determined by corporate + Scanalyze security requirements |
| Account baseline role | **Verify** membership and standards |
| Local unilateral enablement | **Prohibited** without confirming delegated admin status |

### AWS Backup

| Responsabilidad | Owner |
|---|---|
| Organization backup policies | Organization Team |
| Delegated administration | Organization Team |
| Cross-account monitoring | Organization Team |
| Recovery account | Organization Team |
| **Resource tags for backup selection** | **Scanalyze workload** |
| **Local vault when required by tier** | **Scanalyze workload** |
| **Restore testing** | **Scanalyze workload** |
| **Application-specific backup assignments** | **Scanalyze workload** |

---

## 8. RACI Matrix

| Responsibility | Organization Team | Scanalyze Platform | Security | Customer Ops |
|---|---|---|---|---|
| OU / SCP management | **A/R** | C | C | I |
| Account vending | **A/R** | C | C | I |
| Landing zone / Control Tower | **A/R** | I | C | I |
| Deployment role contract | C | **A/R** | C | I |
| GuardDuty / Security Hub | **A/R** | C | C | I |
| Workload deployment | I | **A/R** | C | I |
| Release management | I | **A/R** | C | I |
| Incident response | C | R | **A/R** | I |
| Account suspension | **A/R** | C | C | C |
| Data export / offboarding | C | **A/R** | C | **R** |
| Break-glass | C | I | **A/R** | I |

---

## 9. Management Account Rules

La management account **no contiene**:
- Workloads
- Pipelines
- Customer registry
- ECR repos
- State files
- Deployment orchestration

Solo contiene:
- Organizations service
- Billing
- SCPs
- Control Tower
- CloudTrail Organization
- IAM Identity Center

---

## 10. AFT Repositories (if applicable)

Si AFT existe o se instala, los repos siguen el modelo estándar:

| Repo | Contenido |
|---|---|
| `aft-account-request` | Account requests (Terraform) |
| `aft-account-provisioning-customizations` | Pre-baseline hooks |
| `aft-global-customizations` | Customizations para todas las cuentas |
| `aft-account-customizations` | Customizations por cuenta/OU |

`scanalyze-deployment-platform` puede generar o validar account requests, pero **no es un repo AFT** ni contiene internals de AFT.

---

## 11. Contingency Gate

> [!CAUTION]
> Si TDSynnex no proporciona dentro de un plazo razonable:
>
> - Account vending compatible con la interfaz definida
> - OU and control isolation para Scanalyze
> - Delegated security integration (GuardDuty, Security Hub)
> - Account quota suficiente para el roadmap
> - Cross-account role support
> - SLA operacional para account requests
>
> La dirección ejecutiva deberá evaluar una **Organization dedicada a Scanalyze** bajo una management account corporativa aprobada.
>
> Esto no significa crearla ahora. Significa evitar una dependencia estratégica sin salida.

---

## 12. Evidence Request to Organization Team

No se requiere acceso administrativo directo. Opciones aceptables:

1. Role temporal read-only via IAM Identity Center
2. Reporte firmado/exportado por el Organization Team
3. Sesión conjunta de discovery con evidencia archivada

### Information Required

| Item | Propósito |
|---|---|
| Control Tower home Region y landing-zone version | Compatibilidad |
| OU tree (al menos la parte relevante) | Diseño de Scanalyze OUs |
| OU actual de la cuenta `5334****8743` | Ubicación actual |
| Effective SCPs en la cuenta demo | Compatibilidad con Bedrock, Textract |
| Enabled Control Tower controls | Baseline scope |
| AFT presence, account, version | Account vending strategy |
| Account Factory process y SLA | Capacity planning |
| Log Archive account | Logging integration |
| Audit / Security delegated admin account | Security integration |
| GuardDuty delegated admin | Security enrollment |
| Security Hub delegated admin | Standards enrollment |
| AWS Backup delegated admin / policies | Backup strategy |
| Account quota disponible | Scale planning |
| Soporte para Bedrock y Textract bajo SCPs | Service compatibility |

---

## Consequences

### Positivas
- Aprovechamos infraestructura existente (CT, IdC, CloudTrail)
- No duplicamos servicios de gobernanza
- Acceso a SCPs y controls organizacionales
- Auditoría centralizada via Organization CloudTrail

### Negativas
- Dependencia del equipo de la Organization para account vending
- SCPs corporativas pueden ser más restrictivas de lo necesario
- Menos autonomía que con una Organization propia

### Riesgos
- Si el Organization Team no coopera, el account vending se bloquea
- SCPs corporativas podrían bloquear servicios (Bedrock, Textract)
- Cambios en la landing zone pueden afectar cuentas de Scanalyze
- Contingency gate requiere decisión ejecutiva y timeline significativo

---

## References

- B0.0A Member Account Discovery Report (2026-06-23)
- AWS Control Tower User Guide: Landing Zone, Controls
- AWS Account Factory for Terraform (AFT) Documentation
- AWS Organizations Best Practices Whitepaper
- AWS GuardDuty: Delegated Administrator
- AWS Security Hub: Central Configuration
- AWS Backup: Organization Policies
- ADR-001: Tenancy Model
