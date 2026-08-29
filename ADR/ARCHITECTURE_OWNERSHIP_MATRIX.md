# Architecture Ownership Matrix

> **Status**: `DRAFT rev3`
> **Date**: 2026-06-25; executable-manifest reconciliation 2026-08-28
> **Scope**: Scanalyze Dedicated Deployment Platform  
> **Cross-references**: ADR-003 rev4, ADR-004 rev3, ADR-006 rev4, ADR-007 rev3, ADR-008 rev3, ADR-010 rev3, `deployment/layers.yaml`

> [!CAUTION]
> This matrix describes the repository candidate. No connected deployment or
> live AWS readback is evidence here. `NOT_DEPLOYED`; production remains
> `PRODUCTION_NO_GO`.

---

## 1. Layer → Resources → State → Roles

### Single-Region Deployment

| Stage | Kind / Root | State Key | Produces Contract | Managed by Role |
|---|---|---|---|---|
| **account-ready-gate** | gate / `roots/account-ready-gate` | — | — | no terminal role |
| **global** | `roots/global` | `{dep_id}/global/terraform.tfstate` | `contracts/global/v1` | Plan (read), Apply (write) |
| **network** | `roots/network` | `{dep_id}/{region}/network/terraform.tfstate` | `contracts/network/v2` | Plan (read), Apply (write) |
| **platform** | `roots/platform` | `{dep_id}/{region}/platform/terraform.tfstate` | `contracts/platform/v2` | Plan (read), Apply (write) |
| **data-foundation** | `roots/data-foundation` | `{dep_id}/{region}/data-foundation/terraform.tfstate` | `contracts/data-foundation/v2` | Plan (read), Apply (write) |
| **cicd** | `roots/cicd` | `{dep_id}/{region}/cicd/terraform.tfstate` | `contracts/cicd/v2` | Plan (read), Apply (write) |
| **artifact-publication** | artifact / no Terraform root | — | `release-manifest/v1` | Validation (read), Promotion (write) |
| **identity-control-plane** | `roots/identity-control-plane` | `{dep_id}/{region}/identity-control-plane/terraform.tfstate` | `contracts/identity-control-plane/v1` | Identity-Plan (read), Identity-Apply (write) |
| **services** | `roots/services` | `{dep_id}/{region}/services/terraform.tfstate` | `contracts/services/v2` | Plan (read), Apply (write) |
| **edge-identity** | `roots/edge-identity` | `{dep_id}/{region}/edge-identity/terraform.tfstate` | `contracts/edge-identity/v2` | Plan (read), Apply (write) |
| **edge** | `roots/edge` | `{dep_id}/edge/terraform.tfstate` | `contracts/edge/v2` | Plan (read), Apply (write) |
| **addons** | `roots/addons` | `{dep_id}/{region}/addons/terraform.tfstate` | `contracts/addons/v2` | Plan (read), Apply (write) |
| **synthetic-validation** | validation / no Terraform root | — | — | Validation (read-only) |

This 13-stage order is authoritative because it is generated from
`deployment/layers.yaml`: ten Terraform state owners and three stages with
`state_key: null`.

### Multi-Region Deployment (ADR-008 rev3)

For multi-region deployments, regional layers have separate state per region:

```
{dep_id}/global/terraform.tfstate              ← global (no region)
{dep_id}/edge/terraform.tfstate                ← edge (no region, always us-east-1)
{dep_id}/us-east-1/network/terraform.tfstate   ← primary
{dep_id}/us-east-1/platform/terraform.tfstate
{dep_id}/us-east-1/data-foundation/terraform.tfstate
{dep_id}/us-east-1/cicd/terraform.tfstate
{dep_id}/us-east-1/identity-control-plane/terraform.tfstate
{dep_id}/us-east-1/services/terraform.tfstate
{dep_id}/us-east-1/edge-identity/terraform.tfstate
{dep_id}/us-east-1/addons/terraform.tfstate
{dep_id}/us-west-2/network/terraform.tfstate   ← recovery
{dep_id}/us-west-2/platform/terraform.tfstate
...
```

SSM contracts are regional natively. Each region has its own Parameter Store namespace for contracts.

---

## 2. Resource → Layer Ownership

### Global Layer (layer 0) — No region in state key

| Resource | Terraform Type | Owned by |
|---|---|---|
| ECS task execution role | `aws_iam_role` | global |
| ECS task execution policy | `aws_iam_role_policy_attachment` | global |
| Permissions boundaries (all) | `aws_iam_policy` | global |
| Service-linked role policies | `aws_iam_role_policy` | global |
| Workload IAM roles (per service) | `aws_iam_role` | global |

> [!IMPORTANT]
> **The eight terminal roles (Plan, Apply, Identity-Plan, Identity-Apply,
> Promotion, Validation, Diagnostic, StateRecovery) are NOT in the global
> layer.** The account-baseline candidate provisions them before any workload
> root may run. See §3 Account Baseline.

### Network Layer (layer 1) — Regional

| Resource | Terraform Type | Owned by |
|---|---|---|
| VPC | `aws_vpc` | network |
| Public subnets | `aws_subnet` | network |
| Private subnets | `aws_subnet` | network |
| Data subnets | `aws_subnet` | network |
| Internet Gateway | `aws_internet_gateway` | network |
| NAT Gateways | `aws_nat_gateway` | network |
| Elastic IPs (NAT) | `aws_eip` | network |
| Route tables | `aws_route_table` | network |
| VPC endpoints (S3, DDB, SQS, ECR, etc.) | `aws_vpc_endpoint` | network |
| VPC endpoint security groups | `aws_security_group` | network |
| VPC Flow Logs | `aws_flow_log` | network |

### Platform Layer (layer 2) — Regional

| Resource | Terraform Type | Owned by |
|---|---|---|
| ECS cluster | `aws_ecs_cluster` | platform |
| ALB | `aws_lb` | platform |
| ALB listeners (HTTPS) | `aws_lb_listener` | platform |
| ALB target groups | `aws_lb_target_group` | platform |
| ALB security group | `aws_security_group` | platform |
| ECS task security group | `aws_security_group` | platform |

### Data Foundation Layer (layer 3) — Regional

| Resource | Terraform Type | Owned by |
|---|---|---|
| DynamoDB tables (batches, documents, workflows) | `aws_dynamodb_table` | data-foundation |
| DynamoDB Global Table replicas (HA tiers) | `aws_dynamodb_table_replica` | data-foundation (primary region root) |
| S3 document buckets (per processing domain) | `aws_s3_bucket` | data-foundation |
| SQS queues (per processing domain) | `aws_sqs_queue` | data-foundation |
| SQS dead-letter queues | `aws_sqs_queue` | data-foundation |
| KMS keys (per-domain: documents, queues) | `aws_kms_key` | data-foundation |
| KMS aliases | `aws_kms_alias` | data-foundation |
| KMS multi-region key replicas (HA tiers) | `aws_kms_replica_key` | data-foundation (primary region root) |
| CloudWatch alarms (queue/metering) | `aws_cloudwatch_metric_alarm` | data-foundation |
| SSM parameters (table ARNs, queue URLs) | `aws_ssm_parameter` | data-foundation |

> [!WARNING]
> **DynamoDB Global Table settings are per-replica, not globally synchronized.** The primary region root owns the table definition including replicas. However, deletion protection, PITR, tags, and resource policies must be configured per replica explicitly.

### Services Layer (layer 4) — Regional, Terraform sole owner of task definitions

| Resource | Terraform Type | Owned by |
|---|---|---|
| ECS task definitions (all 7 services) | `aws_ecs_task_definition` | services |
| ECS services (all 7) | `aws_ecs_service` | services |
| Application auto-scaling targets | `aws_appautoscaling_target` | services |
| Application auto-scaling policies | `aws_appautoscaling_policy` | services |
| CloudWatch alarms (service health) | `aws_cloudwatch_metric_alarm` | services |
| CloudWatch log groups (service logs) | `aws_cloudwatch_log_group` | services |

> [!IMPORTANT]
> **All 7 services are always declared in every plan.** The `deploy_wave` variable controls which services have their image digest updated in each wave — it NEVER controls resource existence. Changing `deploy_wave` from 1 to 2 does NOT destroy Wave 1 services.

### Edge-Identity Layer (layer 5a) — Regional

| Resource | Terraform Type | Owned by |
|---|---|---|
| Cognito user pool | `aws_cognito_user_pool` | edge-identity |
| Cognito user pool clients (SPA + M2M) | `aws_cognito_user_pool_client` | edge-identity |
| Cognito user pool domain | `aws_cognito_user_pool_domain` | edge-identity |
| API Gateway HTTP API | `aws_apigatewayv2_api` | edge-identity |
| API Gateway stages | `aws_apigatewayv2_stage` | edge-identity |
| API Gateway integrations | `aws_apigatewayv2_integration` | edge-identity |
| API Gateway routes | `aws_apigatewayv2_route` | edge-identity |
| API Gateway authorizer (Lambda for multi-issuer) | `aws_apigatewayv2_authorizer` | edge-identity |
| Lambda authorizer function | `aws_lambda_function` | edge-identity |
| Lambda authorizer IAM | `aws_iam_role` | edge-identity |
| API Gateway default endpoint (disabled) | `aws_apigatewayv2_api` (disable_execute_api_endpoint) | edge-identity |

> [!NOTE]
> **API Gateway JWT authorizer replaced with Lambda authorizer** per ADR-008 rev3 corrections. Lambda authorizer validates multi-issuer during failover. Default execute-api endpoint disabled to prevent clients from bypassing Route53 routing controls.

### Edge Layer — Global (no region in state key)

| Resource | Terraform Type | Owned by |
|---|---|---|
| CloudFront distribution | `aws_cloudfront_distribution` | edge |
| CloudFront origin access control | `aws_cloudfront_origin_access_control` | edge |
| CloudFront response headers policy | `aws_cloudfront_response_headers_policy` | edge |
| WAF WebACL (CLOUDFRONT scope) | `aws_wafv2_web_acl` | edge |
| Route53 hosted zone | `aws_route53_zone` | edge |
| Route53 A/AAAA/CNAME records | `aws_route53_record` | edge |
| Route53 health checks | `aws_route53_health_check` | edge |
| ACM certificates (us-east-1 for CloudFront) | `aws_acm_certificate` | edge |

> [!IMPORTANT]
> **CloudFront serves ONLY frontend static assets.** All API traffic routes through Route53 failover to regional API Gateway (ADR-008 rev3). Route53 failover records and health checks are owned by edge layer, NOT by regional layers.

### Addons Layer (layer 5b) — Regional

| Resource | Terraform Type | Owned by |
|---|---|---|
| CloudWatch dashboards | `aws_cloudwatch_dashboard` | addons |
| CloudWatch composite alarms | `aws_cloudwatch_composite_alarm` | addons |
| Additional SNS topics (alerting) | `aws_sns_topic` | addons |
| Additional monitoring integrations | various | addons |

---

## 3. Account Baseline Resources (NOT in deployment state)

The account-baseline candidate is owned by AccountVendingProvider (ADR-004
rev3), with organization services owned by Control Tower. A deployment may
proceed only after exact ACCOUNT_READY v2 readback proves these resources; this
document does not prove that they currently exist.

| Resource | Provisioner | State |
|---|---|---|
| **ScanalyzeCustomer-Plan role** | AccountVendingProvider | Bootstrap state |
| **ScanalyzeCustomer-Apply role** | AccountVendingProvider | Bootstrap state |
| **ScanalyzeCustomer-Identity-Plan role** | AccountVendingProvider | Bootstrap state |
| **ScanalyzeCustomer-Identity-Apply role** | AccountVendingProvider | Bootstrap state |
| **ScanalyzeCustomer-Promotion role** | AccountVendingProvider | Bootstrap state |
| **ScanalyzeCustomer-Validation role** | AccountVendingProvider | Bootstrap state |
| **ScanalyzeCustomer-Diagnostic role** | AccountVendingProvider | Bootstrap state |
| **ScanalyzeCustomer-StateRecovery role** | AccountVendingProvider | Bootstrap state |
| State S3 bucket | AccountVendingProvider | Bootstrap state |
| Plan S3 bucket | AccountVendingProvider | Bootstrap state |
| Evidence S3 bucket | AccountVendingProvider | Bootstrap state |
| Contracts S3 bucket | AccountVendingProvider | Bootstrap state |
| State KMS key | AccountVendingProvider | Bootstrap state |
| Evidence KMS key | AccountVendingProvider | Bootstrap state |
| Contracts KMS key | AccountVendingProvider | Bootstrap state |
| CloudTrail (Organization trail) | Control Tower | Organization state |
| AWS Config recorder | Control Tower | Organization state |
| CT execution roles | Control Tower | Organization state |
| GuardDuty detector (if delegated) | Organization | Organization state |
| Security Hub subscription (if delegated) | Organization | Organization state |

> [!IMPORTANT]
> **The eight terminal roles are NOT created by the deployment pipeline.** The
> account-baseline candidate creates them under AccountVendingProvider custody.
> Live existence and authority remain unproven until connected readback.

---

## 4. Cross-Account Roles → Permitted Operations

| Role | AssumeRole source | Can read | Can write | Cannot |
|---|---|---|---|---|
| **Plan** | Orchestrator | All TF-managed resources, state bucket, SSM contracts | State bucket (`.tflock` only), exact create-only object in the dedicated plan bucket | Infrastructure write, saved-plan delete, ECR push, SSM contract write |
| **Apply** | Orchestrator | All, including the exact saved-plan object version | Infrastructure resources, state bucket, SSM contracts (own layer prefix through identity policy + mandatory `layer`/`operation` tags) | Evidence/recovery bucket writes, saved-plan put/delete, ECR push, IAM user creation, Organizations |
| **Identity-Plan** | Orchestrator | Identity-control-plane resources, its state and required contracts | Identity `.tflock`, exact create-only identity saved plan | Identity mutation, saved-plan delete, evidence write |
| **Identity-Apply** | Orchestrator | Identity-control-plane resources, exact identity saved-plan version and required contracts | Identity resources, its state and own contract | Evidence/recovery writes, saved-plan put/delete, unrelated workload layers |
| **Promotion** | Orchestrator | ECR (source), S3 (frontend), release manifests | ECR (push images + full OCI artifact graph), S3 (frontend immutable release prefix), CloudFront (invalidation) | Infrastructure, IAM, state |
| **Validation** | Orchestrator | ECS, ALB, DDB, SQS, CW, SSM, logs | Nothing | All writes |
| **Diagnostic** | Break-glass | All resources, state (read), logs, evidence (read) | Nothing | All writes |
| **StateRecovery** | Break-glass | Versioned state objects | Restored state via explicit get+put and stale lock delete, with `operation=state-recovery` | Infrastructure, ECR, SSM, IAM, saved-plan/recovery-prefix access |

### Terminal Identity Policy and Session-Tag Enforcement (ADR-006 rev4)

The generic Apply role identity policy resolves the mandatory `layer` principal
tag into the producer prefix and requires `operation=apply`:

```
Identity policy restricts ssm:PutParameter to:
  arn:aws:ssm:{region}:{account}:parameter/scanalyze/deployments/{dep_id}/contracts/${aws:PrincipalTag/layer}/*
```

This prevents a correctly tagged services Apply session from writing the
network contract. Identity-Apply has a fixed identity-control-plane prefix.
The terminal-session adapter does not yet pass a per-execution STS session
policy; broader per-layer/service/resource narrowing remains downstream.

---

## 5. Contract Dependency Graph (`deployment/layers.yaml`)

The manifest carries 13 ordered stages. Its exact producer/consumer bindings
are:

| Contract | Producer | Direct consumers |
|---|---|---|
| `account-ready/v2` | external account baseline | account-ready-gate, global |
| `global/v1` | global | network, identity-control-plane, services |
| `network/v2` | network | platform, services, edge-identity |
| `platform/v2` | platform | data-foundation, cicd, services, edge-identity |
| `data-foundation/v2` | data-foundation | cicd, services |
| `cicd/v2` | cicd | artifact-publication, services |
| `release-manifest/v1` | artifact-publication | identity-control-plane, services, synthetic-validation |
| `identity-contract/v2` | external identity authority | identity-control-plane |
| `identity-control-plane/v1` | identity-control-plane | services, edge-identity, synthetic-validation |
| `services/v2` | services | edge-identity, synthetic-validation |
| `edge-identity/v2` | edge-identity | edge, synthetic-validation |
| `edge/v2` | edge | addons, synthetic-validation |
| `addons/v2` | addons | synthetic-validation |

---

## 6. S3 Buckets per Customer Account (Four-Bucket Model, ADR-003 rev4)

| Bucket | Purpose | Object Lock | KMS Key | Accessed by roles |
|---|---|---|---|---|
| `scanalyze-{acct}-tf-state` | Terraform state + .tflock files | NONE (required for lockfile deletion) | State KMS key | Plan (r + .tflock write/delete), Apply (rw), Diagnostic (r), StateRecovery (rw) |
| `scanalyze-{acct}-tf-plan` | Exact versioned saved-plan binaries under `plan-execution/` | NONE; current and noncurrent versions expire after one day | Evidence KMS key | Plan (create exact object), Apply (read exact version) |
| `scanalyze-{acct}-tf-evidence` | Sanitized immutable audit evidence only; no current Plan/Apply publisher | COMPLIANCE default retention, 90 days | Evidence KMS key | Diagnostic/Validation (read); future isolated evidence publisher (write) |
| `scanalyze-{acct}-contracts` | Large contract payloads (>8KB SSM limit) | NONE | Contracts KMS key | Apply (write own layer prefix), Plan+Validation (read all) |

> [!NOTE]
> The dedicated plan bucket and its policy use `DeletionPolicy: Retain` and
> `UpdateReplacePolicy: Retain`; stack deletion or replacement therefore does
> not erase it. Its lifecycle is the implemented cleanup mechanism for current
> and noncurrent saved-plan versions. The controller has no saved-plan delete
> API, so apply, rejection, or expiry does not perform immediate deletion.

---

## 7. Operational Ownership (Non-Terraform)

### Migration Utility (ADR-010 rev3)

| Resource/Operation | Owner | Notes |
|---|---|---|
| DynamoDB table schema + configuration | **Terraform** (data-foundation) | Exclusive owner. Migration utility NEVER creates, modifies, or deletes tables |
| Migration data writes (BatchWriteItem baseline) | Migration Utility | Operational writer only. Writes to existing TF-managed tables |
| Migration data writes (PutItem/UpdateItem delta) | Migration Utility | Conditional writes with version attributes |
| Migration checkpoint store | Migration Utility | Separate DynamoDB table or S3-based checkpoint |
| Migration dead-letter records | Migration Utility | Items that fail after max retries, logged for manual review |
| S3 document sync | Migration Utility + `aws s3 sync` | SHA-256 verified |
| Cognito user migration | Migration Utility | Lazy (UserMigration trigger) OR bulk import — never both |

### Wave Rollout (ADR-010 rev3)

| Operation | Owner | Notes |
|---|---|---|
| Wave sequencing | Orchestrator | Controls which `deploy_wave` value is passed |
| Wave go/no-go decision | Orchestrator + runtime validation | Automated for Ring 0, manual for Ring 2+ |
| Per-service release tracking | Deployment record | Tracks per service: desired_release, observed_release, image_digest, task_definition_arn, rollout_status, validation_status, wave_id |
| Schema compatibility matrix | Release process | Reviewed per release, documents producer/consumer compatibility |

### ECS Reconciliation (ADR-010 rev3)

| Operation | Owner | Notes |
|---|---|---|
| Detect DEPLOYMENT_FAILED | Orchestrator | Monitors ECS deployment events |
| Confirm active revision | Orchestrator (Validation role) | `ecs:DescribeServices` + `ecs:DescribeTaskDefinition` |
| Generate reconciliation plan | Orchestrator (Plan role) | `terraform plan` with previous release config |
| Review reconciliation plan | Mandatory (all rings) | Human review required — reconciliation is sensitive |
| Apply reconciliation | Orchestrator (Apply role) | Forward apply, not state restoration |
| Block failed release | Orchestrator | Marks release N+1 as blocked across all rings |

### Write Fencing (ADR-008 rev3)

| Operation | Owner | Notes |
|---|---|---|
| Write-authority mechanism | TBD (ADR-008 corrections pending) | MRSC table or ARC routing control + signed write lease |
| Epoch management | Orchestrator | Monotonically increasing writer epoch |
| Write fence verification | Orchestrator (Validation role) | Confirm primary cannot accept writes |
| DNS routing change | Orchestrator (via ARC or Route53) | Only after fence confirmed |

---

## 8. Multi-Region Resource Ownership (ADR-008 rev3)

> [!WARNING]
> **Resources that span regions must have exactly ONE Terraform owner.** Parts of a DynamoDB Global Table must not be declared from two independent regional roots.

| Namespace | Resources | Owner | State Key |
|---|---|---|---|
| **global** | Workload IAM roles, permissions boundaries | global root | `{dep_id}/global/terraform.tfstate` |
| **edge** | Route53, CloudFront, WAF (CLOUDFRONT), ACM (us-east-1) | edge root | `{dep_id}/edge/terraform.tfstate` |
| **replicated-data** | DynamoDB global table (primary + replicas), multi-region KMS (primary + replicas), S3 replication configuration | data-foundation root (primary region) | `{dep_id}/{primary_region}/data-foundation/terraform.tfstate` |
| **regional** | VPC, ECS, SQS, regional KMS, Cognito, API Gateway, regional S3 | per-region roots | `{dep_id}/{region}/{layer}/terraform.tfstate` |
| **write-authority** | Write fence mechanism (TBD: MRSC table or external lease) | global-control or edge root (TBD) | TBD — depends on fencing mechanism chosen |

---

## 9. Forbidden Ownership Patterns

| Pattern | Why forbidden | Detection |
|---|---|---|
| Two roots own same resource type in same namespace | Dual ownership | CI: ownership.yaml validation |
| Pipeline step registers ECS task definition | TF sole owner (ADR-010 rev3) | CI: no `aws ecs register-task-definition` in pipeline scripts |
| Ad hoc script writes an SSM contract outside the typed producer-layer publisher | Producer layer is the sole authority (ADR-006 rev4) | CI: only the canonical publisher may invoke create-only contract writes |
| Break-glass assumes Plan/Apply/Promotion role | Break-glass limited to Diagnostic + StateRecovery (ADR-004 rev3) | IAM: trust policy enforcement |
| `terraform_remote_state` | Cross-layer coupling | CI: grep |
| Hardcoded account ID | Not replicable | CI: regex `\d{12}` |
| `timestamp()` in TF code | Non-deterministic plans | CI: grep |
| `check { assert {} }` for contract validation | Use `precondition` for fail-closed (ADR-006 rev4) | CI: grep for `check {` in contract validation paths |
| `deploy_wave` controls resource existence | Must control only digest, not resource lifecycle | CI: review services module for conditional resource creation via deploy_wave |
| `BatchWriteItem` for delta migration loads | No conditional writes; use PutItem/UpdateItem (ADR-010 rev3 corrections) | Code review of migration utility |
| Migration utility creates/modifies DynamoDB tables | TF is exclusive table owner | Code review; IAM policy: migration role cannot `dynamodb:CreateTable` |
| UserMigration trigger + pre-imported users | Incompatible strategies (ADR-008 rev3 corrections) | Architecture review |
| Native JWT authorizer for multi-issuer | API Gateway JWT authorizer accepts only one issuer | Architecture review; edge-identity uses Lambda authorizer |
| `region_active` boolean as primary write fence | MREC DDB conditional writes are locally evaluated, not globally consistent | Architecture review (ADR-008 rev3 corrections) |
| DDB Global Table replicas declared from separate regional roots | Dual ownership | CI: ownership check — global table + replicas must be in single root |

---

## 10. ADR Cross-Reference Index

| Topic | Primary ADR | Supporting ADRs |
|---|---|---|
| Tenancy model (1:1 account) | ADR-001 | ADR-002, ADR-004 |
| Organization / Control Tower | ADR-002 | ADR-001 |
| State backend (four buckets, regional keys) | ADR-003 rev4 | ADR-004 rev3, ADR-006 rev4, ADR-008 rev3 |
| Cross-account roles (eight terminal roles, bootstrap) | ADR-004 rev3 | ADR-003 rev4, ADR-006 rev4, ADR-007 rev3 |
| Schemas (canonical) | ADR-005 | ADR-006 rev4, ADR-008 rev3 |
| Modules + contracts (preconditions, tag-scoped identity policy, future session-policy narrowing) | ADR-006 rev4 | ADR-003 rev4, ADR-004 rev3, ADR-005 |
| Supply chain (OCI graph, DSSE, proxy egress) | ADR-007 rev3 | ADR-004 rev3, ADR-005, ADR-010 rev3 |
| DR (write fencing, Lambda authorizer, outbox) | ADR-008 rev3 | ADR-003 rev4, ADR-006 rev4, ADR-007 rev3 |
| Threat model (10 domains, 28 threats) | ADR-009 rev3 | All others |
| Testing + rollout + migration (zero write loss, waves) | ADR-010 rev3 | ADR-003 rev4, ADR-006 rev4, ADR-007 rev3, ADR-008 rev3 |
| Ownership matrix | This document (rev3) | ADR-003 rev4, ADR-004 rev3, ADR-006 rev4, ADR-008 rev3, ADR-010 rev3 |
