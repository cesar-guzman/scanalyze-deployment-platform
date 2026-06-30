# Architecture Ownership Matrix

> **Status**: `DRAFT rev2`  
> **Date**: 2026-06-25  
> **Scope**: Scanalyze Dedicated Deployment Platform  
> **Cross-references**: ADR-003 rev3, ADR-004 rev3, ADR-006 rev3, ADR-007 rev3, ADR-008 rev3, ADR-010 rev3

---

## 1. Layer → Resources → State → Roles

### Single-Region Deployment

| Layer | Terraform Root | State Key | Produces Contract | Managed by Role |
|---|---|---|---|---|
| **global** | `roots/global` | `{dep_id}/global/terraform.tfstate` | `contracts/global/v1` | Plan (read), Apply (write) |
| **network** | `roots/network` | `{dep_id}/{region}/network/terraform.tfstate` | `contracts/network/v1` | Plan (read), Apply (write) |
| **platform** | `roots/platform` | `{dep_id}/{region}/platform/terraform.tfstate` | `contracts/platform/v1` | Plan (read), Apply (write) |
| **data-foundation** | `roots/data-foundation` | `{dep_id}/{region}/data-foundation/terraform.tfstate` | `contracts/data-foundation/v1` | Plan (read), Apply (write) |
| **services** | `roots/services` | `{dep_id}/{region}/services/terraform.tfstate` | `contracts/services/v1` | Plan (read), Apply (write) |
| **edge-identity** (5a) | `roots/edge-identity` | `{dep_id}/{region}/edge-identity/terraform.tfstate` | `contracts/edge-identity/v1` | Plan (read), Apply (write) |
| **edge** | `roots/edge` | `{dep_id}/edge/terraform.tfstate` | `contracts/edge/v1` | Plan (read), Apply (write) |
| **addons** | `roots/addons` | `{dep_id}/{region}/addons/terraform.tfstate` | `contracts/addons/v1` | Plan (read), Apply (write) |

### Multi-Region Deployment (ADR-008 rev3)

For multi-region deployments, regional layers have separate state per region:

```
{dep_id}/global/terraform.tfstate              ← global (no region)
{dep_id}/edge/terraform.tfstate                ← edge (no region, always us-east-1)
{dep_id}/us-east-1/network/terraform.tfstate   ← primary
{dep_id}/us-east-1/platform/terraform.tfstate
{dep_id}/us-east-1/data-foundation/terraform.tfstate
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
> **The 6 control-plane deployment roles (Plan, Apply, Promotion, Validation, Diagnostic, StateRecovery) are NOT in the global layer.** They are provisioned by the AccountVendingProvider during account bootstrap (ADR-004 rev3). See §3 Account Baseline.

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

Provisioned by AccountVendingProvider (ADR-004 rev3) or Control Tower. These resources exist BEFORE any deployment layer runs.

| Resource | Provisioner | State |
|---|---|---|
| **ScanalyzeCustomer-Plan role** | AccountVendingProvider | Bootstrap state |
| **ScanalyzeCustomer-Apply role** | AccountVendingProvider | Bootstrap state |
| **ScanalyzeCustomer-Promotion role** | AccountVendingProvider | Bootstrap state |
| **ScanalyzeCustomer-Validation role** | AccountVendingProvider | Bootstrap state |
| **ScanalyzeCustomer-Diagnostic role** | AccountVendingProvider | Bootstrap state |
| **ScanalyzeCustomer-StateRecovery role** | AccountVendingProvider | Bootstrap state |
| State S3 bucket | AccountVendingProvider | Bootstrap state |
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
> **The 6 deployment roles are NOT created by the deployment pipeline.** They are created during account bootstrap by the AccountVendingProvider, which runs with a corporate principal identity. This resolves the bootstrap chicken-and-egg problem (ADR-004 rev3).

---

## 4. Cross-Account Roles → Permitted Operations

| Role | AssumeRole source | Can read | Can write | Cannot |
|---|---|---|---|---|
| **Plan** | Orchestrator | All TF-managed resources, state bucket, SSM contracts | State bucket (.tflock only), plan-execution zone | Infrastructure write, ECR push, SSM contract write |
| **Apply** | Orchestrator | All | Infrastructure resources, state bucket, SSM contracts (own layer prefix only via session policy), evidence bucket (pre-apply snapshots) | ECR push, IAM user creation, Organizations |
| **Promotion** | Orchestrator | ECR (source), S3 (frontend), release manifests | ECR (push images + full OCI artifact graph), S3 (frontend immutable release prefix), CloudFront (invalidation) | Infrastructure, IAM, state |
| **Validation** | Orchestrator | ECS, ALB, DDB, SQS, CW, SSM, logs | Nothing | All writes |
| **Diagnostic** | Break-glass | All resources, state (read), logs, evidence (read) | Nothing | All writes |
| **StateRecovery** | Break-glass | State bucket | State bucket (put/copy/delete, requires `operation=state-recovery` tag) | Infrastructure, ECR, SSM, IAM |

### Session Policy Enforcement (ADR-006 rev3)

Apply role uses session policy to restrict SSM writes to producer's layer prefix:

```
Session policy restricts ssm:PutParameter to:
  arn:aws:ssm:{region}:{account}:parameter/scanalyze/deployments/{dep_id}/contracts/{layer}/*
```

This prevents a services apply from writing to the network contract.

---

## 5. Contract Dependency Graph (8-layer)

```
global/v1 ─────────────────────────────────┐
    │                                       │
    ▼                                       │
network/v1 ────────────────────┐            │
    │                          │            │
    ▼                          ▼            ▼
platform/v1            data-foundation/v1
    │                          │
    └──────────┬───────────────┘
               ▼
          services/v1
               │
        ┌──────┴──────┐
        ▼             ▼
  edge-identity/v1  edge/v1
        │             │
        └──────┬──────┘
               ▼
          addons/v1
```

| Contract | Producer | Consumers |
|---|---|---|
| `global/v1` | global root | network, platform, data-foundation, services, edge-identity, edge, addons |
| `network/v1` | network root | platform, data-foundation |
| `platform/v1` | platform root | services, edge-identity, addons |
| `data-foundation/v1` | data-foundation root | services |
| `services/v1` | services root | edge-identity, edge, addons |
| `edge-identity/v1` | edge-identity root | addons |
| `edge/v1` | edge root | addons |
| `addons/v1` | addons root | (terminal — no consumers) |

---

## 6. S3 Buckets per Customer Account (Three-Bucket Model, ADR-003 rev3)

| Bucket | Purpose | Object Lock | KMS Key | Accessed by roles |
|---|---|---|---|---|
| `scanalyze-{acct}-tf-state` | Terraform state + .tflock files | NONE (required for lockfile deletion) | State KMS key | Plan (r + .tflock write/delete), Apply (rw), Diagnostic (r), StateRecovery (rw) |
| `scanalyze-{acct}-tf-evidence` | Pre-apply snapshots (recovery prefix), applied plan evidence (evidence prefix), plan-execution zone (ephemeral plans, short TTL) | COMPLIANCE on evidence objects; NO default retention on bucket | Evidence KMS key | Apply (write evidence + recovery), Plan (write plan-execution zone), Diagnostic (read) |
| `scanalyze-{acct}-contracts` | Large contract payloads (>8KB SSM limit) | NONE | Contracts KMS key | Apply (write own layer prefix), Plan+Validation (read all) |

> [!NOTE]
> **Plan-execution zone** within the evidence bucket stores ephemeral saved plans with short retention. Retention is NOT set via bucket-level COMPLIANCE default (which would prevent deletion). Instead, individual evidence objects get per-object COMPLIANCE retention; plan-execution objects get lifecycle-based cleanup.

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
| Script writes SSM contract | Producer root is sole writer (ADR-006 rev3) | CI: no `aws ssm put-parameter` in pipeline scripts for contract paths |
| Break-glass assumes Plan/Apply/Promotion role | Break-glass limited to Diagnostic + StateRecovery (ADR-004 rev3) | IAM: trust policy enforcement |
| `terraform_remote_state` | Cross-layer coupling | CI: grep |
| Hardcoded account ID | Not replicable | CI: regex `\d{12}` |
| `timestamp()` in TF code | Non-deterministic plans | CI: grep |
| `check { assert {} }` for contract validation | Use `precondition` for fail-closed (ADR-006 rev3) | CI: grep for `check {` in contract validation paths |
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
| State backend (three buckets, regional keys) | ADR-003 rev3 | ADR-004 rev3, ADR-006 rev3, ADR-008 rev3 |
| Cross-account roles (6 scoped, bootstrap) | ADR-004 rev3 | ADR-003 rev3, ADR-006 rev3, ADR-007 rev3 |
| Schemas (canonical) | ADR-005 | ADR-006 rev3, ADR-008 rev3 |
| Modules + contracts (preconditions, session policy) | ADR-006 rev3 | ADR-003 rev3, ADR-004 rev3, ADR-005 |
| Supply chain (OCI graph, DSSE, proxy egress) | ADR-007 rev3 | ADR-004 rev3, ADR-005, ADR-010 rev3 |
| DR (write fencing, Lambda authorizer, outbox) | ADR-008 rev3 | ADR-003 rev3, ADR-006 rev3, ADR-007 rev3 |
| Threat model (10 domains, 28 threats) | ADR-009 rev3 | All others |
| Testing + rollout + migration (zero write loss, waves) | ADR-010 rev3 | ADR-003 rev3, ADR-006 rev3, ADR-007 rev3, ADR-008 rev3 |
| Ownership matrix | This document (rev2) | ADR-003 rev3, ADR-004 rev3, ADR-006 rev3, ADR-008 rev3, ADR-010 rev3 |
