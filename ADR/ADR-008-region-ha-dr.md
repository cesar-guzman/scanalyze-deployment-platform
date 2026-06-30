# ADR-008: Region Support, HA, DR, Global/Regional/Account Stacks, and AZ IDs

> **Status**: `DRAFT rev3`  
> **Date**: 2026-06-23  
> **Decision makers**: César Guzmán  
> **Scope**: Scanalyze Dedicated Deployment Platform  
> **Depends on**: ADR-001, ADR-003 rev3, ADR-005, ADR-006 rev3  
> **Rev3 changes**: P1 multi-region — regional state model, write fencing, Cognito issuer strategy, simplified API routing, cost model extracted

---

## Context

Scanalyze initially deploys in `us-east-1` but the architecture must be region-portable. Customers may require multi-AZ HA, cross-region DR, or specific region placement for data residency. The platform must honestly document limitations and require tested evidence before committing RTO/RPO targets.

---

## Decision

### 1. Initial Region: `us-east-1`

All greenfield deployments start in `us-east-1`. Region expansion follows the capability matrix and customer requirements.

### 2. Region Capability Matrix

Each target region must be validated against a capability matrix before deployment. The matrix is a versioned JSON document per region (`configs/regions/{region}.json`).

Required capabilities:
- ECS Fargate
- DynamoDB (and Global Tables for HA tiers)
- S3 (with CRR support)
- KMS (with multi-region key support for HA tiers)
- API Gateway HTTP API
- Cognito
- ECR (with enhanced scanning)
- CloudWatch (Logs, Metrics, Alarms)
- SQS
- Secrets Manager
- AWS Signer (same region as ECR — see ADR-007)

The orchestrator validates the capability matrix as a precondition before any regional deployment.

### 3. Deployment Tiers and Resilience Profiles

| Tier | AZs | NAT GWs | ECS Deployment | DR Profile | RTO | RPO |
|---|---|---|---|---|---|---|
| `internal-demo` | 2 | 1 | Rolling | None | 24h | 24h |
| `enterprise-standard` | 2 | 1 | Rolling + circuit breaker | `backup-restore` | 4h | 1h |
| `enterprise-ha` | 3 | 3 | Rolling + circuit breaker | `pilot-light` or `warm-standby` | 1h / 15min | 15min / ~0 |

> [!CAUTION]
> **RTO/RPO claims are UNTESTED design goals.** Each target requires a DR drill with measured evidence before it can be contractually committed. See §14.

> [!NOTE]
> **Cost estimates are in a separate document** (`docs/cost-model.md`). This ADR defines architecture; pricing tables are maintained independently because they change with AWS pricing updates and customer negotiations.

### 4. AZ IDs

Use AZ IDs (`use1-az1`, `use1-az2`) not AZ names (`us-east-1a`) for consistent placement across accounts. AZ names map differently per account.

### 5. Resource Classification

| Category | Examples | Region behavior |
|---|---|---|
| **Global** | IAM roles, Route53 hosted zones, CloudFront distributions | Created once, no region prefix in state key |
| **Edge** | ACM certificates (us-east-1 for CloudFront), WAF WebACLs (CloudFront scope) | Created in us-east-1 regardless of primary region |
| **Regional** | VPC, ECS, DynamoDB, S3, SQS, Cognito, API Gateway, KMS | Created per-region, region included in state key |

### 6. Regional State Model

State keys include region for regional layers, aligning with ADR-003 rev3:

```
State bucket:
  {dep_id}/global/terraform.tfstate              ← no region (global)
  {dep_id}/edge/terraform.tfstate                ← no region (edge, always us-east-1)
  {dep_id}/{region}/network/terraform.tfstate    ← regional
  {dep_id}/{region}/platform/terraform.tfstate
  {dep_id}/{region}/data-foundation/terraform.tfstate
  {dep_id}/{region}/services/terraform.tfstate
  {dep_id}/{region}/edge-identity/terraform.tfstate
  {dep_id}/{region}/addons/terraform.tfstate
```

SSM contracts are regional natively — each region has its own Parameter Store namespace:

```
Primary region (us-east-1):
  /scanalyze/deployments/{dep_id}/contracts/network/v1
  /scanalyze/deployments/{dep_id}/contracts/platform/v1
  ...

Recovery region (us-west-2):
  /scanalyze/deployments/{dep_id}/contracts/network/v1   ← same path, different region
  /scanalyze/deployments/{dep_id}/contracts/platform/v1
  ...
```

The deployment record tracks which regions have been deployed and the state version per region:

```json
{
  "deployment_id": "dep_01J5ABCDEF",
  "regions": {
    "us-east-1": {
      "role": "primary",
      "status": "active",
      "layers": {
        "network": { "state_version_id": "v42", "contract_digest": "sha256:..." },
        "platform": { "state_version_id": "v38", "contract_digest": "sha256:..." }
      }
    },
    "us-west-2": {
      "role": "recovery",
      "status": "standby",
      "layers": {
        "network": { "state_version_id": "v12", "contract_digest": "sha256:..." }
      }
    }
  }
}
```

The ownership manifest (ADR-003 rev3) records which region produces each contract:

```yaml
deployments:
  dep_01J5ABCDEF:
    us-east-1:
      network: { owner: "apply", contract: "/scanalyze/.../contracts/network/v1" }
      platform: { owner: "apply", contract: "/scanalyze/.../contracts/platform/v1" }
    us-west-2:
      network: { owner: "apply", contract: "/scanalyze/.../contracts/network/v1" }
```

### 7. Write Fencing During Failover

> [!CAUTION]
> **Without write fencing, DynamoDB Global Tables accepts writes from BOTH regions simultaneously.** This causes last-writer-wins conflicts, potential data corruption, and split-brain behavior. The primary region MUST be fenced BEFORE the recovery region accepts writes.

#### Five-phase failover sequence

```
Phase 1 — DETECT
  Health check failure triggers alert
  Automated: Route53 health check (API /health endpoint)
  Manual: on-call engineer confirms (to prevent false positive failover)

Phase 2 — FENCE PRIMARY
  Disable write access to primary region:
    a. DynamoDB: set region_active=false in deployment config table
       Application reads this flag and rejects writes with 503
    b. SQS: remove SendMessage permission from application roles
       (via IAM policy update or SQS queue policy)
    c. API Gateway: deploy throttle-all stage (0 req/s) or disable stage
  Timeout: 5 minutes. If primary is unreachable, fence is implicit
    (network partition = naturally fenced from client perspective)

Phase 3 — CONFIRM FENCE
  Verify primary is no longer accepting writes:
    a. Attempt test write to primary DynamoDB → expect failure
    b. Attempt test SQS send to primary → expect failure
    c. If primary unreachable: skip (already fenced by partition)
  Record fence timestamp in deployment record

Phase 4 — ACTIVATE RECOVERY
  a. Set region_active=true in recovery region deployment config
  b. Switch Route53 failover records (API write path)
  c. CloudFront: update origin to recovery region S3 (frontend)
  d. Run document replay for in-flight processing (§8.2)
  e. Scale up ECS tasks in recovery region (if pilot-light/warm-standby)

Phase 5 — VALIDATE
  a. Runtime validation suite against recovery region
  b. Verify writes succeed in recovery
  c. Verify reads return consistent data
  d. Monitor for 15 minutes before declaring stable
  e. Record failover evidence in deployment record
```

#### Failback (return to primary)

```
Failback follows the SAME five-phase sequence in reverse:
  DETECT: primary region healthy
  FENCE RECOVERY: stop writes in recovery
  CONFIRM FENCE: verify no recovery writes
  ACTIVATE PRIMARY: re-enable primary, sync data
  VALIDATE: runtime suite + consistency check

DynamoDB Global Tables sync must complete before failback:
  Monitor replication lag → wait until lag < target RPO
  Verify all recovery writes are replicated to primary
```

### 8. DR Profiles — Revised

#### 8.1 CloudFront Failover Limitation

**CloudFront origin failover only retries GET/HEAD for 5xx/timeout.** POST/PUT/DELETE are NOT retried.

**Decision**: CloudFront serves **ONLY frontend static assets**. ALL API traffic (read AND write) routes through Route53 failover to regional API Gateway. No split read/write hostname.

```
Frontend (static assets):
  Client → CloudFront → S3 (primary region)
  Failover: CloudFront origin group → S3 (recovery region)

ALL API traffic (GET/POST/PUT/DELETE):
  Client → api.{customer}.scanalyze.com
         → Route53 failover record
         → API Gateway (active region) → ALB → ECS
  Failover: Route53 health check → DNS switch (TTL 60s)
```

> [!IMPORTANT]
> **Unified API endpoint simplifies the client.** The frontend `config.json` provides a single `apiBaseUrl` that points to the Route53 failover domain. The client does not need to know which region is active or use different URLs for read vs write.

#### 8.2 SQS Cross-Region Limitation

SQS does not replicate messages cross-region. In-flight messages during failover are lost.

**Solution**: DynamoDB audit trail replay + client idempotency.

| Strategy | Description | Tiers |
|---|---|---|
| **DynamoDB-first writes** | All ingest API calls write to DynamoDB BEFORE publishing to SQS. DynamoDB record is source of truth. | All tiers |
| **Post-failover replay** | Query documents with status=QUEUED or PROCESSING, re-publish to recovery SQS. Idempotent workers prevent duplicates. | Standard, HA |
| **Client idempotency** | Ingest API accepts `X-Idempotency-Key`. After failover, clients can safely retry. | All tiers |

```
Replay procedure (post-failover):
  1. Wait for write fence confirmation (Phase 3 complete)
  2. Query documents table in recovery region (Global Tables replica):
     status IN (QUEUED, PROCESSING) AND region = primary_region
  3. For each unfinished document:
     a. Re-publish processing request to recovery region SQS
     b. Update status to RE_QUEUED, set recovery_region
  4. Workers in recovery region process normally
  5. Idempotency check (document_id + version) prevents duplicate processing
```

> [!WARNING]
> **If DynamoDB write succeeded but SQS publish failed (pre-failover):** The document record exists with status=QUEUED but no SQS message was sent. Replay catches this case because it queries by status, not by SQS state. This is the primary reason for DynamoDB-first ordering.

#### 8.3 Cognito Token/Issuer Strategy

**Problem**: Cognito tokens contain the issuer URL of the pool that issued them (`https://cognito-idp.{region}.amazonaws.com/{pool_id}`). After failover, existing tokens reference the primary pool. The recovery pool has a different pool ID and possibly different region.

**Solution**: Dual-issuer authorizer with auto-expiry.

```
During normal operation:
  API Gateway JWT authorizer trusts: [primary_pool_issuer]

During failover (Phase 4):
  API Gateway JWT authorizer trusts: [primary_pool_issuer, recovery_pool_issuer]
  
  Behavior:
    - Existing tokens from primary pool: ACCEPTED (until they expire naturally)
    - New tokens from recovery pool: ACCEPTED
    - Token max lifetime: 1 hour (Cognito access token default)
  
After failover stabilization (Phase 5 + 1 hour):
  API Gateway JWT authorizer trusts: [recovery_pool_issuer]
  Primary tokens have expired naturally
```

| Approach | Pros | Cons | Recommendation |
|---|---|---|---|
| **Dual-issuer (temporary)** | Transparent to users with valid tokens | Authorizer must accept two issuers for up to 1 hour | ✅ Recommended |
| **Force re-auth** | Clean break, single issuer | All users must re-authenticate immediately | Not recommended |
| **Custom domain** | Single issuer URL | Cognito custom domain complexity, certificate management | Future consideration |

> [!IMPORTANT]
> **Users whose tokens have expired must authenticate against the recovery Cognito pool.** If the user's password is not migrated (§8.4), they must reset. The UserMigration trigger (§8.4) attempts transparent migration first.

#### 8.4 Cognito Password Limitation

Cognito does not export password hashes. After failover, the recovery pool cannot import passwords.

| DR Profile | Strategy | User Impact |
|---|---|---|
| `backup-restore` | New pool in recovery region. Import attributes. Force password reset. | Users reset passwords |
| `pilot-light` | Pool pre-provisioned. Import attributes from DynamoDB backup. Force reset. | Same as above, faster |
| `warm-standby` | UserMigration Lambda trigger: on login attempt, call primary Cognito `AdminInitiateAuth`. If primary reachable → migrate transparently. If not → force reset. | Mostly transparent |

```
UserMigration Lambda trigger:
  Input: {userName, password} from recovery Cognito
  Logic:
    1. Call AdminInitiateAuth on PRIMARY Cognito pool
    2. If auth succeeds → return user attributes → user migrated transparently
    3. If primary unreachable → return error → user must reset password
    4. If auth fails → return error → wrong password
  Constraint: ONLY works if primary Cognito is accessible
```

> [!CAUTION]
> **UserMigration only works if primary Cognito is running.** In a full region failure where Cognito itself is down, ALL users must reset passwords. This must be documented in the customer DR SLA.

#### 8.5 `backup-restore` Profile

```
Primary Region (us-east-1)
├── Full deployment (all layers)
├── DynamoDB PITR enabled
├── S3 versioning + cross-region replication (async)
├── ECS task definitions in release manifest (portable)
├── State backup: S3 versioning + version ID recorded
└── Cognito user attributes: daily automated export to S3

Recovery (manual, guided by runbook):
  1. Verify write fence on primary (Phase 2-3)
  2. Create new deployment in recovery region (same deployment request + release)
  3. Terraform plan + apply all regional layers (forward apply, new state)
  4. Restore DynamoDB from PITR or CRR export
  5. Restore S3 document buckets from replicated bucket
  6. Create/configure Cognito pool in recovery region
  7. Import user attributes, send password reset emails
  8. Update API Gateway JWT authorizer (dual-issuer)
  9. Switch Route53 failover records
  10. Update CloudFront origins to recovery region S3
  11. Run document replay (§8.2)
  12. Validate with runtime suite (Phase 5)
```

| Metric | Target | Evidence |
|---|---|---|
| RTO | 4 hours (**UNTESTED**) | DR drill: end-to-end measured |
| RPO | 1 hour (**UNTESTED**) | S3 CRR lag + DynamoDB PITR coverage |
| Auth RTO | +5–30 min (password reset) | Measured in drill |
| In-flight messages | Within RPO window | Replay completeness |

#### 8.6 `pilot-light` Profile

```
Primary (us-east-1)                  Recovery (us-west-2)
├── Full deployment                  ├── VPC provisioned (network layer)
├── Active services                  ├── ECS cluster (0 tasks)
├── DynamoDB global tables           ├── DynamoDB replica (active-active)
├── S3 CRR                          ├── S3 replicated bucket
├── KMS multi-region key             ├── KMS replica key
├── Cognito active pool              ├── Cognito pool pre-provisioned (empty)
├── API GW active                    ├── API GW provisioned (inactive)
└── Route53 primary                  └── Route53 standby

Failover:
  1. Fence primary writes (Phase 2-3)
  2. Terraform apply services layer in recovery (scale up ECS)
  3. Promote images to recovery ECR (full OCI graph, ADR-007)
  4. Import user attributes to recovery Cognito
  5. Enable UserMigration Lambda trigger
  6. Update API GW authorizer (dual-issuer)
  7. Switch Route53 failover records
  8. Update CloudFront origins
  9. Run document replay
  10. Validate (Phase 5)
```

| Metric | Target | Evidence |
|---|---|---|
| RTO | 1 hour (**UNTESTED**) | DR drill: measured timestamps |
| RPO | 15 minutes (**UNTESTED**) | DynamoDB Global Tables replication lag |
| Auth | Transparent if primary Cognito accessible | Measured migration % |

#### 8.7 `warm-standby` Profile

```
Primary (us-east-1)                  Recovery (us-west-2)
├── Full deployment                  ├── Full deployment (reduced scale)
├── Active services (full scale)     ├── Active services (min tasks)
├── DynamoDB global tables           ├── DynamoDB replica (active-active)
├── S3 CRR                          ├── S3 replicated bucket
├── KMS multi-region key             ├── KMS replica key
├── Cognito active pool              ├── Cognito pool w/ UserMigration
├── API GW active                    ├── API GW active (standby routing)
└── Route53 primary                  └── Route53 standby (health-checked)

Failover:
  1. Fence primary writes (Phase 2-3)
  2. Route53 health check → automatic DNS switch (TTL 60s)
  3. Auto-scaling scales up recovery ECS tasks
  4. Update API GW authorizer (dual-issuer)
  5. Run document replay
  6. Validate (Phase 5)
```

| Metric | Target | Evidence |
|---|---|---|
| RTO | 15 minutes (**UNTESTED**) | DR drill: failure detection → first successful write |
| RPO | Near-zero (**UNTESTED**) | DynamoDB Global Tables + S3 CRR lag |
| Auth | Mostly transparent via UserMigration | Measured auto-migration % vs forced reset |
| Write failover | 60–120s (DNS TTL + propagation) | Measured in drill |

### 9. Multi-Region Service Considerations

| Service | Regional? | DR Limitation | Mitigation |
|---|---|---|---|
| **VPC** | Regional | Must pre-provision or create during recovery | Pilot-light pre-provisions |
| **ECS** | Regional | Task definitions not replicated | Release manifest is source of truth |
| **DynamoDB** | Regional (global tables optional) | Global tables: ~30% cost; standard: PITR | Tier-dependent |
| **S3** | Regional (CRR) | CRR is async; large objects lag | RPO accounts for lag |
| **SQS** | Regional | **Messages NOT replicated** | DDB-first + replay + idempotency |
| **KMS** | Regional (multi-region) | Must pre-create replica key | Included in HA profiles |
| **Cognito** | Regional | **Passwords NOT exportable** | UserMigration trigger or forced reset |
| **ECR** | Regional | Images promoted per-region | ADR-007 promotion pipeline |
| **API Gateway** | Regional | Must exist per-region | Terraform provisions in recovery |
| **CloudFront** | Global | **Origin failover: GET/HEAD only** | CF for frontend only; Route53 for API |
| **CloudWatch** | Regional | No automatic aggregation | Cross-region dashboard |
| **Secrets Manager** | Regional (replication) | Must configure replication | Included in HA profiles |
| **IAM** | Global | Works across regions | No DR concern |
| **SSM Parameter Store** | Regional | Contracts are per-region | Deployment record tracks per-region |
| **AWS Signer** | Regional | Profile must be in same region as ECR | Capability matrix validates |

### 10. CloudFront Distribution Strategy

| Property | Value |
|---|---|
| Distribution | One per customer deployment (not shared) |
| Origins | **Frontend S3 ONLY** (primary + recovery origin group) |
| Origin failover | Primary S3 → Recovery S3 (GET/HEAD automatic) |
| **API traffic** | **NOT via CloudFront** — Route53 failover to regional API GW |
| WAF | Per-distribution WebACL |
| Response headers | CSP, HSTS, X-Content-Type-Options, X-Frame-Options |
| Cache policy | Static assets: 1 day. config.json: no cache. |

> [!IMPORTANT]
> **CloudFront does NOT proxy API traffic.** This is a deliberate simplification from rev2 that eliminates the GET/HEAD limitation for API failover. All API calls go through Route53 → API Gateway → ALB → ECS. CloudFront serves only the frontend SPA and static assets.

### 11. Network Architecture

Per-region VPC with consistent CIDR scheme:

```
Primary (us-east-1):
  VPC CIDR: 10.{x}.0.0/16
  Private subnets: 10.{x}.{1-3}.0/24 (one per AZ)
  Public subnets:  10.{x}.{11-13}.0/24 (one per AZ)

Recovery (us-west-2):
  VPC CIDR: 10.{x+1}.0.0/16
  Private subnets: 10.{x+1}.{1-3}.0/24
  Public subnets:  10.{x+1}.{11-13}.0/24
```

No VPC peering between primary and recovery (independent stacks). Cross-region communication is via AWS APIs (DynamoDB Global Tables, S3 CRR, etc.).

### 12. Data Sovereignty

- Data remains in the regions specified by the deployment record
- Cross-region replication is opt-in (HA tiers only)
- S3 CRR destination region must be in the same data sovereignty jurisdiction unless explicitly approved
- Deployment record documents all regions where data resides
- Cognito user data exports stay within approved regions

### 13. Observability Across Regions

| Component | Primary | Recovery | Cross-region |
|---|---|---|---|
| CloudWatch Metrics | Per-region | Per-region | Cross-region dashboard (read-only) |
| CloudWatch Logs | Per-region | Per-region | Cross-account log aggregation |
| CloudWatch Alarms | Per-region | Per-region | SNS topic per region |
| X-Ray | Per-region | Per-region | No cross-region tracing |
| Health checks | Route53 (global) | Route53 (global) | Single health dashboard |

### 14. DR Drill Requirements

> [!IMPORTANT]
> **No RTO/RPO claim may be contractually committed until validated by a DR drill with measured evidence.**

| Drill type | Frequency | Scope | Evidence |
|---|---|---|---|
| **Tabletop** | Quarterly | Walk through runbook with team | Gaps documented, estimated timestamps |
| **Component** | Semi-annually | Individual recovery steps | Measured time per step, success/failure |
| **Full** | Annually (HA tiers) | Simulate region failure, full failover | Full evidence schema below |

#### DR drill evidence schema

```json
{
  "drill_id": "DR-2026-Q3-001",
  "drill_type": "full",
  "drill_date": "2026-09-15",
  "deployment_id": "dep_01J5ABCDEF",
  "tier": "enterprise-ha",
  "profile": "warm-standby",
  "primary_region": "us-east-1",
  "recovery_region": "us-west-2",
  "results": {
    "failure_injected_at": "2026-09-15T14:00:00Z",
    "failure_detected_at": "2026-09-15T14:01:23Z",
    "write_fence_initiated_at": "2026-09-15T14:01:45Z",
    "write_fence_confirmed_at": "2026-09-15T14:02:30Z",
    "recovery_activated_at": "2026-09-15T14:02:45Z",
    "dns_failover_at": "2026-09-15T14:03:15Z",
    "first_successful_read_at": "2026-09-15T14:03:22Z",
    "first_successful_write_at": "2026-09-15T14:03:48Z",
    "dual_issuer_configured_at": "2026-09-15T14:02:50Z",
    "all_services_healthy_at": "2026-09-15T14:12:00Z",
    "measured_rto_seconds": 720,
    "target_rto_seconds": 900,
    "rto_met": true,
    "last_primary_write_at": "2026-09-15T13:59:58Z",
    "first_recovery_data_at": "2026-09-15T14:00:02Z",
    "measured_rpo_seconds": 4,
    "target_rpo_seconds": 0,
    "rpo_met": true,
    "write_fence": {
      "method": "ddb_region_active_flag",
      "fence_verified": true,
      "primary_write_after_fence_attempted": true,
      "primary_write_after_fence_rejected": true
    },
    "cognito": {
      "dual_issuer_enabled": true,
      "primary_tokens_accepted": true,
      "recovery_tokens_accepted": true,
      "auto_migrated_users": 142,
      "forced_reset_users": 3,
      "migration_rate": "97.9%",
      "primary_cognito_accessible": true
    },
    "api_routing": {
      "route53_failover_time_seconds": 75,
      "cloudfront_origin_failover_time_seconds": 8,
      "api_endpoint_verified": "api.customer.scanalyze.com"
    },
    "message_replay": {
      "messages_in_flight_at_failure": 47,
      "messages_replayed": 47,
      "messages_lost": 0,
      "replay_duration_seconds": 120
    },
    "issues_found": [],
    "runbook_gaps": []
  }
}
```

### 15. Preflight Region Validation

Before deploying to any region, the orchestrator runs a preflight check:

```
1. Load region capability matrix (configs/regions/{region}.json)
2. Verify all required services are available in target region
3. Verify AWS Signer profile exists in target region (ADR-007)
4. Verify KMS keys exist (or can be created) in target region
5. Verify ECR repositories exist (or will be created) in target region
6. Verify deployment tier's DR profile is compatible with region pair
7. Record preflight result in deployment record
```

---

## Consequences

### Positive
- Architecture is region-portable from day one
- DR limitations honestly documented (not hidden behind aspirational claims)
- Write fencing prevents split-brain during failover
- Unified API routing through Route53 eliminates CloudFront POST/PUT limitation
- Dual-issuer Cognito strategy provides transparent auth failover for most users
- DynamoDB-first write ordering enables SQS message replay
- DR drill requirement prevents unvalidated RTO/RPO claims
- Regional state keys and SSM contracts align with ADR-003 and ADR-006
- Cost model maintained separately from architecture decisions

### Negative
- Write fencing adds 1-2 minutes to failover sequence
- Dual-issuer authorizer requires temporary configuration change during failover
- Route53 DNS propagation adds 60-120s to API failover
- DynamoDB-first ordering is an architectural constraint on all write paths
- Cognito password limitation cannot be fully eliminated without third-party IdP
- DR drills require dedicated environments and engineering time
- Warm-standby doubles infrastructure cost

---

## References

- ADR-003 rev3: State Backend (regional state keys, ownership manifest)
- ADR-005: Schemas (region capability matrix, DR drill evidence schema)
- ADR-006 rev3: Modules (network module, deployment profiles, edge-identity layer)
- ADR-007 rev3: Supply Chain (per-region promotion, Signer same-region requirement)
- ADR-009: Threat Model (T8.1 data residency)
- [AWS Disaster Recovery Whitepaper](https://docs.aws.amazon.com/whitepapers/latest/disaster-recovery-workloads-on-aws/disaster-recovery-workloads-on-aws.html)
- [CloudFront Origin Failover](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/high_availability_origin_failover.html) (GET/HEAD only)
- [DynamoDB Global Tables](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/GlobalTables.html)
- [S3 Cross-Region Replication](https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication.html)
- [KMS Multi-Region Keys](https://docs.aws.amazon.com/kms/latest/developerguide/multi-region-keys-overview.html)
- [Cognito UserMigration Trigger](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-migrate-user.html)
- [Route53 Health Checks and Failover](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover.html)
- [AWS Availability Zone IDs](https://docs.aws.amazon.com/ram/latest/userguide/working-with-az-ids.html)
