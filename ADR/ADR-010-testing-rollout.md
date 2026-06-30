# ADR-010: Testing, Rollout, Migration, and Reproducibility

> **Status**: `DRAFT rev3`  
> **Date**: 2026-06-25  
> **Decision makers**: César Guzmán  
> **Scope**: Scanalyze Dedicated Deployment Platform  
> **Depends on**: ADR-003 rev3, ADR-004 rev3, ADR-005, ADR-006 rev3, ADR-007 rev3, ADR-008 rev3  
> **Rev3 changes**: P0-6 (zero write loss, DDB migration utility, full async drain) + P0-7 (ECS reconciliation, wave-based rollout)

---

## Context

The deployment platform must guarantee:

1. Every release is tested before reaching any customer
2. Rollout is incremental and reversible
3. The brownfield demo can be migrated to the greenfield architecture **without losing any accepted write**
4. The same inputs always produce the same outputs (reproducibility)
5. Rollback works even when data migrations are involved
6. ECS task definitions are managed by Terraform (sole owner), not by a separate pipeline step
7. ECS circuit breaker rollback must be reconciled with Terraform state

---

## Decision

### 1. Testing Layers

| Layer | Tool | Scope | Runs |
|---|---|---|---|
| **Unit tests** | pytest, vitest | Function/module logic | Every PR |
| **Contract tests** | JSON Schema + terraform test | Producer/consumer compatibility | Every PR |
| **Plan tests** | terraform plan + golden fixtures | Resource counts, expected changes | Every PR |
| **Policy tests** | IAM policy fixtures + Access Analyzer | IAM/S3/KMS least-privilege | Every PR |
| **Integration tests** | Terraform apply in test account | Full stack, real AWS resources | Per release |
| **Runtime validation** | Custom suite (§5) | Live deployment health | Per deployment |
| **Async drain tests** | Custom suite (§5.1) | SQS/DLQ/workflow completeness | Per deployment |
| **E2E smoke** | Playwright | Critical user journeys | Per deployment |

### 2. Test Data Management

- Test accounts use synthetic data exclusively
- No production data in test environments
- Synthetic data generators produce deterministic fixtures from seed values
- PII masking enforced in all test fixtures (ADR-009)

### 3. Golden Fixtures

Committed golden fixtures for both valid and invalid scenarios:

```
tests/golden/
├── valid/
│   ├── deployment-request-standard.json
│   ├── deployment-request-ha.json
│   ├── release-manifest-complete.json
│   └── contract-network-v1.json
├── invalid/
│   ├── deployment-request-missing-region.json
│   ├── contract-wrong-digest.json
│   ├── contract-wrong-deployment-id.json
│   └── release-manifest-unsigned.json
└── migration/
    ├── brownfield-dynamodb-export-sample.json
    ├── brownfield-s3-manifest-sample.json
    └── migration-checkpoint-sample.json
```

### 4. Rollout Strategy: Rings

| Ring | Environment | Approval | Soak time | Rollback |
|---|---|---|---|---|
| Ring 0 | Internal test account | Automated | 2 hours | Automated |
| Ring 1 | Internal demo | Automated + alert | 24 hours | Semi-automated |
| Ring 2 | First customer (canary) | Manual | 72 hours | Manual |
| Ring 3 | All remaining customers | Manual (batch) | — | Manual |

> [!IMPORTANT]
> Each ring must pass the full runtime validation suite (§5) including async verification before the next ring begins.

### 5. Runtime Validation Suite

| Check | Method | Pass criteria |
|---|---|---|
| All ECS services stable | `ecs:DescribeServices` | `runningCount == desiredCount` for all services |
| ALB target health | `elbv2:DescribeTargetHealth` | All targets healthy |
| API health endpoint | `GET /health` | 200 OK, response time < 500ms |
| API auth endpoint | `GET /auth/me` with valid token | 200 OK |
| SQS queue depth | `sqs:GetQueueAttributes` | `ApproximateNumberOfMessages < threshold` |
| SQS DLQ depth | `sqs:GetQueueAttributes` | `ApproximateNumberOfMessages == 0` for all DLQs |
| SQS in-flight | `sqs:GetQueueAttributes` | `ApproximateNumberOfMessagesNotVisible < threshold` |
| ECS task exits | `ecs:ListTasks` STOPPED filter | No non-zero exit codes in last 15 min |
| DynamoDB table status | `dynamodb:DescribeTable` | Status == ACTIVE |
| CloudWatch alarms | `cloudwatch:DescribeAlarms` | No alarms in ALARM state |
| Contract integrity | Read all SSM contracts | All parseable, all digests valid |
| Error rate | CloudWatch metrics | Error rate < 1% over 15 minutes |
| Latency p99 | CloudWatch metrics | p99 < 5 seconds |
| Log verification | CloudWatch Logs Insights | No ERROR-level entries in last 15 minutes |
| **Task digests** | `ecs:DescribeTaskDefinition` | Image digests match release manifest |

#### 5.1 Full Async Drain Criteria

> [!CAUTION]
> **Async drain is NOT just "SQS depth == 0".** Scanalyze has multiple async processing stages that must ALL complete before migration cutover or maintenance operations.

Complete drain requires ALL of the following to be true **and stable for ≥ 1× SQS visibility timeout**:

| Check | Query | Criteria |
|---|---|---|
| SQS queue depth | `ApproximateNumberOfMessages` per queue | == 0 for all queues |
| SQS in-flight | `ApproximateNumberOfMessagesNotVisible` per queue | == 0 for all queues |
| SQS DLQ depth | `ApproximateNumberOfMessages` per DLQ | == 0 for all DLQs |
| Workflow records | DynamoDB query: status IN (QUEUED, PROCESSING, RETRYING) | == 0 items |
| Active Textract jobs | DynamoDB query: textract_job_status IN (IN_PROGRESS, SUBMITTED) | == 0 items |
| Bedrock invocations | DynamoDB query: bedrock_status IN (IN_PROGRESS, SUBMITTED) | == 0 items |
| Postprocess pending | DynamoDB query: postprocess_status = PENDING | == 0 items |
| Metering events | DynamoDB query: metering_status = PENDING_FLUSH | == 0 items |
| Scheduled retries | DynamoDB query: next_retry_at < NOW + 1h | == 0 items |
| Worker tasks | `ecs:ListTasks` with RUNNING status for worker services | == 0 tasks (after scale-to-zero) |

Stable check: all conditions must remain true across 3 consecutive checks spaced by visibility timeout intervals (default: 30s × 3 = 90 seconds minimum).

### 6. Upgrade Procedure (per deployment)

> [!IMPORTANT]
> **Terraform is the sole owner of ECS task definitions.** There is NO separate "register task definition" step. The services root creates/updates `aws_ecs_task_definition` and `aws_ecs_service` resources together.

```
PRE-UPGRADE:
  1. Verify deployment status == ACTIVE
  2. Verify release manifest signature (KMS DSSE, ADR-007 rev3)
  3. Verify release attestation signature
  4. Record pre-upgrade state snapshot (all state version IDs to evidence)
  5. Promote full OCI artifact graph to customer ECR (ADR-007 rev3)
  6. Verify all destination digests match source
  7. Wait for customer ECR scan completion
  8. Evaluate scan gate policy (ADR-007 §13)

INFRASTRUCTURE UPGRADE:
  9. Update deployment record: status → UPGRADING
  10. For each layer (global → network → platform → data-foundation):
      a. terraform plan (Plan role, session policy scoped to layer)
      b. Verify plan within expected bounds
      c. Review plan (automated Ring 0; manual Ring 2+)
      d. Snapshot pre-apply state to recovery prefix
      e. terraform apply (Apply role, from saved plan)
      f. Record post-apply state version ID
      g. Verify contract readable and valid
      h. Per-layer health check

SERVICES LAYER — WAVE-BASED (§6.1):
  11. Deploy services in waves (not all simultaneously)
  12. Per wave: terraform plan → apply → wait for ECS steady state
  13. If circuit breaker fires → reconciliation procedure (§8)

EDGE-IDENTITY LAYER:
  14. terraform plan + apply for edge-identity root
  15. Verify Cognito, API Gateway, CloudFront configuration
  16. Verify authorizer configuration

ADDONS LAYER:
  17. terraform plan + apply for addons root
  18. Verify dashboards, alarms

FRONTEND CUTOVER:
  19. Deploy frontend to immutable release prefix (ADR-007 rev3)
  20. Update pointer/origin path to new release
  21. CloudFront invalidation
  22. Verify config.json correct for release

POST-UPGRADE:
  23. Runtime validation suite (§5, full async verification)
  24. Update deployment record: status → ACTIVE, release_version, evidence
  25. Notify operations (per ring communication plan)
```

#### 6.1 Wave-Based Service Deployment

> [!IMPORTANT]
> **Services are NOT deployed as a single `terraform apply` for all 7 services simultaneously.** A failing worker should not block the ingest API, and the ingest API should be verified before processing workers are updated.

| Wave | Services | Rationale |
|---|---|---|
| Wave 1 | `ingest-api` | Entry point — verify ingestion works before processing |
| Wave 2 | `classifier-worker` | Classification must work before domain workers |
| Wave 3 | `bank-worker`, `personal-worker`, `gov-worker` | Domain workers (parallelizable, no interdependency) |
| Wave 4 | `ocr-worker`, `postprocess-worker` | Supporting workers |

Implementation: The orchestrator executes the services root with wave-scoped variables. Each wave:

```
For each wave in [1, 2, 3, 4]:
  1. Set wave_target = [services in this wave]
  2. terraform plan for services root
     - Plan shows changes only for targeted services
     - Other services remain at current state
  3. Review plan (wave-level approval for Ring 2+)
  4. terraform apply
  5. Wait for ECS steady state for this wave's services
  6. Runtime validation (focused on this wave's services)
  7. If any service in wave fails:
     - STOP remaining waves
     - Trigger reconciliation (§8) for failed services
     - Do NOT proceed to next wave
```

> [!NOTE]
> Wave deployment is implemented via orchestrator sequencing and service-group variables, NOT via `terraform -target`. Using `-target` routinely is fragile and skips dependency graph validation. The services module accepts a `deploy_wave` variable that controls which services are updated in each apply.

### 7. Automated Rollback Triggers

| Trigger | Source | Action |
|---|---|---|
| ECS task failure (>50%) | ECS circuit breaker | Automatic: ECS reverts to previous task def revision |
| Error rate > 5% for 5 min | CloudWatch alarm | Alert → investigate → reconciliation if confirmed |
| p99 latency > 10s for 10 min | CloudWatch alarm | Alert → investigate |
| DLQ messages > 0 post-deploy | CloudWatch alarm | Alert → investigate → reconciliation if processing failure |
| ECS tasks exiting non-zero | CloudWatch alarm | Alert → investigate |
| Health endpoint non-200 | ALB health check | ECS replaces task |

### 8. ECS Circuit Breaker → Terraform Reconciliation

> [!CAUTION]
> **When ECS circuit breaker fires, Terraform state and ECS runtime diverge.** Terraform state says "ECS service uses task def revision N+1" but ECS has already rolled back to revision N. This MUST be reconciled.

#### Reconciliation procedure

```
TRIGGER: ECS circuit breaker reverts service to previous task definition

DETECT:
  1. Orchestrator monitors ECS deployment events
  2. Detects DEPLOYMENT_FAILED event
  3. Halts current release for this wave

CONFIRM:
  4. Query ECS: ecs:DescribeServices → get active task definition revision
  5. Query ECS: ecs:DescribeTaskDefinition → get image digests of active revision
  6. Compare with Terraform state expectation
  7. Record drift: "TF expects revision N+1, ECS running revision N"

RECONCILE (forward apply with previous release config):
  8. Identify previous release version (N) from deployment record
  9. Orchestrator re-renders terraform.tfvars with release N configuration
  10. terraform plan for services root:
      - Plan should show: task definition → revision matching what ECS is running
      - Plan should show: ECS service → task_definition attribute matches active
  11. Review plan (mandatory for all rings — reconciliation is sensitive)
  12. terraform apply
      - Terraform state now matches ECS runtime
      - No ECS deployment triggered (already running the right revision)
  13. Runtime validation suite

POST-RECONCILIATION:
  14. Update deployment record:
      - release_version → N (previous)
      - status → ACTIVE
      - reconciliation_evidence → { drift detected, plan reviewed, applied }
  15. Release N+1 blocked for ALL rings until root cause resolved
  16. Fix → new release candidate (N+2) → restart from Ring 0
  17. Mandatory incident report
```

> [!IMPORTANT]
> **Reconciliation is a FORWARD APPLY, not a state restoration.** The state always moves forward. The desired config is set to match what ECS is actually running (the previous release). This is consistent with ADR-003 rev3: state restoration is only for corruption/loss.

### 9. Manual Rollback Procedure

```
TRIGGER: upgrade failure at any step, or metric threshold exceeded

RELEASE ROLLBACK (forward-apply with previous config):
  1. Identify previous release version (N) and failed release (N+1)
  2. Update deployment record: release_version → N
  3. Orchestrator re-renders terraform.tfvars with release N configuration
  4. For each layer (in dependency order):
     a. terraform plan (shows revert to N's configuration)
     b. Review plan
     c. terraform apply (forward apply)
  5. Services layer: wave-based rollback (reverse wave order: 4→3→2→1)
  6. ECS performs rolling deployment to previous image digests

FRONTEND ROLLBACK:
  1. Update pointer/origin path to previous release prefix
  2. CloudFront invalidation
  3. Verify config.json correct for previous release

POST-ROLLBACK:
  1. Runtime validation suite (§5, full async verification)
  2. Deployment record: status → ACTIVE (previous release version)
  3. Mandatory incident report
  4. Release N+1 blocked for ALL rings until root cause resolved
  5. Fix → new release candidate (N+2) → restart from Ring 0
```

> [!IMPORTANT]
> **Rollback does NOT restore previous state versions.** That is state restoration, used only for corruption/loss (ADR-003 rev3). Release rollback re-deploys the previous release's configuration using the normal pipeline.

### 10. Data Migration: Brownfield → Greenfield

> [!CAUTION]
> **ZERO accepted writes may be lost during migration.** The 60-minute write-loss window from rev2 is eliminated. After the first accepted write in greenfield, the migration is forward-only.

#### Phase M0: Parallel Deployment

```
Greenfield deployed in same account (or new account):
  - All layers provisioned by Terraform
  - All tables created by Terraform (empty)
  - All queues created by Terraform (empty)
  - Cognito pool created (empty)
  - ECR images promoted
  - Frontend deployed to immutable release prefix
  - Greenfield operates in VALIDATION mode:
    * Accepts only synthetic test traffic
    * Does NOT accept real user traffic
    * Validates all layers functional
    * Runs full runtime validation suite
```

#### Phase M1: Data Migration

##### S3 Document Migration

```
Brownfield S3 → Greenfield S3:
  - aws s3 sync --sse aws:kms --checksum-algorithm SHA256
  - Integrity verification:
    a. Object count: source count == destination count
    b. Per-object checksum: S3 additional checksums (SHA-256)
       aws s3api head-object --bucket DEST --key KEY --checksum-mode ENABLED
       Compare ChecksumSHA256 between source and destination
    c. For objects without S3 checksums: download + local SHA-256
    d. Sample verification: randomly verify 10% with full download + hash
  - NEVER use ETags as sole integrity check
    (multipart ETags are composite, SSE-KMS ETags are not plaintext MD5)
```

##### DynamoDB Migration (Custom Utility, NOT ImportTable)

> [!WARNING]
> **`aws dynamodb import-table` creates a NEW table.** This conflicts with Terraform's ownership of the table resource. The greenfield table is already created by Terraform. Data must be loaded into the existing table.

```
Migration utility:
  1. Export brownfield table:
     aws dynamodb export-table-to-point-in-time \
       --table-arn BROWNFIELD_TABLE \
       --s3-bucket EXPORT_BUCKET \
       --export-format DYNAMODB_JSON

  2. Convert and load into greenfield table (existing, TF-managed):
     For each exported item (paginated, checkpointed):
       a. Parse DynamoDB JSON format
       b. Add migration metadata:
          _migration_id: "M-2026-Q3-001"
          _migration_source: "brownfield"
          _migration_version: 1
       c. Write via BatchWriteItem (25 items/batch)
       d. Use conditional write: attribute_not_exists(PK)
          OR version_attribute < source_version
       e. Checkpoint: record last processed export segment + offset

  3. Integrity verification:
     a. Item count: export manifest count == greenfield scan count
     b. Sample verification: randomly read 5% of items, compare all attributes
     c. Key verification: scan all PKs in source, verify all exist in destination
     d. Hash verification: SHA-256 of JSON-serialized items (sorted keys)

  4. Incremental sync (during M1-M2 gap):
     a. Export incremental changes since M1 full export
     b. Apply deltas with conditional writes (version check)
     c. NOTE: incremental exports are NOT transactionally consistent
        Items may appear in inconsistent states; the final sync
        in M2 resolves this with the maintenance window drain
```

> [!NOTE]
> **Checkpointed resume**: if the migration utility crashes, it resumes from the last checkpoint. Each checkpoint records: export segment, offset within segment, items written, items skipped (already exist), items failed (logged for manual review).

##### Cognito User Migration

> [!WARNING]
> **UserMigration trigger and pre-importing users are incompatible strategies.** The UserMigration trigger only fires when a user does NOT exist in the pool. If users are pre-created, the trigger never fires and passwords cannot be migrated.

Choose ONE strategy per migration:

| Strategy | Steps | Password impact | When to use |
|---|---|---|---|
| **Lazy migration** | Do NOT pre-create users. Configure UserMigration trigger. On first login, trigger authenticates against brownfield pool and creates user in greenfield. | Transparent (if brownfield accessible) | Brownfield Cognito will remain accessible during migration |
| **Bulk import** | Pre-create all users via AdminCreateUser. Force RESET_REQUIRED. | All users must reset password | Brownfield Cognito may be decommissioned before migration |

Additional Cognito migration items:
- Groups: recreate in greenfield pool, reassign memberships
- App clients: create with matching scopes and callback URLs
- M2M credentials: create new client_credentials grants, update consumers
- Custom attributes: ensure schema matches (custom:customerId, etc.)
- MFA: re-enrollment required (TOTP seeds are not exportable)

#### Phase M2: Traffic Cutover

> [!CAUTION]
> **After the first accepted write in greenfield, rollback is forward-only.** There is no write-loss window. The cutover sequence ensures brownfield is fully drained before greenfield accepts any real traffic.

```
PRE-CUTOVER:
  1. Greenfield passes full validation suite (synthetic traffic)
  2. Schedule maintenance window (communicated to customer per §11)

BROWNFIELD DRAIN:
  3. Brownfield enters maintenance mode:
     a. API returns 503 with Retry-After header for all write endpoints
     b. Read endpoints remain available (read-only mode)
  4. Full async drain (§5.1 criteria):
     ALL conditions stable for ≥ 1× visibility timeout
  5. Brownfield reads disabled (full maintenance mode)

FINAL SYNC:
  6. Final incremental data sync:
     a. S3: sync objects modified since last M1 sync
     b. DynamoDB: export incremental + apply deltas with conditional writes
     c. Integrity verification (counts, sample hashes)
     d. Record sync evidence: item counts, checksum results, duration

CUTOVER:
  7. Greenfield transitions from VALIDATION to ACTIVE mode
  8. DNS switch: brownfield domain → greenfield endpoints
  9. Greenfield begins accepting real traffic (first accepted write)
  10. FROM THIS POINT: forward-only (no rollback to brownfield without
      data reconciliation)

POST-CUTOVER MONITORING:
  11. Runtime validation suite running continuously for 24 hours
  12. On-call monitoring with 15-minute response SLA
  13. If critical failure detected:
      → STOP greenfield writes (503 maintenance mode)
      → Assess: is data reconciliation feasible?
      → If data reconciliation needed: supervised reverse delta sync (§10.1)
      → This is NOT automatic — requires manual assessment
  14. After 24h clean: brownfield → SUSPENDED
```

#### 10.1 Reverse Delta Sync (Emergency Only)

> [!WARNING]
> **Reverse delta sync is a supervised, manual emergency procedure.** It is NOT an automated rollback. It exists for the case where greenfield must be abandoned after accepting writes.

```
TRIGGER: critical greenfield failure after accepting writes

  1. STOP greenfield writes (503 maintenance mode)
  2. Full async drain on greenfield (§5.1)
  3. Identify writes that occurred only in greenfield:
     a. DynamoDB: query items with _migration_source != "brownfield"
        OR updated_at > cutover_timestamp
     b. S3: list objects with LastModified > cutover_timestamp
  4. Sync deltas to brownfield:
     a. DynamoDB: PutItem with condition (version check, no overwrite of older data)
     b. S3: copy new objects with SHA-256 verification
  5. Integrity verification on brownfield
  6. DNS revert to brownfield
  7. Brownfield exits maintenance mode
  8. This is a MANUAL, SUPERVISED operation
  9. Mandatory incident report with root cause analysis
```

#### Phase M3: Brownfield Decommission

```
After 30 days of stable greenfield operation:
  1. Verify no traffic to brownfield endpoints (access logs)
  2. Final data backup of brownfield (regulatory retention)
  3. Decommission brownfield infrastructure
  4. Retain brownfield data backups per retention policy
  5. Update deployment record: brownfield_status → DECOMMISSIONED
```

### 11. Communication Plan

| Event | Audience | Channel | Lead time |
|---|---|---|---|
| Maintenance window (migration) | Customer + operations | Email + in-app banner | 72 hours |
| Ring 2+ deployment | Customer | Email notification | 48 hours |
| Emergency rollback | Customer + operations | Email + phone | Immediate |
| Post-deployment summary | Operations | Automated report | Within 1 hour |

### 12. Feature Flags

Feature flags via runtime configuration (config.json for frontend, SSM parameters for backend) enable gradual feature rollout independent of infrastructure deployment:

- New features deployed behind flags (default: disabled)
- Flags enabled per ring after infrastructure stability confirmed
- Flags are NOT a substitute for tested releases
- Flag state recorded in deployment record

### 13. Reproducibility Guarantees

| Input | Must produce same output |
|---|---|
| Same deployment request + same release | Same terraform plan (deterministic) |
| Same release manifest | Same image digests, module digests, toolchain versions |
| Same contract inputs | Same contract outputs (deterministic module logic) |
| Same configuration | Same task definitions (Terraform-managed) |

### 14. Graduation Criteria

A release graduates from Ring N to Ring N+1 when:

| Criteria | Evidence |
|---|---|
| Runtime validation passes | Automated report |
| Soak time complete | Timestamp verification |
| No rollback triggers fired | CloudWatch alarm history |
| Async verification passes | DLQ == 0, no stuck workflows |
| Error rate < baseline | CloudWatch metrics comparison |
| No manual incidents | Incident log |

---

## Consequences

### Positive
- **Zero accepted-write loss** — no data discarded during migration
- Terraform sole owner of ECS task definitions eliminates dual-ownership
- ECS circuit breaker reconciliation keeps TF state consistent with runtime
- Wave-based rollout isolates service failures
- Full async drain criteria prevents premature cutover
- DynamoDB migration utility works with existing TF-managed tables
- Checkpointed, resumable, idempotent migration with integrity verification
- Forward-only after first write is an honest, defensible position
- Cognito migration strategy clearly separates lazy vs bulk approaches

### Negative
- Migration utility is custom code that must be tested thoroughly
- Wave-based deployment is slower than single apply
- Full async drain may require extended maintenance window
- Reconciliation after circuit breaker requires manual plan review
- No instant rollback for container image changes (must go through TF)
- Reverse delta sync is manual and risky (emergency only)
- Incremental DynamoDB exports are not transactionally consistent

---

## References

- ADR-003 rev3: State (recovery procedure, state restoration vs rollback, plan-execution zone)
- ADR-004 rev3: Cross-Account Identity (Plan/Apply roles, session policies)
- ADR-005: Schemas (golden fixtures, contract tests)
- ADR-006 rev3: Modules (services layer, wave deployment, precondition gates)
- ADR-007 rev3: Supply Chain (full OCI graph promotion, release manifest signing, immutable frontend)
- ADR-008 rev3: Region/HA/DR (Cognito migration, SQS replay, write fencing)
- ADR-009: Threat Model (T7.3 rollback failure, T7.5 insider)
- [AWS ECS Rolling Deployments](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/deployment-type-ecs.html)
- [AWS ECS Deployment Circuit Breaker](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/deployment-circuit-breaker.html)
- [AWS S3 Additional Checksums](https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html)
- [AWS DynamoDB Export](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/S3DataExport.HowItWorks.html)
- [AWS DynamoDB ImportTable](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/S3DataImport.HowItWorks.html) (NOT used — creates new table)
- [AWS Cognito UserMigration Trigger](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-migrate-user.html)
- [Terraform Saved Plans](https://developer.hashicorp.com/terraform/cli/commands/plan#out-filename)
