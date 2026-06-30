# ADR-003: Terraform State, Backend Strategy, Locking, Recovery, and Ownership

> **Status**: `DRAFT rev3`  
> **Date**: 2026-06-23  
> **Decision makers**: César Guzmán  
> **Scope**: Scanalyze Dedicated Deployment Platform  
> **Depends on**: ADR-001, ADR-002, ADR-004 rev3  
> **Rev3 changes**: P0-4 (correct principals, valid S3 actions, per-key permissions, targeted deny patterns) + P0-5 (ephemeral plans, sanitized evidence, restricted recovery) + regional state keys + ownership updated for account baseline

---

## Context

The current brownfield deployment has fragmented Terraform state with dual ownership issues (see state audit). The greenfield platform must enforce strict state ownership from day one.

State files contain resource identifiers, some configuration values, and can contain sensitive attributes. Saved plans contain configuration, input variables, and **sensitive values in cleartext** even when Terraform redacts them in console output. Both require careful access control and lifecycle management.

---

## Decision

### 1. Three Storage Zones per Customer Account

Each customer account has **three S3 storage zones** for Terraform operations, each with distinct security properties:

```
Customer Account (${CUSTOMER_ACCT})

├── S3: scanalyze-${CUSTOMER_ACCT}-tf-state               ← STATE BUCKET
│   ├── Purpose: Terraform state files + .tflock files
│   ├── KMS: alias/scanalyze-tf-state-key
│   ├── Versioning: ENABLED
│   ├── Object Lock: NONE (lockfiles must be deletable)
│   ├── Lifecycle: noncurrent versions retained 90 days
│   ├── Access: Plan (read+lock), Apply (read+write), Diagnostic (read),
│   │          StateRecovery (read+write on state keys only)
│   └── Block Public Access: ALL enabled
│
├── S3: scanalyze-${CUSTOMER_ACCT}-tf-evidence             ← EVIDENCE BUCKET
│   ├── Purpose: Sanitized audit trail (digests, summaries, approval records)
│   ├── KMS: alias/scanalyze-tf-evidence-key
│   ├── Versioning: ENABLED
│   ├── Object Lock: COMPLIANCE
│   │   ├── Default: 90 days (summaries), 365 days (apply logs)
│   ├── Access: Apply (write sanitized records), Diagnostic (read),
│   │          Validation (read)
│   └── Block Public Access: ALL enabled
│
└── Prefix in state bucket: plan-execution/                 ← PLAN EXECUTION ZONE
    ├── Purpose: Ephemeral plan binaries and full plan JSON
    ├── TTL: 24–72 hours (S3 lifecycle rule)
    ├── Object Lock: NONE
    ├── Access: Plan (write), Apply (read+delete after use)
    ├── Contains: plan binary, plan JSON, plan digest, state lineage/serial
    └── Automatically deleted by lifecycle rule after TTL
```

> [!IMPORTANT]
> **Why three zones:**
> - **State bucket**: No Object Lock because `.tflock` must be deletable. Contains live state and ephemeral plan-execution artifacts.
> - **Evidence bucket**: COMPLIANCE Object Lock for immutable audit. Contains ONLY sanitized summaries — never raw plans, state snapshots, or secrets.
> - **Plan execution prefix**: Ephemeral within state bucket. Plans contain secrets in cleartext. Short TTL + auto-deletion ensures no long-lived sensitive copies.

### 2. State Restoration vs Release Rollback

These are **two completely different operations**:

| | State Restoration | Release Rollback |
|---|---|---|
| **When** | State file is corrupt, deleted, or out of sync with reality | Deployed release N+1 is broken, want to return to N |
| **Cause** | Operational failure (S3 issue, partial write, accidental deletion) | Application failure (bugs, regressions, broken config) |
| **Action** | Restore previous S3 object version → verify with `terraform plan` | Re-run deployment pipeline with release N's configuration → new forward apply |
| **Role** | `ScanalyzeCustomer-StateRecovery` (break-glass) | `ScanalyzeCustomer-Plan` + `ScanalyzeCustomer-Apply` (orchestrator) |
| **State mutation** | Yes (restoring a previous version) | No (normal plan+apply cycle with previous release config) |
| **Trigger** | Break-glass with incident_id | Orchestrator rollback command |
| **Evidence** | Incident report, version restored, plan diff | Normal deployment record with rollback flag |

> [!WARNING]
> **Release rollback NEVER restores a previous state version.** It creates a NEW plan using the previous release's configuration (images, modules, variables) and applies it forward. The state always moves forward — only the desired configuration changes.

#### State Restoration Procedure (break-glass only)

```
TRIGGER: State corruption, deletion, or unrecoverable inconsistency
ROLE: ScanalyzeCustomer-StateRecovery (via break-glass)

1. DECLARE incident and obtain incident_id
2. Assume Diagnostic role → identify corruption:
   - terraform state list → parse error? → corruption
   - terraform plan → unexpected destroy-all? → inconsistency
   - S3 object missing? → deletion
3. Assume StateRecovery role (requires operation=state-recovery tag)
4. List S3 object versions for affected key:
   aws s3api list-object-versions --bucket scanalyze-ACCT-tf-state \
     --prefix "{dep_id}/{region}/{layer}/terraform.tfstate"
5. Identify last known-good version (cross-reference with evidence)
6. Restore by GET + PUT (NOT s3:CopyObject which is not a valid IAM action):
   aws s3api get-object --bucket scanalyze-ACCT-tf-state \
     --key "{dep_id}/{region}/{layer}/terraform.tfstate" \
     --version-id GOOD_VERSION /tmp/restored.tfstate
   aws s3api put-object --bucket scanalyze-ACCT-tf-state \
     --key "{dep_id}/{region}/{layer}/terraform.tfstate" \
     --body /tmp/restored.tfstate \
     --server-side-encryption aws:kms --ssekms-key-id alias/scanalyze-tf-state-key
7. Securely delete local copy: shred -u /tmp/restored.tfstate
8. Verify via normal orchestrator:
   terraform state list → resources match expectations
   terraform plan → review diff
9. If plan is clean or expected: apply via normal orchestrator pipeline
10. If plan is unexpected: STOP, escalate
11. Document: root cause, version restored, plan diff, preventive measures
```

> [!IMPORTANT]
> **`s3:CopyObject` is NOT a valid IAM action.** S3 CopyObject requires `s3:GetObject` (or `s3:GetObjectVersion`) on the source and `s3:PutObject` on the destination. The StateRecovery role has both permissions on the state bucket.

### 3. Ownership Rules — Logical Resource Namespaces

State ownership uses **logical resource namespaces**, not resource-type prefixes:

| Rule | Description | Enforcement |
|---|---|---|
| **1 root = 1 state key** | Each root writes exactly one S3 key | CI check |
| **1 state key = 1 root** | Each key is written by exactly one root | CI check |
| **Namespace ownership** | Each root owns a declared logical namespace | `ownership.yaml` |
| **No cross-layer reads** | Layers use SSM contracts, never `terraform_remote_state` | CI grep |
| **No import without evidence** | `terraform import` requires reason, plan diff, approval | Process |
| **No workspaces** | Terraform workspaces rejected (see §8) | CI check |

### 4. Ownership Manifest — Logical Namespaces

```yaml
# ownership.yaml
version: "2"
deployment_template: true
account_baseline_owner: "AccountVendingProvider"

# Account baseline resources (NOT managed by deployment layers)
account_baseline:
  owner: "AccountVendingProvider"
  state: "managed by account vending, NOT in deployment state"
  owns:
    - "ScanalyzeCustomer-Plan role, trust policy, permissions boundary"
    - "ScanalyzeCustomer-Apply role, trust policy, permissions boundary"
    - "ScanalyzeCustomer-Promotion role, trust policy, permissions boundary"
    - "ScanalyzeCustomer-Validation role, trust policy, permissions boundary"
    - "ScanalyzeCustomer-Diagnostic role, trust policy, permissions boundary"
    - "ScanalyzeCustomer-StateRecovery role, trust policy, permissions boundary"
    - "State S3 bucket, evidence S3 bucket, contracts S3 bucket"
    - "Infrastructure KMS keys (state, evidence, contracts)"

namespaces:
  global:
    root: roots/global
    backend_key: "{deployment_id}/global/terraform.tfstate"
    description: "ECS task execution role, ECS task roles, application IAM policies"
    owns:
      - "ECS task execution role and policy attachments"
      - "ECS task roles (per-service)"
      - "Application permissions boundaries"
    note: "Control-plane roles (Plan/Apply/Promotion/Validation/Diagnostic/StateRecovery) are NOT here. They belong to account baseline."

  network:
    root: roots/network
    backend_key: "{deployment_id}/{region}/network/terraform.tfstate"
    description: "VPC, subnets, NAT gateways, VPC endpoints, route tables"
    owns:
      - "VPC and all child networking resources"
      - "VPC endpoints for AWS services"
      - "Security groups for VPC endpoints"
      - "VPC Flow Logs"
    contract: "/scanalyze/deployments/{deployment_id}/contracts/network/v1"

  platform:
    root: roots/platform
    backend_key: "{deployment_id}/{region}/platform/terraform.tfstate"
    description: "ECS cluster, ALB, listener rules, security groups for compute"
    owns:
      - "ECS cluster"
      - "Application Load Balancer and listeners"
      - "Target groups"
      - "Security groups for ALB and ECS tasks"
    contract: "/scanalyze/deployments/{deployment_id}/contracts/platform/v1"

  data-foundation:
    root: roots/data-foundation
    backend_key: "{deployment_id}/{region}/data-foundation/terraform.tfstate"
    description: "DynamoDB tables, S3 document buckets, SQS queues, KMS app keys"
    owns:
      - "All DynamoDB tables (per processing domain)"
      - "All S3 document/output buckets (per processing domain)"
      - "All SQS queues and DLQs"
      - "All application KMS keys (per processing domain)"
    contract: "/scanalyze/deployments/{deployment_id}/contracts/data-foundation/v1"

  services:
    root: roots/services
    backend_key: "{deployment_id}/{region}/services/terraform.tfstate"
    description: "ECS services, task definitions, auto-scaling"
    owns:
      - "All ECS task definitions (Terraform sole owner — ADR-010)"
      - "All ECS services"
      - "Application auto-scaling targets and policies"
      - "CloudWatch alarms for ECS services"
      - "CloudWatch log groups for services"
    contract: "/scanalyze/deployments/{deployment_id}/contracts/services/v1"

  edge-identity:
    root: roots/edge-identity
    backend_key: "{deployment_id}/edge/terraform.tfstate"
    description: "Cognito, API Gateway, CloudFront, WAF, ACM, Route53"
    owns:
      - "Cognito user pool, clients, domain"
      - "API Gateway HTTP API, stages, routes, integrations, JWT authorizer"
      - "CloudFront distribution, OAC, response headers policy"
      - "WAF WebACL"
      - "Route53 records"
      - "ACM certificates"
    contract: "/scanalyze/deployments/{deployment_id}/contracts/edge-identity/v1"
    note: "Global/edge resources — not regional. Single state key without region prefix."

  addons:
    root: roots/addons
    backend_key: "{deployment_id}/{region}/addons/terraform.tfstate"
    description: "CloudWatch dashboards, composite alarms, optional enterprise features"
    owns:
      - "CloudWatch dashboards"
      - "CloudWatch composite alarms"
      - "Optional enterprise feature resources"
    contract: "/scanalyze/deployments/{deployment_id}/contracts/addons/v1"
```

> [!IMPORTANT]
> **Key change from rev2**: `global` layer no longer owns the 6 control-plane roles — those moved to the account baseline (ADR-004 rev3). `addons` has been split: auth/CDN/API resources → `edge-identity`, optional features → `addons`.

### 5. State Key Naming Convention — Regional

```
Non-regional layers (one instance per deployment):
  {deployment_id}/global/terraform.tfstate
  {deployment_id}/edge/terraform.tfstate

Regional layers (one instance per deployment × region):
  {deployment_id}/{region}/network/terraform.tfstate
  {deployment_id}/{region}/platform/terraform.tfstate
  {deployment_id}/{region}/data-foundation/terraform.tfstate
  {deployment_id}/{region}/services/terraform.tfstate
  {deployment_id}/{region}/addons/terraform.tfstate
```

| Layer | Key pattern | Regional? |
|---|---|---|
| global | `{dep_id}/global/terraform.tfstate` | No |
| edge-identity | `{dep_id}/edge/terraform.tfstate` | No (CloudFront/Route53 are global/edge) |
| network | `{dep_id}/{region}/network/terraform.tfstate` | Yes |
| platform | `{dep_id}/{region}/platform/terraform.tfstate` | Yes |
| data-foundation | `{dep_id}/{region}/data-foundation/terraform.tfstate` | Yes |
| services | `{dep_id}/{region}/services/terraform.tfstate` | Yes |
| addons | `{dep_id}/{region}/addons/terraform.tfstate` | Yes |

> [!NOTE]
> SSM Parameter Store is regional. The same contract path can exist in different regions natively. The deployment record must register `{region}/{layer}` explicitly for each contract produced.

### 6. Evidence Key Naming Convention

Evidence store contains **sanitized summaries only** — never raw plans, state files, or secrets.

```
s3://scanalyze-${CUSTOMER_ACCT}-tf-evidence/{deployment_id}/{region}/{layer}/...
```

| Content | Key pattern | Retention | Contains secrets? |
|---|---|---|---|
| Plan summary (sanitized) | `{dep_id}/{region}/{layer}/plans/{change_id}-summary.json` | 90 days | **NO** — digest, resource counts, action list only |
| Plan digest | `{dep_id}/{region}/{layer}/plans/{change_id}-digest.sha256` | 90 days | No |
| Approval record | `{dep_id}/{region}/{layer}/plans/{change_id}-approval.json` | 90 days | No |
| Apply execution log (sanitized) | `{dep_id}/{region}/{layer}/apply-logs/{change_id}.log` | 365 days | **NO** — sanitized, credential patterns redacted |
| Apply metadata | `{dep_id}/{region}/{layer}/apply-logs/{change_id}-meta.json` | 365 days | No — state version IDs, release manifest digest, execution ID |
| Drift detection report | `{dep_id}/{region}/{layer}/drift/{date}.json` | 90 days | No |

> [!CAUTION]
> **The evidence bucket NEVER contains:**
> - Plan binary (`.tfplan`) — contains secrets in cleartext
> - Full plan JSON — contains sensitive attribute values
> - State file copies — contain resource configs
> - Raw input variables — may contain sensitive values
>
> These are stored temporarily in the **plan-execution zone** (§1) with 24-72h auto-deletion.

### 7. Plan Execution Zone (Ephemeral)

Plans contain sensitive data. They are stored briefly for the apply step and then auto-deleted.

```
s3://scanalyze-${CUSTOMER_ACCT}-tf-state/plan-execution/{dep_id}/{change_id}/...
```

| Content | Key | TTL | Purpose |
|---|---|---|---|
| Plan binary | `plan-execution/{dep_id}/{change_id}/{layer}.tfplan` | 24–72h | Apply reads this to execute the saved plan |
| Plan JSON | `plan-execution/{dep_id}/{change_id}/{layer}.plan.json` | 24–72h | Optional — only if policy evaluation requires full JSON |
| Plan digest | `plan-execution/{dep_id}/{change_id}/{layer}.sha256` | 24–72h | Apply verifies digest before executing |
| State lineage | `plan-execution/{dep_id}/{change_id}/{layer}-lineage.json` | 24–72h | Verify state hasn't changed between plan and apply |

| Role | Permissions on plan-execution/ prefix |
|---|---|
| Plan | `s3:PutObject` (writes plan artifacts) |
| Apply | `s3:GetObject`, `s3:DeleteObject` (reads then deletes after apply) |
| Diagnostic | No access (default) |
| StateRecovery | No access |

> [!NOTE]
> S3 lifecycle rule deletes objects under `plan-execution/` prefix after 72 hours. Even if the Apply role fails to delete after use, the lifecycle rule ensures no long-lived sensitive copies.

### 8. Recovery Store (Restricted)

Pre-apply state snapshots for disaster recovery are stored in a separate restricted prefix within the state bucket.

```
s3://scanalyze-${CUSTOMER_ACCT}-tf-state/recovery/{dep_id}/{change_id}/...
```

| Content | Key | Retention | Purpose |
|---|---|---|---|
| Pre-apply state snapshot | `recovery/{dep_id}/{change_id}/{layer}-pre.tfstate` | 30 days | Restore point if apply causes corruption |

| Role | Permissions on recovery/ prefix |
|---|---|
| Apply | `s3:PutObject` (writes snapshot before each apply) |
| StateRecovery | `s3:GetObject`, `s3:GetObjectVersion` (reads for restoration) |
| Diagnostic | No access (contains sensitive state data) |
| Plan | No access |

### 9. Bucket Policies

#### State Bucket Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PlanRoleStateRead",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${CUSTOMER_ACCT}:role/ScanalyzeCustomer-Plan"
      },
      "Action": [
        "s3:GetObject",
        "s3:GetObjectVersion"
      ],
      "Resource": "arn:aws:s3:::scanalyze-${CUSTOMER_ACCT}-tf-state/${DEPLOYMENT_ID}/*/terraform.tfstate"
    },
    {
      "Sid": "PlanRoleLockReadWriteDelete",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${CUSTOMER_ACCT}:role/ScanalyzeCustomer-Plan"
      },
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject"
      ],
      "Resource": "arn:aws:s3:::scanalyze-${CUSTOMER_ACCT}-tf-state/${DEPLOYMENT_ID}/*/terraform.tfstate.tflock"
    },
    {
      "Sid": "PlanRoleListBucket",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${CUSTOMER_ACCT}:role/ScanalyzeCustomer-Plan"
      },
      "Action": [
        "s3:ListBucket",
        "s3:ListBucketVersions"
      ],
      "Resource": "arn:aws:s3:::scanalyze-${CUSTOMER_ACCT}-tf-state",
      "Condition": {
        "StringLike": {
          "s3:prefix": "${DEPLOYMENT_ID}/*"
        }
      }
    },
    {
      "Sid": "PlanRolePlanExecutionWrite",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${CUSTOMER_ACCT}:role/ScanalyzeCustomer-Plan"
      },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::scanalyze-${CUSTOMER_ACCT}-tf-state/plan-execution/${DEPLOYMENT_ID}/*"
    },
    {
      "Sid": "ApplyRoleStateReadWrite",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${CUSTOMER_ACCT}:role/ScanalyzeCustomer-Apply"
      },
      "Action": [
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::scanalyze-${CUSTOMER_ACCT}-tf-state/${DEPLOYMENT_ID}/*/terraform.tfstate"
    },
    {
      "Sid": "ApplyRoleLockReadWriteDelete",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${CUSTOMER_ACCT}:role/ScanalyzeCustomer-Apply"
      },
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject"
      ],
      "Resource": "arn:aws:s3:::scanalyze-${CUSTOMER_ACCT}-tf-state/${DEPLOYMENT_ID}/*/terraform.tfstate.tflock"
    },
    {
      "Sid": "ApplyRoleListBucket",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${CUSTOMER_ACCT}:role/ScanalyzeCustomer-Apply"
      },
      "Action": [
        "s3:ListBucket",
        "s3:ListBucketVersions"
      ],
      "Resource": "arn:aws:s3:::scanalyze-${CUSTOMER_ACCT}-tf-state",
      "Condition": {
        "StringLike": {
          "s3:prefix": "${DEPLOYMENT_ID}/*"
        }
      }
    },
    {
      "Sid": "ApplyRolePlanExecutionRead",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${CUSTOMER_ACCT}:role/ScanalyzeCustomer-Apply"
      },
      "Action": [
        "s3:GetObject",
        "s3:DeleteObject"
      ],
      "Resource": "arn:aws:s3:::scanalyze-${CUSTOMER_ACCT}-tf-state/plan-execution/${DEPLOYMENT_ID}/*"
    },
    {
      "Sid": "ApplyRoleRecoveryWrite",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${CUSTOMER_ACCT}:role/ScanalyzeCustomer-Apply"
      },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::scanalyze-${CUSTOMER_ACCT}-tf-state/recovery/${DEPLOYMENT_ID}/*"
    },
    {
      "Sid": "DiagnosticRoleStateReadOnly",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${CUSTOMER_ACCT}:role/ScanalyzeCustomer-Diagnostic"
      },
      "Action": [
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:ListBucket",
        "s3:ListBucketVersions"
      ],
      "Resource": [
        "arn:aws:s3:::scanalyze-${CUSTOMER_ACCT}-tf-state",
        "arn:aws:s3:::scanalyze-${CUSTOMER_ACCT}-tf-state/${DEPLOYMENT_ID}/*/terraform.tfstate"
      ]
    },
    {
      "Sid": "StateRecoveryRoleReadWrite",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${CUSTOMER_ACCT}:role/ScanalyzeCustomer-StateRecovery"
      },
      "Action": [
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:PutObject",
        "s3:ListBucket",
        "s3:ListBucketVersions"
      ],
      "Resource": [
        "arn:aws:s3:::scanalyze-${CUSTOMER_ACCT}-tf-state",
        "arn:aws:s3:::scanalyze-${CUSTOMER_ACCT}-tf-state/${DEPLOYMENT_ID}/*/terraform.tfstate"
      ]
    },
    {
      "Sid": "StateRecoveryRoleRecoveryRead",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${CUSTOMER_ACCT}:role/ScanalyzeCustomer-StateRecovery"
      },
      "Action": [
        "s3:GetObject",
        "s3:GetObjectVersion"
      ],
      "Resource": "arn:aws:s3:::scanalyze-${CUSTOMER_ACCT}-tf-state/recovery/${DEPLOYMENT_ID}/*"
    },
    {
      "Sid": "DenyNonTLS",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::scanalyze-${CUSTOMER_ACCT}-tf-state",
        "arn:aws:s3:::scanalyze-${CUSTOMER_ACCT}-tf-state/*"
      ],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    },
    {
      "Sid": "DenyUnencryptedPuts",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::scanalyze-${CUSTOMER_ACCT}-tf-state/*",
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption": "aws:kms"
        }
      }
    },
    {
      "Sid": "DenyWrongKMSKey",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::scanalyze-${CUSTOMER_ACCT}-tf-state/*",
      "Condition": {
        "StringNotEqualsIfExists": {
          "s3:x-amz-server-side-encryption-aws-kms-key-id": "${STATE_KMS_KEY_ARN}"
        }
      }
    }
  ]
}
```

> [!IMPORTANT]
> **Key differences from rev2:**
> 1. **Principals are customer-account roles** (e.g., `ScanalyzeCustomer-Diagnostic`), NOT `ScanalyzeBreakGlass` from Shared Services. After AssumeRole, S3 calls are made by the assumed role's session.
> 2. **No `s3:CopyObject`** — not a valid IAM action. StateRecovery uses `GetObject`+`GetObjectVersion` (read) + `PutObject` (write).
> 3. **Plan role cannot DeleteObject on state keys** — only on `.tflock`. This prevents accidental state deletion during plan.
> 4. **No blanket DenyAllOthers** — replaced with targeted denies (non-TLS, unencrypted puts, wrong KMS key). This avoids blocking replication, AWS Backup, lifecycle rules, and security tooling.
> 5. **Plan-execution and recovery prefixes** have separate permission grants.

#### Evidence Bucket Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ApplyRoleWriteEvidence",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${CUSTOMER_ACCT}:role/ScanalyzeCustomer-Apply"
      },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::scanalyze-${CUSTOMER_ACCT}-tf-evidence/${DEPLOYMENT_ID}/*"
    },
    {
      "Sid": "DiagnosticRoleReadEvidence",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${CUSTOMER_ACCT}:role/ScanalyzeCustomer-Diagnostic"
      },
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::scanalyze-${CUSTOMER_ACCT}-tf-evidence",
        "arn:aws:s3:::scanalyze-${CUSTOMER_ACCT}-tf-evidence/${DEPLOYMENT_ID}/*"
      ]
    },
    {
      "Sid": "ValidationRoleReadEvidence",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${CUSTOMER_ACCT}:role/ScanalyzeCustomer-Validation"
      },
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::scanalyze-${CUSTOMER_ACCT}-tf-evidence",
        "arn:aws:s3:::scanalyze-${CUSTOMER_ACCT}-tf-evidence/${DEPLOYMENT_ID}/*"
      ]
    },
    {
      "Sid": "DenyNonTLS",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::scanalyze-${CUSTOMER_ACCT}-tf-evidence",
        "arn:aws:s3:::scanalyze-${CUSTOMER_ACCT}-tf-evidence/*"
      ],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    },
    {
      "Sid": "DenyUnencryptedPuts",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::scanalyze-${CUSTOMER_ACCT}-tf-evidence/*",
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption": "aws:kms"
        }
      }
    },
    {
      "Sid": "DenyObjectLockOverride",
      "Effect": "Deny",
      "Principal": "*",
      "Action": [
        "s3:PutObjectRetention",
        "s3:PutBucketObjectLockConfiguration"
      ],
      "Resource": [
        "arn:aws:s3:::scanalyze-${CUSTOMER_ACCT}-tf-evidence",
        "arn:aws:s3:::scanalyze-${CUSTOMER_ACCT}-tf-evidence/*"
      ]
    }
  ]
}
```

### 10. KMS Permissions per Role

| Role | State KMS key | Evidence KMS key |
|---|---|---|
| **Plan** | `kms:Decrypt` (read state), `kms:Encrypt` + `kms:GenerateDataKey` (write plan-execution artifacts) | — |
| **Apply** | `kms:Encrypt`, `kms:Decrypt`, `kms:GenerateDataKey` (read+write state, read+delete plan-execution, write recovery) | `kms:Encrypt`, `kms:GenerateDataKey` (write evidence) |
| **Promotion** | — | — |
| **Validation** | — | `kms:Decrypt` (read evidence) |
| **Diagnostic** | `kms:Decrypt` (read state) | `kms:Decrypt` (read evidence) |
| **StateRecovery** | `kms:Encrypt`, `kms:Decrypt`, `kms:GenerateDataKey` (read+write state, read recovery) | — |

> [!NOTE]
> The S3 backend with a customer-managed KMS key requires `kms:Encrypt`, `kms:Decrypt`, and `kms:GenerateDataKey` for any write operation. Read-only access requires only `kms:Decrypt`.

### 11. Terraform Workspaces: Explicitly Rejected

Each customer uses a separate backend configuration (different S3 bucket in different account), not workspaces. Unchanged from rev1 rationale.

### 12. Backend Templating

Orchestrator renders `backend.tf` from template + deployment record. Updated to include regional keys:

```hcl
# Generated by orchestrator — do not edit manually
terraform {
  backend "s3" {
    bucket         = "scanalyze-${account_id}-tf-state"
    key            = "${deployment_id}/${region}/${layer}/terraform.tfstate"
    region         = "${region}"
    encrypt        = true
    kms_key_id     = "alias/scanalyze-tf-state-key"
    use_lockfile   = true
  }
}
```

For non-regional layers (global, edge-identity), the key omits the region:
```hcl
    key = "${deployment_id}/${layer}/terraform.tfstate"
```

### 13. State Locking

| Property | Details |
|---|---|
| Method | `use_lockfile = true` (S3-native) |
| Lock mechanism | `.tflock` object alongside state |
| Object Lock conflict | **NONE** — state bucket has no Object Lock |
| Stale lock recovery | Delete `.tflock` via break-glass `StateRecovery` role |

### 14. Provider Lock File

`.terraform.lock.hcl` committed to repo. Unchanged from rev1.

### 15. Drift Detection

Scheduled `terraform plan -detailed-exitcode` (no apply). Results stored in evidence bucket. Unchanged from rev1.

### 16. CI Ownership Validation

```
CI checks on every PR:
1. Each root declares exactly one backend key in ownership.yaml
2. No two roots share a backend key
3. Namespace descriptions are non-overlapping (manual review for ambiguous cases)
4. No terraform_remote_state data sources
5. No hardcoded account IDs, bucket names, or deployment IDs
6. timestamp() not used in any resource or local (see ADR-006)
7. No s3:CopyObject in any policy document
8. Control-plane role resources not declared in any workload root
9. Regional layers include {region} in backend key template
```

### 17. Sensitive State Data

State files may contain sensitive attributes. Mitigations:
- `sensitive = true` on Terraform outputs
- No `terraform show` in CI/CD pipelines (use plan JSON only in plan-execution zone)
- State never in build artifacts, logs, or evidence
- Pre-apply snapshots in recovery prefix (restricted to StateRecovery role)
- KMS encryption at rest with per-role key access
- No `terraform state pull` in CI

### 18. Track A vs Track B State Strategy

| Aspect | Track A (brownfield) | Track B (greenfield) |
|---|---|---|
| **State location** | Existing buckets (freeze, capture evidence) | New per-account buckets (account baseline) |
| **Ownership** | Audit and document → ownership.yaml v1 | Ownership.yaml from day one |
| **Recovery** | Capture version IDs, validate lineage | Recovery prefix + evidence from first apply |
| **Migration** | After ADRs accepted → controlled import with evidence | N/A (clean start) |

---

## Consequences

### Positive
- State bucket can be locked/unlocked freely (no Object Lock interference)
- Evidence bucket provides immutable, sanitized audit trail
- Plan binaries (with secrets) are ephemeral — auto-deleted after 24–72h
- Logical namespaces are human-readable and resilient to resource type reuse
- State restoration is a distinct operation from release rollback
- Bucket policies reference correct principals (customer roles, not shared services)
- All S3 actions are valid IAM actions
- Per-key permissions prevent Plan from deleting state files
- Targeted deny patterns don't block legitimate AWS services
- Regional state keys prevent multi-region collisions
- Account baseline resources are explicitly excluded from workload state

### Negative
- Three storage zones add operational complexity
- Plan-execution TTL must be longer than the plan→apply window
- Recovery prefix adds a third lifecycle rule to manage
- Evidence sanitization requires discipline (pipeline must strip sensitive fields)

---

## References

- ADR-001: Tenancy Model
- ADR-004 rev3: Cross-Account Identity (6 scoped roles, account baseline ownership)
- ADR-006: Modules & Contracts (SSM-based, no `terraform_remote_state`)
- ADR-009: Threat Model (T4.3 state credential access, T6.1–T6.4)
- State Ownership Audit (brownfield)
- [Terraform S3 Backend: use_lockfile](https://developer.hashicorp.com/terraform/language/backend/s3)
- [AWS S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)
- [AWS S3 API: CopyObject requires GetObject + PutObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_CopyObject.html)
- [AWS S3 Bucket Policy Examples](https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-bucket-policies.html)
