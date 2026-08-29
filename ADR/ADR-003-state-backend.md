# ADR-003: Terraform State, Backend Strategy, Locking, Recovery, and Ownership

> **Status**: `DRAFT rev4`
> **Date**: 2026-06-23; GUG-379 amendment 2026-08-16; saved-plan storage amendment 2026-08-28
> **Decision makers**: César Guzmán  
> **Scope**: Scanalyze Dedicated Deployment Platform  
> **Depends on**: ADR-001, ADR-002, ADR-004 rev3  
> **Rev4 changes**: ACCOUNT_READY v2 is the only operational baseline contract; the account baseline owns eight terminal roles, four buckets and three KMS keys; S3 native lockfiles replace the legacy DynamoDB backend lock; raw saved plans use a dedicated one-day ephemeral bucket; repository-only materialization remains distinct from live readback

---

## Context

The current brownfield deployment has fragmented Terraform state with dual ownership issues (see state audit). The greenfield platform must enforce strict state ownership from day one.

State files contain resource identifiers, some configuration values, and can contain sensitive attributes. Saved plans contain configuration, input variables, and **sensitive values in cleartext** even when Terraform redacts them in console output. Both require careful access control and lifecycle management.

---

## Decision

### 1. Four Buckets per Customer Account

Each customer account has **four S3 buckets**, each with distinct security
properties:

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
├── S3: scanalyze-${CUSTOMER_ACCT}-tf-plan                 ← PLAN BUCKET
│   ├── Purpose: One exact ephemeral saved-plan binary per approved change
│   ├── KMS: evidence KMS key
│   ├── Versioning: ENABLED
│   ├── Object Lock: NONE
│   ├── Lifecycle: current and noncurrent plan-execution objects expire after 1 day
│   ├── Access: Plan (create-only write), Apply (read exact version)
│   └── Block Public Access: ALL enabled
│
├── S3: scanalyze-${CUSTOMER_ACCT}-tf-evidence             ← EVIDENCE BUCKET
│   ├── Purpose: Sanitized audit trail (digests, summaries, approval records)
│   ├── KMS: alias/scanalyze-tf-evidence-key
│   ├── Versioning: ENABLED
│   ├── Object Lock: COMPLIANCE
│   │   └── Default: 90 days for every object
│   ├── Access: future isolated evidence publisher (write), Diagnostic (read),
│   │          Validation (read); Plan/Apply never publish
│   └── Block Public Access: ALL enabled
│
└── S3: scanalyze-${CUSTOMER_ACCT}-contracts               ← CONTRACTS BUCKET
│   ├── Purpose: Content-addressed producer contracts and release bindings
│   ├── KMS: dedicated contracts KMS key
│   ├── Versioning: ENABLED
│   ├── Access: producer writes; authorized consumers read exact digests
│   └── Block Public Access: ALL enabled
```

> [!IMPORTANT]
> **Why these zones:**
> - **State bucket**: No Object Lock because `.tflock` must be deletable. Contains only state and native lockfiles.
> - **Plan bucket**: No Object Lock. Contains only exact-version raw saved-plan binaries under a one-day fail-safe lifecycle.
> - **Evidence bucket**: COMPLIANCE Object Lock for immutable audit. Contains ONLY sanitized summaries — never raw plans, state snapshots, or secrets.
> - **Contracts bucket**: Stores only content-addressed contract envelopes and bindings; it is never inferred from a name or caller input.
> Raw plan JSON is inspected only in a mode-`0600` runner scratch file and is
> deleted immediately; it is never uploaded.

The four deterministic bucket names are normative template invariants, not
discovery or proof of ownership. Operational coordinates come only from an
exact, separately anchored ACCOUNT_READY v2 contract produced from baseline
readback. A matching name alone never proves that a bucket exists or belongs to
the destination account.

### 1.1 GUG-379 account-baseline boundary

`AccountVendingProvider` remains the sole baseline owner. The reviewed
`bootstrap/cfn-tf-state-backend.yaml` candidate defines the four retained
buckets and three retained KMS keys, then references the exact
content-addressed `bootstrap/cfn-terminal-roles.yaml` child. That child
materializes the eight terminal roles and quota-valid managed policies. The
repository-only `tooling.account_ready_v2_materializer` consumes an exact
closed readback of those outputs and emits the single content-addressed
ACCOUNT_READY v2 envelope. It never calls AWS, Terraform, or a subprocess. It
verifies that returned bucket outputs match the template's exact naming
invariant; it does not discover, adopt, or claim a resource because its name
happens to match.

The `account-ready-gate` remains a validation-only consumer with no state and
no apply authority. A dry-run or schema-valid candidate proves deterministic
repository behavior only; resource existence, control effectiveness, writer
authority, deployment readiness, and production readiness remain
`NOT_PROVEN_LIVE` until separately authorized readback.

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

`deployment/layers.yaml` is the canonical executable layer manifest. It defines
13 ordered operational stages: one account-ready gate, ten Terraform roots,
one artifact-publication stage, and one synthetic-validation stage. Only the
ten Terraform roots own state keys:

| Terraform layer | State key | Contract produced |
|---|---|---|
| `global` | `{deployment_id}/global/terraform.tfstate` | `global/v1` |
| `network` | `{deployment_id}/{region}/network/terraform.tfstate` | `network/v2` |
| `platform` | `{deployment_id}/{region}/platform/terraform.tfstate` | `platform/v2` |
| `data-foundation` | `{deployment_id}/{region}/data-foundation/terraform.tfstate` | `data-foundation/v2` |
| `cicd` | `{deployment_id}/{region}/cicd/terraform.tfstate` | `cicd/v2` |
| `identity-control-plane` | `{deployment_id}/{region}/identity-control-plane/terraform.tfstate` | `identity-control-plane/v1` |
| `services` | `{deployment_id}/{region}/services/terraform.tfstate` | `services/v2` |
| `edge-identity` | `{deployment_id}/{region}/edge-identity/terraform.tfstate` | `edge-identity/v2` |
| `edge` | `{deployment_id}/edge/terraform.tfstate` | `edge/v2` |
| `addons` | `{deployment_id}/{region}/addons/terraform.tfstate` | `addons/v2` |

The account baseline, not any deployment root, owns the four buckets, three KMS
keys, and all eight terminal roles: Plan, Apply, Identity-Plan,
Identity-Apply, Promotion, Validation, Diagnostic, and StateRecovery. The three
non-state stages in `deployment/layers.yaml` must keep `state_key: null`.

### 5. State Key Naming Convention — Regional

```
Non-regional layers (one instance per deployment):
  {deployment_id}/global/terraform.tfstate
  {deployment_id}/edge/terraform.tfstate

Regional layers (one instance per deployment × region):
  {deployment_id}/{region}/network/terraform.tfstate
  {deployment_id}/{region}/platform/terraform.tfstate
  {deployment_id}/{region}/data-foundation/terraform.tfstate
  {deployment_id}/{region}/cicd/terraform.tfstate
  {deployment_id}/{region}/identity-control-plane/terraform.tfstate
  {deployment_id}/{region}/services/terraform.tfstate
  {deployment_id}/{region}/edge-identity/terraform.tfstate
  {deployment_id}/{region}/addons/terraform.tfstate
```

| Layer | Key pattern | Regional? |
|---|---|---|
| global | `{dep_id}/global/terraform.tfstate` | No |
| edge | `{dep_id}/edge/terraform.tfstate` | No |
| network | `{dep_id}/{region}/network/terraform.tfstate` | Yes |
| platform | `{dep_id}/{region}/platform/terraform.tfstate` | Yes |
| data-foundation | `{dep_id}/{region}/data-foundation/terraform.tfstate` | Yes |
| cicd | `{dep_id}/{region}/cicd/terraform.tfstate` | Yes |
| identity-control-plane | `{dep_id}/{region}/identity-control-plane/terraform.tfstate` | Yes |
| services | `{dep_id}/{region}/services/terraform.tfstate` | Yes |
| edge-identity | `{dep_id}/{region}/edge-identity/terraform.tfstate` | Yes |
| addons | `{dep_id}/{region}/addons/terraform.tfstate` | Yes |

> [!NOTE]
> SSM Parameter Store is regional. The same contract path can exist in different regions natively. The deployment record must register `{region}/{layer}` explicitly for each contract produced.

### 6. Evidence Key Naming Convention (Reserved Publisher Contract)

The evidence store is reserved for **sanitized summaries only** — never raw
plans, state files, or secrets. The current Plan/Apply controller does not have
evidence-bucket write authority and does not publish any of the following
objects. These keys describe the future publisher contract, not live evidence
that exists today:

```
s3://scanalyze-${CUSTOMER_ACCT}-tf-evidence/{deployment_id}/{region}/{layer}/...
```

| Content | Key pattern | Retention | Contains secrets? |
|---|---|---|---|
| Plan summary (sanitized) | `{dep_id}/{region}/{layer}/plans/{change_id}-summary.json` | 90 days | **NO** — digest, resource counts, action list only |
| Plan digest | `{dep_id}/{region}/{layer}/plans/{change_id}-digest.sha256` | 90 days | No |
| Approval record | `{dep_id}/{region}/{layer}/plans/{change_id}-approval.json` | 90 days | No |
| Apply execution log (sanitized) | `{dep_id}/{region}/{layer}/apply-logs/{change_id}.log` | 90-day bucket default unless a future publisher sets a separately reviewed retention | **NO** — sanitized, credential patterns redacted |
| Apply metadata | `{dep_id}/{region}/{layer}/apply-logs/{change_id}-meta.json` | 90-day bucket default unless a future publisher sets a separately reviewed retention | No — state version IDs, release manifest digest, execution ID |
| Drift detection report | `{dep_id}/{region}/{layer}/drift/{date}.json` | 90 days | No |

> [!CAUTION]
> **The evidence bucket NEVER contains:**
> - Plan binary (`.tfplan`) — contains secrets in cleartext
> - Full plan JSON — contains sensitive attribute values
> - State file copies — contain resource configs
> - Raw input variables — may contain sensitive values
>
> Only the exact plan binary is uploaded to the dedicated **plan-execution
> zone** (§1), whose current and noncurrent versions expire after one day. Raw
> plan JSON exists only in private runner scratch and is deleted immediately.

### 7. Plan Execution Zone (Ephemeral)

Plans contain sensitive data. The exact binary is stored briefly for the apply
step. There is no immediate delete operation after apply, rejection, or expiry;
the one-day lifecycle rule is the only implemented cleanup mechanism.

```
s3://scanalyze-${CUSTOMER_ACCT}-tf-plan/plan-execution/{dep_id}/{change_id}/{layer}/plan.tfplan
```

| Content | Key | TTL | Purpose |
|---|---|---|---|
| Plan binary | `plan-execution/{dep_id}/{change_id}/{layer}/plan.tfplan` | 1 day | Apply reads the exact version bound by bucket, key, `VersionId`, SHA-256 and byte size in the durable control record |

| Role | Permissions on plan-execution/ prefix |
|---|---|
| Plan | `s3:PutObject` (writes plan artifacts) |
| Apply | `s3:GetObject`, `s3:GetObjectVersion` (read-only, exact saved version) |
| Diagnostic | No access (default) |
| StateRecovery | No access |

> [!NOTE]
> S3 lifecycle expires current and noncurrent objects under `plan-execution/`
> after one day. Apply cannot overwrite or delete the reviewed plan; it reads
> the exact bucket/key/`VersionId` and verifies the bound hash and size. Raw
> plan JSON is created only as a mode-`0600` scratch file for semantic
> inspection and is deleted before the runner exits; it is never uploaded.

### 8. Recovery Store (Reserved, Not Implemented)

The current baseline does **not** create pre-apply state snapshots or expose a
recovery-prefix writer. State recovery relies on the versioned state object and
requires a separately reviewed break-glass procedure. The path below is
reserved for a future design only; it is not an operational producer or an
Apply permission.

```
s3://scanalyze-${CUSTOMER_ACCT}-tf-state/recovery/{dep_id}/{change_id}/...
```

No current role has an implemented `recovery/` producer or consumer path.
Normal Apply and stale-Apply reentry must not write this prefix. A future
snapshot design must add explicit IAM, retention, custody, authorization and
readback controls in a separate reviewed change before this path can be used.

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
> 5. **The state policy contains no plan-bucket resource and no `recovery/`
> writer.** Saved-plan access lives only in the separate plan-bucket policy;
> the recovery prefix remains reserved and unimplemented.

#### Plan Bucket Policy

The dedicated plan bucket has its own policy. Plan and Identity-Plan may create
only the exact session-tagged key. Apply and Identity-Apply may read only the
exact version of that key. Neither apply role receives put or delete authority.
The canonical policy is `policies/s3/plan-bucket.json`; the baseline template
also enforces TLS and the evidence KMS key on this bucket independently of the
state policy.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowPlanWriteExactExecution",
      "Effect": "Allow",
      "Principal": {
        "AWS": [
          "arn:aws:iam::${CUSTOMER_ACCT}:role/ScanalyzeCustomer-Plan",
          "arn:aws:iam::${CUSTOMER_ACCT}:role/ScanalyzeCustomer-Identity-Plan"
        ]
      },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::scanalyze-${CUSTOMER_ACCT}-tf-plan/plan-execution/${DEPLOYMENT_ID}/${aws:PrincipalTag/change_id}/${aws:PrincipalTag/layer}/plan.tfplan",
      "Condition": {
        "StringEquals": {"aws:PrincipalTag/operation": "plan"}
      }
    },
    {
      "Sid": "AllowApplyReadExactExecutionVersion",
      "Effect": "Allow",
      "Principal": {
        "AWS": [
          "arn:aws:iam::${CUSTOMER_ACCT}:role/ScanalyzeCustomer-Apply",
          "arn:aws:iam::${CUSTOMER_ACCT}:role/ScanalyzeCustomer-Identity-Apply"
        ]
      },
      "Action": "s3:GetObjectVersion",
      "Resource": "arn:aws:s3:::scanalyze-${CUSTOMER_ACCT}-tf-plan/plan-execution/${DEPLOYMENT_ID}/${aws:PrincipalTag/change_id}/${aws:PrincipalTag/layer}/plan.tfplan",
      "Condition": {
        "StringEquals": {"aws:PrincipalTag/operation": "apply"}
      }
    }
  ]
}
```

#### Evidence Bucket Policy

There is no current Plan/Apply evidence publisher. In particular, the evidence
policy must not grant either apply role `s3:PutObject`. The executable baseline
keeps the bucket immutable and encrypted, while the companion policy grants
Diagnostic read-only access to sanitized evidence if a separately reviewed
publisher creates it later.

```json
{
  "Version": "2012-10-17",
  "Statement": [
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

| Role | State KMS key | Evidence KMS key | Contracts KMS key |
|---|---|---|---|
| **Plan** | `Decrypt`, `DescribeKey`, `Encrypt`, `GenerateDataKey` for state reads and native lockfiles | `Decrypt`, `Encrypt`, `GenerateDataKey` only for the dedicated plan bucket | `Decrypt`, `DescribeKey`, `Encrypt`, `GenerateDataKey` per the baseline fixture |
| **Apply** | `Decrypt`, `DescribeKey`, `Encrypt`, `GenerateDataKey` for state | `Decrypt` only for the exact saved-plan object; no evidence/recovery writer | `Decrypt`, `DescribeKey`, `Encrypt`, `GenerateDataKey` per the baseline fixture |
| **Identity-Plan** | `Decrypt`, `DescribeKey`, `Encrypt`, `GenerateDataKey` for identity state and lockfiles | `Decrypt`, `Encrypt`, `GenerateDataKey` only for the identity saved plan | `Decrypt`, `DescribeKey` for required contracts |
| **Identity-Apply** | `Decrypt`, `DescribeKey`, `Encrypt`, `GenerateDataKey` for identity state | `Decrypt` only for the exact identity saved-plan version | `Decrypt`, `DescribeKey`, `Encrypt`, `GenerateDataKey` for its contract |
| **Promotion** | — | — | — |
| **Validation** | — | `Decrypt`, `DescribeKey` for read-only evidence | `Decrypt`, `DescribeKey` for read-only contracts |
| **Diagnostic** | `Decrypt`, `DescribeKey` | `Decrypt`, `DescribeKey` | `Decrypt`, `DescribeKey` |
| **StateRecovery** | `Decrypt`, `DescribeKey`, `Encrypt`, `GenerateDataKey` on state only | — | — |

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

For non-regional layers (`global`, `edge`), the key omits the region:
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

Scheduled `terraform plan -detailed-exitcode` remains a future read-only
control. The current implementation has no evidence-bucket publisher, so any
result remains private runner evidence until a separate sanitized publisher is
reviewed and implemented.

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
- `terraform show -json` writes only to a mode-`0600` runner scratch file for
  semantic inspection; that raw JSON is deleted and never uploaded
- State never in build artifacts, logs, or evidence
- S3 version IDs and state lineage support a separately authorized recovery;
  no automated pre-apply snapshot prefix is implemented
- KMS encryption at rest with per-role key access
- No `terraform state pull` in CI

### 18. Track A vs Track B State Strategy

| Aspect | Track A (brownfield) | Track B (greenfield) |
|---|---|---|
| **State location** | Existing buckets (freeze, capture evidence) | New per-account buckets (account baseline) |
| **Ownership** | Audit and document → ownership.yaml v1 | Ownership.yaml from day one |
| **Recovery** | Capture version IDs, validate lineage | Version IDs and lineage; separate break-glass recovery, with no snapshot prefix implemented |
| **Migration** | After ADRs accepted → controlled import with evidence | N/A (clean start) |

---

## Consequences

### Positive
- State bucket can be locked/unlocked freely (no Object Lock interference)
- Evidence bucket provides the retained destination for a future isolated,
  sanitized publisher; the current Plan/Apply path does not publish to it
- Plan binaries (with secrets) are ephemeral — current and noncurrent versions expire after one day
- Logical namespaces are human-readable and resilient to resource type reuse
- State restoration is a distinct operation from release rollback
- Bucket policies reference correct principals (customer roles, not shared services)
- All S3 actions are valid IAM actions
- Per-key permissions prevent Plan from deleting state files
- Targeted deny patterns don't block legitimate AWS services
- Regional state keys prevent multi-region collisions
- Account baseline resources are explicitly excluded from workload state

### Negative
- Four buckets with distinct policies and lifecycles add operational complexity
- Plan-execution TTL must be longer than the plan→apply window
- Saved-plan cleanup is lifecycle-driven; there is no immediate-delete path
- The recovery prefix is reserved but has no current producer, consumer, or lifecycle
- Evidence sanitization requires discipline (pipeline must strip sensitive fields)

---

## References

- ADR-001: Tenancy Model
- ADR-004 rev3: Cross-Account Identity (eight terminal roles, account baseline ownership)
- ADR-006: Modules & Contracts (SSM-based, no `terraform_remote_state`)
- ADR-009: Threat Model (T4.3 state credential access, T6.1–T6.4)
- State Ownership Audit (brownfield)
- [Terraform S3 Backend: use_lockfile](https://developer.hashicorp.com/terraform/language/backend/s3)
- [AWS S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)
- [AWS S3 API: CopyObject requires GetObject + PutObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_CopyObject.html)
- [AWS S3 Bucket Policy Examples](https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-bucket-policies.html)
