# ADR-004: Cross-Account Identity, Trust Policies, Session Tags, and Break-Glass

> **Status**: `DRAFT rev3`  
> **Date**: 2026-06-23  
> **Decision makers**: César Guzmán  
> **Scope**: Scanalyze Dedicated Deployment Platform  
> **Depends on**: ADR-001, ADR-002, ADR-009  
> **Rev3 changes**: P0-1 (trust policy JSON validity, SourceIdentity dynamic, deployment binding, tag allowlist, layer scoping) + P0-2 (bootstrap cycle broken — roles in account baseline)

---

## Context

The deployment orchestrator in Shared Services assumes roles in customer accounts to provision and manage infrastructure. This cross-account access must be:

1. Precisely scoped to the orchestrator identity and the specific operation
2. Conditional on session metadata that binds the session to a specific deployment
3. Traceable via CloudTrail with an immutable per-execution identity
4. Auditable per deployment action
5. Revocable per customer account
6. Protected against confused deputy attacks
7. Split by responsibility so that a plan operation cannot mutate resources
8. Bootstrappable without circular dependencies

---

## Decision

### 1. Principal Hierarchy

```
Shared Services Account (scanalyze-shared-services)
├── ScanalyzeOrchestrator (IAM Role)
│   ├── Trust: ScanalyzePipelineExecution (same account)
│   ├── Permissions: sts:AssumeRole + sts:TagSession + sts:SetSourceIdentity
│   │   on customer Plan/Apply/Promotion/Validation roles
│   ├── Permissions boundary: ScanalyzeOrchestratorBoundary
│   ├── Max session: 1 hour
│   └── Sets SourceIdentity: exec_{ULID} (once, immutable)
│
├── ScanalyzePipelineExecution (IAM Role)
│   ├── Trust: CodeBuild/CodePipeline service principals
│   ├── Permissions: invoke orchestrator, read artifacts, ECR push
│   ├── Permissions boundary: ScanalyzePipelineBoundary
│   └── Max session: 1 hour
│
├── ScanalyzeReleaseSigningRole (IAM Role)
│   ├── Trust: release pipeline only
│   ├── Permissions: AWS Signer + KMS asymmetric Sign (release manifests)
│   └── Permissions boundary: ScanalyzeSigningBoundary
│
└── ScanalyzeBreakGlass (IAM Role)
    ├── Trust: IAM Identity Center admin permission set
    ├── Condition: MFA required
    ├── Permissions: sts:AssumeRole + sts:TagSession + sts:SetSourceIdentity
    │   on customer Diagnostic and StateRecovery roles ONLY
    ├── Permissions boundary: ScanalyzeBreakGlassBoundary
    ├── Max session: 30 minutes
    └── Sets SourceIdentity: bg_{operator_id_hash8} (once, immutable)

Customer Account (per deployment) — 6 scoped roles:
├── ScanalyzeCustomer-Plan       ← Trust: Orchestrator │ Terminal role
├── ScanalyzeCustomer-Apply      ← Trust: Orchestrator │ Terminal role
├── ScanalyzeCustomer-Promotion  ← Trust: Orchestrator │ Terminal role
├── ScanalyzeCustomer-Validation ← Trust: Orchestrator │ Terminal role
├── ScanalyzeCustomer-Diagnostic ← Trust: BreakGlass   │ Terminal role
└── ScanalyzeCustomer-StateRecovery ← Trust: BreakGlass │ Terminal role
```

> [!IMPORTANT]
> **All six customer roles are terminal.** They do not perform further `sts:AssumeRole`. No `sts:TransitiveTagKeys` are required. SourceIdentity persists from the first hop. Tags are passed directly.

> [!IMPORTANT]
> **Break-glass NEVER assumes Plan, Apply, Promotion, or Validation roles.** Orchestrator NEVER assumes Diagnostic or StateRecovery roles. These trust boundaries are enforced in the trust policies themselves.

### 2. Ownership — Account Baseline, NOT Golden Workload

> [!CAUTION]
> **The 6 customer control-plane roles are NOT created by the Terraform workload layers.** They are provisioned by the **AccountVendingProvider** as part of the account baseline, before any workload Terraform runs.

| Owner | Resources |
|---|---|
| **Account baseline** (AccountVendingProvider) | 6 scoped roles, trust policies, permissions boundaries, state/evidence/contracts S3 buckets, infra KMS keys, role resource tags |
| **Golden workload — global layer** | ECS task execution role, ECS task roles, application IAM policies, application permissions boundaries |

Bootstrap sequence:
```
AccountVendingProvider
  → creates account (Organization/AFT)
  → provisions baseline (roles, buckets, KMS, tags)
  → produces ACCOUNT_READY contract
  → registers in deployment registry
  → Orchestrator reads registry
  → Orchestrator assumes Plan (account is now ready for workload)
  → global layer → network → platform → data-foundation → services → edge-identity → addons
```

### 3. Role Purpose and Permissions Summary

| Role | Trust source | Can read | Can write | Special restrictions |
|---|---|---|---|---|
| **Plan** | Orchestrator | All TF-managed resources, state key (read), SSM contracts | Lock key only (.tflock) | No infra writes. KMS: Decrypt only |
| **Apply** | Orchestrator | All TF-managed resources, state key, SSM contracts | Infrastructure, state key, SSM contracts (own layer prefix), lock key | No IAM user creation, no Organizations, no billing. KMS: Encrypt+Decrypt+GenerateDataKey. `iam:PassRole` scoped to exact ARNs |
| **Promotion** | Orchestrator | ECR (source images), S3 (frontend source) | ECR (push images+OCI artifacts), S3 frontend prefix, CloudFront invalidation | No infra, no IAM, no state access |
| **Validation** | Orchestrator | ECS, ALB, DDB, SQS, CW, SSM, CloudWatch Logs | Nothing | Read-only health checks |
| **Diagnostic** | BreakGlass | All resources, state bucket (read), logs, CloudWatch | Nothing | Read-only investigation |
| **StateRecovery** | BreakGlass | State bucket | State bucket (put/get for state key) | No infra writes, no SSM, no IAM. KMS: Encrypt+Decrypt+GenerateDataKey (state key only) |

### 4. Trust Policies — Separated by Action

> [!IMPORTANT]
> **Each STS action gets its own statement** because IAM condition keys have action-specific applicability. Combining `sts:AssumeRole`, `sts:TagSession`, and `sts:SetSourceIdentity` under one set of conditions causes `UNSUPPORTED_ACTION_FOR_CONDITION_KEY` findings in IAM Access Analyzer.

#### Template parameters (for reusable golden stack)

```
${ORGANIZATION_ID}          — e.g. o-rpnh6nbjnt (current) or variable for reuse
${SHARED_SERVICES_ACCT}     — Shared Services account ID
${CUSTOMER_ACCT}            — This customer account ID
${DEPLOYMENT_ID}            — Deployment identifier for this account
```

#### ScanalyzeCustomer-Plan Trust Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowOrchestratorAssumeRole",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${SHARED_SERVICES_ACCT}:role/ScanalyzeOrchestrator"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "${ORGANIZATION_ID}",
          "aws:RequestTag/deployment_id": "${aws:ResourceTag/deployment_id}",
          "aws:RequestTag/operation": "plan"
        }
      }
    },
    {
      "Sid": "AllowOrchestratorTagSession",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${SHARED_SERVICES_ACCT}:role/ScanalyzeOrchestrator"
      },
      "Action": "sts:TagSession",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "${ORGANIZATION_ID}",
          "aws:RequestTag/operation": "plan"
        },
        "ForAllValues:StringEquals": {
          "aws:TagKeys": [
            "deployment_id",
            "release_version",
            "change_id",
            "operation",
            "layer"
          ]
        },
        "Null": {
          "aws:RequestTag/deployment_id": "false",
          "aws:RequestTag/release_version": "false",
          "aws:RequestTag/change_id": "false",
          "aws:RequestTag/operation": "false",
          "aws:RequestTag/layer": "false"
        }
      }
    },
    {
      "Sid": "AllowOrchestratorSetSourceIdentity",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${SHARED_SERVICES_ACCT}:role/ScanalyzeOrchestrator"
      },
      "Action": "sts:SetSourceIdentity",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "${ORGANIZATION_ID}"
        },
        "StringLike": {
          "sts:SourceIdentity": "exec_*"
        }
      }
    }
  ]
}
```

#### ScanalyzeCustomer-Apply Trust Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowOrchestratorAssumeRole",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${SHARED_SERVICES_ACCT}:role/ScanalyzeOrchestrator"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "${ORGANIZATION_ID}",
          "aws:RequestTag/deployment_id": "${aws:ResourceTag/deployment_id}",
          "aws:RequestTag/operation": "apply"
        }
      }
    },
    {
      "Sid": "AllowOrchestratorTagSession",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${SHARED_SERVICES_ACCT}:role/ScanalyzeOrchestrator"
      },
      "Action": "sts:TagSession",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "${ORGANIZATION_ID}",
          "aws:RequestTag/operation": "apply"
        },
        "ForAllValues:StringEquals": {
          "aws:TagKeys": [
            "deployment_id",
            "release_version",
            "change_id",
            "operation",
            "layer"
          ]
        },
        "Null": {
          "aws:RequestTag/deployment_id": "false",
          "aws:RequestTag/release_version": "false",
          "aws:RequestTag/change_id": "false",
          "aws:RequestTag/operation": "false",
          "aws:RequestTag/layer": "false"
        }
      }
    },
    {
      "Sid": "AllowOrchestratorSetSourceIdentity",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${SHARED_SERVICES_ACCT}:role/ScanalyzeOrchestrator"
      },
      "Action": "sts:SetSourceIdentity",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "${ORGANIZATION_ID}"
        },
        "StringLike": {
          "sts:SourceIdentity": "exec_*"
        }
      }
    }
  ]
}
```

#### ScanalyzeCustomer-Promotion Trust Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowOrchestratorAssumeRole",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${SHARED_SERVICES_ACCT}:role/ScanalyzeOrchestrator"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "${ORGANIZATION_ID}",
          "aws:RequestTag/deployment_id": "${aws:ResourceTag/deployment_id}",
          "aws:RequestTag/operation": "promote"
        }
      }
    },
    {
      "Sid": "AllowOrchestratorTagSession",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${SHARED_SERVICES_ACCT}:role/ScanalyzeOrchestrator"
      },
      "Action": "sts:TagSession",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "${ORGANIZATION_ID}",
          "aws:RequestTag/operation": "promote"
        },
        "ForAllValues:StringEquals": {
          "aws:TagKeys": [
            "deployment_id",
            "release_version",
            "change_id",
            "operation"
          ]
        },
        "Null": {
          "aws:RequestTag/deployment_id": "false",
          "aws:RequestTag/release_version": "false",
          "aws:RequestTag/change_id": "false",
          "aws:RequestTag/operation": "false"
        }
      }
    },
    {
      "Sid": "AllowOrchestratorSetSourceIdentity",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${SHARED_SERVICES_ACCT}:role/ScanalyzeOrchestrator"
      },
      "Action": "sts:SetSourceIdentity",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "${ORGANIZATION_ID}"
        },
        "StringLike": {
          "sts:SourceIdentity": "exec_*"
        }
      }
    }
  ]
}
```

#### ScanalyzeCustomer-Validation Trust Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowOrchestratorAssumeRole",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${SHARED_SERVICES_ACCT}:role/ScanalyzeOrchestrator"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "${ORGANIZATION_ID}",
          "aws:RequestTag/deployment_id": "${aws:ResourceTag/deployment_id}",
          "aws:RequestTag/operation": "validate"
        }
      }
    },
    {
      "Sid": "AllowOrchestratorTagSession",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${SHARED_SERVICES_ACCT}:role/ScanalyzeOrchestrator"
      },
      "Action": "sts:TagSession",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "${ORGANIZATION_ID}",
          "aws:RequestTag/operation": "validate"
        },
        "ForAllValues:StringEquals": {
          "aws:TagKeys": [
            "deployment_id",
            "release_version",
            "change_id",
            "operation"
          ]
        },
        "Null": {
          "aws:RequestTag/deployment_id": "false",
          "aws:RequestTag/release_version": "false",
          "aws:RequestTag/change_id": "false",
          "aws:RequestTag/operation": "false"
        }
      }
    },
    {
      "Sid": "AllowOrchestratorSetSourceIdentity",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${SHARED_SERVICES_ACCT}:role/ScanalyzeOrchestrator"
      },
      "Action": "sts:SetSourceIdentity",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "${ORGANIZATION_ID}"
        },
        "StringLike": {
          "sts:SourceIdentity": "exec_*"
        }
      }
    }
  ]
}
```

#### ScanalyzeCustomer-Diagnostic Trust Policy (break-glass only)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowBreakGlassAssumeRole",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${SHARED_SERVICES_ACCT}:role/ScanalyzeBreakGlass"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "${ORGANIZATION_ID}",
          "aws:RequestTag/deployment_id": "${aws:ResourceTag/deployment_id}",
          "aws:RequestTag/operation": "diagnostic"
        }
      }
    },
    {
      "Sid": "AllowBreakGlassTagSession",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${SHARED_SERVICES_ACCT}:role/ScanalyzeBreakGlass"
      },
      "Action": "sts:TagSession",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "${ORGANIZATION_ID}",
          "aws:RequestTag/operation": "diagnostic"
        },
        "ForAllValues:StringEquals": {
          "aws:TagKeys": [
            "deployment_id",
            "incident_id",
            "operator_id",
            "operation"
          ]
        },
        "Null": {
          "aws:RequestTag/deployment_id": "false",
          "aws:RequestTag/incident_id": "false",
          "aws:RequestTag/operator_id": "false",
          "aws:RequestTag/operation": "false"
        }
      }
    },
    {
      "Sid": "AllowBreakGlassSetSourceIdentity",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${SHARED_SERVICES_ACCT}:role/ScanalyzeBreakGlass"
      },
      "Action": "sts:SetSourceIdentity",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "${ORGANIZATION_ID}"
        },
        "StringLike": {
          "sts:SourceIdentity": "bg_*"
        }
      }
    }
  ]
}
```

#### ScanalyzeCustomer-StateRecovery Trust Policy (break-glass only)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowBreakGlassAssumeRole",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${SHARED_SERVICES_ACCT}:role/ScanalyzeBreakGlass"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "${ORGANIZATION_ID}",
          "aws:RequestTag/deployment_id": "${aws:ResourceTag/deployment_id}",
          "aws:RequestTag/operation": "state-recovery"
        }
      }
    },
    {
      "Sid": "AllowBreakGlassTagSession",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${SHARED_SERVICES_ACCT}:role/ScanalyzeBreakGlass"
      },
      "Action": "sts:TagSession",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "${ORGANIZATION_ID}",
          "aws:RequestTag/operation": "state-recovery"
        },
        "ForAllValues:StringEquals": {
          "aws:TagKeys": [
            "deployment_id",
            "incident_id",
            "operator_id",
            "operation"
          ]
        },
        "Null": {
          "aws:RequestTag/deployment_id": "false",
          "aws:RequestTag/incident_id": "false",
          "aws:RequestTag/operator_id": "false",
          "aws:RequestTag/operation": "false"
        }
      }
    },
    {
      "Sid": "AllowBreakGlassSetSourceIdentity",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${SHARED_SERVICES_ACCT}:role/ScanalyzeBreakGlass"
      },
      "Action": "sts:SetSourceIdentity",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "${ORGANIZATION_ID}"
        },
        "StringLike": {
          "sts:SourceIdentity": "bg_*"
        }
      }
    }
  ]
}
```

### 5. Trust Policy Design Rules

| Rule | Implementation | Why |
|---|---|---|
| **Separate statements per action** | `sts:AssumeRole`, `sts:TagSession`, `sts:SetSourceIdentity` each in own statement | Condition keys have action-specific applicability; combining causes `UNSUPPORTED_ACTION_FOR_CONDITION_KEY` |
| **No duplicate JSON keys** | Each `StringEquals`, `Null`, `ForAllValues:StringEquals` appears exactly once per statement | Duplicate keys → parser drops first → silent condition elimination |
| **Exact principal** | Full role ARN, not account root or wildcard | Prevents any other role in the account from assuming |
| **PrincipalOrgID** | Defense-in-depth: verifies calling account is within Organization | Mitigates principal ARN spoofing if account is compromised |
| **Deployment binding** | `aws:RequestTag/deployment_id == aws:ResourceTag/deployment_id` | Binds session to the specific deployment this role represents |
| **Tag allowlist** | `ForAllValues:StringEquals` on `aws:TagKeys` | Prevents caller from adding unexpected tags |
| **Required tags via Null** | Each required tag checked with `Null: false` individually | `ForAllValues` is vacuously true on empty set; `Null` catches missing tags |
| **Operation tag per role** | `plan`, `apply`, `promote`, `validate`, `diagnostic`, `state-recovery` | Even if someone obtains the role ARN, they must know the correct operation |
| **No TransitiveTagKeys** | Customer roles are terminal (no further AssumeRole) | Simpler, more secure; SourceIdentity persists natively |
| **SourceIdentity format** | `exec_{ULID}` for orchestrator, `bg_{hash8}` for break-glass | Dynamic, per-execution, immutable through chain, ≤64 chars |

### 6. SourceIdentity Model

```
Pipeline execution starts
  → ScanalyzePipelineExecution role (no SourceIdentity yet)
  → assumes ScanalyzeOrchestrator
     SourceIdentity = "exec_01J5ABCDEFGHJKMNP" (ULID, set ONCE)
  → assumes ScanalyzeCustomer-Plan
     SourceIdentity persists: "exec_01J5ABCDEFGHJKMNP"
     (sts:SetSourceIdentity is allowed on the Plan trust, but STS
      preserves the existing SourceIdentity from the chained session;
      the caller does NOT re-set it — it is immutable after first hop)
```

| Property | Value |
|---|---|
| **Set at** | First trusted hop (Orchestrator for automation, BreakGlass for incidents) |
| **Format** | `exec_{ULID}` (26 chars total) or `bg_{hash8}` (11 chars total) |
| **Immutable** | Once set, persists through all subsequent role assumptions in the chain |
| **Cannot be replaced** | STS rejects if a chained session attempts to set a different SourceIdentity |
| **Length** | 2–64 characters (AWS limit) |
| **Trust policy** | `StringLike: {"sts:SourceIdentity": "exec_*"}` for orchestrator roles |
| **CloudTrail** | `requestParameters.sourceIdentity` in every AssumeRole event |

### 7. Session Tags Schema

#### Orchestrator sessions (Plan, Apply, Promotion, Validation)

| Tag | Source | Purpose | Required | Example |
|---|---|---|---|---|
| `deployment_id` | Registry lookup | Target deployment | ✅ | `dep_01J5ABC` |
| `release_version` | Release manifest | Release being deployed | ✅ | `2026.06.1` |
| `change_id` | Pipeline execution ID | Traceability | ✅ | `chg_01J5XYZ` |
| `operation` | Pipeline step | `plan`, `apply`, `promote`, `validate` | ✅ | `plan` |
| `layer` | Orchestrator logic | Terraform layer being operated | ✅ (Plan/Apply) | `network` |

> [!NOTE]
> `layer` is required for Plan and Apply operations. It is NOT required for Promotion or Validation because those operations are not layer-specific. The `ForAllValues:StringEquals` on `aws:TagKeys` for Promotion/Validation omits `layer` from the allowlist.

#### Break-glass sessions (Diagnostic, StateRecovery)

| Tag | Source | Purpose | Required | Example |
|---|---|---|---|---|
| `deployment_id` | Operator + registry | Target deployment | ✅ | `dep_01J5ABC` |
| `incident_id` | Incident management | Traceability | ✅ | `INC-2026-0042` |
| `operator_id` | Identity Center user | Who is accessing | ✅ | `cesar` |
| `operation` | Operator | `diagnostic` or `state-recovery` | ✅ | `diagnostic` |

### 8. Session Name Convention

```
Format: {op}-{dep_hash8}-{change_ulid8}

Orchestrator:
  "pln-a1b2c3d4-01J5ABCD"    (plan)
  "apl-a1b2c3d4-01J5ABCD"    (apply)
  "prm-a1b2c3d4-01J5ABCD"    (promote)
  "val-a1b2c3d4-01J5ABCD"    (validate)

Break-glass:
  "diag-a1b2c3d4-INC20260042" (diagnostic)
  "srec-a1b2c3d4-INC20260042" (state-recovery)

Max length: 3 + 1 + 8 + 1 + 8-12 = 21-25 chars (well within 64)
Full deployment_id, release_version, change_id in session tags.
```

### 9. Layer-Scoped Authorization

A single Apply role per account has a high blast radius. Authorization is scoped per layer using **session policies** passed by the orchestrator at AssumeRole time.

```
Orchestrator assumes ScanalyzeCustomer-Apply with:
  Session tags:
    layer = "network"
  Session policy (inline, max 2048 chars):
    {
      "Version": "2012-10-17",
      "Statement": [{
        "Effect": "Allow",
        "Action": [...network-layer actions...],
        "Resource": [...network-layer resources...]
      }]
    }
```

Session policies can only **reduce** permissions, never expand them. The effective permissions are the intersection of:
1. Role identity policy
2. Permissions boundary
3. Session policy

| Layer | Session policy allows |
|---|---|
| **global** | IAM (ECS task roles only), application policies |
| **network** | VPC, subnets, route tables, NAT, IGW, VPC endpoints, SGs, flow logs |
| **platform** | ECS cluster, ALB, target groups, listeners, SGs |
| **data-foundation** | DynamoDB, S3 document buckets, SQS, KMS app keys, CloudWatch alarms |
| **services** | ECS task definitions, ECS services, autoscaling, CloudWatch log groups |
| **edge-identity** | Cognito, API Gateway, CloudFront, WAF, Route53, ACM |
| **addons** | CloudWatch dashboards, composite alarms, optional features |

> [!IMPORTANT]
> **`iam:PassRole` is restricted in the session policy** to the exact task role ARN(s) for the layer being applied, with `iam:PassedToService` condition limiting it to `ecs-tasks.amazonaws.com`. Apply cannot PassRole to arbitrary services.

### 10. Control-Role Protection

The workload Apply role cannot modify the control-plane roles created by the account baseline. This is enforced by the Apply role's permissions boundary.

#### Apply Permissions Boundary — Control-Role Protection

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyControlRoleModification",
      "Effect": "Deny",
      "Action": [
        "iam:TagRole",
        "iam:UntagRole",
        "iam:UpdateAssumeRolePolicy",
        "iam:DeleteRole",
        "iam:PutRolePolicy",
        "iam:DeleteRolePolicy",
        "iam:AttachRolePolicy",
        "iam:DetachRolePolicy",
        "iam:PutRolePermissionsBoundary",
        "iam:DeleteRolePermissionsBoundary"
      ],
      "Resource": [
        "arn:aws:iam::${CUSTOMER_ACCT}:role/ScanalyzeCustomer-Plan",
        "arn:aws:iam::${CUSTOMER_ACCT}:role/ScanalyzeCustomer-Apply",
        "arn:aws:iam::${CUSTOMER_ACCT}:role/ScanalyzeCustomer-Promotion",
        "arn:aws:iam::${CUSTOMER_ACCT}:role/ScanalyzeCustomer-Validation",
        "arn:aws:iam::${CUSTOMER_ACCT}:role/ScanalyzeCustomer-Diagnostic",
        "arn:aws:iam::${CUSTOMER_ACCT}:role/ScanalyzeCustomer-StateRecovery"
      ]
    },
    {
      "Sid": "DenyBaselineResourceModification",
      "Effect": "Deny",
      "Action": [
        "s3:DeleteBucket",
        "s3:PutBucketPolicy",
        "kms:ScheduleKeyDeletion",
        "kms:DisableKey",
        "kms:PutKeyPolicy"
      ],
      "Resource": [
        "arn:aws:s3:::scanalyze-${CUSTOMER_ACCT}-tf-state",
        "arn:aws:s3:::scanalyze-${CUSTOMER_ACCT}-tf-evidence",
        "arn:aws:s3:::scanalyze-${CUSTOMER_ACCT}-contracts",
        "arn:aws:kms:*:${CUSTOMER_ACCT}:key/*"
      ],
      "Condition": {
        "StringEquals": {
          "aws:ResourceTag/managed_by": "scanalyze-account-baseline"
        }
      }
    }
  ]
}
```

> [!IMPORTANT]
> This prevents a compromised Apply session from modifying the trust policies, tags, or permissions boundaries of the very roles that authorize its own access.

### 11. ACCOUNT_READY Bootstrap Contract

The AccountVendingProvider produces this contract after baseline provisioning. The orchestrator validates it fail-closed before any workload deployment.

```json
{
  "$schema": "https://scanalyze.io/schemas/account-ready/v1.json",
  "contract_type": "account_ready",
  "contract_version": "v1",
  "deployment_id": "dep_01J5ABCDEFGHJKMNP",
  "account_id": "123456789012",
  "organization_id": "o-rpnh6nbjnt",
  "baseline_version": "1.0.0",
  "region": "us-east-1",
  "roles": {
    "plan": "arn:aws:iam::123456789012:role/ScanalyzeCustomer-Plan",
    "apply": "arn:aws:iam::123456789012:role/ScanalyzeCustomer-Apply",
    "promotion": "arn:aws:iam::123456789012:role/ScanalyzeCustomer-Promotion",
    "validation": "arn:aws:iam::123456789012:role/ScanalyzeCustomer-Validation",
    "diagnostic": "arn:aws:iam::123456789012:role/ScanalyzeCustomer-Diagnostic",
    "state_recovery": "arn:aws:iam::123456789012:role/ScanalyzeCustomer-StateRecovery"
  },
  "buckets": {
    "state": "arn:aws:s3:::scanalyze-123456789012-tf-state",
    "evidence": "arn:aws:s3:::scanalyze-123456789012-tf-evidence",
    "contracts": "arn:aws:s3:::scanalyze-123456789012-contracts"
  },
  "kms_keys": {
    "state": "arn:aws:kms:us-east-1:123456789012:key/key-id-state",
    "evidence": "arn:aws:kms:us-east-1:123456789012:key/key-id-evidence",
    "contracts": "arn:aws:kms:us-east-1:123456789012:key/key-id-contracts"
  },
  "created_at": "2026-06-23T12:00:00Z",
  "contract_digest": "sha256:abc123..."
}
```

#### Orchestrator validation (fail-closed)

```
1. contract_type == "account_ready"           → else ABORT
2. deployment_id == registry.deployment_id    → else ABORT
3. account_id == registry.account_id          → else ABORT
4. organization_id == config.organization_id  → else ABORT
5. All 6 role ARNs present and parseable      → else ABORT
6. All 3 bucket ARNs present and parseable    → else ABORT
7. All 3 KMS key ARNs present and parseable   → else ABORT
8. account_id in all ARNs matches account_id  → else ABORT
9. contract_digest == sha256(contract_body)   → else ABORT
10. baseline_version >= minimum_required      → else ABORT
```

### 12. Role × Operation × Layer × Actions Matrix

#### Plan Role — per layer

| Layer | Key AWS actions allowed | Resources |
|---|---|---|
| **global** | `iam:Get*`, `iam:List*` | ECS task roles, app policies only (not control roles) |
| **network** | `ec2:Describe*` | VPC, subnets, route tables, NAT, IGW, endpoints, SGs |
| **platform** | `ecs:Describe*`, `ecs:List*`, `elasticloadbalancing:Describe*` | ECS cluster, ALB, TGs |
| **data-foundation** | `dynamodb:Describe*`, `dynamodb:List*`, `sqs:GetQueue*`, `sqs:List*`, `kms:Describe*`, `kms:List*` | Tables, queues, keys |
| **services** | `ecs:Describe*`, `ecs:List*`, `logs:Describe*`, `application-autoscaling:Describe*` | Task defs, services, log groups |
| **edge-identity** | `cognito-idp:Describe*`, `apigateway:GET`, `cloudfront:Get*`, `wafv2:Get*`, `route53:Get*`, `acm:Describe*` | Auth/API/CDN resources |
| **addons** | `cloudwatch:Describe*`, `cloudwatch:List*` | Dashboards, alarms |
| **All layers** | `s3:GetObject` (state key), `s3:GetObject`+`s3:PutObject`+`s3:DeleteObject` (lock key), `kms:Decrypt` (state KMS) | State bucket scoped to layer prefix |

#### Apply Role — per layer (via session policy)

| Layer | Key AWS write actions | Critical restrictions |
|---|---|---|
| **global** | `iam:CreateRole`, `iam:PutRolePolicy`, `iam:AttachRolePolicy`, `iam:PassRole` | Only ECS task roles. NOT control-plane roles (denied by boundary). `iam:PassRole` only to `ecs-tasks.amazonaws.com` |
| **network** | `ec2:CreateVpc`, `ec2:CreateSubnet`, `ec2:CreateRouteTable`, `ec2:CreateNatGateway`, `ec2:CreateVpcEndpoint`, `ec2:*SecurityGroup*` | No VPC peering, no TGW |
| **platform** | `ecs:CreateCluster`, `elasticloadbalancing:Create*`, `ec2:*SecurityGroup*` | No ECS services (that's services layer) |
| **data-foundation** | `dynamodb:CreateTable`, `dynamodb:UpdateTable`, `sqs:CreateQueue`, `s3:CreateBucket` (document buckets), `kms:CreateKey` (app keys) | No deleting baseline buckets/keys |
| **services** | `ecs:RegisterTaskDefinition`, `ecs:CreateService`, `ecs:UpdateService`, `ecs:DeregisterTaskDefinition` | `iam:PassRole` only to exact ECS task role ARN |
| **edge-identity** | `cognito-idp:*`, `apigateway:*`, `cloudfront:*`, `wafv2:*`, `route53:*`, `acm:*` | No IAM modifications |
| **addons** | `cloudwatch:PutDashboard`, `cloudwatch:PutCompositeAlarm` | No infrastructure changes |
| **All layers** | `s3:GetObject`+`s3:PutObject` (state key), `s3:*` (lock key), `ssm:PutParameter` (own layer contract prefix), `kms:Encrypt`+`Decrypt`+`GenerateDataKey` (state KMS) | SSM write restricted to `/scanalyze/deployments/{dep}/contracts/{layer}/*` |

### 13. Break-Glass Model

| Attribute | Value |
|---|---|
| **Purpose** | Emergency access when automated orchestration fails |
| **Trigger** | Operational incident requiring manual investigation or state repair |
| **Source role** | `ScanalyzeBreakGlass` in Shared Services |
| **Targets** | `ScanalyzeCustomer-Diagnostic` (read) and `ScanalyzeCustomer-StateRecovery` (state write) |
| **NOT accessible** | Plan, Apply, Promotion, Validation (orchestrator-only) |
| **Access method** | IAM Identity Center permission set → API/CLI (NOT console Switch Role) |
| **Why not console** | Console Switch Role does not support SourceIdentity or session tags |
| **MFA** | Required at Identity Center level |
| **Approval** | Dual approval (two humans, incident ticket mandatory) |
| **Session** | 30 minutes maximum |
| **SourceIdentity** | `bg_{operator_hash8}` (set once at BreakGlass assumption) |
| **Monitoring** | CloudWatch alarm fires ≤ 1 minute |
| **Post-incident** | Mandatory report: actions, resources read/modified, root cause, preventive action |
| **Prohibition** | Never for routine operations, deployments, promotions, or validation |

### 14. Role Resource Tags (Immutable — set by account baseline)

Each of the 6 customer roles is tagged by the AccountVendingProvider at creation time. These tags **cannot be modified by the workload Apply role** (denied by permissions boundary §10).

| Tag | Purpose | Example |
|---|---|---|
| `deployment_id` | Binds role to specific deployment (used in trust condition) | `dep_01J5ABC` |
| `account_id` | Redundant validation | `123456789012` |
| `baseline_version` | Track which baseline template created the role | `1.0.0` |
| `managed_by` | Ownership marker | `scanalyze-account-baseline` |

### 15. Customer-Managed Accounts (Future)

| Attribute | Provider-managed (in Org) | Customer-managed (outside Org) |
|---|---|---|
| `aws:PrincipalOrgID` | ✅ Enforced | ❌ Not applicable |
| `sts:ExternalId` | Optional | ✅ Mandatory (unique per deployment, rotatable) |
| Account baseline | Scanalyze provisions | Customer provisions from template |
| ACCOUNT_READY contract | Automatic | Customer submits, Scanalyze validates |

### 16. Session Duration

| Role chain | Max duration | Rationale |
|---|---|---|
| Pipeline → Orchestrator | 1 hour | Pipeline step timeout |
| Orchestrator → Plan | 1 hour | Plan can be slow for large stacks |
| Orchestrator → Apply | 1 hour | Apply + post-apply checks |
| Orchestrator → Promotion | 1 hour | Image push + verification |
| Orchestrator → Validation | 30 minutes | Health checks are fast |
| BreakGlass → Diagnostic | 30 minutes | Emergency read-only |
| BreakGlass → StateRecovery | 30 minutes | State mutation should be brief |

### 17. CloudTrail Logging

All cross-account AssumeRole events include:

| Field | Value |
|---|---|
| `eventName` | `AssumeRole` |
| `requestParameters.roleArn` | Scoped role ARN (operation in role name) |
| `requestParameters.roleSessionName` | `{op}-{hash8}-{ulid8}` |
| `requestParameters.sourceIdentity` | `exec_{ULID}` or `bg_{hash8}` |
| `requestParameters.tags` | All session tags |

#### Required audit queries

| Query | Purpose |
|---|---|
| All Apply role assumptions in last 24h | Mutation audit |
| All break-glass events in last 30 days | Emergency access review |
| All Diagnostic events without corresponding incident ticket | Unauthorized investigation |
| Apply without preceding Plan for same change_id | Procedure violation |
| StateRecovery events | State mutation audit |
| SourceIdentity appearing across different deployments | Potential compromise |

### 18. Credential Hygiene

| Rule | Implementation |
|---|---|
| No credentials in environment variables | Use ECS task roles, not `AWS_ACCESS_KEY_ID` |
| No credentials in code | Pre-commit hooks scan for credential patterns |
| No credentials in logs | Structured logging redacts credential patterns |
| No credentials on disk | Metadata service only; never written to files |
| No credential forwarding | Each hop authenticates independently |
| Rotate M2M secrets | Secrets Manager auto-rotation |

### 19. Trust Policy Drift Detection

| Check | Frequency | Action |
|---|---|---|
| All 6 scoped role trust policies match template | Per deployment, pre-plan | Drift → block deployment, alert |
| Permissions boundaries attached and correct | Per deployment, pre-plan | Missing → block, alert |
| Role resource tags match baseline | Per deployment, pre-plan | Mismatch → block, alert |
| IAM Access Analyzer findings | Weekly | New external access → investigate |
| Unused permissions report | Monthly | Remove from role policies |

### 20. Role Change Escalation

| Change type | Approval required |
|---|---|
| New principal in any trust policy | Security team + engineering lead |
| New scoped role added | Security team + engineering lead + ADR update |
| Session tag schema change | Engineering lead + ADR-004/005 update |
| Permissions boundary expansion | Security team + justification |
| Break-glass target expansion | Security team + threat model update |
| Control-role tag modification | Account baseline owner + security team |

### 21. Security Tests

| # | Test | Expected result |
|---|---|---|
| 1 | Wrong principal (not Orchestrator/BreakGlass) assumes any role | DENIED |
| 2 | Principal outside Organization assumes any role | DENIED |
| 3 | AssumeRole without SourceIdentity | DENIED |
| 4 | AssumeRole with invalid SourceIdentity format (not `exec_*` / `bg_*`) | DENIED |
| 5 | AssumeRole missing any required tag (deployment_id, release_version, change_id, operation) | DENIED |
| 6 | AssumeRole with unexpected tag key (e.g., `admin=true`) | DENIED |
| 7 | AssumeRole with wrong operation (e.g., `apply` on Plan role) | DENIED |
| 8 | AssumeRole with wrong deployment_id (doesn't match role resource tag) | DENIED |
| 9 | Plan/Apply without `layer` tag | DENIED |
| 10 | Break-glass assumes Plan role | DENIED (not in trust) |
| 11 | Break-glass assumes Apply role | DENIED (not in trust) |
| 12 | Break-glass assumes Promotion role | DENIED (not in trust) |
| 13 | Orchestrator assumes Diagnostic role | DENIED (not in trust) |
| 14 | Orchestrator assumes StateRecovery role | DENIED (not in trust) |
| 15 | Apply role modifies control-role trust policy | DENIED (permissions boundary) |
| 16 | Apply role tags/untags control role | DENIED (permissions boundary) |
| 17 | Apply role deletes control-role permissions boundary | DENIED (permissions boundary) |
| 18 | Apply role deletes baseline S3 bucket | DENIED (permissions boundary) |
| 19 | Apply role schedules baseline KMS key deletion | DENIED (permissions boundary) |
| 20 | RoleSessionName > 64 characters | Rejected by STS API |
| 21 | SourceIdentity > 64 characters | Rejected by STS API |
| 22 | Plan role attempts terraform apply (infrastructure write) | DENIED (no write perms) |
| 23 | Apply role attempts ECR push | DENIED (wrong scope) |
| 24 | Promotion role attempts terraform apply | DENIED (wrong scope) |
| 25 | Validation role attempts any write | DENIED |
| 26 | Diagnostic role attempts any write | DENIED |
| 27 | StateRecovery role writes to non-state-bucket resource | DENIED |
| 28 | Break-glass use → CloudWatch alarm fires | ≤ 1 minute |
| 29 | Apply without preceding Plan (same change_id) | Orchestrator rejects (pipeline logic, not IAM) |
| 30 | Orchestrator validates ACCOUNT_READY with wrong account_id | ABORT |
| 31 | Orchestrator validates ACCOUNT_READY with missing role ARN | ABORT |
| 32 | Orchestrator validates ACCOUNT_READY with tampered digest | ABORT |

---

## Consequences

### Positive
- Least-privilege per operation: plan cannot write, apply cannot push images
- Break-glass cannot bypass deployment pipeline (no access to Apply/Promotion)
- Every operation is attributable via SourceIdentity (per-execution ULID) + scoped role name + session tags
- Deployment binding prevents confused deputy (deployment_id must match role's immutable tag)
- Tag allowlist prevents tag injection
- Control-role protection prevents Apply from modifying its own authorization
- No bootstrap cycle: account baseline creates roles before workload Terraform runs
- Layer-scoped session policies reduce blast radius of a single Apply session
- Customer roles are terminal: no further role chaining, simpler threat model
- Trust policies pass IAM Access Analyzer validation (no duplicate keys, no action/condition mismatches)

### Negative
- 6 roles per customer account adds IAM complexity
- Session policy per layer requires orchestrator to maintain layer-specific policy templates
- AccountVendingProvider must be implemented before any customer deployment
- Break-glass requires API/CLI (not console Switch Role) for SourceIdentity and tags
- Per-layer SSM write restrictions require careful prefix management

---

## References

- ADR-001: Tenancy Model (1:1 account per deployment)
- ADR-002: Organization (OrgID, SCPs, account vending)
- ADR-009: Threat Model (T1.1 orchestrator compromise, T1.4 IAM persistence, T1.5 break-glass abuse, T1.6 confused deputy)
- AWS IAM: [SourceIdentity](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_sts_source-identity.html)
- AWS IAM: [Session Tags](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_session-tags.html)
- AWS IAM: [Permissions Boundaries](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html)
- AWS STS: [AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)
- AWS IAM: [Session Policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html#policies_session)
- AWS IAM: [aws:TagKeys condition key](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-tagkeys)
- AWS IAM Access Analyzer: [Policy Validation](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-validation.html)
