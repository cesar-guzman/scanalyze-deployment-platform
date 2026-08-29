# ADR-006: Terraform Modules, Roots, States, and Inter-Layer Contracts

> **Status**: `DRAFT rev4`<br>
> **Date**: 2026-06-23  
> **Decision makers**: César Guzmán  
> **Scope**: Scanalyze Dedicated Deployment Platform  
> **Depends on**: ADR-003 rev4, ADR-004 rev3, ADR-005<br>
> **Rev4 changes**: Retains rev3 contract controls and adds the dedicated tf-plan bucket, exact saved-plan/state object bindings, private plan-JSON handling, and separately approved Plan/Apply runs

---

## Context

The current brownfield implementation has fragmented Terraform roots with unclear ownership boundaries and implicit dependencies between layers. The greenfield platform must provide:

1. Reusable modules that work identically across customer accounts
2. Clear ownership: 1 root = 1 state = 1 logical namespace
3. Explicit contracts between layers (no `terraform_remote_state`)
4. One and only one contract writer per contract
5. Deterministic plans without volatile functions
6. **Fail-closed contract validation** — invalid or missing contracts must block plan/apply, not produce warnings

---

## Decision

### 1. Repository Layout

```
scanalyze-deployment-platform/
├── .github/workflows/                 # Validation and protected orchestration
├── bootstrap/                         # Account-baseline CloudFormation candidates
├── deployment/
│   ├── layers.yaml                    # Canonical 13-stage DAG and contracts
│   └── ownership.yaml                 # Canonical root/resource ownership
├── modules/                           # Reusable Terraform modules
├── roots/                             # Terraform roots selected by the DAG
├── schemas/                           # Versioned public contracts
├── policies/                          # IAM, KMS and S3 policy candidates
├── scripts/deployment/                # Thin reviewed CLI entrypoints
├── tooling/                           # Typed materializers/controllers/adapters
└── tests/                             # Python and Terraform contract tests
```

`deployment/layers.yaml` is the executable inventory. This layout summary must
not be used to infer a missing root, stage, contract version or role.

### 2. Layer Dependency Graph

The external account baseline is not one of the repository roots. It creates
the eight terminal roles, four buckets and three KMS keys, then produces the
`ACCOUNT_READY` v2 prerequisite. The executable repository DAG is:

| Order | Stage | Kind/root | Direct predecessor | Produced contract | Terminal roles |
|---:|---|---|---|---|---|
| 1 | `account-ready-gate` | gate / `roots/account-ready-gate` | — | — | none |
| 2 | `global` | Terraform / `roots/global` | `account-ready-gate` | `global/v1` | Plan / Apply |
| 3 | `network` | Terraform / `roots/network` | `global` | `network/v2` | Plan / Apply |
| 4 | `platform` | Terraform / `roots/platform` | `network` | `platform/v2` | Plan / Apply |
| 5 | `data-foundation` | Terraform / `roots/data-foundation` | `platform` | `data-foundation/v2` | Plan / Apply |
| 6 | `cicd` | Terraform / `roots/cicd` | `data-foundation` | `cicd/v2` | Plan / Apply |
| 7 | `artifact-publication` | artifact / no root | `cicd` | `release-manifest/v1` | Validation / Promotion |
| 8 | `identity-control-plane` | Terraform / `roots/identity-control-plane` | `artifact-publication` | `identity-control-plane/v1` | Identity-Plan / Identity-Apply |
| 9 | `services` | Terraform / `roots/services` | `identity-control-plane` | `services/v2` | Plan / Apply |
| 10 | `edge-identity` | Terraform / `roots/edge-identity` | `services` | `edge-identity/v2` | Plan / Apply |
| 11 | `edge` | Terraform / `roots/edge` | `edge-identity` | `edge/v2` | Plan / Apply |
| 12 | `addons` | Terraform / `roots/addons` | `edge` | `addons/v2` | Plan / Apply |
| 13 | `synthetic-validation` | validation / no root | `addons` | — | Validation only |

> [!IMPORTANT]
> **Dependencies are strictly acyclic.** A layer at level N can only consume contracts from layers at level < N.
>
> **Services layer is the sole owner of ECS task definitions** — no separate task-definition registration exists in the deployment pipeline (ADR-010).
>
> **edge-identity is separated from addons** because: (a) Cognito/API Gateway/CloudFront are foundational to the platform's auth and routing — they are not optional; (b) addons are optional enterprise features with different lifecycle; (c) WAF/ACM/Route53 changes need distinct approval and testing.

### 3. Inter-Layer Contracts via SSM

**`terraform_remote_state` is prohibited.** Layers communicate exclusively via SSM Parameter Store contracts.

#### Single Producer-Layer Authority Rule

> [!WARNING]
> **Each contract has EXACTLY ONE producer layer.** In the connected path, the
> typed controller invokes the canonical create-only publisher under that
> producer layer's exact terminal role and mandatory session tags; this is the producer root's
> publication boundary, not a second writer. Other roots, ad hoc scripts,
> operators and pipeline stages remain read-only. The deployed terminal-role
> identity policy scopes the SSM resource by the required `layer` principal tag
> (or by the dedicated identity role's fixed prefix), and consumers never write.
> Per-execution session-policy narrowing is a downstream control, not an
> implemented claim (§9).

#### Contract producer boundary

The Terraform root emits only its declared output object. After the exact saved
plan is applied and the post-apply gates succeed, the typed controller builds a
`schemas/layer-contract.v2.schema.json` envelope from the private Terraform
output plus sealed deployment, release, state-key and module-source bindings.
For `network/v2`, the immutable parameter name is derived as:

```text
/scanalyze/deployments/{deployment_id}/contracts/network/v2/
  releases/{release_digest}/digests/{contract_digest}
```

The conceptual `sha256:<hex>` components are encoded with the repository's
one-to-one SSM-safe mapping. Publication is one create-only Standard/String
`PutParameter`, followed by two exact value and tag readbacks. A lost response
may be reconciled only from those readbacks; it never causes an overwrite or a
second write.

The explicit `produced_at` value is bound by sealed action-time input. Terraform
configuration must not call `timestamp()` or derive mutable publication
authority from SSM metadata.

#### Contract Consumer — Fail-Closed with Preconditions

> [!CAUTION]
> **`check` blocks produce WARNINGS, not ERRORS.** They do NOT block `terraform plan` or `terraform apply`. For contract validation that MUST prevent deployment on failure, use `precondition` blocks inside `lifecycle` on a `terraform_data` resource. Preconditions cause `terraform plan` to exit with code 1 (error).

The live resolver, not Terraform, performs bounded discovery and two exact reads
of each catalog-declared immutable parameter. It validates the closed v2
envelope, producer, customer/deployment/account/region/scope tuple, release,
state key, module source, output schema and recomputed output digest. It writes
only a private mode-`0600` resolution-v3 document. The Terraform wrapper
validates that resolution again and injects its bounded projection. Each root
then uses `terraform_data` preconditions to reject a missing or mismatched
upstream digest/schema before any resource change.

**Why `terraform_data` with `precondition` instead of `check` with `assert`:**

| Mechanism | On failure | Blocks plan? | Blocks apply? | Test framework |
|---|---|---|---|---|
| `check { assert {} }` | Warning in plan output | ❌ No | ❌ No | `terraform test` (expects warning) |
| `resource "terraform_data" { lifecycle { precondition {} } }` | Error, plan exits code 1 | ✅ Yes | ✅ Yes | `terraform test` (expects error) |
| `data source { lifecycle { precondition {} } }` | Error, plan exits code 1 | ✅ Yes | ✅ Yes | `terraform test` (expects error) |

> [!NOTE]
> Preconditions on the `data "aws_ssm_parameter"` resource itself would also work, but placing them on a dedicated `terraform_data` gate resource makes the intent explicit and keeps the contract validation separate from the data fetch.

### 4. Content-Addressed Contract Verification

Contracts include `contract_digest` (SHA-256 of canonical `outputs`) plus exact
producer, release, `state_key` and `module_source_digest` bindings. State
VersionId/hash/size, lineage and serial remain in the saved-plan and durable
execution evidence; they are not duplicated into the public SSM envelope.

#### How consumers verify

```
1. Parse with duplicate-key and non-finite-number rejection.
2. Validate the closed `layer-contract.v2` schema.
3. Require the exact catalog producer, tuple, release, state key, module digest
   and output-schema version.
4. Recompute the canonical outputs SHA-256 and require `contract_digest` equality.
5. Require two identical exact SSM value/tag readbacks; any absence, ambiguity,
   denial or movement is `BLOCKED`.
```

#### How the orchestrator verifies contract freshness

Before running the consumer layer, the orchestrator verifies that every
upstream contract is the exact immutable leaf declared by the canonical DAG:

```
For each required contract in deployment/layers.yaml:
  1. Derive its exact versioned release prefix from sealed authority.
  2. Take two bounded discovery snapshots and require one digest leaf.
  3. Read that exact parameter and tags twice.
  4. Validate freshness, tuple, producer, release, state key and digests.
  5. Persist the private resolution-v3 projection; otherwise ABORT.
```

### 5. Contract Schema Versioning

| Change type | Version action | SSM path | Consumer impact |
|---|---|---|---|
| **Additive** (new optional output accepted by the same schema) | Keep the declared contract ID | New content-addressed digest leaf under the same `/vN/releases/...` prefix | Existing consumers remain schema-compatible |
| **Breaking** (remove field, rename, type change) | Increment the contract ID | New `/vN` prefix and catalog entry | Consumers must explicitly declare the new ID |
| **Deprecation** | Keep old and new IDs during a reviewed window | Distinct immutable leaves; no mutable alias | Consumers migrate explicitly; unknown IDs block |

### 6. Contract Size Strategy — Large Payloads

The implemented live transport accepts only one canonical Standard/String SSM
value of at most 4,096 bytes. An oversized envelope fails before the write.
Advanced-tier parameters and S3 pointer manifests are not implemented and must
not be inferred from the retained contracts bucket; either requires a separate
schema, IAM, lifecycle and connected-validation decision.

### 7. Variable Injection

Orchestrator renders `terraform.tfvars` from deployment record. Unchanged from rev1.

### 8. Deployment Profiles

Unchanged from rev1.

### 9. Contract IAM Enforcement per Layer

The generic Apply role's identity policy restricts SSM writes to a resource ARN
containing `${aws:PrincipalTag/layer}` and requires `operation=apply`. The trust
and controller require the exact layer and operation session tags. The dedicated
Identity-Apply role has only the fixed `identity-control-plane` contract prefix.
The current terminal session does not pass STS `--policy` or `--policy-arns`;
per-execution session-policy narrowing remains blocked downstream.

```
When orchestrator assumes Apply for layer "network":
  Session tag: layer = "network"
  Terminal-role identity policy resolves:
    {
      "Effect": "Allow",
      "Action": "ssm:PutParameter",
      "Resource": "arn:aws:ssm:${region}:${account}:parameter/scanalyze/deployments/${dep_id}/contracts/${aws:PrincipalTag/layer}/*",
      "Condition": {"StringEquals": {"aws:PrincipalTag/operation": "apply"}}
    }
```

| Layer executing | Can write SSM contracts under |
|---|---|
| global | `/scanalyze/deployments/{dep}/contracts/global/*` |
| network | `/scanalyze/deployments/{dep}/contracts/network/*` |
| platform | `/scanalyze/deployments/{dep}/contracts/platform/*` |
| data-foundation | `/scanalyze/deployments/{dep}/contracts/data-foundation/*` |
| cicd | `/scanalyze/deployments/{dep}/contracts/cicd/*` |
| identity-control-plane | `/scanalyze/deployments/{dep}/contracts/identity-control-plane/*` |
| services | `/scanalyze/deployments/{dep}/contracts/services/*` |
| edge-identity | `/scanalyze/deployments/{dep}/contracts/edge-identity/*` |
| edge | `/scanalyze/deployments/{dep}/contracts/edge/*` |
| addons | `/scanalyze/deployments/{dep}/contracts/addons/*` |

> [!IMPORTANT]
> This prevents the current tagged terminal session from writing another
> layer's contract. It is an IAM identity-policy control, not proof of the
> broader service/resource isolation that future per-execution session policies
> must provide.

### 10. Module Testing Strategy

| Test type | Tool | Scope | Runs on |
|---|---|---|---|
| **Module unit tests** | `terraform test` (HCL) | Module logic, variable validation, output format | Every PR |
| **Contract tests** | Custom script + JSON Schema | Producer output matches schema; Consumer can parse | Every PR |
| **Precondition tests** | `terraform test` with invalid fixtures | Contract gate rejects bad input (exit code 1) | Every PR |
| **Plan tests** | `terraform plan` with golden fixtures | Resource counts and types match expectations | Every PR |
| **Session policy tests** | Hermetic policy/command tests | SSM write restricted to the exact producer prefix | Every PR |
| **Connected denial tests** | Authorized short-lived AWS session | Effective IAM and SSM create-only/readback behavior | Separately approved DEV exercise |
| **Integration tests** | Protected saved-plan workflow | Full stack deployment + validation suite | Separately approved DEV exercise |

#### Precondition test example

The regression matrix must cover wrong deployment/account/region/release,
foreign producer or state key, unsupported output schema, duplicate keys,
non-finite values, stale/ambiguous/moving SSM evidence, digest tampering,
oversize values, overwrite attempts and wrong-layer publication. Terraform
tests assert that a mismatched injected digest or schema fails at the root's
`terraform_data.contract_gate`; Python tests exercise the resolver, publisher,
closed schemas, exact command construction and response-loss reconciliation.

### 11. Deployment Orchestration Sequence

```
For each layer in dependency order:
  global → network → platform → data-foundation → cicd
    → artifact-publication → identity-control-plane → services
    → edge-identity → edge → addons → synthetic-validation

  PRE-DEPLOY (orchestrator logic):
    1. Read deployment record from registry
    2. Render backend.tf from template + deployment record
    3. Render terraform.tfvars from deployment record + profile
    4. terraform init (verify provider lock, download providers)

  PLAN (first protected workflow dispatch/run, using Plan role and a session
        policy scoped to this layer):
    5. Read upstream contracts from SSM
       → preconditions fire if invalid → plan fails → deployment blocked
    6. terraform validate
    7. Read the exact current state object and bind bucket, key, VersionId,
       SHA-256, size, lineage, and serial; require the same object immediately
       after planning
    8. terraform plan -out=plan.tfplan
    9. Render terraform show -json only in 0600 private scratch, derive the
       bounded sanitized action manifest, and delete the raw JSON
    10. Compute the plan binary SHA-256 and verify the plan within bounds
    11. Write only plan.tfplan to the dedicated tf-plan plan-execution zone
        (versioned, one-day current/noncurrent lifecycle)
    12. Persist a saved-plan record binding the exact plan bucket, key,
        VersionId, SHA-256 and size and the exact state object binding from
        step 7; stop the Plan run
    13. Obtain independent approval for the immutable plan record and reviewer
        packet; store the approval append-only by digest

  APPLY (a separate protected workflow dispatch/run, using the exact Apply role
         and mandatory layer/operation tags; no STS session policy is wired):
    14. Load and verify the exact append-only approval and saved-plan record
    15. Fetch the exact saved-plan VersionId, recheck its hash/size, and require
        the current state VersionId/hash/size to equal the Plan binding
    16. terraform apply plan.tfplan (from the saved binary, never re-planned)
    17. Advance the durable CAS execution ledger to APPLIED, or to UNCERTAIN
        when the apply result cannot be classified safely

  POST-APPLY (core state machine implemented; live workflow adapters pending):
    18. Re-enter APPLIED/RECONCILED_APPLIED without reapproval or re-apply
    19. Require two identical read-only state observations, structural
        NO_CHANGE, verified input contracts, and explicitly non-sensitive
        outputs written only to 0600 private scratch
    20. Create the health receipt once, publish the exact output contract, and
        verify its exact readback before the CAS transition to HEALTHY
    21. Reconcile UNCERTAIN through read-only observations only; never retry
        terraform apply
```

> [!IMPORTANT]
> The protected path does not write a pre-apply recovery snapshot or any
> COMPLIANCE evidence object, and it never calls `DeleteObject` for the consumed
> plan. Current and noncurrent saved-plan versions are removed only by the
> dedicated plan-bucket lifecycle. The post-apply health/contract interfaces are
> fail-closed but their real workflow adapters are not yet wired, so repository
> implementation does not prove a connected deployment.

### 12. Forbidden Patterns

CI checks reject the following patterns in any `.tf` file:

| Pattern | Reason | Detection |
|---|---|---|
| `terraform_remote_state` | Cross-layer coupling; use SSM contracts | `grep -r "terraform_remote_state"` |
| `source = "hashicorp/..."` | External modules prohibited | `grep -r 'source.*=.*"hashicorp'` |
| `source = "github.com/..."` | External modules prohibited | `grep -r 'source.*=.*"github'` |
| `source = "registry.terraform.io/..."` | External modules prohibited | `grep -r 'source.*=.*"registry'` |
| Hardcoded account ID | Use variable injection | `grep -rP '\d{12}' --include='*.tf'` |
| Hardcoded bucket name | Use variable injection | `grep -r 'scanalyze-[0-9]' --include='*.tf'` |
| `terraform workspace` | Workspaces rejected (ADR-003) | `grep -r 'terraform.workspace'` |
| `:latest` tag | Pin by digest | `grep -r ':latest' --include='*.tf'` |
| `sensitive = false` on outputs with ARN/ID | Must be `sensitive = true` | Custom linter |
| `timestamp()` | Non-deterministic plans; use metadata | `grep -r 'timestamp()' --include='*.tf'` |
| `file("ERROR` | Use `precondition` blocks | `grep -r 'file("ERROR' --include='*.tf'` |
| `check {` for contract validation | Use `precondition` blocks (fail-closed) | Custom linter |
| Control-plane role resources | Belong to account baseline, not workload | Ownership YAML cross-check |
| `ssm:PutParameter` without layer scope | Must be enforced by terminal identity policy plus mandatory principal tags | Policy test |

### 13. Output Sensitivity Rules

Unchanged from rev1.

---

## Consequences

### Positive
- Modules are reusable across all customer deployments identically
- 1:1 root/state/namespace eliminates ownership ambiguity
- SSM contracts are versioned, validated, and **fail-closed** with preconditions (not warnings)
- Single contract writer eliminates race conditions
- Contract writer identity enforced by terminal IAM policy and mandatory
  principal tags, not just convention
- No `timestamp()` means deterministic plans
- Content-addressed contracts plus exact release, state-key and module-source
  bindings detect tampering and substitution
- edge-identity separated from addons: auth/routing changes have dedicated approval
- Plan binaries with secrets are ephemeral (one-day current/noncurrent expiry)
- Evidence-store policy accepts only sanitized summaries; this protected path
  has no evidence writer

### Negative
- 13 stages, including 10 state-owning Terraform roots, add more contracts and
  orchestration boundaries to manage
- Precondition blocks on `terraform_data` are less intuitive than `check` blocks
- Session policy per layer adds orchestrator complexity
- Contract size strategy requires monitoring parameter size growth

---

## References

- ADR-003 rev4: State Backend (four buckets, dedicated saved-plan lifecycle, regional state keys, ownership manifest)
- ADR-004 rev3: Cross-Account Identity (terminal roles/tags and Apply SSM
  scoping; per-execution session-policy narrowing remains downstream)
- ADR-005: Schemas (contract envelope, deployment record)
- ADR-007: Supply Chain (module digest verification)
- ADR-008: Region (network module AZ handling, regional state keys)
- ADR-010: Testing/Rollout (ECS task definition sole ownership)
- [Terraform: Preconditions and Postconditions](https://developer.hashicorp.com/terraform/language/expressions/custom-conditions)
- [Terraform: Check Blocks](https://developer.hashicorp.com/terraform/language/checks) (not used — warnings only)
- [Terraform: Test Framework](https://developer.hashicorp.com/terraform/language/tests)
- [AWS SSM Parameter Store Limits](https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-paramstore-about.html)
