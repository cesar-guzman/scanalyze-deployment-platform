# ADR-006: Terraform Modules, Roots, States, and Inter-Layer Contracts

> **Status**: `DRAFT rev3`  
> **Date**: 2026-06-23  
> **Decision makers**: César Guzmán  
> **Scope**: Scanalyze Dedicated Deployment Platform  
> **Depends on**: ADR-003 rev3, ADR-004 rev3, ADR-005  
> **Rev3 changes**: P0-3 (preconditions bloqueantes, content-addressed contracts, edge-identity split, contract IAM per layer)

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
├── modules/                           # Reusable Terraform modules
│   ├── global/                        # ECS task/app IAM roles (NOT control-plane roles)
│   ├── network/                       # VPC, subnets, NAT, endpoints
│   ├── container-platform/            # ECS cluster, ALB, security groups
│   ├── data-foundation/               # DynamoDB, S3 doc buckets, SQS, KMS app keys
│   ├── services/                      # ECS services, task definitions (TF sole owner)
│   ├── edge-identity/                 # Cognito, API GW, CloudFront, WAF, ACM, Route53
│   └── addons/                        # CloudWatch dashboards, composite alarms, optional
│
├── roots/                             # Deployment roots (instantiate modules)
│   ├── global/
│   │   ├── main.tf
│   │   ├── backend.tf.tmpl            # Templated by orchestrator
│   │   ├── variables.tf
│   │   ├── contracts.tf               # This root's contract output
│   │   └── .terraform.lock.hcl        # Committed
│   ├── network/
│   ├── platform/
│   ├── data-foundation/
│   ├── services/
│   ├── edge-identity/                 # NEW — separated from addons
│   └── addons/
│
├── schemas/                           # JSON Schemas (canonical, versioned)
│   ├── deployment-request.v1.json
│   ├── deployment-record.v1.json
│   ├── release.v1.json
│   ├── release-attestation.v1.json
│   ├── account-ready.v1.json          # ACCOUNT_READY contract (ADR-004)
│   ├── contract-envelope.v1.json      # Generic envelope
│   ├── contract-global.v1.json
│   ├── contract-network.v1.json
│   ├── contract-platform.v1.json
│   ├── contract-data-foundation.v1.json
│   ├── contract-services.v1.json
│   ├── contract-edge-identity.v1.json # NEW
│   └── region-capability.v1.json
│
├── session-policies/                  # Per-layer session policies (ADR-004 §9)
│   ├── plan-global.json
│   ├── plan-network.json
│   ├── apply-global.json
│   ├── apply-network.json
│   ├── apply-platform.json
│   ├── apply-data-foundation.json
│   ├── apply-services.json
│   ├── apply-edge-identity.json
│   └── apply-addons.json
│
├── configs/
│   ├── profiles/                      # Deployment profiles (sizing)
│   ├── retention/                     # Retention profiles
│   └── regions/                       # Region capability matrices
│
├── scripts/
│   ├── orchestrator/                  # Deployment orchestration
│   ├── validate/                      # Validation utilities
│   └── release/                       # Release automation
│
├── tests/
│   ├── modules/                       # Module unit tests (terraform test)
│   ├── contract/                      # Contract compatibility tests
│   ├── golden/                        # Golden fixtures (valid + invalid)
│   ├── sentinel/                      # PII sentinel tests
│   ├── policy/                        # IAM/S3/KMS policy validation tests
│   └── integration/                   # Full-stack integration tests
│
├── pipelines/                         # CI/CD pipeline definitions
│   ├── ci.yml                         # PR checks
│   ├── release.yml                    # Release pipeline
│   └── deployment.yml                 # Per-customer deployment
│
├── ownership.yaml                     # Logical namespace ownership (ADR-003 rev3)
└── CODEOWNERS                         # GitHub code ownership
```

### 2. Layer Dependency Graph

```
account-baseline (layer -1) — AccountVendingProvider (NOT a TF root in this repo)
    │
    ├── Creates: 6 control-plane roles, state/evidence/contracts buckets, KMS keys
    ├── Produces: ACCOUNT_READY contract
    │
    ▼
global (layer 0) — ECS task execution role, ECS task roles, app IAM policies
    │
    ├── Consumes: ACCOUNT_READY (verified by orchestrator, not TF)
    ├── Produces contract: /scanalyze/deployments/{id}/contracts/global/v1
    │
    ▼
network (layer 1) — VPC, subnets, NAT, endpoints
    │
    ├── Consumes: global contract
    ├── Produces contract: /scanalyze/deployments/{id}/contracts/network/v1
    │
    ▼
platform (layer 2) — ECS cluster, ALB, security groups
    │
    ├── Consumes: global, network contracts
    ├── Produces contract: /scanalyze/deployments/{id}/contracts/platform/v1
    │
    ▼
data-foundation (layer 3) — DynamoDB, S3 doc buckets, SQS, KMS app keys
    │
    ├── Consumes: global, network contracts
    ├── Produces contract: /scanalyze/deployments/{id}/contracts/data-foundation/v2
    │
    ▼
services (layer 4) — ECS services, task definitions (Terraform sole owner)
    │
    ├── Consumes: global, platform, data-foundation contracts
    ├── Produces contract: /scanalyze/deployments/{id}/contracts/services/v1
    │
    ▼
edge-identity (layer 5a) — Cognito, API Gateway, CloudFront, WAF, ACM, Route53
    │
    ├── Consumes: global, platform, services contracts
    ├── Produces contract: /scanalyze/deployments/{id}/contracts/edge-identity/v1
    │
    ▼
addons (layer 5b) — CloudWatch dashboards, composite alarms, optional features
    │
    ├── Consumes: global, services, edge-identity contracts
    └── Produces contract: /scanalyze/deployments/{id}/contracts/addons/v1
```

> [!IMPORTANT]
> **Dependencies are strictly acyclic.** A layer at level N can only consume contracts from layers at level < N.
>
> **Services layer is the sole owner of ECS task definitions** — no separate task-definition registration exists in the deployment pipeline (ADR-010).
>
> **edge-identity is separated from addons** because: (a) Cognito/API Gateway/CloudFront are foundational to the platform's auth and routing — they are not optional; (b) addons are optional enterprise features with different lifecycle; (c) WAF/ACM/Route53 changes need distinct approval and testing.

### 3. Inter-Layer Contracts via SSM

**`terraform_remote_state` is prohibited.** Layers communicate exclusively via SSM Parameter Store contracts.

#### Single Contract Writer Rule

> [!WARNING]
> **Each contract is written by EXACTLY ONE Terraform root** — the producer root for that layer. No other root, script, orchestrator step, or pipeline stage may write to a contract SSM parameter. Consumers read only. This is enforced by IAM session policy (§9).

#### Contract Producer (example: network root)

```hcl
# roots/network/contracts.tf

locals {
  contract_outputs = {
    vpc_id             = module.network.vpc_id
    private_subnet_ids = module.network.private_subnet_ids
    public_subnet_ids  = module.network.public_subnet_ids
    nat_gateway_ids    = module.network.nat_gateway_ids
    vpc_endpoint_ids   = module.network.endpoint_ids
  }
}

resource "aws_ssm_parameter" "contract" {
  name  = "/scanalyze/deployments/${var.deployment_id}/contracts/network/v1"
  type  = "String"
  value = jsonencode({
    schema_version        = "scanalyze.contract.v1"
    layer                 = "network"
    contract_version      = 1
    deployment_id         = var.deployment_id
    account_id            = data.aws_caller_identity.current.account_id
    region                = data.aws_region.current.name
    producer_release      = var.release_version
    producer_module_digest = var.module_digest
    producer_state_serial = data.terraform_remote_state_serial.self
    contract_digest       = sha256(jsonencode(local.contract_outputs))
    output_schema_version = "scanalyze.contract-network.v1"
    outputs               = local.contract_outputs
  })

  tags = {
    Layer        = "network"
    DeploymentId = var.deployment_id
    ManagedBy    = "scanalyze-deployment-platform"
  }
}
```

> [!IMPORTANT]
> **No `timestamp()` in contract value.** The SSM parameter's `last_modified_date` attribute records when the value was written. `producer_state_serial` provides monotonic advancement tracking without introducing plan non-determinism.

#### Contract Consumer — Fail-Closed with Preconditions

> [!CAUTION]
> **`check` blocks produce WARNINGS, not ERRORS.** They do NOT block `terraform plan` or `terraform apply`. For contract validation that MUST prevent deployment on failure, use `precondition` blocks inside `lifecycle` on a `terraform_data` resource. Preconditions cause `terraform plan` to exit with code 1 (error).

```hcl
# roots/platform/contracts.tf

data "aws_ssm_parameter" "network_contract" {
  name = "/scanalyze/deployments/${var.deployment_id}/contracts/network/v1"
}

locals {
  network_raw = jsondecode(data.aws_ssm_parameter.network_contract.value)
  network     = local.network_raw.outputs
}

# === Hard-blocking preconditions ===

resource "terraform_data" "network_contract_gate" {
  lifecycle {
    precondition {
      condition     = local.network_raw.deployment_id == var.deployment_id
      error_message = "BLOCKED: Network contract deployment_id '${local.network_raw.deployment_id}' does not match expected '${var.deployment_id}'."
    }

    precondition {
      condition     = local.network_raw.account_id == data.aws_caller_identity.current.account_id
      error_message = "BLOCKED: Network contract account_id mismatch — possible cross-account contract confusion."
    }

    precondition {
      condition     = local.network_raw.region == data.aws_region.current.name
      error_message = "BLOCKED: Network contract region '${local.network_raw.region}' does not match current region."
    }

    precondition {
      condition     = local.network_raw.output_schema_version == "scanalyze.contract-network.v1"
      error_message = "BLOCKED: Network contract schema '${local.network_raw.output_schema_version}' is not compatible."
    }

    precondition {
      condition     = local.network_raw.contract_digest == sha256(jsonencode(local.network_raw.outputs))
      error_message = "BLOCKED: Network contract digest mismatch — contract data integrity compromised."
    }
  }
}
```

**Why `terraform_data` with `precondition` instead of `check` with `assert`:**

| Mechanism | On failure | Blocks plan? | Blocks apply? | Test framework |
|---|---|---|---|---|
| `check { assert {} }` | Warning in plan output | ❌ No | ❌ No | `terraform test` (expects warning) |
| `resource "terraform_data" { lifecycle { precondition {} } }` | Error, plan exits code 1 | ✅ Yes | ✅ Yes | `terraform test` (expects error) |
| `data source { lifecycle { precondition {} } }` | Error, plan exits code 1 | ✅ Yes | ✅ Yes | `terraform test` (expects error) |

> [!NOTE]
> Preconditions on the `data "aws_ssm_parameter"` resource itself would also work, but placing them on a dedicated `terraform_data` gate resource makes the intent explicit and keeps the contract validation separate from the data fetch.

### 4. Content-Addressed Contract Verification

Contracts include `contract_digest` (SHA-256 of the `outputs` JSON) and `producer_state_serial` (monotonically increasing Terraform state serial).

#### How consumers verify

```
1. Parse contract JSON
2. Recompute sha256(jsonencode(contract.outputs))
3. Compare with contract.contract_digest → mismatch = BLOCKED
4. (Optional) Compare contract.producer_state_serial ≥ last known serial
   → regression = WARNING (possible state rollback in producer)
```

#### How the orchestrator verifies contract freshness

Before running the consumer layer, the orchestrator verifies the upstream contract is from the expected producer run:

```
Orchestrator pre-flight for layer N:
  For each upstream layer M (where M < N and N consumes M's contract):
    1. Read SSM parameter last_modified_date
    2. Read expected_change_id from deployment record
    3. If this is a fresh deployment: verify last_modified_date is from current run
    4. If this is an incremental update: verify contract is from expected release
    5. Compute contract_digest independently → match? Continue. Mismatch? ABORT.
```

### 5. Contract Schema Versioning

| Change type | Version action | SSM path | Consumer impact |
|---|---|---|---|
| **Additive** (new optional output) | Minor: contract_version + 1 | Same path (`/v1`) | No change needed |
| **Breaking** (remove field, rename, type change) | Major: new path | New path (`/v2`) | Must update to consume `/v2` |
| **Deprecation** | Mark old field as deprecated | Same path | Consumer logs warning, migration window |

### 6. Contract Size Strategy — Large Payloads

| Size | Approach |
|---|---|
| Small (< 4 KB) | JSON directly in SSM Parameter (String type) |
| Medium (4 KB – 8 KB) | SSM Parameter (Advanced tier) |
| Large (> 8 KB) | SSM stores compact manifest pointing to S3 contracts bucket |

> [!WARNING]
> **Large payloads are stored in the dedicated contracts bucket** (`scanalyze-{account_id}-contracts`) — NOT the state bucket or the evidence bucket. Contract payloads have different retention and access patterns from both.

Large payload SSM manifest:

```json
{
  "schema_version": "scanalyze.contract.v1",
  "layer": "services",
  "payload_location": "s3",
  "payload_uri": "s3://scanalyze-ACCT-contracts/dep_01J5/us-east-1/services-v1-payload.json",
  "payload_digest": "sha256:abc123...",
  "output_schema_version": "scanalyze.contract-services.v1"
}
```

### 7. Variable Injection

Orchestrator renders `terraform.tfvars` from deployment record. Unchanged from rev1.

### 8. Deployment Profiles

Unchanged from rev1.

### 9. Contract IAM Enforcement per Layer

The Apply role's write access to SSM parameters is restricted by the **session policy** (ADR-004 rev3 §9) to the current layer's contract prefix.

```
When orchestrator assumes Apply for layer "network":
  Session tag: layer = "network"
  Session policy includes:
    {
      "Effect": "Allow",
      "Action": "ssm:PutParameter",
      "Resource": "arn:aws:ssm:${region}:${account}:parameter/scanalyze/deployments/${dep_id}/contracts/network/*"
    }
```

| Layer executing | Can write SSM contracts under |
|---|---|
| global | `/scanalyze/deployments/{dep}/contracts/global/*` |
| network | `/scanalyze/deployments/{dep}/contracts/network/*` |
| platform | `/scanalyze/deployments/{dep}/contracts/platform/*` |
| data-foundation | `/scanalyze/deployments/{dep}/contracts/data-foundation/*` |
| services | `/scanalyze/deployments/{dep}/contracts/services/*` |
| edge-identity | `/scanalyze/deployments/{dep}/contracts/edge-identity/*` |
| addons | `/scanalyze/deployments/{dep}/contracts/addons/*` |

> [!IMPORTANT]
> This prevents a compromised or misconfigured Terraform root from overwriting another layer's contract. The restriction is enforced at the IAM level, not just by convention.

### 10. Module Testing Strategy

| Test type | Tool | Scope | Runs on |
|---|---|---|---|
| **Module unit tests** | `terraform test` (HCL) | Module logic, variable validation, output format | Every PR |
| **Contract tests** | Custom script + JSON Schema | Producer output matches schema; Consumer can parse | Every PR |
| **Precondition tests** | `terraform test` with invalid fixtures | Contract gate rejects bad input (exit code 1) | Every PR |
| **Plan tests** | `terraform plan` with golden fixtures | Resource counts and types match expectations | Every PR |
| **Session policy tests** | AWS CLI + `--policy` flag | SSM write restricted to layer prefix | Per release |
| **Integration tests** | Terraform apply in test account | Full stack deployment + validation suite | Per release |

#### Precondition test example

```hcl
# tests/contract/network_contract_validation.tftest.hcl

variables {
  deployment_id = "dep_test_001"
}

run "rejects_wrong_deployment_id" {
  command = plan

  override_data {
    target = data.aws_ssm_parameter.network_contract
    values = {
      value = jsonencode({
        schema_version        = "scanalyze.contract.v1"
        layer                 = "network"
        deployment_id         = "dep_WRONG"
        account_id            = "123456789012"
        region                = "us-east-1"
        output_schema_version = "scanalyze.contract-network.v1"
        contract_digest       = "sha256:..."
        outputs               = { vpc_id = "vpc-abc123" }
      })
    }
  }

  expect_failures = [
    terraform_data.network_contract_gate,
  ]
}

run "rejects_tampered_digest" {
  command = plan

  override_data {
    target = data.aws_ssm_parameter.network_contract
    values = {
      value = jsonencode({
        schema_version        = "scanalyze.contract.v1"
        layer                 = "network"
        deployment_id         = "dep_test_001"
        account_id            = "123456789012"
        region                = "us-east-1"
        output_schema_version = "scanalyze.contract-network.v1"
        contract_digest       = "sha256:TAMPERED"
        outputs               = { vpc_id = "vpc-abc123" }
      })
    }
  }

  expect_failures = [
    terraform_data.network_contract_gate,
  ]
}
```

### 11. Deployment Orchestration Sequence

```
For each layer in dependency order:
  global → network → platform → data-foundation → cicd
    → artifact-publication → services → edge-identity → edge → addons
    → synthetic-validation

  PRE-DEPLOY (orchestrator logic):
    1. Read deployment record from registry
    2. Render backend.tf from template + deployment record
    3. Render terraform.tfvars from deployment record + profile
    4. terraform init (verify provider lock, download providers)

  VALIDATE (using Plan role, session policy scoped to this layer):
    5. Read upstream contracts from SSM
       → preconditions fire if invalid → plan fails → deployment blocked
    6. terraform validate
    7. terraform plan -out=plan.tfplan
    8. terraform show -json plan.tfplan > plan.json (ephemeral)
    9. Compute plan digest (SHA-256 of plan binary)
    10. Verify plan within bounds (resource counts, no unexpected deletes)
    11. Write plan.tfplan + plan.json to plan-execution zone (state bucket,
        ephemeral prefix, 24-72h TTL)
    12. Write sanitized summary to evidence bucket:
        - Plan digest
        - Resource action counts (create/update/delete/no-op)
        - Layer name, change_id, release_version
        - NO plan binary, NO raw JSON, NO secrets

  APPLY (using Apply role, session policy scoped to this layer):
    13. Read plan digest from plan-execution zone
    14. Verify plan digest matches expected
    15. Write pre-apply state snapshot to recovery prefix (state bucket)
    16. terraform apply plan.tfplan (from saved plan, not re-planned)
    17. Record post-apply state version ID
    18. Terraform writes this layer's contract to SSM
        (the aws_ssm_parameter.contract resource in contracts.tf)
    19. Orchestrator verifies contract is readable and valid
    20. Delete consumed plan artifacts from plan-execution zone
    21. Write sanitized apply metadata to evidence bucket:
        - Apply execution ID, state version IDs, release manifest digest
        - Duration, exit code
        - NO state contents, NO secrets
    22. Update deployment record with evidence references
```

> [!IMPORTANT]
> **Step 18: Contract is written by the Terraform apply itself** (the `aws_ssm_parameter.contract` resource). It is NOT written by the orchestrator. The session policy (§9) ensures the Apply role can only write to its own layer's contract prefix.

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
| `ssm:PutParameter` without layer scope | Must be enforced by session policy | Policy test |

### 13. Output Sensitivity Rules

Unchanged from rev1.

---

## Consequences

### Positive
- Modules are reusable across all customer deployments identically
- 1:1 root/state/namespace eliminates ownership ambiguity
- SSM contracts are versioned, validated, and **fail-closed** with preconditions (not warnings)
- Single contract writer eliminates race conditions
- Contract writer identity enforced by IAM session policy, not just convention
- No `timestamp()` means deterministic plans
- Content-addressed contracts (digest + state serial) detect tampering and staleness
- edge-identity separated from addons: auth/routing changes have dedicated approval
- Plan binaries with secrets are ephemeral (24-72h auto-deletion)
- Evidence contains only sanitized summaries — no secrets at rest

### Negative
- 8 layers (up from 6) adds more roots and contracts to manage
- Precondition blocks on `terraform_data` are less intuitive than `check` blocks
- Session policy per layer adds orchestrator complexity
- Contract size strategy requires monitoring parameter size growth

---

## References

- ADR-003 rev3: State Backend (three storage zones, regional state keys, ownership manifest)
- ADR-004 rev3: Cross-Account Identity (session policies per layer, Apply SSM scoping)
- ADR-005: Schemas (contract envelope, deployment record)
- ADR-007: Supply Chain (module digest verification)
- ADR-008: Region (network module AZ handling, regional state keys)
- ADR-010: Testing/Rollout (ECS task definition sole ownership)
- [Terraform: Preconditions and Postconditions](https://developer.hashicorp.com/terraform/language/expressions/custom-conditions)
- [Terraform: Check Blocks](https://developer.hashicorp.com/terraform/language/checks) (not used — warnings only)
- [Terraform: Test Framework](https://developer.hashicorp.com/terraform/language/tests)
- [AWS SSM Parameter Store Limits](https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-paramstore-about.html)
