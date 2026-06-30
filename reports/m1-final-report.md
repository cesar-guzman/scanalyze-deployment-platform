# M1 Final Report — Terraform Contract Framework & Module Interface Evidence

> **Milestone:** M1 Level A — Local Evidence  
> **Status:** `M1_LOCAL_EVIDENCE_GENERATED`  
> **Branch:** `feature/platform-v2-repository-bootstrap`  
> **Date:** 2026-06-30  
> **Toolchain Status:** `BLOCKED_TOOLING_REVERIFY`

---

## 1. Executive Summary

M1 Level A establishes the complete Terraform module/root skeleton layer,
contract producer/consumer validation framework, task definition ownership
evidence, IAM negative access matrix, and supply chain policy gate.

All work is local — zero AWS mutations, zero remote operations, zero provider
downloads.

### Key Metrics

| Metric | Value |
|--------|-------|
| Modules created | 9 (global, network, container-platform, data-foundation, services, edge-identity, edge, addons, replicated-data) |
| Roots created | 9 (account-ready-gate + 8 deployable) |
| Module files | 55 |
| Root files | 64 |
| Schemas | 17 |
| Fixtures (valid+invalid) | 36 |
| Python tests | 51 (all pass) |
| Contract matrix scenarios | 84+ (7 pairs × 12 scenarios) |
| HCL harness preconditions | 14+ gates |
| Supply chain scenarios | 7 (13 tests) |
| Task def valid fixtures | 7 (all 7 services) |
| Task def invalid fixtures | 6 (all rejection patterns) |
| IAM negative matrix tests | 14 |
| Make targets added | 7 (toolchain-status, module-check, root-check, taskdef-check, supply-chain-check, preflight-m1, lint-forbidden-patterns fix) |

---

## 2. Workstream Evidence

### WS1 — Toolchain Reconciliation

```
make toolchain-status
→ BLOCKED_TOOLING_REVERIFY
  Python: 3.11.14 (pin: 3.11.12)
  Terraform: 1.14.6 (pin: 1.12.1)
```

**Decision:** Proceed with local evidence generation. Reverification required
on pinned versions before any AWS-facing work.

### WS2 — Module Interface Skeletons

9 modules created with standardized files:

| Module | Layer | Scope | Contract | Notes |
|--------|-------|-------|----------|-------|
| `global` | 0 | global | global/v1 | Base IAM, permissions boundaries |
| `network` | 1 | regional | network/v1 | VPC, subnets, NATs, endpoints |
| `container-platform` | 2 | regional | platform/v1 | ECS cluster, ALB |
| `data-foundation` | 3 | regional | data-foundation/v1 | DynamoDB, S3, SQS, KMS |
| `services` | 4 | regional | services/v1 | ECS services, task definitions |
| `edge-identity` | 5a | regional | edge-identity/v1 | Cognito, API Gateway, CloudFront |
| `edge` | 5a+ | global | edge/v1 | ACM, Route53, CF domain |
| `addons` | 5b | regional | addons/v1 | Monitoring, alarms |
| `replicated-data` | sub | regional | none | Sub-module of data-foundation |

Each module contains: `versions.tf`, `variables.tf`, `outputs.tf`, `locals.tf`,
`contract.tf`, `README.md`.

**Naming convention enforced:**
- Module dir: `modules/container-platform/`
- Root dir: `roots/platform/`
- Contract: `platform/v1`

### WS3 — Root Skeletons

9 roots created (8 deployable + 1 validation):

| Root | Deployable | Module | State Key Pattern |
|------|-----------|--------|-------------------|
| `account-ready-gate` | No | none | N/A |
| `global` | Yes | global | `{dep_id}/global/terraform.tfstate` |
| `network` | Yes | network | `{dep_id}/{region}/network/terraform.tfstate` |
| `platform` | Yes | container-platform | `{dep_id}/{region}/platform/terraform.tfstate` |
| `data-foundation` | Yes | data-foundation | `{dep_id}/{region}/data-foundation/terraform.tfstate` |
| `services` | Yes | services | `{dep_id}/{region}/services/terraform.tfstate` |
| `edge-identity` | Yes | edge-identity | `{dep_id}/{region}/edge-identity/terraform.tfstate` |
| `edge` | Yes | edge | `{dep_id}/edge/terraform.tfstate` |
| `addons` | Yes | addons | `{dep_id}/{region}/addons/terraform.tfstate` |

Each root contains: `versions.tf`, `variables.tf`, `main.tf`, `outputs.tf`,
`contract_validation.tf`, `backend.example.hcl`, `README.md`.

**Contract gates:** All use `terraform_data` + `precondition` (never `check {}`).

### WS4 — Contract Producer/Consumer Tests

Data-driven matrix in `tests/preconditions/layer_contract_matrix/`:

- **7 layer pairs** × **12 scenarios** = 84+ test cases
- **6 state path scope tests** (global vs regional)
- **HCL harness** with 14+ precondition gates
- **Scenarios:** valid, wrong-deployment-id, wrong-account-id, wrong-producer-layer,
  wrong-schema-version, tampered-digest, stale-contract-version, stale-producer-release,
  stale-release-manifest-digest, consumer-bypass-attempt, state-path-global-with-region,
  state-path-regional-without-region

### WS5 — Task Definition Ownership Evidence

- **Schema:** `task-definition-input.v1.schema.json` (Draft 2020-12)
  - `image` pinned by `@sha256:` (rejects `:latest`)
  - `canonical_field` = `SCANALYZE_DEPLOYMENT_CUSTOMER_ID` (rejects `tenantId`, `SCANALYZE_TENANT`)
  - `secrets.valueFrom` must be ARN (rejects plain values)
  - `additionalProperties: false` (rejects `imagedefinitions_source`)

- **7 valid fixtures** (all services): ingest-api, ocr-worker, postprocess-worker,
  classifier-worker, bank-worker, personal-worker, gov-worker

- **6 invalid fixtures:**
  1. Mutable tag (`:latest`)
  2. Legacy tenant authoritative (`tenantId`)
  3. `SCANALYZE_TENANT` as canonical
  4. Missing `customer_identity`
  5. `imagedefinitions_source` extra field
  6. Leaked secret value

- **13 pytest tests:** All pass (7 valid + 6 rejection)

### WS6 — Policy Tests Hardening

`tests/test_policies/test_iam_negative_matrix.py` — 14 tests:

| Test Class | Tests | Result |
|-----------|-------|--------|
| BreakGlassScope | 3 | ✓ |
| OrchestratorScope | 2 | ✓ |
| ApplyRoleScope | 1 | ✓ |
| PromotionRoleScope | 1 | ✓ |
| ValidationRoleScope | 1 | ✓ |
| StateRecoveryRoleScope | 1 | ✓ |
| S3PrefixBoundaries | 3 | ✓ |
| KMSActionMatrix | 2 | ✓ |

### WS7 — Supply Chain Local Evidence

- **`tooling/release_policy_gate.py`**: fail-closed policy gate
- **7 scenarios (13 tests):**
  1. Unsigned digest → BLOCKED
  2. Digest not in manifest → BLOCKED
  3. Mutable tag → BLOCKED
  4. Missing SBOM → BLOCKED
  5. Missing provenance → BLOCKED
  6. Waiver without ID → BLOCKED
  7. Approved digest with attestation → ALLOWED

---

## 3. Validation Evidence

### pytest (51 tests)

```
tests/test_account_ready/                        11 passed
tests/test_policies/test_iam_negative_matrix.py  14 passed
tests/test_supply_chain/                         13 passed
tests/test_task_definitions/                     13 passed
─────────────────────────────────────────────────
                                          Total: 51 passed in 0.08s
```

### make checks

```
make module-check      → 9/9 modules OK
make root-check        → 9/9 roots OK, 0 forbidden patterns
make taskdef-check     → 7 valid PASS, 6 invalid EXPECTED FAIL, 0 errors
make supply-chain-check → 13 passed
make preflight-m0      → COMPLETE
make toolchain-status  → BLOCKED_TOOLING_REVERIFY
make git-safety        → OK
```

---

## 4. Toolchain Discrepancy (carried from M0)

| Tool | Pinned | Actual | Impact |
|------|--------|--------|--------|
| Python | 3.11.12 | 3.11.14 | Tests passed locally, pending reverify |
| Terraform | 1.12.1 | 1.14.6 | HCL harness uses no-provider, pending reverify |

**Status:** `BLOCKED_TOOLING_REVERIFY` — evidence is valid for local review but
must be reverified on pinned versions before any AWS-facing operations.

---

## 5. Residual Risks

| Risk | Severity | Mitigation |
|------|----------|-----------|
| Toolchain mismatch | Medium | Reverify on pinned versions before M2 |
| Contract matrix not yet run with `terraform plan` | Low | HCL harness ready, requires TF init (M2) |
| replicated-data sub-module is a no-op | Low | By design — requires architecture review before activation |
| No actual provider configuration | Expected | M1 is interface-only; providers added in M2 |

---

## 6. Files Created/Modified

### Created (M1)

**Modules (55 files):**
- `modules/{global,network,container-platform,data-foundation,services,edge-identity,edge,addons,replicated-data}/` — each with `versions.tf`, `variables.tf`, `outputs.tf`, `locals.tf`, `contract.tf`, `README.md`

**Roots (64 files):**
- `roots/{account-ready-gate,global,network,platform,data-foundation,services,edge-identity,edge,addons}/` — each with `versions.tf`, `variables.tf`, `main.tf`, `outputs.tf`, `contract_validation.tf`, `backend.example.hcl`, `README.md`

**Schemas:**
- `schemas/task-definition-input.v1.schema.json`

**Fixtures:**
- `fixtures/valid/task-definition-{7 services}.json`
- `fixtures/invalid/task-definition-{6 rejection patterns}.json`

**Tests:**
- `tests/test_task_definitions/test_task_definition_schema.py`
- `tests/test_policies/test_iam_negative_matrix.py`
- `tests/test_supply_chain/test_release_policy_gate.py`
- `tests/preconditions/layer_contract_matrix/{scenarios.yaml,main.tf,run_matrix.sh}`

**Tooling:**
- `tooling/release_policy_gate.py`

### Modified (M1)

- `Makefile` — added M1 targets
- `tooling/lint_forbidden_patterns.py` — fixed regex bug, added comment exclusion
- `tooling/validate_schema.py` — added `--filter` flag and task-definition mapping

---

## 7. Approval Requested

- [ ] Review M1 evidence
- [ ] Approve/reject local commit
- [ ] NOT requesting: push, AWS writes, terraform apply, M2 start
