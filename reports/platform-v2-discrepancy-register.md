# Platform v2 Discrepancy Register

> **Date**: 2026-06-30  
> **Status**: M2 Level A evidence generated — pending commit approval  
> **Last updated**: M2 Level A implementation complete

---

## Active Discrepancies

### D-001: Terraform Version Mismatch (OPEN)

| Field | Value |
|---|---|
| **Severity** | ⚠ Warning |
| **Description** | Local Terraform 1.14.6 ≠ pinned 1.12.1 |
| **Impact** | HCL harness (90 scenarios) passed with 1.14.6. Module declarations authored with 1.14.6. Both need re-verify with 1.12.1 |
| **Resolution** | Install TF 1.12.1 via tfenv, or update .terraform-version |
| **Status** | OPEN — blocks `verified_in_aws` and `provider_validated` status |
| **Blocks** | Any promotion beyond `authored_not_provider_validated` |

### D-001b: Python Patch Version Mismatch (OPEN)

| Field | Value |
|---|---|
| **Severity** | ℹ Low |
| **Description** | Local Python 3.11.14 ≠ pinned 3.11.12 (same minor series) |
| **Impact** | Low risk — 51 pytest tests, 4 linters, interface check all pass on 3.11.14 |
| **Resolution** | Install exact 3.11.12 via pyenv, or accept 3.11.14 |
| **Status** | OPEN — documented, low risk |

### D-002: All AWS Declarations Are authored_not_provider_validated (OPEN)

| Field | Value |
|---|---|
| **Severity** | ⚠ Expected |
| **Description** | All resource declarations in modules/ are HCL-authored but never validated by the AWS Terraform provider |
| **Impact** | API errors, deprecated attributes, or type mismatches may exist and will only surface during `terraform plan` |
| **Resolution** | Level B approval: `terraform init` with provider download + `terraform validate` |
| **Status** | OPEN — expected for M2 Level A, blocks any `provider_validated` claim |

### D-003: Roots Not Wired to Modules (OPEN)

| Field | Value |
|---|---|
| **Severity** | ℹ Info |
| **Description** | Root skeletons (M1) reference module blocks but do not pass the new M2 variables. Roots need updating to consume module interfaces. |
| **Impact** | `terraform plan` on any root will fail until roots are wired to modules |
| **Resolution** | M2 Level B or M3: update root main.tf to pass all required variables |
| **Status** | OPEN — not in M2 Level A scope |

### D-004: replicated-data Module Remains M1 Skeleton (OPEN)

| Field | Value |
|---|---|
| **Severity** | ℹ Info |
| **Description** | modules/replicated-data/ has M1 skeleton with placeholder outputs |
| **Impact** | Module interface check skips this module as M1-only |
| **Resolution** | Implement when cross-region replication is in scope |
| **Status** | OPEN — not in M2 scope |

---

## Resolved Discrepancies

### D-R001: Gates Over-Marked as implemented_locally (RESOLVED 2026-06-28)
All 8 gates degraded to partial_local with explicit blockers.

### D-R002: ADR/ Blanket Exclusion from Sentinel (RESOLVED 2026-06-28)
Replaced with sentinel_allowlist.yaml with per-path, per-pattern documented exceptions.

### D-R003: Missing Required Artifacts Inventory (RESOLVED 2026-06-28)
Created required-artifacts.yaml + check_required_artifacts.py + make required-artifacts-check.

### D-R004: Preflight Did Not Distinguish Core vs M0 (RESOLVED 2026-06-28)
Split into preflight-core (existing only) and preflight-m0 (full gate with required-artifacts + schema-check).

### D-R005: jsonschema Not Installed (RESOLVED 2026-06-30)
Created .venv with Python 3.11.14, installed jsonschema 4.26.0 from pyproject.toml.

### D-R006: ACCOUNT_READY Authenticity Mechanism (RESOLVED 2026-06-30)
Implemented external anchoring verification with 11 pytest tests. DSSE/KMS signing pending_aws for M1+.

### D-R007: Contract Fail-Closed HCL Harness (RESOLVED 2026-06-30)
Created tests/preconditions/contract_gate/ with terraform_data + precondition. 7 scenarios pass. M2 expanded to 90 scenarios with release digest value-match and unknown-field detection.

### D-R008: S3 Evidence Layout Reconciliation (RESOLVED 2026-06-30)
Decision adopted: plan-execution and recovery in state bucket (ephemeral), sanitized evidence in evidence bucket (immutable). Documented in M0 final report.

### D-R009: Rollback Used rm -rf (RESOLVED 2026-06-30)
Replaced with manifest-based rollback in rollback/ROLLBACK_MANIFEST.md. M2 update: also prohibits git stash, git checkout --, git reset, git clean.

### D-R010: ADR-009 Threat Count Inflation (RESOLVED 2026-06-30)
4 ECON threats reclassified as maturity control annotations. Count remains 48 threats.

### D-R011: Tracker Inconsistency Before M1 Commit (RESOLVED 2026-06-30)
Tracker showed pending items that walkthrough claimed were complete. Reconciled before commit b8fcc37.

### D-R012: preflight-m1 Missing git-safety and security-check (RESOLVED 2026-06-30)
Added git-safety and security-check as dependencies of preflight-m1.
