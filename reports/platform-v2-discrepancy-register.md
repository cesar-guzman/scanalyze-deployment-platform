# Platform v2 Discrepancy Register

> **Date**: 2026-07-02
> **Status**: M2B provider validated locally
> **Last updated**: M2 Level B provider validation complete

---

## Active Discrepancies

### D-004: replicated-data Module Remains M1 Skeleton (OPEN)

| Field | Value |
|---|---|
| **Severity** | ℹ Info |
| **Description** | modules/replicated-data/ has M1 skeleton with placeholder outputs |
| **Impact** | Module interface check skips this module as M1-only |
| **Resolution** | Implement when cross-region replication is in scope |
| **Status** | OPEN — not in M2 scope |

### D-005: AWS Provider Not Tested Against Real AWS Account (OPEN)

| Field | Value |
|---|---|
| **Severity** | ⚠ Expected |
| **Description** | Provider 5.100.0 validated via `terraform validate` but never `terraform plan` against a real AWS account |
| **Impact** | Runtime attribute errors, IAM permission issues, or API deprecations may surface during plan |
| **Resolution** | M2 Level C or M3: terraform plan against real account |
| **Status** | OPEN — expected for M2B, blocks `verified_in_aws` |

---

## Resolved Discrepancies

### D-R013: Terraform Version Mismatch (RESOLVED 2026-07-02, was D-001)
Pin updated from 1.12.1 to 1.14.6 in `.terraform-version` and `.tool-versions`. All evidence was always generated with 1.14.6.

### D-R014: Python Patch Version Mismatch (RESOLVED 2026-07-02, was D-001b)
Pin updated from 3.11.12 to 3.11.14 in `.tool-versions`. All evidence was always generated with 3.11.14.

### D-R015: All Declarations authored_not_provider_validated (RESOLVED 2026-07-02, was D-002)
All 9 roots now pass `terraform validate` with hashicorp/aws 5.100.0. Status promoted to `provider_validated_locally`.

### D-R016: Roots Not Wired to Modules (RESOLVED 2026-07-02, was D-003)
All roots updated with proper variable pass-through to modules. `terraform validate` confirms type correctness.

### D-R017: access_log_settings Missing format (RESOLVED 2026-07-02)
Provider validation caught missing `format` argument in `aws_apigatewayv2_stage.live.access_log_settings`. Fixed with structured JSON log format.

### D-R018: private_subnet_ids Type Mismatch (RESOLVED 2026-07-02)
Root variables declared `list(string)` but modules use `map(string)`. Fixed in roots/platform, roots/services, roots/edge-identity.

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
Implemented external anchoring verification with 11 pytest tests.

### D-R007: Contract Fail-Closed HCL Harness (RESOLVED 2026-06-30)
Created tests/preconditions/contract_gate/ with terraform_data + precondition. 90 scenarios pass.

### D-R008: S3 Evidence Layout Reconciliation (RESOLVED 2026-06-30)
Decision adopted: plan-execution and recovery in state bucket, sanitized evidence in evidence bucket.

### D-R009: Rollback Used rm -rf (RESOLVED 2026-06-30)
Replaced with manifest-based rollback.

### D-R010: ADR-009 Threat Count Inflation (RESOLVED 2026-06-30)
4 ECON threats reclassified as maturity control annotations. Count remains 48 threats.

### D-R011: Tracker Inconsistency Before M1 Commit (RESOLVED 2026-06-30)
Reconciled before commit b8fcc37.

### D-R012: preflight-m1 Missing git-safety and security-check (RESOLVED 2026-06-30)
Added as dependencies.
