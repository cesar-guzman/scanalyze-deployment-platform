# Platform v2 Discrepancy Register

> **Date**: 2026-06-30  
> **Status**: M0 evidence generated — pending commit approval

---

## Active Discrepancies

### D-001: Terraform Version Mismatch (OPEN)

| Field | Value |
|---|---|
| **Severity** | ⚠ Warning |
| **Description** | Local Terraform 1.14.6 ≠ pinned 1.12.1 |
| **Impact** | HCL harness passed with 1.14.6 but should be re-verified with 1.12.1 |
| **Resolution** | Install TF 1.12.1 via tfenv, or update .terraform-version |
| **Status** | OPEN — documented in M0 final report |

### D-001b: Python Patch Version Mismatch (OPEN)

| Field | Value |
|---|---|
| **Severity** | ℹ Low |
| **Description** | Local Python 3.11.14 ≠ pinned 3.11.12 (same minor series) |
| **Impact** | Low risk — schema validation and pytest reliable within 3.11.x |
| **Resolution** | Install exact 3.11.12 via pyenv, or accept 3.11.14 |
| **Status** | OPEN — documented, low risk |

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
Created tests/preconditions/contract_gate/ with terraform_data + precondition. 7 scenarios pass.

### D-R008: S3 Evidence Layout Reconciliation (RESOLVED 2026-06-30)
Decision adopted: plan-execution and recovery in state bucket (ephemeral), sanitized evidence in evidence bucket (immutable). Documented in M0 final report.

### D-R009: Rollback Used rm -rf (RESOLVED 2026-06-30)
Replaced with manifest-based rollback in rollback/ROLLBACK_MANIFEST.md.

### D-R010: ADR-009 Threat Count Inflation (RESOLVED 2026-06-30)
4 ECON threats reclassified as maturity control annotations. Count remains 48 threats.
