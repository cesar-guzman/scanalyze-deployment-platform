# Architecture Acceptance Gates

> [!IMPORTANT]
> This is a dated repository-foundation gate inventory, not the GUG-115
> Production Readiness phase model. Some status details may be stale relative to
> the current repository. For Phase 0-11 entry, exit, evidence, dependency, and
> NO-GO criteria, use
> [`docs/production-readiness/phase-gates.md`](docs/production-readiness/phase-gates.md).
> Do not use `preflight-m0` or this summary to claim that GUG-116 is complete.

> **Status**: M2 Level B — Provider Validated Locally (provider_validated_locally)
> **Date**: 2026-07-02
> **Format**: Machine-readable YAML blocks + human narrative
> **Toolchain**: Python 3.11.14 / Terraform 1.14.6 / AWS Provider 5.100.0

---

## Gate Status Legend

| Status | Meaning |
|---|---|
| `pending_design` | Architecture decision or mechanism not yet defined |
| `partial_local` | Some local artifacts exist but required evidence is incomplete |
| `implemented_locally` | ALL required local code/fixtures/tests exist and pass |
| `verified_in_test` | Verified in test environment with real AWS resources |
| `verified_in_aws` | Verified in target AWS account |
| `accepted` | Production-ready, evidence logged |
| `blocked_tooling` | Cannot verify — toolchain mismatch or missing dependency |

---

## M0 Gates

### Gate 1: IAM Trust/Identity Policies Executable

```yaml
gate_id: GATE-IAM-001
title: IAM trust and identity policies are structurally valid and scoped
adr: ADR-004 rev3
evidence_required: All 10 IAM role policies, 6 trust policies, structural validation, positive/negative permission tests
blocks: Account baseline deployment
status: partial_local
local_progress:
  - plan-role policy fixture exists and passes structural validation
  - promotion-role policy fixture exists and passes
  - validation-role policy fixture exists and passes
  - plan-trust policy fixture exists
  - diagnostic-trust policy fixture exists
  - state-bucket S3 policy exists with role-scoped access
  - evidence-bucket S3 policy exists with 3-prefix isolation
  - state KMS key policy exists with role-scoped crypto
blockers:
  - apply-role fixture missing
  - diagnostic-role fixture missing
  - state-recovery-role fixture missing
  - orchestrator-role fixture missing
  - break-glass-role fixture missing
  - signing-role fixture missing
  - pipeline-build-role fixture missing
  - apply-trust, promotion-trust, validation-trust, state-recovery-trust policies missing
  - session policies for all 8 layers missing
  - negative tests (wrong role, wrong tag, escalation) not implemented
verification_level: static_partial
```

### Gate 2: ACCOUNT_READY Authenticated

```yaml
gate_id: GATE-ACCT-001
title: ACCOUNT_READY contract schema validates binding integrity
adr: ADR-004, ADR-005
evidence_required: Schema + binding verification fixtures + digest check + authenticity mechanism
blocks: Workload deployment (orchestrator cannot proceed without ACCOUNT_READY)
status: partial_local
local_progress:
  - account-ready.v1.schema.json exists (strict, additionalProperties:false)
  - valid fixture with 6 roles and state infrastructure exists
  - invalid fixtures: missing-role, wrong-binding exist
blockers:
  - ACCOUNT_READY authenticity mechanism not locally evidenced (no signature or external anchor)
  - schema-check requires jsonschema (BLOCKED_TOOLING)
  - binding cross-check test (deployment_id across all roles) not implemented
verification_level: static_partial
```

### Gate 3: State S3/KMS Policies Executable

```yaml
gate_id: GATE-STATE-001
title: S3 bucket and KMS key policies enforce exact prefix isolation
adr: ADR-003 rev3
evidence_required: All S3 bucket policies, all KMS key policies, exact-prefix tests, lifecycle assertions
blocks: TF backend creation
status: partial_local
local_progress:
  - state-bucket S3 policy exists with exact-prefix per role
  - evidence-bucket S3 policy exists with 3-prefix isolation
  - state KMS key policy exists with role-scoped crypto operations
blockers:
  - contracts-bucket S3 policy missing
  - frontend-bucket S3 policy missing
  - evidence-key KMS policy missing
  - contracts-key KMS policy missing
  - lifecycle rule assertions not implemented
  - exact-prefix negative tests not implemented
verification_level: static_partial
```

### Gate 4: Ephemeral Plan Isolation

```yaml
gate_id: GATE-PLAN-001
title: Plan-execution zone is ephemeral; raw plans never reach immutable evidence
adr: ADR-003 rev3
evidence_required: S3 policy separates plan-execution/evidence/recovery prefixes; lifecycle rules documented; negative test for plan→evidence write
blocks: Apply pipeline
status: partial_local
local_progress:
  - evidence-bucket S3 policy defines separate plan-execution, evidence, recovery prefixes
  - Plan role can only write to plan-execution prefix
  - Apply role can read plan-execution and write to evidence and recovery
blockers:
  - lifecycle rule for plan-execution auto-expiry not defined
  - negative test (Plan writing to evidence prefix) not implemented
  - bucket layout reconciliation with ADR-003 (state vs evidence bucket for plan-execution) not explicit
verification_level: static_partial
```

### Gate 5: Contract Fail-Closed

```yaml
gate_id: GATE-CONTRACT-001
title: Bad identity, schema, digest, or replay produces plan exit 1
adr: ADR-006 rev3
evidence_required: Invalid fixtures fail schema validation; canonicalization tests pass; precondition harness tests exist
blocks: Layer deployment
status: implemented_locally
local_progress:
  - Invalid fixtures exist (wrong-digest, missing fields, extra fields)
  - Canonicalization determinism verified
  - Digest computation and verification tool exists
  - HCL contract harness with terraform_data + precondition: 90/90 scenarios pass
  - Replay rejection: stale-release-manifest-digest, missing-expected-release-digest fail
  - Bad identity: wrong-deployment-id, wrong-account-id fail
  - Unknown field detection: unknown-critical-field, unknown-non-allowlisted-field fail
  - Release manifest digest value-match (not just format)
  - Schema validation via jsonschema (Draft 2020-12)
blockers:
  - Toolchain version mismatch (Terraform 1.14.6 vs pin 1.12.1)
  - Provider-backed validation pending
verification_level: local_full
```

### Gate 6: Contract Canonicalization

```yaml
gate_id: GATE-CONTRACT-002
title: Deterministic canonical JSON + stable SHA-256 digest
adr: ADR-006 rev3
evidence_required: Golden fixture digest matches computed digest; determinism test passes
blocks: Contract publication
status: partial_local
local_progress:
  - validate_digest.py implements canonical JSON (sorted keys, compact separators, UTF-8)
  - contract-envelope-network fixture has computed-correct digest
  - Determinism and stability tests pass
blockers:
  - Only 1 contract fixture has verified digest (need at least 1 per layer)
  - toolchain mismatch means these tests ran on Python 3.14, not pinned 3.11
verification_level: local_partial
```

### Gate 7: OCI Promotion Proof

```yaml
gate_id: GATE-SUPPLY-001
title: OCI graph copy and central signature verification
adr: ADR-007 rev3
evidence_required: Two-registry/account graph copy, central sig verification
blocks: Customer image promotion
status: pending_design
evidence_id: null
verification_level: aws_write
blockers:
  - ECR customer account not available
  - AWS Signer profile not created
```

### Gate 8: DSSE Signing Proof

```yaml
gate_id: GATE-SUPPLY-002
title: Release manifest DSSE/in-toto signing and verification
adr: ADR-007 rev3
evidence_required: Canonical bytes, online/offline verify, rotation tests
blocks: Release manifests
status: pending_design
evidence_id: null
verification_level: aws_read
blockers:
  - KMS signing key not created
```

### Gate 9: Supply-Chain Policy Gate

```yaml
gate_id: GATE-SUPPLY-003
title: Unsigned/unapproved digest cannot reach services plan
adr: ADR-007 rev3
evidence_required: Precondition rejects unknown digest in services plan
blocks: Runtime deployment
status: partial_local
local_progress:
  - Services module implemented with task definition ownership
  - lint_services_ownership.py validates forbidden patterns
  - Supply chain policy gate: 13 pytest tests pass
  - Task definition schema validation: mutable tag rejection, SCANALYZE_TENANT rejection
blockers:
  - Provider-backed validation pending
  - AWS deployment not available for live test
verification_level: local_partial
```

### Gate 10: Strong Write Authority

```yaml
gate_id: GATE-DR-001
title: Write fencing mechanism selected and tested
adr: ADR-008 rev3
evidence_required: Mechanism chosen, stale-primary rejection demonstrated
blocks: Enterprise HA tier
status: pending_design
evidence_id: null
verification_level: aws_write
blockers:
  - Write fencing mechanism TBD (MRSC table vs ARC)
  - Enterprise HA not available until proven
```

### Gate 11: Migration Semantics

```yaml
gate_id: GATE-MIGRATE-001
title: Zero-write-loss migration with baseline/delta/checkpoint/tombstone
adr: ADR-010 rev3
evidence_required: Migration utility design, conditional writes, checkpoint resume
blocks: Brownfield migration
status: partial_local
local_progress:
  - deployment-record schema includes migration status fields
  - ADR-010 documents migration flow
blockers:
  - Migration utility not implemented
  - Conditional write tests not implemented
  - Checkpoint resume logic not designed
verification_level: static_partial
```

### Gate 12: ECS Rollback Reconciliation

```yaml
gate_id: GATE-ECS-001
title: Circuit-breaker → forward reconciliation → TF state alignment
adr: ADR-010 rev3
evidence_required: Circuit-breaker simulation, forward apply reconciliation
blocks: Production rollout
status: pending_design
evidence_id: null
verification_level: aws_write
blockers:
  - ECS services not deployed
```

### Gate 13: Threat Controls Evidenced

```yaml
gate_id: GATE-THREAT-001
title: All ADR-009 threats have control status and evidence IDs
adr: ADR-009 rev3
evidence_required: Per-threat control_status, evidence_id, residual risk assessment
blocks: Production readiness
status: partial_local
local_progress:
  - ADR-009 imported with provenance
  - Sentinel scanner with allowlist validates PII/secret controls
blockers:
  - WS8 focused consistency patches not applied to ADR-009
  - Per-threat control_status and evidence_id not added
  - Residual risk assessment not documented
verification_level: static_partial
```

### Gate 14: Organization Integration

```yaml
gate_id: GATE-ORG-001
title: Organization Team provides Control Tower integration
adr: ADR-002
evidence_required: Organization Team evidence of CT setup
blocks: New account creation
status: pending_design
evidence_id: null
verification_level: aws_write
blockers:
  - Organization Team engagement required
  - Control Tower setup external to this repository
```

---

## M2 Level A Summary

| Category | implemented_locally | partial_local | pending_design | Total |
|---|---|---|---|---|
| Identity/IAM | 0 | 2 | 0 | 2 |
| State/Evidence | 0 | 2 | 0 | 2 |
| Contracts | 1 | 1 | 0 | 2 |
| Supply Chain | 0 | 1 | 2 | 3 |
| DR/HA | 0 | 0 | 1 | 1 |
| Migration/Rollout | 0 | 1 | 1 | 2 |
| Threat Model | 0 | 1 | 0 | 1 |
| Organization | 0 | 0 | 1 | 1 |
| **Total** | **1** | **8** | **5** | **14** |

> **M2B current**: 1 gate at `implemented_locally`, 8 at `partial_local`, 5 at `pending_design`.
> **M2B changes**: Toolchain pins resolved (D-001, D-001b). All 9/9 roots `terraform validate` pass. Provider aws 5.100.0 locked.
> **Toolchain**: Python 3.11.14 / Terraform 1.14.6 (pins match actuals).
> **All declarations**: provider_validated_locally.
