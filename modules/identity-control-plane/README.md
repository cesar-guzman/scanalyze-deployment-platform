# Module: identity-control-plane

> **Layer:** identity-control-plane
> **Scope:** regional
> **Produces contract:** `identity-control-plane/v1`
> **Consumes:** verified root inputs from `global/v1`, `release-manifest/v1`,
> and the reviewed external `identity-contract/v2` registry

## Purpose

Creates one portable, deployment-bound identity control plane. The module owns
the Cognito authentication adapter, membership and sanitized authorization-audit
stores, pre-token hook, bounded control processor, FIFO queue/DLQ, encryption,
and operational alarms. It derives authority only from explicit root inputs
bound to one customer, deployment, account, and region.

## Security posture

- Self-signup, provider-group authority, ID-token API use, general human
  provisioning, and destructive replacement are disabled.
- The pre-token human path starts fail-closed with `USER_POOL_ID=UNBOUND`, an
  empty client allowlist, and `HUMAN_RUNTIME_ENABLED=false`.
- M2M credentials are created only by the control processor and immediately
  escrowed outside Terraform; no credential is an input, output, state value,
  log field, contract field, or test fixture.
- A newly created M2M client remains inactive until its exact binding is
  reviewed in `identity-contract/v2` and a later consumer plan accepts the new
  digest.
- Every runtime role uses the exact customer-owned permissions boundary and
  resource-scoped IAM/KMS permissions.
- Provider resources and data stores use deletion protection or
  `prevent_destroy`; migration and decommission are separate reviewed changes.

## Files

| File | Purpose |
|---|---|
| `versions.tf` | Pinned Terraform/provider requirements |
| `variables.tf` | Typed portable inputs and fail-closed validation |
| `locals.tf` | Canonical names, tags, roles, scopes, and alarm metadata |
| `cognito.tf` | Protected user pool, SPA client, scopes, and non-authoritative groups |
| `pre_token.tf` | Versioned pre-token runtime, role, permission, and alias |
| `control_processor.tf` | M2M/bootstrap dispatcher, least-privilege role, and event source |
| `storage.tf` | Encrypted membership/audit data, KMS, logs, and alarms |
| `bootstrap.tf` | FIFO control queue and paired DLQ containment |
| `contract.tf` | Atomic non-sensitive downstream contract |
| `outputs.tf` | Explicit statement that no parallel outputs exist |
| `tests/` | Mock-provider authorization, IAM, storage, artifact, and contract tests |

## Execution boundary

This module performs no state import, user migration, credential delivery,
queue redrive, deployment, or live validation by itself. GUG-93 repository and
CI evidence does not authorize an AWS plan/apply or production use.
