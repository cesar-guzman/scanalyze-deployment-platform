# SSM Contracts Reference

## Status

SSM envelopes are the accepted target interface between Terraform layers.
GUG-121 implements real root payloads, strict offline resolution, and the
pre-plan consumer guard. IAM enforcement and live SSM publication remain
blocked by GUG-123 through GUG-125.

## Canonical Contract

Each producer owns one atomic, versioned envelope:

```text
/scanalyze/deployments/{deployment_id}/contracts/{layer}/vN/releases/{release_digest}/digests/{contract_digest}
```

The active Terraform envelope is validated by
`schemas/layer-contract.v2.schema.json`. It additionally binds customer and
module source. `contract_digest` is the SHA-256 of canonicalized `outputs`.

## Rules

1. Each layer contract has one producer boundary.
2. Consumers read only the contracts declared in `deployment/layers.yaml`.
3. A missing producer, envelope, field, owner, schema, or digest blocks the
   consumer.
4. Contracts never contain credentials, customer documents, PII, state, raw
   plans, or real tfvars.
5. Identity contracts contain public provider/client identifiers and policy
   metadata only. Passwords, enrollment/MFA values, tokens, memberships, user
   inventories, and M2M credential values are prohibited even when an output
   could be marked sensitive.
6. A hash proves content integrity, not writer authority. IAM enforces the writer
   boundary; the deployment record anchors expected release and version.
7. GitHub outputs and artifacts are not an infrastructure contract transport.
8. `terraform_remote_state` between layers is prohibited.

## Canonical Stage Order

```text
account-ready-gate -> global -> network -> platform -> data-foundation
  -> cicd -> artifact-publication -> identity-control-plane -> services
  -> edge-identity -> edge -> addons -> synthetic-validation
```

`deployment/layers.yaml`, not this prose copy, is machine authoritative.

## Identity Control-Plane Contract

`identity-control-plane/v1` is produced only by the dedicated identity root and
is consumed by services, edge identity, and synthetic validation as declared in
the DAG. Its envelope follows the canonical SSM path:

```text
/scanalyze/deployments/{deployment_id}/contracts/identity-control-plane/v1/releases/{release_digest}/digests/{contract_digest}
```

The payload binds:

- exact customer, deployment, account, region, release, and contract digest;
- provider issuer, pool identifier, and public SPA/M2M client identifiers;
- `scanalyze.api.v1` and its exact `read`, `write`, and `admin` scopes;
- access-token-only use and non-authoritative provider-group semantics;
- canonical customer/deployment claim names;
- authorization, role, scope, and policy versions plus policy digest; and
- explicit no-cross-account, no-cross-deployment, no-ID-token, no-legacy-
  identity-fallback, and no-credential-exposure restrictions.

The contract must not contain generated M2M credential values. Runtime M2M
provisioning escrows the value in the approved credential store and may publish
only a public client ID and non-sensitive credential reference through the
separately reviewed binding workflow. The raw value never crosses SSM.

Consumers validate contract identity, expected digest, tuple, issuer, clients,
versions, scopes, and restrictions before planning. A missing, stale, foreign,
ambiguous, or unsupported identity contract blocks services and edge identity;
there is no fallback to `edge-identity/v1`, a copied provider identifier, ID
token, provider group, or legacy tenant map.

## Local Validation

```bash
python scripts/deployment/validate-layer-dag.py deployment/layers.yaml
make gitops-orchestrator-check
```

`publish-contract.py` renders a candidate envelope to a local output file. It
does not write SSM. `resolve-contracts.py` accepts only explicitly acknowledged
test fixtures and creates a content-bound owner-readable resolution outside the
repository. `terraform-layer.sh` requires that resolution and has no fallback.
Live reads and writes remain disabled.

The identity stage's local fixture and mock-provider tests prove only schema,
binding, DAG, and Terraform configuration behavior. They do not prove live SSM
publication, writer IAM, provider creation, token issuance, bootstrap, M2M
credential custody, migration, or consumer readback. Those remain **Blocked**
and production remains **NO-GO**.

## Legacy Per-Key Parameters

`modules/container-platform/ssm_contracts.tf` contains an older per-output path
convention. Those parameters are implementation evidence, not the canonical
cross-layer envelope. They must be migrated or compatibility-scoped before live
orchestration is enabled; new consumers must not expand the legacy convention.
