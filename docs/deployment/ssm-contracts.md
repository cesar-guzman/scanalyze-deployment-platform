# SSM Contracts Reference

## Status

SSM envelopes are the accepted target interface between Terraform layers. This
repository currently formalizes and validates the envelope offline; complete
root producers, consumers, IAM enforcement, and live SSM publication remain
blocked pending a separate non-production live change.

## Canonical Contract

Each producer owns one atomic, versioned envelope:

```text
/scanalyze/deployments/{deployment_id}/contracts/{layer}/v1
```

The contract is validated by `schemas/layer-contract.schema.json`. It binds the
outputs to deployment, account, region/scope, layer, producer, state key, output
schema, and immutable release digest. `contract_digest` is the SHA-256 of the
canonicalized `outputs` object.

## Rules

1. Each layer contract has one producer boundary.
2. Consumers read only the contracts declared in `deployment/layers.yaml`.
3. A missing producer, envelope, field, owner, schema, or digest blocks the
   consumer.
4. Contracts never contain credentials, customer documents, PII, state, raw
   plans, or real tfvars.
5. A hash proves content integrity, not writer authority. IAM enforces the writer
   boundary; the deployment record anchors expected release and version.
6. GitHub outputs and artifacts are not an infrastructure contract transport.
7. `terraform_remote_state` between layers is prohibited.

## Canonical Stage Order

```text
account-ready-gate -> global -> network -> platform -> data-foundation
  -> cicd -> artifact-publication -> services -> edge-identity -> edge
  -> addons -> synthetic-validation
```

`deployment/layers.yaml`, not this prose copy, is machine authoritative.

## Local Validation

```bash
python scripts/deployment/validate-layer-dag.py deployment/layers.yaml
make gitops-orchestrator-check
```

`publish-contract.py` renders a candidate envelope to a local output file in
this change. It does not write SSM. `resolve-contracts.py` accepts local fixtures
or explicitly enabled mocks and creates only an ephemeral, owner-readable
var-file outside the repository. Live reads and writes remain disabled.

## Legacy Per-Key Parameters

`modules/container-platform/ssm_contracts.tf` contains an older per-output path
convention. Those parameters are implementation evidence, not the canonical
cross-layer envelope. They must be migrated or compatibility-scoped before live
orchestration is enabled; new consumers must not expand the legacy convention.
