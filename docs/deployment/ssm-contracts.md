# SSM Contracts Reference

## Status

SSM envelopes are the accepted target interface between Terraform layers.
GUG-121 implements real root payloads, strict offline resolution, and the
pre-plan consumer guard. GUG-381 makes contract resolution v3 the only active
offline artifact. The protected live-path amendment adds typed private
materialization plus explicit live SSM resolution and publication adapters.
Those adapters are repository candidates: their AWS behavior is covered by
hermetic command-contract tests, but no connected AWS execution or deployment
is claimed by this document.

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

`publish-contract.py` defaults to a local dry run. `resolve-contracts.py`
accepts fixtures only with `--allow-fixtures`. Both create exclusive mode-0600
outputs outside the repository. Resolution v3 carries canonical Terraform v2
envelopes and catalog-owned `account-ready/v2` evidence in disjoint, closed
record shapes. It binds ACCOUNT_READY to the authorized backend-binding digest
and never carries independently editable materialized variables.

The explicit `--live` modes implement the AWS transport boundary. They require:

- `SCANALYZE_ALLOW_LIVE=1` as an action-time acknowledgement;
- an explicit `--aws-region` and exactly one of a named `--aws-profile` or
  `--use-runtime-credentials`;
- a successful `sts:GetCallerIdentity` match to the expected 12-digit account,
  with root identities rejected;
- canonical repository schemas, catalog, DAG, contract set and action-time
  timestamps; and
- an exclusive private output reserved before the first AWS call.

The live resolver performs two bounded, paginated
`ssm:GetParametersByPath` snapshots for each exact catalog release prefix. It
requires one immutable digest leaf, then performs two exact
`ssm:GetParameter` reads and rejects missing, ambiguous, moving or foreign
content. The conceptual `sha256:<hex>` digest is mapped one-to-one to the
SSM-safe path component `sha256-<hex>`; no mutable `latest` pointer exists.

The live publisher validates Terraform outputs and the canonical envelope
before AWS access. It performs one `ssm:PutParameter` with Standard/String,
version 1, exact tags and `--no-overwrite`, followed by two exact parameter and
two exact tag readbacks. If the create response is lost, or an earlier protected
invocation already created the same content-addressed record, those four exact
readbacks reconcile success without a second write. Missing or different
content remains a terminal conflict; the tool never overwrites or silently
selects it. IAM limits the writer to its own deployment/layer contract prefix
and permits only the readbacks needed to attest publication.

Example shapes (placeholders are intentional):

```bash
SCANALYZE_ALLOW_LIVE=1 python scripts/deployment/resolve-contracts.py \
  --live --use-runtime-credentials \
  --layer <consumer-layer> \
  --customer-id <cust_ULID> \
  --deployment-id <deployment-id> \
  --account-id <12-digit-account-id> \
  --region <contract-region> --aws-region <aws-api-region> \
  --release-digest sha256:<64-hex> \
  --release-version <version> \
  --resolved-at <RFC3339> \
  --required-contract <producer>/v1 \
  --out <private-absolute-path>

SCANALYZE_ALLOW_LIVE=1 python scripts/deployment/publish-contract.py \
  --live --use-runtime-credentials \
  --from-terraform-output-json <private-output-json> \
  --layer <producer-layer> \
  --customer-id <cust_ULID> \
  --deployment-id <deployment-id> \
  --account-id <12-digit-account-id> \
  --region <contract-region> --aws-region <aws-api-region> \
  --release-digest sha256:<64-hex> \
  --release-version <version> \
  --produced-at <RFC3339> \
  --state-key <exact-state-key> \
  --out <private-absolute-path>
```

These commands are runtime primitives, not permission to execute them. The
protected workflow must derive every argument from sealed authority and exact
plan/state evidence; a workflow variable, artifact, repository file or
caller-supplied substitute cannot become authority. `terraform-layer.sh`
requires resolution v3, rejects ambient `TF_*`, and has no fallback.

The local and hermetic tests prove schema, binding, DAG, command construction,
failure behavior and Terraform configuration behavior. They do not prove a
connected SSM read/write, deployed IAM, provider creation, token issuance,
bootstrap, M2M credential custody, migration, application health or production
acceptance. The current path is therefore
`REPOSITORY_CANDIDATE / CONNECTED_DEV_NOT_PROVEN / PRODUCTION_NO_GO`;
`AWS_CALLS=0` and `AWS_MUTATIONS=0` while implementing this amendment.

## Legacy Per-Key Parameters

`modules/container-platform/ssm_contracts.tf` contains an older per-output path
convention. Those parameters are implementation evidence, not the canonical
cross-layer envelope. They must be migrated or compatibility-scoped before live
orchestration is enabled; new consumers must not expand the legacy convention.
