# ADR-029: Strict Contracts and Canonical Deployment DAG

- **Status:** Proposed; accepted only after reviewed merge and main verification
- **Date:** 2026-07-14
- **Work package:** GUG-121
- **Baseline:** `b33796d8803972a62b303f06992ca830feb32762`
- **Program:** GUG-115
- **Upstream:** GUG-84, GUG-109, ADR-006, ADR-017, ADR-024
- **Downstream gates:** GUG-122, GUG-123, GUG-124, GUG-125
- **Live validation:** No
- **AWS activity:** None

Production: **NO-GO**

## Context

The deployment graph declared dependencies, but the local plan wrapper could
fill missing digests, network identifiers, IAM ARNs, service definitions, and
other cross-layer values with synthetic defaults. Several producer schemas also
described fields that their Terraform modules did not publish. A plan could
therefore start without proving an exact producer, customer, deployment,
account, region, release, schema, state owner, or freshness window.

That behavior made the graph documentary rather than executable and allowed
the same variable name from multiple upstream layers to become ambiguous.

## Decision

### 1. One catalog owns every mapping

`deployment/contract-catalog.v1.json` is the machine-readable registry for
contract authority, sole producer, output schema, scope, content-addressed
transport, consumers, and consumer-specific input bindings. Its consumer list
and binding keys must match exactly, and the catalog must cover every contract
declared by `deployment/layers.yaml`.

Terraform envelopes use a customer-bound v2 envelope. They bind the exact
customer, deployment, AWS account, region or global marker, producer root,
state key, immutable release version and digest, output schema version, module source digest,
production timestamp, and canonical output digest.

### 2. Contracts are immutable and content addressed

The canonical SSM address is:

```text
/scanalyze/deployments/{deployment_id}/contracts/{layer}/vN/releases/{release_digest}/digests/{contract_digest}
```

There is no unversioned or `latest` pointer. Old v1 output schemas remain in the
repository for explicit rollback and staged migration, while the active DAG
uses v2 for network, platform, CI/CD, services, edge, and addons. A consumer
must name the exact accepted generation.

### 3. Real producers own the schema fields

Each active Terraform producer exposes all publishable fields under
`contract_payload.outputs`. Sibling Terraform outputs may remain for operator
compatibility, but the publisher ignores them when the nested boundary exists.
They cannot add or shadow contract fields. Sensitive Terraform outputs block
publication before any file is created.

### 4. Resolution is target bound and fail closed

`resolve-contracts.py` validates fixtures only with `--allow-fixtures`; its SSM
mode remains blocked for GUG-125. It rejects a missing, duplicated, foreign,
stale, future-dated, altered, wrongly produced, wrongly scoped, wrongly
versioned, or wrongly targeted contract. It also requires the exact Terraform
upstream set declared by the DAG.

Consumer bindings create only reviewed Terraform variables. Multiple upstream
contracts never merge by coincidental key name. Typed projections carry the
verified envelope metadata and schema outputs to consumers that need a whole
contract object.

The resolver writes an owner-only resolution artifact outside the repository.
The artifact has its own canonical digest and contains sanitized contract
evidence plus the exact materialized variables.

### 5. Terraform plan has no fallback

`terraform-layer.sh` requires an external resolution artifact, verifies its
digest, exact canonical DAG contract set and producers, and exact
customer/deployment/account/region/release-version/release-digest/consumer tuple,
materializes an owner-only temporary var-file, verifies the caller account, and
then invokes Terraform. The temporary file is removed on success, error, or
signal. No missing value is inferred or fabricated.

Local apply remains disabled by ADR-017. Live SSM read/write, remote backend
ownership, OIDC/IAM, signed supply-chain evidence, and exact saved-plan apply
belong respectively to GUG-125, GUG-122, GUG-123, and GUG-124.

## Security consequences

- A wrong customer, deployment, account, region, release, producer, schema,
  state key, digest, target, or freshness window fails before Terraform plan.
- Contract output names do not establish authority; catalog bindings do.
- Resolution files and materialized tfvars are mode `0600` and cannot live in
  the repository.
- Error messages identify the failed invariant without printing contract
  contents, ARNs, customer IDs, account IDs, or variable values.
- Hashes prove content integrity, not writer identity. Terminal writer IAM and
  signed provenance remain mandatory downstream gates.

## Rollout and rollback

Merge does not publish SSM, initialize a backend, create AWS resources, or
authorize a deployment. GUG-122 may start only after reviewed merge and main
verification of this ADR and its code.

Rollback is a normal revert of the GUG-121 commit. Existing v1 schemas remain
available, but selecting them requires an explicit DAG/catalog version; no
automatic downgrade or `latest` lookup is permitted.

## Evidence classification

- **Implemented:** candidate catalog, v2 envelopes/output schemas, real producer
  payloads, resolver, plan guard, canonical DAG, tests, runbook, and threat delta.
- **Locally validated:** only named local commands for the candidate commit.
- **CI validated:** pending the exact PR commit.
- **Live validated:** no.
- **Blocked:** reviewed PR, main verification, GUG-122 through GUG-125, and
  authorized non-production execution.
- **Production:** **NO-GO**.
