# ADR-033: Non-Production Live Engine and Exact Saved Plans

- **Status:** Proposed; accepted only after reviewed merge and main verification
- **Date:** 2026-07-15
- **Work package:** GUG-125
- **Baseline:** `76a04da02dbf563973d59309035be1272192c66f`
- **Program / phase gate:** GUG-115 / GUG-117
- **Upstream:** GUG-121, GUG-122, GUG-123, GUG-124
- **AWS live validation:** Blocked; no successful AWS session was established
- **Production:** **NO-GO**

## Context

The repository had a canonical layer DAG, strict contracts, target registry and
backend bindings, terminal identity contracts, and a signed build-once release
model. It did not have an implementation that could prove that the plan reviewed
for one exact deployment was the binary applied once to that same deployment.
The dry-run workflow intentionally rejected live execution, the live SSM
resolver was disabled, and no durable state machine reconciled an apply whose
client response was lost.

A raw Terraform plan is both sensitive and short-lived. A content digest alone
does not establish authority: target, state, contracts, release, source,
toolchain, approval, storage version, execution identity, and expiry must agree.
Likewise, a successful process exit cannot authorize a downstream layer if the
resulting state, producer contract, or runtime health is unknown.

## Decision

### 1. The plan and execution ledger use different authorities

The destination-account Plan terminal role writes exactly one KMS-encrypted,
versioned plan object under:

```text
plan-execution/{deployment_id}/{change_id}/{layer}/plan.tfplan
```

The shared-services orchestrator writes the create-only and compare-and-swap
execution ledger in `scanalyze-deployment-executions`. A destination terminal
role cannot create or approve its own ledger, and the orchestrator cannot write
the plan object. These adapters are separate types and are tested not to expose
each other's methods.

The ledger adapter also derives the only acceptable authority name as
`ScanalyzeOrchestrator-<deployment_id>`. A generic, differently scoped,
path-qualified, or caller-selected role ARN is denied even when it matches the
current AWS session.

### 2. Saved-plan metadata is an immutable complete binding

`saved-plan.v1` binds customer, deployment, account, region, non-production
environment, execution, change, layer, release/version, registry and
ACCOUNT_READY records, execution lock, backend, resolved contracts, toolchain,
root module, source revision, state lineage/serial, plan digest/size, exact S3
bucket/key/version, creation time, expiry, and canonical record digest.

The object is create-only, requires SSE-KMS and an S3 version ID, and expires in
five minutes to 24 hours. A missing field, mutable locator, wrong version,
post-plan state change, digest mismatch, expired record, production target, or
request-derived key denies apply.

### 3. Approval is independent and plan-specific

`saved-plan-approval.v1` binds the plan record digest to immutable repository
owner/repository numeric IDs, the exact main-branch workflow reference and SHA,
run ID, protected Environment, fresh Environment-configuration digest,
initiator numeric ID, distinct approver numeric ID, approval time, and expiry.
The approver must differ from the initiator and the approval lifetime cannot
exceed the plan lifetime.

The `PLANNED -> APPROVED` transition requires this receipt. Apply revalidates
the full receipt and requires its digest to equal the digest recorded in the
ledger. A workflow input, login name, Environment name, or ledger status alone
does not establish approval.

### 4. Apply is single-use and fail-closed

The ledger uses the following allowed transitions:

```text
PLANNED -> APPROVED | REJECTED | EXPIRED
APPROVED -> APPLYING | EXPIRED
APPLYING -> APPLIED | UNCERTAIN | FAILED
APPLIED -> HEALTHY | FAILED_HEALTH
UNCERTAIN -> RECONCILED_APPLIED | RECONCILIATION_REQUIRED
RECONCILED_APPLIED -> HEALTHY | FAILED_HEALTH
```

Every write compares the prior version, digest, and status. Entering `APPLYING`
consumes the only apply attempt. Apply authorization requires exact plan
readback, fresh state lineage/serial, an unused approved ledger, and the exact
approval. Apply never re-plans.

### 5. Health and reconciliation are evidence-bound transitions

A health receipt can be built only from an exact APPLIED or
RECONCILED_APPLIED ledger, its plan, post-apply state readback, and named
sanitized checks. `HEALTHY` requires that exact receipt; the resulting ledger
stores its digest. A downstream layer requires both the HEALTHY ledger and the
matching receipt and plan.

If the Terraform client loses the apply response, the ledger becomes
`UNCERTAIN`. Reconciliation is read-only. It classifies the result as
RECONCILED_APPLIED only when lineage matches, state serial advanced, a new
speculative plan is `NO_CHANGE`, and the producer contract verifies. Every
other result is `RECONCILIATION_REQUIRED`; it cannot retry or mutate state.

### 6. Dry-run and live activation remain distinct

Dry-run rejects ambient AWS access keys, session tokens, profiles, web-identity
token files, and role ARNs. The CLI has no `--profile` override, emits only
sanitized status, and writes operational files with mode 0600 outside the
repository. CI validates synthetic/fake-adapter behavior without OIDC or AWS.

This change does not activate `id-token: write` in repository workflows. Live
activation requires the GUG-123 shared-services platform authority, an exact
deployment-scoped protected Environment with an independent reviewer,
ACCOUNT_READY v2 in each destination account, and valid short-lived sessions.
Those prerequisites were not available during implementation, so a workflow
that could mint authority would be fail-open and remains disabled.

“Shared-services” means the dedicated or formally designated **Scanalyze
platform-authority account**. It does not authorize access to an unrelated
corporate shared-services account. The platform-authority account must differ
from every destination account; otherwise the ledger and workload trust
boundaries collapse and live execution is denied.

### 7. Platform authority is a portable factory, not a customer deployment

`modules/platform-authority` and `roots/platform-authority` declare the missing
machine control plane. The root is pinned to one exact authority account and
creates one GitHub OIDC provider, one shared runtime policy and permissions
boundary, KMS-protected registry/ledger/release storage, and one exact
`ScanalyzeOrchestrator-<deployment_id>` role for every approved deployment map
entry. Each role carries immutable customer, deployment, destination account,
region, environment, repository, and exact GitHub Environment bindings.
AWS requires the role's configured maximum to be at least one hour; the
deployment contract therefore separately requires the OIDC caller to request
the STS minimum of 900 seconds and treats the one-hour default as invalid.

The module rejects an authority account that equals any destination, mismatched
map keys, duplicate tuples or subjects, wildcard subjects, malformed ownership,
and production environments. It contains no customer workloads or terminal
roles. Destination bootstrap remains owned by AccountVendingProvider and its
`ACCOUNT_READY` contract.

The authority root intentionally cannot bootstrap its own state or Identity
Center access. A separately governed, short-lived human bootstrap establishes
that recovery boundary first. This removes the chicken-and-egg dependency
without making an operator laptop, static credential, destination account, or
Terraform request field authoritative.

## Security and portability consequences

- The implementation is account-, region-, customer-, and deployment-agnostic;
  all real bindings remain in external authoritative records.
- Generic and identity-control-plane Plan/Apply roles have only the evidence
  key and versioned-object permissions required for the exact plan handoff.
- The shared-services orchestrator receives only exact execution-ledger item
  actions scoped by the deployment leading key.
- Raw plans, state, plan JSON, backend files, credentials, protected identifiers,
  and AWS responses remain outside Git, Linear, NotebookLM, and general GitHub
  artifacts.
- No automatic state repair, force-unlock, replacement, destroy, migration, or
  production target is accepted.

## Alternatives rejected

- **Apply a newly generated plan:** review and execution would refer to
  different binaries.
- **Keep ledger in the destination account:** a terminal role could combine
  infrastructure and approval authority.
- **Use a digest without S3 versioning:** the locator could resolve to a
  different object.
- **Retry an uncertain apply:** it can duplicate or conflict with completed
  effects.
- **Enable OIDC before the platform authority exists:** a name or input would
  become authority.

## Rollback

Before live activation, revert this package and retain no operational data.
After any authorized live plan exists, first disable dispatch, preserve the
sanitized ledger/evidence index, classify every active plan as applied,
rejected, expired, or reconciliation-required, delete only exact R0 object
versions after their retention boundary, and then revert code. Never downgrade
an in-flight execution to the legacy re-plan/apply path.

## Evidence classification

| Class | Status |
|---|---|
| Implemented | Typed schemas, authorization core, separated AWS adapters, portable platform-authority module/root, CLI boundary, IAM/KMS/S3 deltas, tests, CI target, ADR and runbooks |
| Locally validated | Focused synthetic tests and offline dry-run gate; broader gates reported separately |
| CI validated | Pending the exact PR commit |
| Live validated | No |
| Blocked | Authorized third-account Identity Center profile/backend; exact protected Environments and independent reviewers; destination ACCOUNT_READY v2; sequential two-account execution |
| Production | **NO-GO** |
