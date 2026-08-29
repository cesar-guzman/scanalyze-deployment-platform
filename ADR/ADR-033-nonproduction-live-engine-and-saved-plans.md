# ADR-033: Non-Production Live Engine and Exact Saved Plans

- **Status:** Proposed; protected DEV path implemented in repository, connected live not proven
- **Date:** 2026-07-15; GUG-382 amendment 2026-08-21; live-path amendment 2026-08-28
- **Work package:** GUG-125, amended by GUG-382
- **GUG-382 baseline:** `2b5f2038d0b7b190e50233713aa4923fb3e95371`
- **Program / phase gate:** GUG-115 / GUG-117
- **Upstream:** GUG-121, GUG-122, GUG-123, GUG-124
- **AWS live validation:** **NOT_PROVEN**; GUG-382 executed no AWS action
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
versioned plan object to the destination ephemeral plan bucket
`scanalyze-<account-id>-tf-plan`, using the exact `evidence_kms_key` anchored
by ACCOUNT_READY, under:

```text
plan-execution/{deployment_id}/{change_id}/{layer}/plan.tfplan
```

The state bucket remains exclusive to Terraform state, lock and state readback;
the evidence bucket remains exclusive to durable sanitized evidence with
90-day COMPLIANCE retention. Neither is saved-plan storage. The dedicated
versioned plan bucket has no Object Lock and expires current and noncurrent
`plan-execution/` objects after one day. CloudFormation retains the bucket and
its policy on stack deletion or replacement. The controller exposes no
saved-plan delete API; lifecycle expiry is the implemented object-cleanup path.

The shared-services orchestrator writes the create-only and compare-and-swap
execution ledger in `scanalyze-deployment-executions`. A destination terminal
role cannot create or approve its own ledger, and the orchestrator cannot write
the plan object. These adapters are separate types and are tested not to expose
each other's methods.

The platform-authority execution table also carries create-only, consistently
read plan, approval, health, and reconciliation control records. Each record is
schema-validated, tuple-bound, and digest-checked again at readback; a workflow
artifact or caller path is not durable authority.

The ledger adapter also derives the only acceptable authority name as
`ScanalyzeOrchestrator-<deployment_id>`. A generic, differently scoped,
path-qualified, or caller-selected role ARN is denied even when it matches the
current AWS session.

### 2. Saved-plan metadata is an immutable complete binding

`saved-plan.v1` binds customer, deployment, account, region, non-production
environment, execution, change, layer, release/version, registry and
ACCOUNT_READY records, execution lock, backend, resolved contracts, toolchain,
root module, source revision, state status/lineage/serial plus exact state-object
VersionId/SHA-256/size when present, plan digest/size, structural plan summary,
exact plan S3 bucket/key/version, creation time, expiry, and canonical record
digest.

The object is create-only, requires SSE-KMS and an S3 version ID, and expires in
five minutes to 24 hours. A missing field, mutable locator, wrong version,
post-plan state change, digest mismatch, expired record, production target, or
request-derived key denies apply.

The state status is `PRESENT` with real lineage/serial or `ABSENT` with both
values null for a first deployment. Only an unambiguous missing-object response
under the exact state-list authority establishes `ABSENT`; `403`,
`AccessDenied`, or an unknown error fails closed. Before publication the
controller inspects `terraform show -json` through a private descriptor,
rejects delete, replacement, malformed, duplicate, or unknown actions, removes
the raw JSON scratch, and persists only sanitized counts and a summary digest.
The canonical reviewer manifests are capped at 256 non-no-op resource actions
and 128 non-no-op output actions.

### 3. Approval is independent and plan-specific

`saved-plan-approval.v1` binds the plan record digest to immutable repository
owner/repository numeric IDs, the exact main-branch workflow reference and SHA,
run ID, protected Environment, fresh Environment-configuration digest,
initiator numeric ID, distinct approver numeric ID, approval time, and expiry.
The approver must differ from the initiator and the approval lifetime cannot
exceed the plan lifetime.

The plan phase derives a `saved-plan-reviewer-packet.v1` document from the
durable plan record. Its digest binds the plan hash/size, cost binding, a digest
of the complete state status/lineage/serial/VersionId/hash/size binding, and the
bounded canonical resource/output action manifests. The GitHub step summary
exposes only that sanitized packet. A later Apply dispatch must provide its exact
packet digest; the controller reconstructs the packet from the durable record
before approval.

The `PLANNED -> APPROVED` transition requires this receipt. Apply revalidates
the full receipt and requires its digest to equal the digest recorded in the
ledger. A workflow input, login name, Environment name, or ledger status alone
does not establish approval.

Approval receipts are append-only and stored under a key derived from the full
approval digest. The ledger, not record existence, selects authority. A
cancelled pre-apply run may be recovered by a dedicated CAS that replaces the
selected approval digest only when status remains `APPROVED` and
`attempt_count=0`. This is not an allowed state-machine self-transition and it
cannot run after the apply attempt is consumed.

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

### 6. Dry-run, protected DEV execution, and production activation remain distinct

Dry-run rejects ambient AWS access keys, session tokens, profiles, web-identity
token files, and role ARNs. The CLI has no `--profile` override, emits only
sanitized status, and writes operational files with mode 0600 outside the
repository. CI validates synthetic/fake-adapter behavior without OIDC or AWS.

GUG-382 established the governed repository shape for a future DEV execution.
The live-path amendment replaces its unconditional sentinel with a typed,
offline materialization boundary and a separate controller boundary. A manual
dispatch selects exactly one `plan` or `apply` phase; plan and apply are
separate workflow runs so approval cannot be inferred from the plan-producing
run. No recovery operation is exposed. `id-token: write` remains allowlisted
only on the canonical `live-layer` caller and the single Environment-protected
`live_saved_plan` reusable job. Only that reusable job contains the pinned AWS
credential action.

The only public live-input selector is
`live_input_claim_digest=sha256:<64-lowercase-hex>`. It is mandatory for a live
phase and forbidden in dry-run. It cannot select a path. The protected
Environment supplies the exact live-input bundle and collector App private-key
transports plus the public collector App ID; neither private value is authority
unless its decoded/verified binding matches the public claim and GitHub
identity contract. The
unprivileged, Environment-gated job uses the fixed private root
`$RUNNER_TEMP/scanalyze-live-inputs`. The CLI receives only the exact
deployment, layer, operation and claim digest selectors. It validates schemas,
source digests, deployment tuple, backend authority, contract-resolution
result, release and GitHub bindings, then publishes create-only
records under `materialized/`.

The typed selectors derive exactly one reviewed claim path:
`deployment/live-input-claims/<deployment_id>/<layer>/<operation>.json`. Its
working-tree bytes must equal the file at exact `HEAD`; a caller cannot choose
another claim or an untracked file.

The sole Environment-protected job runs both `materialize` and `validate`,
accepts only a well-formed receipt digest, and deletes its staging private root.
It then rematerializes independently into the fixed protected root. Both passes
use the same verified repository-scoped App token and require the same claim and
stable sealed-authority projection, but obtain complete current GitHub
snapshots; receipt digests therefore differ. Missing transport,
invalid file, stable-authority mismatch, stale anchor, pre-existing output or
incomplete binding stops before credentials. Repository variables, workflow
artifacts, caller paths and mutable locators cannot replace the protected secret
or bypass this decision.

Both passes compare the materialized release, Region, destination account,
platform-authority account, Environment-configuration digest, terminal roles,
orchestrator role and numeric repository identities with the dispatch and
protected Environment. Live execution is limited to workflow run attempt `1`;
a failed attempt requires a new workflow run and fresh Environment review.

Both phases require receipt code `LIVE_INPUTS_MATERIALIZED`,
`oidc_authorized=true`, and `terminal_operation_authorized=false`. For `plan`,
the sealed inputs may advance to the exact Plan session. For `apply`, the
receipt additionally requires `durable_readback_required=true`:
materialization alone never authorizes a mutation. The controller must read
back the exact approved durable plan and ledger state before the single apply
attempt.

The sealed transport contains no Terraform state observation. The Plan terminal
role reads the versioned backend immediately before the plan, reads it again
after plan creation, and admits only an exact match. That terminal observation
is the state binding stored in the saved plan. Apply rechecks it under the
Apply role immediately before consuming the plan; no externally refreshed
five-minute state snapshot is part of the operator interface.

Immediately before an apply OIDC session, the protected job uses
`scripts/deployment/nonprod-live-approval.py` for exactly two read-only GitHub
REST reads through the same App installation token: workflow-run metadata and
that run's Environment approval history.
It projects only numeric repository, run, Environment, initiator, the exact
protected `SECOND_P0_REVIEWER_ID`, and reviewer-packet digest bindings into the
fixed private controller directory, then revalidates its digest and exact
five-minute lifetime. The token, raw responses, logins, comments and URLs are
neither printed nor persisted. The App token is revoked with confirmed HTTP 204
and its private material removed before OIDC; it is never passed to Terraform
or the controller. No matching review, self-review, unexpected or
multiple distinct approvers, stale evidence, packet mismatch or tuple mismatch
stops before OIDC. This short-lived evidence is controller input; it is not by
itself a durable saved-plan approval or mutation authority.

Only after that receipt passes may the protected job request its exact
platform-authority OIDC session and call
`scripts/deployment/nonprod-live-controller.py` for the selected phase. The
controller consumes the same private root and exact deployment, execution,
change, layer, main SHA, region and operation bindings. `plan` may mint one
immutable saved-plan record. A later, separately approved `apply` dispatch must
use its own reviewed operation-specific `apply.json` claim and name that exact
record digest. It shares the deployment, execution, change, layer, main SHA,
Region and release tuple with the plan; it cannot plan again or substitute
another tuple. The workflow remains restricted to `dev`. `staging` and
`production` are rejected before credentials.

The controller/engine core introduced by this amendment can resume an
`APPLIED` or `RECONCILED_APPLIED` observation without repeating approval,
fetch, or apply. It advances to `HEALTHY` only after exact state bracketing, a
structural `NO_CHANGE` plan, verified input contracts, non-sensitive outputs, a
durable health receipt, and exact contract publication/readback. `UNCERTAIN`
permits only read-only reconciliation and never apply or publication. These
paths are hermetically tested, but the protected workflow does not yet provide
their real verification/publication adapters. The public Apply CLI therefore
stops before destination access or attempt consumption. Historical or
independently wired `APPLIED`/`UNCERTAIN` records remain fail-closed in the
controller core and are not `CONNECTED_DEV_APPLY_PROVEN`.

An orphaned `APPLYING` record is never an apply retry. This workflow exposes no
recovery operation and no alternate Environment/OIDC job; the record remains
stopped for read-only diagnosis and a future separately reviewed recovery
design. Operators may not edit it, redispatch apply, or recreate the removed
privileged path.

This amendment establishes a repository implementation, not connected proof.
No OIDC token, STS session, remote Terraform plan, saved-plan publication,
apply, health check, reconciliation or rollback was executed while implementing
it. Connected activation still requires a configured and independently
reviewed protected Environment transport, the exact GUG-123 platform-authority
account and backend, a non-overlapping DEV network decision, the destination
baseline and terminal roles, and a deployment-scoped protected Environment
with an independent reviewer. Production additionally remains behind GUG-127
staging certification and a separate GUG-128 limited-pilot authorization.

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
the explicit one-hour workflow bound and rejects any different duration.

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
- Live selection is restricted to `dev`; staging and production are explicitly
  denied before any credential step.

## Alternatives rejected

- **Apply a newly generated plan:** review and execution would refer to
  different binaries.
- **Keep ledger in the destination account:** a terminal role could combine
  infrastructure and approval authority.
- **Use a digest without S3 versioning:** the locator could resolve to a
  different object.
- **Retry an uncertain apply:** it can duplicate or conflict with completed
  effects.
- **Make the OIDC credential step reachable before live inputs and platform
  authority are proven:** a name or input would become authority.

## Cost, blast radius and rollback

Every connected authorization must bind one deployment, DEV account, Region,
layer, operation, execution ID, change ID, main SHA, claim digest, release
digest, cost ceiling and time window. The reviewed claim carries integer
`maximum_cost_usd_micros` from 0 through 100,000,000. The sealed request carries
an independently digested USD `cost_model` with an integer modeled upper bound,
model/expiry timestamps and at most a 24-hour validity window. Materialization
stops before OIDC unless the model is current and its upper bound is less than
or equal to the claim ceiling; both values and `cost_model_digest` are bound in
the manifest and receipt.

The cost model is a reviewed external budget attestation, not a cost derived by
this repository from the plan or current AWS prices. Its digest and values are
immutable between plan and apply; estimator accuracy remains an external
precondition. A rollout requiring plan-derived pricing is denied until an
authoritative estimate is bound to the exact plan digest.

One dispatch performs one phase against one layer. Normal execution rejects
destroy and replacement and caps canonical reviewer manifests at 256 non-no-op
resource actions and 128 non-no-op output actions. Concurrency does not cancel
an in-flight run. The platform-authority control-plane OIDC session and
destination terminal sessions are 3,600 seconds, while the live job has a
45-minute ceiling; credential lifetime never extends the job. A missing, stale,
invalid or exceeded cost ceiling is a stop, not a warning.
Sanitized evidence records the bounded model without retaining raw plans, state
or AWS responses. This does not expand break-glass authority: diagnostic and
state-recovery sessions remain human-only, independently controlled, and
capped at 900 seconds.

Before OIDC, rollback is a reviewed repository revert plus invalidation of the
exact private request; no AWS cleanup is required. After a live plan exists,
disable further dispatch, preserve the sanitized ledger/evidence index, and
reject or expire every unused plan record. The controller has no object-delete
path; the retained plan bucket's one-day current/noncurrent lifecycle expires
the raw versions. After apply starts, never retry the saved plan or restore
Terraform state. Read back and reconcile an uncertain outcome; recover forward
with the exact last-known-good signed release and a new reviewed saved plan.
Never downgrade an in-flight execution to the legacy re-plan/apply path.

## Evidence classification

| Class | Status |
|---|---|
| Implemented | Repository candidate: typed private-input materializer, protected controller boundary, exact saved-plan runner, separated plan/apply workflow shape, durable control-record adapters, canonical OIDC job allowlist, tests, CI target, ADR and runbooks |
| Locally validated | Focused synthetic tests, Python compilation, shell syntax and offline dry-run gate; broader gates reported separately |
| CI validated | Pending the exact PR commit |
| Live validated | **NOT_PROVEN**; no AWS action executed |
| Blocked | Configured and independently reviewed protected Environment transport; real workflow adapters for the implemented health/no-change/reconciliation core; connected plan/apply/health/reconciliation evidence; exact platform-authority account/backend; destination baseline and terminal roles; non-overlapping DEV network decision; exact protected Environment; independent reviewer; GUG-127 staging certification; GUG-128 production authorization |
| Classification | `REPOSITORY_CANDIDATE / CONNECTED_DEV_NOT_PROVEN` |
| Production | **NO-GO** |
