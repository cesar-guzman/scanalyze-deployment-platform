# ADR-055: GUG-395 Pre-Plan Seed and Downstream Materialization

- **Status:** Proposed repository contract; not deployed
- **Date:** 2026-08-27
- **Implementation issue:** GUG-395
- **Parent issue:** GUG-376
- **Consumer issues:** GUG-363, GUG-365, GUG-393 and GUG-392
- **Extends:** ADR-053 and ADR-054 for causal bootstrap ordering
- **AWS live validation:** None
- **Production:** **NO-GO**

## Context

The GUG-393 source contract currently validates complete GUG-363 and GUG-365
plans and derives exact provider selectors from them. Those plans are valid
post-run products: their generated ARNs, immutable S3 versions, signing jobs
and signed package bindings exist only after the GUG-376 upstream foundation
has completed and been read back.

Using that post-run source bundle as a prerequisite for the same upstream run
creates a causal cycle:

```text
GUG-376 mutation inputs
  -> GUG-393 source contract
  -> complete GUG-363/GUG-365 plans
  -> completed GUG-376 provider outputs
```

The checked-in GUG-393 templates do not solve the cycle. Empty plans and
placeholder selectors fail closed, while inventing generated ARNs would break
provider provenance. The existing GUG-392/GUG-393 exact collectors also cannot
be relabelled as a pre-plan collision probe: their closed policies and
readbacks require final target ARNs.

## Decision

### 1. Split the pre-plan seed from downstream exact verification

GUG-395 adds one owner-private pre-plan seed that is derived without a
GUG-363 plan, a GUG-365 plan or any provider-generated identifier. It binds:

- the exact clean source commit/tree at fetched `origin/main`, plus committed
  byte digests for every required catalog and package source;
- the closed GUG-377 nine-phase, thirty-operation catalog;
- the provider-slot catalog as unresolved typed outputs;
- fourteen exact owner decisions plus two repository-derived object-key
  bindings, with provenance, impact and rollback boundaries;
- deterministic broker and ledger-factory build inputs; and
- one owner-only custody binding.

The seed and the pending mutation plan are repository products only. They
state `aws_calls=0`, `aws_mutations=0`, `deployment_authorized=false`,
`production=false`, `two_human_status=NOT_PROVEN` and
`independent_approval_present=false`. A digest, review, merge or successful
offline check cannot promote either record into provider authority.

The private root remains outside Git, worktrees and synced/File Provider
storage. Directories are owner-only mode `0700`; inputs and outputs are
single-link regular files mode `0600`; final writes are create-only. Public
output is limited to stable status values and canonical digests.

### 2. Preserve one honest causal order

The only accepted order is:

| Order | Product or action | Evidence boundary |
|---|---|---|
| 1 | Exact clean reviewed source, owner input, deterministic package inputs and GUG-395 seed/plan | Offline and private; zero AWS calls |
| 2 | Additive pre-plan collision probe by source-bound name and tag (ADR-056) | Repository implementation available; connected read-only run not executed; must not require generated ARNs and must not reuse the current exact collectors |
| 3 | Future executable provider, all closed request/readback routes, durable CAS ledger and external verifier | Separately reviewed implementation; still no phase is authorized by repository state |
| 4 | Nine GUG-376 phases, each under fresh action-time authorization and one-attempt semantics | Live non-production evidence; ambiguous outcomes are read-only reconciliation only |
| 5 | Complete terminal provider readback and independent transcript verification | Private, digest-bound terminal handoff |
| 6 | After a future trusted terminal-capability minter exists, the gated GUG-395 downstream checkpoint builder validates the GUG-363 intent/plan, actual package archives and both signing contracts | Emits only `READY_FOR_GUG365_FRESH_CHECKPOINT`; no GUG-365 plan or GUG-393 source bundle |
| 7 | Original GUG-365 run performs a fresh read-only checkpoint and compiles its plan, binding the authoritative downstream receipt and its private-manifest digest | Separate consumer evidence and authority boundary |
| 8 | GUG-395 post-checkpoint helper validates the authoritative receipt, the GUG-365 plan and every terminal package/signing binding before deriving the GUG-393 source bundle | Offline post-phase product bound to one terminal handoff, downstream receipt and fresh checkpoint |
| 9 | GUG-393 input discovery and GUG-392 exact dual-domain verification | Post-run read-only verification using the now-valid complete plans and exact ARNs |
| 10 | GUG-357, GUG-215, GUG-206, GUG-127 staging and GUG-128 production pilot | Separately authorized downstream gates |

No later product may be copied backwards as evidence for an earlier stage.
In particular, GUG-393/GUG-392 v1 remains post-run exact verification and is
not a pre-plan prerequisite.

### 3. Keep unimplemented live routes visible

GUG-395 compiles the closed operation and slot bindings but does not construct
an AWS client, vend credentials, execute a provider request, persist a live
ledger or verify a live transcript. The executable boundary remains blocked:

- the name/tag collision probe is repository-implemented but has no connected
  dual-domain run or live receipt;
- fourteen provider-generated output materialization/readback routes are still
  missing from the live adapter boundary;
- the Identity Center application authentication-method request/readback path
  remains a separate fail-closed STOP; and
- the live mutation provider, durable nine-phase executor and action-time
  mutation authorization verifier are not implemented by GUG-395.

These are implementation blockers, not documentation gaps. The pending plan
therefore records that request materialization awaits an attested mutation
provider. Neither `catalog`, `seed` nor `plan` may claim live readiness.

### 4. Require certified post-phase materialization

After all nine phases, downstream materialization requires all of the
following in one causal chain:

- the exact seed and pending plan;
- nine ordered phase certifications and thirty ordered operation receipts;
- the provider transcript, durable execution ledger and complete artifact
  readback digests;
- exact Authority and Identity Center target projections;
- a terminal handoff with consistent AWS call and mutation counts; and
- a separately reviewed trusted terminal verifier and capability minter, which
  GUG-395 intentionally does not implement.

Structural validation of a serialized terminal handoff is insufficient.
Current v1 stops before handoff acceptance with
`STOP_LIVE_EXECUTION_PLAN_NOT_IMPLEMENTED`; it cannot report successful
structural validation or mint the in-process verification capability consumed
by the downstream builder.

The checked-in downstream receipt fixture is therefore
`SYNTHETIC_CONTRACT_ONLY_BLOCKED`; its schema and shape validator are not
certification. Only a future trusted capability may authorize the first
offline downstream transition.
The GUG-395 downstream checkpoint materializer validates the post-phase
GUG-363 intent/plan, both deterministic package manifests and both signing
contracts. It emits a sanitized digest-only receipt with
`READY_FOR_GUG365_FRESH_CHECKPOINT`, `gug365_plan_materialized=false`, zero new
AWS calls and zero mutations. It neither accepts nor emits a GUG-365 plan or a
GUG-393 source bundle.

The original GUG-365 run must then perform a fresh read-only checkpoint and
compile its own plan. That checkpoint capability binds both the authoritative
downstream receipt digest and its private-manifest digest. Only a separate
GUG-395 post-checkpoint helper may validate that receipt and fresh plan, require
the terminal verifier digest plus every GUG-363/package/signing digest to match
the same handoff, derive the GUG-393 v2 source bundle and compare its exact
Authority and Identity Center projections with the terminal handoff. The first
downstream receipt cannot be resealed, omitted or reinterpreted as that later
capability.

The v2 boundary supports exactly two Identity Center encryption states. An
AWS-owned key is represented by `AWS_OWNED_KMS_KEY` plus a JSON `null` key ARN;
a customer-managed key is represented by `CUSTOMER_MANAGED_KEY` plus the exact
management-account, `us-east-1` KMS key ARN. The complete private binding is
the tuple of Identity Center instance ARN, mode and nullable key ARN. Both the
private source bundle and sanitized downstream receipt bind the canonical
digest of that tuple. The public receipt never carries the raw instance, mode
or key ARN. The immutable v1 receipt remains available only as historical
schema evidence and is never upgraded by relabeling or resealing it. The
[dual-mode operations contract](../docs/operations/platform-authority-gug393-kms-dual-mode-contract.md)
defines the exact matrix, digest projection and public leak boundary.

### 5. Preserve downstream ownership and production gates

GUG-395 neither applies GUG-363 nor executes GUG-365. It does not invoke
GUG-357, GUG-215 or GUG-206 and does not establish staging or production
acceptance. GUG-127 staging certification and GUG-128's separately authorized
production pilot remain mandatory.

## Rollback and recovery

Before any future live action, rollback is a reviewed Git revert of GUG-395
and deletion of only unconsumed GUG-395 private seed/plan files under a
separately confirmed local cleanup. It has no AWS effect.

After a live phase, there is no automatic rollback. Preserve the seed, plan,
ledger, receipts and provider state. A timeout, lost response, malformed
readback or stale in-flight record remains `UNCERTAIN_RECONCILE_ONLY`; it does
not restore an attempt. Any provider cleanup or revocation is a new reviewed
mutation package with its own blast-radius analysis and authorization.

## Rejected alternatives

- **Use empty or synthetic GUG-363/GUG-365 plans before GUG-376.** Rejected
  because placeholders cannot establish generated provider identifiers.
- **Move the current GUG-393/GUG-392 exact collectors before the run.**
  Rejected because their closed contracts require post-run ARNs.
- **Treat stable names as proof of absence.** Rejected; a future bounded
  collision probe must read the provider and classify ambiguity explicitly.
- **Accept a self-sealed terminal handoff.** Rejected because a self-digest is
  integrity evidence, not external provider attestation.
- **Let GUG-395 implement or authorize live mutation.** Rejected to preserve a
  separately reviewable provider, executor and action-time authorization
  boundary.

## Consequences and evidence classification

- The post-plan cycle is removed at the repository contract layer.
- The pre-plan seed and pending mutation plan are reproducible offline.
- The final GUG-393 source bundle becomes a truthful post-phase product.
- Current exact collectors remain unchanged and retain their read-only scope.
- Missing collision, provider-route, authentication-method and durable
  execution work remains explicit.
- Production remains **NO-GO**.

```text
GUG395_SOURCE_CONTRACT=REPOSITORY_VALIDATED_OFFLINE_ONLY
PREPLAN_COLLISION_PROBE=REPOSITORY_IMPLEMENTED_CONNECTED_RUN_PENDING
LIVE_MUTATION_PROVIDER=NOT_IMPLEMENTED
DURABLE_NINE_PHASE_EXECUTOR=NOT_IMPLEMENTED
AWS_CALLS=0
AWS_MUTATIONS=0
DEPLOYMENT_AUTHORIZED=false
PRODUCTION=NO-GO
```

## References

- [ADR-053](ADR-053-gug365-upstream-prerequisites-materialization.md)
- [ADR-054](ADR-054-gug377-provider-backed-upstream-materializer.md)
- [GUG-376 deployment contract](../docs/deployment/platform-authority-gug365-upstream-prerequisites.md)
- [GUG-376 operations runbook](../docs/operations/platform-authority-gug365-upstream-prerequisites.md)
- [GUG-365 deployment contract](../docs/deployment/platform-authority-retirement-entrypoint-service-role.md)
- [GUG-365 operations runbook](../docs/operations/platform-authority-retirement-entrypoint-service-role.md)
