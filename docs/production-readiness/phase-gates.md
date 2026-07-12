# Production Readiness GO/NO-GO Matrix

> **Program:** GUG-115\
> **Phase 0:** GUG-116\
> **Production gate:** GUG-128 — **Blocked / NO-GO**\
> **Policy:** a gate unlocks only the next eligible work package

## Gate semantics

- Entry criteria are prerequisites, not work to complete inside the gate.
- Exit criteria require reviewable evidence in the state named by the gate.
- A dependency expressed only as prose or `relatedTo` remains a dependency; the
  absence of a Linear `blockedBy` relation does not remove it.
- A gate cannot consume evidence from a later phase.
- A local or dry-run result never satisfies a live criterion.
- A GO is scoped to the next work package and does not authorize AWS activity
  unless that work package explicitly includes an approved non-production live
  action.
- Any automatic NO-GO condition overrides schedule, priority, and an existing
  approval.

## Phase matrix

### Phase 0 — GUG-116: Production Readiness Foundation

**Entry criteria**

- GUG-115 is the accepted program record and production is NO-GO.
- The authorized workspace, branch, and baseline are exact and clean.
- Work is documentation/governance only; no AWS, deploy, apply, or remote Git
  mutation is authorized.

**Exit criteria**

- no ambiguous P0 decision;
- accepted Phase 0 ADR and explicit compatibility with existing decisions;
- every root input has an authoritative source and every output one producer;
- deployment identity vocabulary, single-region pilot scope, saved-plan policy,
  approval model, and no-rebuild policy are explicit;
- threat model, RACI, evidence policy, phase matrix, work packages, and recovery
  boundaries are reviewable;
- future PRs and dependencies are explicit without duplicate Linear issues;
- sanitized NotebookLM source is ingested and fail-closed questions pass;
- a fresh-agent read-only dry-run identifies production NO-GO, non-live evidence,
  GUG-128 blocking, and canonical ownership without relying on prior chat;
- negative controls reject a missing decision or owner, dual accountability, a
  contradictory production-GO claim, and sensitive examples;
- local documentation, security, Git safety, tests, and diff checks pass; and
- live and production remain disabled.

**Mandatory evidence:** reviewed documents, local validation record, complete
diff review, fresh-agent positive/negative result, NotebookLM ingestion/check
record, and sanitized Linear closeout.

**Automatic NO-GO:** missing owner/source/producer, ambiguous decision, failed
validation, prohibited data, NotebookLM check failure, or any live/production
enablement.

### Phase 1 — GUG-117: Identity and Multi-Client Isolation

**Entry criteria adopted by Phase 0:** Phase 0 GO; identity vocabulary and owner
accepted; test design covers user and M2M paths plus two isolated deployments;
GUG-114 and related P0 authorization behavior are in scope.

**Exit criteria:** no component substitutes `deployment_id` for `customer_id`;
user and M2M paths verify both bindings; no header or payload selects tenant;
two test deployments cannot read, publish, or process one another's data or
configuration.

**Mandatory evidence:** schema/ADR, reviewed implementation, unit/integration
tests, and sanitized non-production isolation results.

**Dependencies / owners:** GUG-82, GUG-92, GUG-93, GUG-102, GUG-114, GUG-89.

**Automatic NO-GO:** any cross-client ambiguity or attacker-controlled tenant
selection.

### Phase 2 — GUG-118: Runtime Topology, FIFO, Idempotency, and DLQ

**Entry criteria adopted by Phase 0:** Phase 1 isolation evidence accepted;
canonical consumer path and queue ownership identified; failure-injection plan
does not use customer data.

**Exit criteria:** one compatible consumer path is active; no accepted work is
lost; duplicate/replay produces one effect; poison messages are retained and
alarmed; steady state returns after recovery.

**Mandatory evidence:** topology matrix, queue contract, failure-injection
report, no-loss/no-duplicate results, and recovery runbook.

**Dependencies / owners:** GUG-85, GUG-89, GUG-108, GUG-15.

**Automatic NO-GO:** loss, silent poison message, uncontrolled redrive, or
cross-client routing.

### Phase 3 — GUG-121: Strict Contracts and Canonical DAG

**Entry criteria adopted by Phase 0:** Phase 1 binding vocabulary is stable;
Phase 2 runtime producers/consumers are identified; every current root variable
has a proposed authoritative source.

**Exit criteria:** every mapping has one producer; one real
root-to-contract-to-resolver-to-consumer flow succeeds; no live-path mock,
GitHub output data bus, or `terraform_remote_state` remains.

**Mandatory evidence:** contract catalog, producer/consumer matrix, schemas and
test vectors, integration report, and sanitized readback.

**Dependencies / owners:** GUG-84, GUG-109; identity decisions from Phase 1.

**Automatic NO-GO:** missing, stale, ambiguous, unsigned/untrusted, or
cross-layer-writable contract.

### Phase 4 — GUG-122: Registry, Account Baseline, Backend, and Locking

**Entry criteria adopted by Phase 0:** Phase 3 contract ownership accepted;
registry schema and account-ready authority defined; ADR-019 saved-plan storage
decision reflected consistently in policy and design.

**Exit criteria:** users cannot supply arbitrary targets or backend coordinates;
one deployment cannot execute concurrently; state keys, locks, grants, and
ownership are isolated; version recovery is demonstrated safely in
non-production.

**Mandatory evidence:** reviewed baseline policy, registry and binding tests,
collision/locking tests, synthetic recovery evidence, and sanitized backend
isolation results.

**Dependencies / owners:** GUG-84, GUG-109, GUG-16.

**Automatic NO-GO:** arbitrary target input, backend uncertainty, lock bypass,
dual state owner, or unproven recovery authority.

### Phase 5 — GUG-123: GitHub Environments, OIDC, and Terminal IAM

**Entry criteria adopted by Phase 0:** Phase 4 registry and account binding are
authoritative; role inventory and trust tests are complete; GUG-119 has an
approved implementation plan.

**Exit criteria:** PRs, forks, and dry-runs cannot obtain deployment identity;
OIDC is exact to approved repository/workflow/branch/Environment; terminal roles
are scoped by operation, layer, deployment, and account; production prevents
self-review and bypass.

**Mandatory evidence:** reviewed policies, access analysis, simulations,
sanitized denial results, and audited approval configuration.

**Dependencies / owners:** GUG-84, GUG-87, GUG-109, GUG-119.

**Automatic NO-GO:** wildcard/broad OIDC trust, ambient privilege, missing role
separation, or missing independent approval.

### Phase 6 — GUG-124: Build Once and Supply Chain Fail-Closed

**Entry criteria adopted by Phase 0:** Phase 5 release identities are
least-privilege and bound; release-manifest ownership is accepted; GUG-120
publication controls are active.

**Exit criteria:** missing tool or evidence fails; one manifest binds the
complete graph; staging and production use identical digests; mutable tags are
not deployment inputs; production rebuild is impossible by policy.

**Mandatory evidence:** synthetic release manifest, complete SBOM/scan/signature/
provenance results, promotion record, digest readback, and rollback proof.

**Dependencies / owners:** GUG-87, GUG-110, GUG-112, GUG-120.

**Automatic NO-GO:** `SKIPPED` required gate, incomplete graph, critical finding
without eligible treatment, invalid issuer/signature, altered manifest, mutable
reference, or rebuild.

### Phase 7 — GUG-125: Non-Production Live Engine with Saved Plans

**Entry criteria adopted by Phase 0:** Phases 3-6 complete; an explicitly
authorized non-production deployment tuple is available; exact-plan store,
approval, and retention are proven; production inputs remain impossible.

**Exit criteria:** every apply uses a verified saved plan; failed health blocks
downstream stages; uncertain outcomes are reconciled before resume; rerun reaches
no-change; dry-run produces zero cloud mutation.

**Mandatory evidence:** sanitized execution ledger, identity proof, plan/approval
binding, health results, injected-failure results, resume and no-change evidence.

**Dependencies / owners:** GUG-84, GUG-109, GUG-121, GUG-122, GUG-123, GUG-124.

**Automatic NO-GO:** plan substitution/staleness, uncertain state, downstream
continuation after failure, dry-run mutation, or production target.

### Phase 8 — GUG-126: Observability, Resilience, and Operations

**Entry criteria adopted by Phase 0:** Phase 7 non-production execution is
stable; runtime owners and failure domains are known; synthetic test data is
approved.

**Exit criteria:** every critical failure domain has an actionable alert and
owner; delivery is acknowledged; tracing/logs contain no sensitive payload;
backup, restore, application rollback, and infrastructure rollback remain
distinct and exercised.

**Mandatory evidence:** dashboards, alert receipts, runbooks, game-day record,
measured recovery objectives, leakage tests, and cost/backpressure evidence.

**Dependencies / owners:** GUG-39, GUG-15, GUG-85.

**Automatic NO-GO:** missing alert delivery, ownerless alarm, sensitive logging,
unmeasured recovery, or conflated rollback/restore.

### Phase 9 — GUG-127: Staging Certification

**Entry criteria adopted by Phase 0:** Phases 1-8 complete with reviewed
evidence; exact immutable release candidate and last-known-good release exist;
GUG-119 independent reviewer is operational.

**Exit criteria:** no open Critical/High readiness blocker; two non-production
environments remain isolated and unchanged after rerun; all positive/negative
tests pass; rollback and restore are measured separately; on-call owner, change
window, and last-known-good release are confirmed.

**Mandatory evidence:** signed evidence index, test reports, game-day record,
residual risks, and reviewed staging decision.

**Dependencies / owners:** GUG-16, GUG-17, GUG-39, GUG-15, all earlier phase
gates, and their transitive auth/economic blockers.

**Automatic NO-GO:** any certification failure, stale evidence, unresolved
Critical/High risk, or absence of the independent reviewer.

### Phase 10 — GUG-128: Production Pilot

**Entry criteria:** GUG-127 and GUG-119 complete; all prior gates have reviewed
evidence; a human manually reviews and explicitly authorizes the limited pilot;
the production workflow remains disabled until that authorization is verified.

**Exit criteria:** explicit GO with independent approval; exact certified staging
release and verified saved plan; backups, alerts, and on-call are confirmed;
canary and soak finish without a Critical/High incident.

**Mandatory evidence:** approval tuple, immutable digests, deployment record,
health/soak results, and rollback evidence.

**Dependencies / owners:** GUG-127, GUG-119, every prior gate; IPA is final
authorization authority.

**Automatic NO-GO:** current default; stale evidence/approval, wrong target,
rebuild, policy mismatch, missing independent approver, failed canary/soak, or
any open Critical/High blocker.

### Phase 11 — GUG-129: Multi-Client Onboarding Factory

**Entry criteria:** reviewed Phase 10 GO and pilot result; lifecycle and support
owners are available; automation still uses the canonical source and contracts.

**Exit criteria:** a second customer is onboarded without source change or fork;
failures remain isolated and workflows are idempotent; lifecycle/support
ownership is explicit; cross-client access and naming collision fail closed.

**Mandatory evidence:** redacted onboarding timing and diffs, isolation and
negative-access results, lifecycle/support handoff, and drift-detection records.

**Dependencies / owners:** GUG-38, GUG-84, GUG-109, and GUG-128.

**Automatic NO-GO:** one-customer-only evidence, source fork, shared authority,
collision, unowned lifecycle, or failure propagation across customers.

## Cross-cutting risk gates

| Issue | Required exit | Evidence | Blocks |
|---|---|---|---|
| GUG-119 — Single Maintainer Approval | Independent audited production approval and incident backup; notification is not authorization | Reviewer/access record, protected-Environment configuration, negative tests, and support runbook | Phase 5 assurance and hard-blocks Phase 10 |
| GUG-120 — Evidence Hygiene | Publication controls fail closed; NotebookLM uses reviewed derived sources only; real evidence is external and encrypted | Classification, sanitized scan results, retention policy, source manifest, and exercise result | Every phase; specifically Phase 6 and any evidence publication |

## Automatic program NO-GO conditions

Production and the dependent phase remain NO-GO if any of these conditions is
true:

- missing or ambiguous customer/deployment/account/region/environment/release
  binding;
- open cross-customer, authentication, authorization, data-loss, or state
  integrity P0;
- missing owner, dual authoritative producer, or conflicting source of truth;
- required check, security scanner, test, or approval is skipped or weakened;
- static credential, broad OIDC trust, or role/operation separation failure;
- state, plan, real variables/manifests, outputs, logs, protected identifiers,
  PII, or customer data in a prohibited system;
- saved plan is stale, substituted, expired, or not bound to the approval;
- unsigned, mutable, incomplete, substituted, or rebuilt artifact graph;
- ECS or another Terraform-owned resource changes outside Terraform;
- rollback and state recovery are conflated;
- evidence is stale, unsanitized, untraceable, or overclaimed;
- independent production approver is absent; or
- an accepted risk is expired or lacks required approval.

## Exception policy

An exception is never an implicit pass. It must include owner, independent
approver, affected phase/deployments, threat/control, rationale, compensating
controls, evidence, containment/rollback, linked work package, issue reference,
and expiry. It expires before the next dependent gate and no later than 30 days
without a new independent review.

No exception may allow cross-customer or ambiguous binding, static credentials,
CI/approval bypass, sensitive material in prohibited systems, production
rebuild, mutable artifact identity, routine state restore, an unreviewed
Critical/High risk, or weakening a mandatory security gate.

An expired or scope-mismatched exception is an automatic NO-GO. Production risk
acceptance requires TPO, PS, COPS/product owner, and IPA approval; the author or
executor cannot act as IPA.
