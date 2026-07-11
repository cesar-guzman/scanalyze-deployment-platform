# Production Readiness Work Packages and Linear Map

> **Linear source of truth:** Scanalyze — Product & Platform Delivery  
> **Program parent:** GUG-115  
> **Phase 0 gate:** GUG-116  
> **Production pilot:** GUG-128 — **Blocked / NO-GO**

## Mapping rules

1. Linear is the durable operating record; Git/CI is implementation evidence.
2. One implementation issue maps to one branch/worktree and one PR.
3. Phase gates do not duplicate implementation issues or reparent existing
   epics.
4. A gap is documented here before a new issue is proposed. A duplicate search
   against title, scope, parent, and relations is mandatory.
5. GUG-119 and GUG-120 are cross-cutting risks, not numbered phases.
6. Narrative dependencies remain binding even where Linear `blockedBy` is not
   configured.
7. No Phase 1 work begins in this Phase 0 change.

## Canonical sequence

```text
GUG-116
  -> GUG-117
  -> GUG-118
  -> GUG-121
  -> GUG-122
  -> GUG-123
  -> GUG-124
  -> GUG-125
  -> GUG-126
  -> GUG-127
  -> GUG-128 (manual hard block)
  -> GUG-129
```

GUG-119 must be resolved before production approval and is a hard dependency of
GUG-128. GUG-120 applies from Phase 0 to every evidence-producing phase.

## Work-package map

| Phase / gate | Existing implementation owners to reuse | Future deliverable boundary | Real gap or reconciliation |
|---|---|---|---|
| 0 / GUG-116 | GUG-6, GUG-88, GUG-90, GUG-111 | ADR-019, architecture, threat model, RACI, evidence policy, gates, backlog map, recovery, NotebookLM | This document set closes the repository traceability gap; the old repository `M0` is not this gate |
| 1 / GUG-117 | GUG-82, GUG-92, GUG-93, GUG-102, GUG-114, GUG-89; relate GUG-13/GUG-14 where scope matches | Canonical identity contract, user/M2M enforcement, anti-spoofing, two-deployment positive/negative isolation suite | No atomic owner for the integrated two-deployment isolation proof; add only after checking GUG-13/GUG-14 scope. GUG-91 is already a duplicate of GUG-92 and must not be revived |
| 2 / GUG-118 | GUG-85, GUG-89, GUG-108, GUG-15 | Canonical consumer topology, FIFO migration, idempotency ledger, outbox/leases/heartbeat, quarantine, controlled redrive | Routing/task-definition/DLQ work exists; ledger/outbox/leases/visibility/quarantine lack a precise atomic package. Decompose under GUG-85 or expand GUG-89 only after owner review |
| 3 / GUG-121 | GUG-84, GUG-109 | Contract catalog, schemas, root producer/consumer mapping, live resolver, SSM writer isolation, no mocks | GUG-109 is broad; a strict-contract/SSM/canonical-DAG implementation package is not explicit |
| 4 / GUG-122 | GUG-84, GUG-109, GUG-16 | Deployment registry, account baseline, backend isolation, native locking, encrypted plan-execution prefix, recovery exercise | Registry/backend/bootstrap/locking/recovery are too broad in current epics; require an atomic implementation package after duplicate review |
| 5 / GUG-123 | GUG-84, GUG-87, GUG-109, GUG-119 | Protected deployment Environments, exact OIDC trust, terminal roles, access analysis, independent approver | No precise Environments/OIDC/terminal-role implementation issue and no implementation record for the second approver; GUG-119 is risk ownership, not the full technical package |
| 6 / GUG-124 | GUG-87, GUG-110, GUG-112, GUG-120 | Pinned build, complete SBOM/scan/sign/provenance graph, signed release manifest, copy-and-verify promotion, waiver expiry | Main scope is covered. Clarify within existing issues the single producer of the signed manifest and the waiver owner before creating anything new |
| 7 / GUG-125 | GUG-84, GUG-109, plus GUG-121-124 | Non-production live engine, exact saved-plan store/apply, execution ledger, health gates, uncertain-outcome reconciliation, resume/no-change rerun | No atomic package covers exact plan substitution/expiry, resumable ledger, and uncertain-outcome reconciliation end to end |
| 8 / GUG-126 | GUG-39, GUG-15, GUG-85; relate GUG-17/GUG-40/GUG-41 where applicable | Alerts, dashboards, backpressure/cost, backup/restore, leakage tests, game day, measured objectives | Topic coverage exists. Reconcile load/soak/cost ownership and transitive blockers rather than creating a duplicate observability epic |
| 9 / GUG-127 | GUG-16, GUG-17, GUG-39, GUG-15 and all prior gates | Two-environment staging certification, adversarial/E2E/rerun, rollback versus restore, signed evidence index, reviewed decision | No new readiness issue needed. Explicitly include GUG-14 authentication and GUG-41 economic blockers through GUG-17's dependencies |
| 10 / GUG-128 | GUG-128 gate; GUG-119 approval risk; GUG-127 certification | Limited production canary/soak using exact certified release and plan | Intentionally no execution package until manual GO. Formal `blockedBy` relations are absent, but semantic hard blocks remain |
| 11 / GUG-129 | GUG-38, GUG-84, GUG-109; transitive GUG-43 and its dependencies | Repeatable onboarding, upgrade, rollback, offboarding, support, budgets, drift, collision and isolation testing | No duplicate evident. Two-deployment isolation must be proven before the pilot; Phase 11 industrializes it for a second customer |

## Atomic packages that need later backlog decisions

The following are genuine decomposition gaps. Phase 0 records them but does not
create issues or start implementation:

1. integrated two-deployment identity/isolation proof;
2. idempotency ledger, outbox, leases, visibility heartbeat, and quarantine;
3. strict contracts, live SSM transport, and canonical DAG integration;
4. registry, account baseline, backend, locking, and recovery;
5. deployment Environments, exact OIDC, terminal IAM, and independent approver
   implementation;
6. exact saved-plan live engine, execution ledger, and uncertain-outcome resume.

Before creating any issue, the TPO must search the project and relevant epics,
compare acceptance criteria, choose the authoritative parent, and record why the
new issue is not covered by an existing one.

## Implementation order and PR boundaries

Each phase should use small PRs in this order:

1. decision/schema and negative fixtures;
2. local implementation behind a disabled/live-ineligible boundary;
3. local tests and security checks;
4. CI validation without privileged authority;
5. reviewed non-production authorization and live proof only when the phase
   explicitly permits it;
6. operational runbook and rollback/recovery evidence; and
7. phase-gate evidence review.

Cross-phase preparation may produce non-mutating design documents, but a PR must
not introduce a privileged path whose prerequisite phase is incomplete. A
work-package PR references its gate, dependencies, evidence state, risk, and
rollback path.

## Duplicate and dependency findings

- GUG-91 is a confirmed duplicate of GUG-92; do not create another role-model
  ADR issue.
- No duplicate phase gate was identified.
- Most phase dependencies are prose or `relatedTo`, not formal `blockedBy`.
  This is a governance gap, not permission to ignore the dependency.
- The current GUG-116 wording "GO for Phases 1-6" is interpreted by ADR-019 as
  eligibility for the next work package whose entry criteria pass, never a
  blanket or parallel authorization.
- The final GUG-116 sentence saying the gate "does not start Phase 0" conflicts
  with its title, objective, and scope. ADR-019 interprets it as "does not start
  Phase 1 implementation or live execution"; the closeout must record this
  reconciliation or leave the gate `Blocked`.
- Phase numbering is not consecutive by issue ID after GUG-118 because GUG-119
  and GUG-120 are risks. Documentation must use the explicit phase title.

## GUG-128 hard block

GUG-128 remains in Backlog and begins with `BLOCKED — PRODUCTION NO-GO`. It
requires GUG-127, GUG-119, all prior gates, a current evidence index, an exact
certified release and saved plan, and manual independent approval.

A stale approval, wrong target, rebuild, policy mismatch, missing reviewer,
open Critical/High blocker, or failed canary/soak keeps GUG-128 blocked. No
automated status transition may remove this hard block.
