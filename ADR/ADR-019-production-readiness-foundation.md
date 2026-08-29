# ADR-019: Production Readiness Foundation and Phase-Gate Contract

- **Status**: Accepted for implementation governance; not live authorization
- **Date**: 2026-07-11
- **Deciders**: Technical Program Owner, Platform Engineering, Platform Security
- **Program**: GUG-115
- **Phase gate**: GUG-116
- **Scope**: Decisions required to start gated implementation after Phase 0
- **Production decision**: **NO-GO**
- **Refines**: ADR-003, ADR-008, ADR-012, ADR-016, ADR-017, ADR-018

## Context

The repository has an implemented and locally validated dry-run graph plus a
repository candidate for one protected DEV saved-plan path: sealed private
materialization, exact Plan/Apply bindings, terminal IAM boundaries, live SSM
contract I/O adapters, a remote-backend contract, and a public DEV Apply path
wired to real post-apply observation, reconciliation, and publication adapters.
No connected run, deployment evidence, or production evidence has been
produced. The candidate therefore remains fail-closed and cannot be promoted by
inference from repository wiring.

Phase 0 must make the implementation boundary unambiguous without upgrading
local or documentary evidence into AWS evidence. It must also reconcile several
conflicts in the existing documents:

- the old repository milestone named `M0` is not GUG-116 Phase 0;
- draft documents disagree about where ephemeral saved plans belong;
- multi-region write authority is still undecided;
- required supply-chain tooling and evidence fail closed under ADR-032
  closed;
- the current CODEOWNERS model is concentrated in one maintainer;
- the GUG-116 wording could be read as a blanket authorization for Phases 1-6;
  and
- the final GUG-116 sentence says that the gate does not start Phase 0, which
  conflicts with the issue title, objective, scope, and its role as the Phase 0
  gate.

## Decision

### 1. Evidence states are normative

Every readiness claim uses exactly one of these states:

| State | Meaning |
|---|---|
| `Implemented` | Code, configuration, or documentation exists in the identified revision. |
| `Locally validated` | Named local checks passed for the identified revision. No remote or AWS claim is implied. |
| `CI validated` | Named CI checks passed for the identified commit and workflow run. No AWS claim is implied unless the evidence explicitly proves one. |
| `Live validated` | Sanitized, reviewable evidence proves execution against an explicit non-production deployment binding. |
| `Target` | Desired design or control; implementation or validation is incomplete. |
| `Blocked` | A stop condition prevents the dependent action or evidence promotion. |

`Accepted`, `Draft`, and `Proposed` describe decision maturity, not
implementation maturity. A dry-run is never evidence of deployment. Unknown or
ambiguous evidence is treated as absent.

### 2. Deployment identity is an exact tuple

The following vocabulary is authoritative:

- `customer_id`: stable business identity for the customer; it may own more
  than one deployment.
- `deployment_id`: stable operational identity for one isolated deployment. It
  is not interchangeable with `customer_id`.
- `target_account_id`: the account bound to the deployment by the approved
  registry and account-ready contract.
- `region`: the approved execution region for the deployment.
- `logical_environment`: the lifecycle stage such as sandbox, development,
  staging, or production.
- `github_environment`: the protected deployment-scoped authorization boundary;
  it is not the logical environment.
- `release_digest`: the immutable identity of the complete promoted release.
- `change_id`: the reviewed change or execution authorization.

Before any privileged operation, the orchestrator must resolve and compare the
customer, deployment, target account, region, logical environment, GitHub
Environment, release, layer, operation, and change. A missing, conflicting, or
unproven binding stops before OIDC or any mutation is requested.

### 3. Current architecture and target architecture remain distinct

Current executable repository state includes dry-run orchestration and exactly
one protected live job, `live_saved_plan`, for separately dispatched DEV Plan
or Apply phases. It is the only job with a deployment Environment and
`id-token: write`; every other Terraform route remains non-OIDC. This is a
repository candidate only: no connected DEV execution or production
authorization is implied.

The target live path is:

```text
reviewed source and request
  -> deployment registry and account-ready validation
  -> protected deployment-scoped GitHub Environment
  -> OIDC orchestrator identity
  -> Plan terminal role
  -> exact saved plan and policy decision
  -> independent approval
  -> Apply terminal role and exact-plan apply
  -> producer contract and readback
  -> Promotion terminal role for immutable artifacts
  -> Validation terminal role and sanitized evidence
```

GitHub Actions is the target live control plane. Operator-laptop `apply-all` is
not authoritative. `deployment/layers.yaml` remains the machine-authoritative
stage graph.

### 4. Plan, Apply, Promotion, and Validation are separate authorities

- **Plan** may read approved inputs, contracts, and state, acquire the lock, and
  create the saved plan. It cannot mutate infrastructure.
- **Apply** may verify and apply only the exact approved saved plan. It cannot
  create or alter the plan or publish artifacts.
- **Promotion** may copy and verify the complete approved artifact graph. It
  cannot rebuild it, change infrastructure, or write Terraform state.
- **Validation** may read contracts and runtime health and emit sanitized
  evidence. It cannot mutate infrastructure.
- **Diagnostic** and **StateRecovery** are incident identities, never alternate
  deployment identities.

Plan and Apply are separate workflow dispatches/runs, not two steps whose
authority can flow through one run. Each enters the same deployment-scoped
Environment through the sole `live_saved_plan` job, revalidates the immutable
execution binding, and requests its own short-lived terminal authority. Apply
also requires an independent, append-only approval bound to the exact saved
plan and reviewer packet.

### 5. Exact saved-plan policy

The only plan eligible for apply is the reviewed saved plan identified by its
cryptographic digest. The approval record must bind at least the deployment,
account, region, environment, layer, release, source revision, state
lineage/version, contract versions, policy result, plan digest, expiry, and
approver.

The plan is invalid after any relevant state, contract, release, identity,
policy, approval, or expiry change. Apply must not re-plan. A mismatch produces
a new plan and a new approval; it is never waived in place.

The saved-plan binary belongs in the encrypted, versioned `plan-execution/`
prefix of the dedicated tf-plan bucket. Its record binds exact bucket, key,
VersionId, SHA-256, and size plus the exact state bucket/key and
VersionId/hash/size observed before and after Plan. Raw plan JSON exists only in
mode-0600 private scratch for bounded semantic inspection and is deleted after
the sanitized action manifest is derived. The binary is never deleted by the
controller; current and noncurrent versions expire only through the one-day
bucket lifecycle. Durable evidence remains a separate immutable store for
sanitized records only. Saved plans do not belong in the state or evidence
buckets, GitHub artifacts, Git, Linear, or NotebookLM.

This placement refines conflicting text in ADR-003 and adopts its four-bucket
rev4 inventory: state, tf-plan, evidence, and contracts. The repository now
contains a protected saved-plan materializer/controller path, but no connected
live plan or data migration has been proven. The core post-apply state machine
and protected workflow adapters are implemented. Health and reconciliation run
under fresh Plan authority, bracketing `terraform-layer.sh observe` with two
exact state reads; the speculative plan uses `-lock=false` and
`-detailed-exitcode`. Health admits only the minimum named checks
`input_contracts`, `terraform_convergence`, and `producer_contract_schema`, and
discards sensitive outputs. It does not claim generic ECS, ALB, API, or
application runtime health.

Contract publication runs under fresh Apply authority, uses the canonical
catalog-owned layer-contract envelope, creates the content-addressed SSM
parameter without overwrite, and requires exact double parameter/tag readback.
`UNCERTAIN` never retries apply or publishes: its `contract_verified` result is
prospective schema validation, and a later `RECONCILED_APPLIED` reentry performs
the normal health/publication path. Connected DEV has not been executed;
staging and production therefore remain NO-GO.

### 6. Build once and promote; production never rebuilds

One reviewed source revision produces a complete release graph containing all
service and base-image digests plus required SBOM, scan, signature, provenance,
and manifest evidence. Promotion copies and verifies that graph. Staging and
production consume the same digests.

Local developer tolerance for a missing supply-chain tool does not apply to a
release gate. Missing, skipped, stale, unsigned, mutable, or digest-mismatched
release evidence blocks promotion. Production rebuild is prohibited.

### 7. Multi-client strategy uses one source line and no forks

All customers use the same reviewed source, schemas, modules, workflows, and
release train. Customer differences are expressed only through validated
external deployment records, contracts, and approved configuration. Required
CI checks are client-independent; deployment authorization is isolated by
deployment-scoped Environments, accounts, state keys, contracts, roles, and
artifact destinations.

No customer-specific branch, fork, workflow copy, or source modification is an
accepted onboarding mechanism.

### 8. Initial production eligibility is single-region

The first production pilot, if later authorized by GUG-128, is restricted to
one approved region per deployment. Region portability remains a target, but
multi-region active/standby, cross-region failover, write fencing, and claimed
RTO/RPO are **Blocked** until their mechanism is selected and exercised in
non-production.

This decision narrows the first pilot without deleting the ADR-008 target. It
resolves the Phase 0 ambiguity around the still-TBD multi-region write-authority
mechanism. A future accepted ADR and gate evidence are required before
multi-region becomes eligible.

### 9. Separation of duties is mandatory for production

Production requires an independent human approver who is not the author or
executor, has MFA, cannot bypass the protected Environment, and is represented
in an auditable approval record. The current single-maintainer model is an
explicit risk owned by GUG-119. Email notification, self-review, or an AI answer
is not authorization.

Break-glass use requires an incident record, dual approval, short-lived access,
an alarm, complete auditability, and post-incident review. Break-glass cannot
assume Plan, Apply, Promotion, or Validation authority.

### 10. Phase gates are sequential capabilities, not blanket permission

The canonical order is Phase 0 through Phase 11. GUG-119 and GUG-120 are
cross-cutting risks, not numbered phases. A GO at one gate allows only the next
work package whose own entry criteria are satisfied. It does not authorize
Fases 1-6 in parallel, a live run, or production.

GUG-128 remains manually blocked. No earlier gate, successful dry-run, merge,
or non-production result can implicitly unblock it.

GUG-116 is the Phase 0 gate: completing it records the planning and governance
foundation described by its title, objective, and scope. Its conflicting final
sentence is interpreted narrowly as "this planning-only gate does not start
Phase 1 implementation or live execution," not as a separate pre-Phase-0 gate.
This reconciliation must be recorded in GUG-116. If the Linear owner rejects
that interpretation, GUG-116 reopens as `Blocked`; no implementation or live
work is authorized while the conflict is unresolved.

## Compatibility and precedence

This ADR preserves the accepted account-per-deployment model, single monorepo,
strict contracts, Terraform ownership, GitHub orchestration, static required
checks, deployment-scoped Environments, immutable artifacts, and forward
rollback decisions in ADR-001, ADR-005, and ADR-011 through ADR-018.

It does not promote ADR-002 through ADR-004 or ADR-006 through ADR-010 from
`PROPOSED` or `DRAFT` to Accepted. Those non-accepted documents remain design
inputs for later phase gates; ADR-005 retains its existing Accepted status.
Where a design input conflicts on ephemeral saved-plan placement or implies
multi-region eligibility for the first pilot, this ADR governs the
production-readiness program.

If a future implementation already diverges from these decisions, progression
stops. The owner must document compatibility, migration, rollback, and evidence
before changing the control; silent grandfathering is prohibited.

## Consequences

### Positive

- Evidence cannot be promoted by inference.
- A deployment cannot borrow another customer's bindings or approvals.
- The reviewed plan and reviewed artifacts remain exact through execution.
- The initial pilot avoids an unproven multi-region write-authority design.
- Phase work is decomposed without treating one gate as blanket authorization.

### Costs and constraints

- The live engine requires more roles, storage controls, metadata, and negative
  tests than the current dry-run.
- Single-maintainer risk must be resolved before production.
- Phase 4 must reconcile backend policy before Phase 7.
- Supply-chain tools that are optional for local development become mandatory
  for release eligibility.
- Phase 11 remains post-pilot industrialization, not evidence for the first
  production decision.

## Rollback of this decision

Phase 0 changes are documentation and local validation only. They can be
reverted as a reviewed Git change. Reverting this ADR does not restore or alter
cloud resources, Terraform state, GitHub governance, or a deployment.

Any replacement decision must preserve production NO-GO until equivalent
identity, evidence, saved-plan, artifact, approval, and recovery controls are
accepted and reviewable.

## References

- [Phase 0 documentation index](../docs/production-readiness/README.md)
- [GitOps Terraform orchestrator](../docs/deployment/gitops-orchestrator.md)
- [GitHub governance](../docs/operations/github-governance.md)
- [Rollback and recovery boundaries](../docs/operations/rollback-recovery-boundaries.md)
- [Canonical stage graph](../deployment/layers.yaml)
- Linear: GUG-115, GUG-116, GUG-119, GUG-120, GUG-128
