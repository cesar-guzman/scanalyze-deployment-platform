# Phase 0 Architecture Foundation

> **Decision source:** [ADR-019](../../ADR/ADR-019-production-readiness-foundation.md)  
> **Stage graph:** [`deployment/layers.yaml`](../../deployment/layers.yaml)  
> **Evidence boundary:** repository and local validation only  
> **Production:** **NO-GO**

## Current state versus target state

| Capability | Current state | Target state | Phase owner |
|---|---|---|---|
| Source and customer model | One monorepo, no customer forks; account-per-deployment accepted | Same reviewed source and release train for every customer | Phase 0 / 11 |
| PR governance | Static, client-independent required-check contract exists and is locally validated | Remote rules and independent review continuously reconciled | Phase 5 |
| Terraform orchestration | Canonical DAG and reusable workflow execute dry-run only; live branch rejects execution | GitHub Actions sequences exact saved-plan apply and contract validation | Phase 7 |
| Deployment identity | Schemas and dry-run binding checks exist | Registry, account-ready, caller, backend, Environment, and contract bindings revalidated before every privileged stage | Phases 1, 3, 4, 5 |
| OIDC and IAM | Some workflow/policy artifacts exist; complete terminal-role chain is not live proven | Exact OIDC subject and separate Plan, Apply, Promotion, Validation, Diagnostic, and StateRecovery authority | Phase 5 |
| Terraform backend | Draft policy and local fixtures exist; live backend and recovery are not proven | Isolated backend, native locking, exact ownership, encrypted plan execution, and exercised recovery | Phase 4 |
| Layer contracts | Schemas, fixtures, and local envelope validation exist; live SSM transport is disabled | One authenticated, versioned producer envelope per layer with fail-closed consumers | Phase 3 |
| Artifacts | Digest controls and local workflows exist; the complete central build-and-promote graph is incomplete | Build once, sign and attest complete graph, copy and verify by digest, never rebuild in production | Phase 6 |
| Runtime | Terraform roots and application source exist; no production-readiness live evidence is claimed | Isolated, idempotent, recoverable runtime with tested queues, DLQs, health, and rollback | Phases 2, 7, 8, 9 |
| Region and DR | Region portability is designed; multi-region write authority remains undecided | First pilot single-region; multi-region remains blocked until a later accepted design and live exercise | Phase 0, later DR work |
| Production | Workflow disabled; no authorized pilot | Limited pilot only after GUG-127, GUG-119, all earlier gates, and explicit independent GO | Phase 10 |

`Implemented`, `Locally validated`, `CI validated`, `Live validated`, `Target`,
and `Blocked` are used according to the evidence policy. A Terraform declaration
or dry-run does not prove a deployed resource.

## Trust boundaries and responsibilities

```text
developer or contributor
  -> reviewed repository and static required checks
  -> deployment-scoped GitHub Environment
  -> OIDC orchestrator identity
  -> customer-scoped terminal role
  -> Terraform state / contract / artifact boundary
  -> customer runtime
  -> sanitized validation evidence
  -> independent phase or production decision
```

| Boundary | Trust gained only when | Accountable owner |
|---|---|---|
| Contributor to reviewed source | required checks, review, source SHA, and policy identity agree | Repository governance owner |
| Repository to deployment Environment | the Environment pre-exists, is protected, and matches the deployment registry | Platform Security |
| GitHub to AWS identity | issuer, audience, subject, branch/Environment, account, and operation are exact | Platform Security |
| Orchestrator to terminal role | deployment, release, change, layer, and operation are bound to a short-lived session | Platform Engineering |
| Request to resolved deployment | registry and account-ready sources agree; real bindings stay outside Git | Deployment registry owner |
| Plan to Apply | digest, approval, expiry, state lineage/version, inputs, contracts, and policy result agree | Platform Engineering + independent approver |
| Producer to consumer contract | one writer, schema, digest, owner, deployment, region, release, and freshness agree | Producer root owner |
| Build to customer ECR | complete signed graph is copied and read back without rebuild | Release Engineering + Security |
| Customer runtime to evidence | only approved metadata and sanitized results leave the account boundary | Validation owner + Security |
| Incident operator to state recovery | confirmed corruption, incident ID, dual approval, alarm, and audit exist | SRE + Platform Security |
| Customer deployment A to B | no shared role, state, contract namespace, approval, manifest, or artifact destination exists | Platform Security |

## GitOps authority separation

| Stage | May | Must not | Required handoff |
|---|---|---|---|
| Plan | Read approved registry, backend, state, contracts, and release inputs; create a saved plan and sanitized summary | Apply, publish artifacts, change contracts, or expose raw plan content | Plan digest, policy result, state/contract versions, expiry, and approval request |
| Apply | Verify and apply the exact approved saved plan once; write its producer contract and sanitized outcome | Re-plan, substitute inputs, publish artifacts, or operate outside the selected layer | Apply result, state version, contract version/digest, health prerequisite |
| Promotion | Copy and verify the complete approved OCI/release graph | Build, mutate Terraform resources, accept mutable tags, or substitute a digest | Signed release manifest and destination digest readback |
| Validation | Read contracts and runtime health; run synthetic checks; publish sanitized evidence | Mutate runtime, state, contracts, or artifacts | Bound validation result and evidence index |
| Diagnostic | Read incident-relevant resources and evidence | Deploy, apply, promote, or write state | Incident record and findings |
| StateRecovery | Repair state only after confirmed corruption | Act as application/infrastructure rollback or normal deployment | Restored version proof, new reviewed plan, and post-incident review |

Each privileged job must independently target the verified deployment
Environment. Approval of one job does not transfer OIDC authority to another.

## Exact saved-plan lifecycle

```text
resolve exact bindings
  -> lock and read approved state
  -> resolve fresh upstream contracts and immutable release
  -> create saved plan
  -> evaluate policy and expected bounds
  -> store plan in encrypted short-lived plan-execution prefix
  -> record plan digest and sanitized metadata
  -> independent approval bound to the plan digest
  -> revalidate identity, state, contracts, policy, expiry, and digest
  -> apply that exact plan once
  -> read back state, contract, health, and evidence
```

Any mismatch invalidates the plan. Apply never re-plans. The raw saved plan and
its JSON stay out of GitHub artifacts, Git, Linear, NotebookLM, and durable
general-purpose evidence. Durable evidence stores only sanitized metadata and
digests.

## Immutable release and multi-client architecture

The release identity is a signed manifest digest that binds every service image,
the base image, SBOM, vulnerability result, signature, provenance, source
revision, and policy decision. A missing or skipped component blocks promotion.

The same complete graph is promoted from non-production certification to
production. Customer-local ECR is a destination, not a build environment.
Terraform consumes the verified digest from the release manifest. No customer
fork, customer branch, mutable tag, or production rebuild is permitted.

Customer differences are external, validated data. The binding tuple must be
complete before any authority request. A shared customer identity may map to
multiple isolated deployments, but a deployment maps to one account,
environment, and approved region at a time.

## Canonical stage sequence

```text
account-ready-gate
  -> global
  -> network
  -> platform
  -> data-foundation
  -> cicd
  -> artifact-publication
  -> services
  -> edge-identity
  -> edge
  -> addons
  -> synthetic-validation
```

Control stages do not own Terraform state. Terraform stages have one state key
and one output-contract producer. The detailed sources and producers are in the
ownership matrix.

## Program sequence: Phases 0-11

```text
Phase 0 Foundation
  -> Phase 1 Identity and multi-client isolation
  -> Phase 2 Runtime topology, FIFO, idempotency, and DLQ
  -> Phase 3 Strict contracts and canonical DAG
  -> Phase 4 Registry, account baseline, backend, and locking
  -> Phase 5 Environments, OIDC, terminal IAM, and independent approval
  -> Phase 6 Build once and supply-chain fail-closed
  -> Phase 7 Non-production live engine with exact saved plans
  -> Phase 8 Observability, resilience, and operations
  -> Phase 9 Staging certification
  -> Phase 10 Production pilot (manually blocked)
  -> Phase 11 Multi-client onboarding factory
```

GUG-119 (single-maintainer approval) and GUG-120 (evidence hygiene) are
cross-cutting risks. A gate unlocks only the next eligible work package. Later
phases may prepare non-mutating design work, but no gate may claim evidence from
an unmet dependency.

## Automatic stop conditions

Stop before mutation when any identity binding, contract owner, state key,
release digest, plan digest, policy result, approval, or evidence source is
missing or ambiguous. Stop promotion on missing tooling/evidence, a mutable
reference, invalid signature, or digest mismatch. Stop production if independent
approval is absent, a rebuild is attempted, GUG-128 is not manually unblocked,
or any Critical/High readiness risk remains untreated.

