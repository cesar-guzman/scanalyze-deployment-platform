# Phase 0 Ownership, RACI, and Segregation of Duties

> **Program:** GUG-115 / GUG-116\
> **Decision source:** [ADR-019](../../ADR/ADR-019-production-readiness-foundation.md)\
> **Production:** **NO-GO**

## Roles

| Code | Role | Accountable scope |
|---|---|---|
| TPO | Technical Program Owner | Phase sequence, acceptance criteria, risk register, and GO/NO-GO integrity |
| PE | Platform Engineering | Terraform roots, GitOps orchestrator, deployment registry integration, contracts, and state design |
| PS | Platform Security / DevSecOps | OIDC/IAM, repository governance, supply-chain policy, evidence controls, and security approval |
| RE | Release Engineering | Reproducible build, signed release graph, promotion, and release completeness |
| SRE | Operations / SRE | Runtime health, alerts, incident response, rollback, recovery, and on-call readiness |
| APP | Application and Application Security | Identity enforcement, tenant isolation, runtime behavior, data handling, and service tests |
| COPS | Customer Operations / service owner | Change window, customer acceptance, operational handoff, and service-level decisions |
| IPA | Independent Production Approver | Independent review of production plan, evidence, risk, and authorization; never author or executor |

RACI uses `A` for one accountable owner, `R` for execution, `C` for required
consultation, and `I` for informed. An activity may have multiple responsible
roles but exactly one accountable role.

## Organizational RACI

| Activity | TPO | PE | PS | RE | SRE | APP | COPS | IPA |
|---|---|---|---|---|---|---|---|---|
| Accept architecture and phase-gate contract | A | R | C | I | C | C | I | I |
| Maintain source, ADRs, and canonical DAG | C | A/R | C | C | I | C | I | I |
| Maintain required-check and GitHub governance policy | I | R | A | I | I | C | I | I |
| Own deployment registry schema and integration | C | A/R | C | I | C | I | I | I |
| Define OIDC trust and terminal IAM | I | R | A | I | C | I | I | I |
| Maintain portable identity control-plane Terraform, contracts, and provider boundary | C | R | A | I | C | C | I | I |
| Execute first-administrator bootstrap through the approved lifecycle workflow | I | C | C | I | C | A/R | C | I |
| Provision or rotate one deployment-bound M2M client through runtime escrow | I | C | C | I | R | A/R | I | I |
| Approve identity state adoption, blue/green migration, or decommission | C | R | A | I | C | C | C | C when production |
| Create a saved Terraform plan | I | A/R | C | I | C | C | I | I |
| Approve a non-production saved plan | A | I | C | I | C | C | I | I |
| Approve a production saved plan | C | I | C | I | C | C | C | A |
| Apply an approved Terraform plan | I | R | C | I | A for execution control | I | I | I |
| Build and sign a release | I | C | C | A/R | I | C | I | I |
| Define and enforce artifact-promotion policy | I | C | A | R | I | I | I | I |
| Execute non-production artifact promotion | I | C | C | A/R | I | I | I | I |
| Approve production artifact promotion | C | C | C | R | C | I | C | A |
| Validate isolation and application behavior | I | C | C | I | R | A/R | C | I |
| Validate runtime health and evidence | I | C | C | I | A/R | R | C | I |
| Decide a phase GO/NO-GO | A | C | C | C | C | C | I | C for production prerequisites |
| Authorize a production pilot | C | C | C | I | C | C | C | A |
| Execute application or infrastructure rollback | I | R | C | C | A/R | C | I | C when production |
| Authorize break-glass state recovery | I | R | A | I | R | I | I | C |
| Accept customer operational handoff | C | C | C | I | R | C | A | I |

No person may be both author/executor and IPA for the same production change.
Email, an AI response, a successful workflow, or ownership of the repository is
not independent approval.

## Authoritative root input and output ownership

The canonical stage graph is `deployment/layers.yaml`. Identity and release
fields come from the approved external deployment registry, not ad hoc operator
arguments. Infrastructure values come from the declared producer contract, not
GitHub outputs, `terraform_remote_state`, or copied console values. Static
defaults come from reviewed repository code. Secret values remain in their
approved secret store and never enter contracts.

| Stage / root | Authoritative inputs | Single output producer | State owner | Accountable owner | Current evidence |
|---|---|---|---|---|---|
| `account-ready-gate` | Registry binding tuple plus authenticated `account-ready/v1` | No contract or artifact; job success is control flow only. The account bootstrap provider exclusively produces `account-ready/v1` | No deployment state | PE | Local schema/fixture validation; authenticity is Target |
| `global` | Registry tuple, `account-ready/v1`, reviewed module configuration | `roots/global` Apply execution produces `global/v1` | `{deployment_id}/global/...` owned by global root | PE | Root and local contract output exist; live publication Blocked |
| `network` | Registry tuple and `global/v1` | `roots/network` Apply execution produces `network/v1` | Regional network key owned by network root | PE | Local root/contract evidence; live Blocked |
| `platform` | Registry tuple and `network/v1` | `roots/platform` Apply execution produces `platform/v1` | Regional platform key owned by platform root | PE | Local root/contract evidence; live Blocked |
| `data-foundation` | Registry tuple and `platform/v1` | `roots/data-foundation` Apply execution produces `data-foundation/v2` | Regional data-foundation key owned by data-foundation root | PE | Local root/contract evidence; live Blocked |
| `cicd` | Registry tuple, `data-foundation/v2`, reviewed source/repository policy | `roots/cicd` Apply execution produces `cicd/v1` | Regional cicd key owned by cicd root | PE | Local root/contract evidence; live Blocked |
| `artifact-publication` | `cicd/v1`, approved source/release input, complete build evidence | Promotion execution produces signed `release-manifest/v1` and destination digest readback | No Terraform state | RE | Dry-run structure; complete target graph Blocked |
| `identity-control-plane` | Registry tuple, `global/v1`, `release-manifest/v1`, and reviewed ADR-023 policy version/digest | `roots/identity-control-plane` Apply execution produces credential-free `identity-control-plane/v1` | Regional identity-control-plane key owned only by its root | PE | Candidate root/runtime/contract and offline tests; PS/APP consulted; CI pending and live Blocked |
| `services` | Registry tuple, `platform/v1`, `data-foundation/v2`, `cicd/v1`, `release-manifest/v1`, and `identity-control-plane/v1` | `roots/services` Apply execution produces `services/v1` | Regional services key owned by services root | PE | Local ownership/contract evidence; live Blocked |
| `edge-identity` | Registry tuple, `services/v1`, and `identity-control-plane/v1`; route policy from accepted contract | `roots/edge-identity` Apply execution produces `edge-identity/v2` and does not own provider resources | Regional edge-identity key owned by edge-identity root | PE | Candidate root/contract evidence; APP is consulted; CI pending and live Blocked |
| `edge` | Registry tuple and `edge-identity/v2` | `roots/edge` Apply execution produces `edge/v1` | Global edge key owned by edge root | PE | Local root/contract evidence; live Blocked |
| `addons` | Registry tuple and `edge/v1` | `roots/addons` Apply execution produces `addons/v1` | Regional addons key owned by addons root | PE | Local root/contract evidence; live Blocked |
| `synthetic-validation` | `release-manifest/v1`, `identity-control-plane/v1`, `services/v1`, `edge-identity/v2`, `edge/v1`, and `addons/v1` | Validation execution produces a sanitized validation report and handoff summary | No Terraform state | SRE | Dry-run structure; identity/two-deployment live validation Blocked |

The current Terraform variable interfaces accept direct values that the future
resolver must derive from the sources above. Phase 3 cannot exit until a tested
producer/consumer matrix proves the mapping for every variable and no live-path
mock or operator-supplied infrastructure value remains.

## Resource, contract, and authority owners

| Object | Authoritative owner / producer | Authorized writer | Authorized readers | Forbidden alternate owner |
|---|---|---|---|---|
| Reviewed source and ADRs | Repository on reviewed main revision | Reviewed contributor workflow | All delivery roles | Customer fork or copied source tree |
| Canonical stage graph | PE through `deployment/layers.yaml` | Reviewed repository change | Workflows, tooling, reviewers | Workflow-local divergent DAG |
| Deployment request | Request author through reviewed Git-safe schema | Reviewed repository change | Registry resolver and reviewers | Resolved manifest or real bindings in Git |
| Resolved deployment record | Deployment registry owner | Registry control plane | Approved orchestrator jobs | Operator file, GitHub output, or NotebookLM |
| Account-ready contract | Account bootstrap / vending provider | Bootstrap identity only | Validation and Plan identities | Deployment Apply role |
| GitHub Environment/OIDC anchor | Independent read-only GitHub governance collector | Governance evidence identity only | GUG-123 authorizer and reviewers during its bounded lifetime | Release workflow, workflow input, repository variable, or self-generated snapshot |
| Layer contract | The declared Terraform producer root | That layer's Apply session only | Declared downstream consumers and Validation | Script, another layer, or manual SSM write |
| Identity provider resources | Identity control-plane Terraform root | Identity Apply only; bounded runtime adapters may perform only reviewed lifecycle effects | Identity runtime, declared contract consumers, Validation, and Diagnostic as policy permits | Edge root, services root, console/manual creation, or customer-specific fork |
| Enterprise membership | Authoritative deployment-local membership store | GUG-94 lifecycle processor using conditional writes | Pre-token/PDP and approved audit/diagnostic paths | Cognito group, token claim, request payload, Terraform state, or email domain |
| M2M credential value | Approved runtime credential store | Runtime provider-to-store adapter only at creation/rotation | Bound workload through approved retrieval; no general evidence reader | Terraform plan/state/output, layer contract, GitHub output, log, audit, Linear, or NotebookLM |
| Bootstrap request and approval state | GUG-94 approved lifecycle workflow | Conditional bootstrap processor for claim/consume only | Bootstrap runtime and approved audit/diagnostic paths | Queue body, self-signup, target self-approval, or manual provider action |
| Release manifest | RE promotion stage | Promotion identity after all gates | Terraform services, Validation, reviewers | Individual matrix leg or mutable metadata write |
| Terraform state key | Exactly one Terraform root | Apply; Plan only for lock operations; StateRecovery under incident | Plan, Apply, Diagnostic as policy allows | Another root, pipeline script, or manual import |
| Saved plan | Plan execution | Plan identity in short-lived plan-execution prefix | Matching Apply execution and approved reviewer surface | GitHub artifact, repository, state bucket, or operator laptop |
| ECS task definition and service | Services Terraform root | Services Apply identity | Validation and Diagnostic | Build pipeline or imperative ECS command |
| Frontend runtime config | Edge Terraform root per ADR-014 | Edge Apply identity | Runtime and Validation | Manual edit or application build |
| Sanitized evidence index | Validation stage | Validation evidence publisher | Reviewers and gate owner | Raw log/state/plan upload |
| Risk acceptance | TPO for phase risk; IPA plus required owners for production | Authorized change system | Reviewers and auditors | AI-generated answer or untracked chat decision |

## Evidence ownership and custody

| Evidence class | Producer | Custodian | Durable location rule | Integrity rule |
|---|---|---|---|---|
| Local validation result | Named local command | PE | Repository diff or review note may contain sanitized summary only | Command, revision, tool version, timestamp, and result |
| CI validation result | Named workflow run | Repository governance owner | CI system | Commit, workflow identity, run identity, and immutable log retention policy |
| Saved-plan approval metadata | Plan/approval workflow | PE + PS | Approved external evidence store | Plan digest, state/contract versions, expiry, change, and approver |
| Apply result | Apply workflow | SRE | Approved external evidence store | Deployment tuple, plan digest, execution identity, state version, and result |
| Artifact provenance | Build/sign/promotion workflow | RE + PS | Approved artifact/evidence stores | Source, artifact, signature, policy, and destination digests |
| Live validation | Validation workflow | SRE | Approved external evidence store | Exact environment/release binding and sanitized result |
| Break-glass recovery | Incident process | SRE + PS | Incident/evidence system | Incident, dual approval, state versions, actions, and post-checks |
| Phase decision | TPO | Linear and reviewed repository docs | Sanitized summary and links only | Criteria/evidence references, risks, decision, owner, and date |

Git, Linear, and NotebookLM are not stores for raw operational evidence. Their
records contain only sanitized summaries, stable references, classifications,
and digests that disclose no protected values.

## Single-maintainer risk treatment

The current CODEOWNERS model concentrates review ownership in one identity.
Until GUG-119 has reviewable evidence, the current residual risk is **High** and
production is a hard NO-GO.

Required treatment:

1. appoint at least one independent human reviewer with minimum access and MFA;
2. require that reviewer in the protected production Environment;
3. prevent author self-review and administrative bypass;
4. provide an on-call backup and incident escalation path;
5. test that author-only, stale, missing, or wrong-Environment approval fails;
6. audit the approval tuple; and
7. document removal and break-glass procedures without granting routine deploy
   authority.

One maintainer may continue non-production design and implementation through
normal review, but cannot create valid evidence of independent production
approval alone.

## Decision authority by gate

- Phases 0-8: TPO is accountable; PE/PS/SRE/APP review according to scope.
- Phase 9 staging certification: TPO accountable with mandatory PE, PS, SRE, and
  APP review.
- Phase 10 production pilot: IPA is the final authorization authority after the
  TPO and owners present complete evidence; no self-approval.
- Phase 11 onboarding factory: TPO accountable for program acceptance; COPS is
  accountable for customer operational handoff.

Any owner vacancy, dual accountable owner, or ambiguous producer is an automatic
NO-GO for the dependent gate.
