# Phase 0 Production Readiness Threat Model

> **Status:** Accepted Phase 0 governance supplement\
> **Scope:** repository and delivery control plane for GUG-115 / GUG-116\
> **Relationship to ADR-009:** supplements ADR-009; does not change its `DRAFT rev3` status\
> **Evidence boundary:** repository baseline only; no GitHub or AWS live evidence was collected\
> **Production:** **NO-GO**

## Overview

ADR-009 remains the broad STRIDE design input for the Scanalyze platform. This
repository-scoped supplement concentrates on the GitHub/GitOps control plane,
customer binding, Terraform execution, contract transport, artifact promotion,
runtime reconciliation, and the evidence used to authorize phase progression.

The security objectives are:

1. bind every operation to one exact customer, deployment, account, region,
   environment, release, layer, change, and operation;
2. prevent one customer's identity, approval, state, contract, or artifact
   destination from being reused for another customer;
3. keep PR and dry-run execution unprivileged;
4. separate Plan, Apply, Promotion, Validation, Diagnostic, and StateRecovery;
5. apply only the exact reviewed saved plan while it remains fresh;
6. build once and promote an immutable, complete artifact graph by digest;
7. fail closed when authorization, provenance, contract, or evidence is absent
   or ambiguous;
8. keep real manifests, state, plans, customer material, and sensitive evidence
   outside Git, general GitHub artifacts, Linear, and NotebookLM;
9. preserve recovery without treating Terraform state restore as rollback; and
10. prevent local or dry-run results from being represented as AWS evidence.

Repository evidence establishes local controls and target architecture. It does
not establish that remote branch protection, protected GitHub Environments,
OIDC trust, terminal IAM roles, a remote backend, SSM publication, ECR
promotion, ECS runtime, or recovery procedures are live validated.

## Threat Model, Trust Boundaries, and Assumptions

### Actors

| Actor | Legitimate authority | Security concern |
|---|---|---|
| Repository contributor | Propose source and documentation changes | A malicious or compromised contributor can alter workflows, policies, contracts, or tests |
| Independent reviewer | Review architecture, source, and production changes | Review can be absent, bypassed, stale, or performed by the author |
| Release manager | Select approved source and release | Can select a partial, substituted, or rebuilt artifact |
| GitHub Actions runner | Execute CI and future GitOps stages | Workflow, Action, cache, or dependency compromise can reach repository or OIDC authority |
| Governance controller | Verify required checks and deployment Environments | Overprivilege or self-modification can weaken enforcement |
| Deployment registry / account bootstrap | Provide authoritative deployment and account bindings | Tampering can redirect operations across customers |
| Orchestrator | Sequence stages and select terminal roles | A confused deputy or compromise can affect multiple deployments |
| Plan identity | Read state and create a saved plan | Must not mutate infrastructure or write producer contracts |
| Apply identity | Apply an approved plan | Must not re-plan, substitute inputs, or operate outside one layer |
| Promotion identity | Copy and verify release artifacts | Must not build or mutate infrastructure |
| Validation identity | Read health and emit sanitized evidence | Must not mutate runtime resources |
| Diagnostic / StateRecovery operator | Investigate incidents or repair state | Break-glass authority can be abused as an alternate deployment path |
| Application or customer operator | Operate the isolated deployment | Must not cross customer or platform control boundaries |
| Identity provider adapter | Authenticate deployment-local humans and issue tokens after the reviewed hook | Provider groups, metadata, and lifecycle state can be mistaken for application authority |
| Bootstrap / workload identity processor | Execute one conditionally approved identity transition | Replay, partial effects, dependency failure, or credential exposure can create standing privilege |
| Malicious insider | Misuse legitimate access | Single-maintainer concentration increases likelihood and reduces challenge |
| External attacker | Compromise credentials, dependencies, or Actions | Targets the repository-to-customer trust chain |

### Assets

- reviewed source commit, branch history, ADRs, and canonical stage graph;
- required-check policy, CODEOWNERS, workflow definitions, and approvals;
- protected GitHub Environment configuration;
- OIDC issuer, audience, subject, and role trust;
- deployment request, registry record, resolved manifest, and account-ready
  contract;
- customer, deployment, account, region, environment, release, and change
  bindings;
- Terraform backend identity, state lineage, versions, and lock;
- saved plan binary, digest, approval, expiry, and state-freshness metadata;
- SSM envelopes and large contract payloads;
- release manifest, attestation, images, base images, SBOMs, scans, signatures,
  and provenance;
- customer ECR repositories, ECS task definitions, and services;
- deployment-local user pool, public clients, membership and authorization-audit
  stores, bootstrap queue/DLQ, runtime identity artifact, and
  `identity-control-plane/v1` contract;
- one-use bootstrap approvals/idempotency state and runtime-created M2M
  credential references, but never credential values in general evidence;
- sanitized evidence, approval records, and audit events; and
- last-known-good release and recovery records.

### Trust boundaries

| Boundary | Transition | Required property |
|---|---|---|
| TB-01 | Contributor or fork -> reviewed main branch | Static required checks, review, and no privileged PR authority |
| TB-02 | Repository-global configuration -> deployment GitHub Environment | The Environment pre-exists, is protected, and belongs to one deployment |
| TB-03 | GitHub job -> OIDC -> AWS role | Exact repository, ref/Environment, audience, account, and operation |
| TB-04 | Orchestrator -> customer terminal role | Exact deployment, release, change, layer, and operation with least privilege |
| TB-05 | Git-safe request -> external registry / resolved record | All bindings are re-resolved from an authoritative source |
| TB-06 | Plan job -> saved-plan store -> Apply job | Digest, approval, expiry, state, policy, and contract freshness |
| TB-07 | Terraform producer -> contract store -> consumer | Single writer, schema, digest, owner, and freshness validation |
| TB-08 | Approved build/signing -> customer ECR | Complete immutable graph copied and verified without rebuild |
| TB-09 | Customer ECR -> services Terraform -> ECS | Running digest matches the approved release manifest |
| TB-10 | Runtime validation -> durable evidence | Only sanitized, integrity-protected evidence crosses the customer boundary |
| TB-11 | Human incident authority -> Diagnostic / StateRecovery | Incident-bound, dual-approved, time-limited, and audited |
| TB-12 | Deployment A -> deployment B | No shared approval, role, state, contract namespace, or artifact destination |
| TB-13 | Provider token event -> pre-token processor -> membership store | Exact pool/client/event and customer/deployment binding; groups and metadata are non-authoritative |
| TB-14 | Approved bootstrap/M2M command -> conditional runtime -> provider and stores | One-use/idempotent effect, exact binding, sanitized audit, no credential return or logging |
| TB-15 | Identity Terraform root -> contract -> services/edge consumers | Single writer, exact tuple/digest/versions, access-token-only, and no credential values |

### Assumptions and invariants

- Production and GUG-128 remain NO-GO and manually blocked.
- GitHub Actions is the target authoritative live orchestrator; local
  `apply-all` is not authorized.
- PR and dry-run jobs have no AWS credentials or OIDC authority.
- GitHub variable equality is not proof of Environment provenance or protection.
- Real manifests and resolved customer bindings never enter Git.
- Missing customer, deployment, account, region, environment, release, layer,
  change, or operation binding aborts before authority is requested.
- Production promotes the exact non-production-certified release and never
  rebuilds it.
- Mutable tags are metadata; digests are artifact identity.
- A saved plan is invalid after any relevant state, contract, release,
  identity, approval, policy, or expiry change.
- Protected APIs accept access tokens only; provider group names and ID tokens
  cannot establish Scanalyze authorization.
- Terraform creates no users and no generated M2M credential values. Bootstrap
  and workload provisioning remain bounded runtime operations.
- Existing identity resources are retained and denied when ownership, immutable
  schema, state, or migration evidence is partial or ambiguous.
- State restore is only for confirmed state corruption or loss.
- An accepted ADR or local pass is not live evidence.
- The current single-maintainer model is a risk, not independent approval.

## Attack Surface, Mitigations, and Attacker Stories

### TM-01: Required-check, review, or CI bypass

**Attacker story:** A compromised maintainer weakens required checks, renames a
required context, bypasses review, or merges a workflow that removes a security
gate.

- **Preventive:** versioned static required-check contract, stable aggregate
  jobs, full-SHA Action pins, CODEOWNERS, protected rules, and a controller that
  cannot silently rewrite its own enforcement.
- **Detective:** reconcile remote policy to the reviewed manifest; audit policy,
  ruleset, workflow, and administrative-bypass changes.
- **Recovery:** suspend privileged workflows and transactionally restore the
  last reviewed policy snapshot before new execution.
- **Evidence:** repository policy and local validation exist; remote enforcement
  and independent review are not evidenced here.
- **Residual risk:** **High**. **Owner:** Platform Security and repository
  governance owner.

### TM-02: Malicious workflow, Action, dependency, or cache

**Attacker story:** An attacker controlling a third-party Action, dependency,
cache, or workflow executes code in a privileged job and obtains repository or
OIDC authority.

- **Preventive:** full-SHA pins, least job permissions, no persisted Git
  credential, separate unprivileged and privileged jobs, trusted dependency
  sources, and review of workflow changes.
- **Detective:** Action-pin validation, dependency review, workflow-diff review,
  and audit of unexpected token or network use.
- **Recovery:** disable the workflow, deny the affected OIDC subject, invalidate
  produced artifacts, and rerun only from a reviewed commit.
- **Evidence:** pins and minimum permissions exist locally; complete CI
  supply-chain enforcement is incomplete.
- **Residual risk:** **Medium**. **Owner:** Platform Security.

### TM-03: OIDC confused deputy or broad subject

**Attacker story:** A job from another branch, workflow, or deployment
Environment obtains a token accepted by a role intended for a different
operation or customer.

- **Preventive:** exact issuer, audience, repository, branch/Environment, and
  operation trust; separate terminal roles; no wildcard subject; every
  privileged job targets the verified deployment Environment itself.
- **Detective:** trust-policy analysis, AssumeRole audit, SourceIdentity and
  session-tag correlation, and detection of one identity crossing deployments.
- **Recovery:** deny the subject, suspend the Environment, investigate sessions,
  and deploy a newly reviewed trust policy.
- **Evidence:** GUG-123 candidate contracts, exact policy fixtures, independent
  Environment-anchor model, and negative tests are locally implemented; the
  complete GitHub/AWS chain is not live validated.
- **Residual risk:** **High**. **Owner:** Platform Security.

### TM-04: Account, region, environment, or customer mismatch

**Attacker story:** An operator supplies a valid-looking request that resolves to
another account, region, environment, or customer.

- **Preventive:** external registry and account-ready authority; compare request,
  Environment, registry, caller identity, backend, and contracts before every
  stage; fail on ambiguity.
- **Detective:** sanitized binding digest, per-stage validation record, and
  mismatch alert.
- **Recovery:** abort before mutation, quarantine the request, and reconcile the
  registry and Environment.
- **Evidence:** request and dry-run binding tests exist; live caller/backend
  binding is blocked.
- **Residual risk:** **Critical if live is enabled without the controls; High
  while enablement remains blocked**. **Owner:** Platform Engineering with
  Security approval.

### TM-05: IAM escalation or segregation-of-duties collapse

**Attacker story:** Plan mutates resources, Apply re-plans, break-glass assumes a
deployment role, or one identity builds, signs, approves, and deploys.

- **Preventive:** terminal roles, layer session policies, permissions boundaries,
  restricted role passing, separate break-glass trust, and independent approval.
- **Detective:** policy tests, access analysis, audit correlation by change and
  layer, and approval-graph review.
- **Recovery:** disable affected trust, stop the DAG, investigate actions, and
  restore least privilege through the baseline owner.
- **Evidence:** GUG-123 candidate terminal trust/action separation, tag
  bindings, break-glass separation, and local negative tests exist; deployed
  behavior is not live validated.
- **Residual risk:** **High**. **Owner:** Platform Security.

### TM-06: Saved-plan substitution or stale-plan apply

**Attacker story:** An attacker replaces the reviewed plan or applies it after
state, contract, release, identity, policy, or approval changes.

- **Preventive:** content-addressed plan, digest-bound approval, separate Plan
  and Apply identities, expiry, state lineage/version, contract freshness, and
  no re-plan in Apply.
- **Detective:** compare plan digest, state version, contracts, policy, release,
  and approval immediately before apply.
- **Recovery:** reject and expire the plan; create and approve a new plan from
  current authoritative inputs.
- **Evidence:** `Target / Blocked`; the current workflow does not create or
  apply a live saved plan.
- **Residual risk:** **High**. **Owner:** Platform Engineering and Platform
  Security.

### TM-07: Terraform state disclosure, tampering, locking failure, or recovery abuse

**Attacker story:** An unauthorized identity reads or alters state, force-unlocks
it, restores an unrelated version, or presents state restore as rollback.

- **Preventive:** isolated backend and encryption, exact key ownership, native
  locking, distinct Diagnostic and StateRecovery roles, incident binding, and
  dual approval.
- **Detective:** object-version audit, lock anomalies, state-lineage checks,
  drift detection, and alarm on every StateRecovery use.
- **Recovery:** break-glass restore only after confirmed corruption, followed by
  a new reviewed plan and post-incident review; otherwise use forward rollback.
- **Evidence:** design and local policy exist; backend and recovery are not live
  validated.
- **Residual risk:** **High**. **Owner:** SRE / Operations with Platform Security.

### TM-08: SSM or contract tampering, replay, or cross-layer write

**Attacker story:** A producer overwrites another layer's contract, replays a
stale version, or alters a payload while retaining plausible metadata.

- **Preventive:** one writer per contract, layer-scoped IAM, schema and canonical
  digest, complete binding tuple, version, and freshness checks.
- **Detective:** consumer preconditions, writer audit, digest mismatch telemetry,
  and contract-to-deployment-record comparison.
- **Recovery:** block downstream planning and republish only from the
  authoritative producer before consumers re-plan.
- **Evidence:** schemas and local fail-closed tests exist; live SSM publication
  is blocked.
- **Residual risk:** **High until writer IAM and publication are live validated**.
  **Owner:** Platform Engineering; Security owns writer authorization.

### TM-09: Registry, request, or resolved-manifest tampering

**Attacker story:** An attacker changes the deployment-to-account mapping or
substitutes a resolved manifest after request approval.

- **Preventive:** Git-safe request contains only non-sensitive intent; resolved
  record is encrypted outside Git; registry is authoritative and versioned;
  bindings are revalidated before authority requests.
- **Detective:** registry audit, request-to-record digest comparison, and binding
  mismatch detection.
- **Recovery:** stop the release, restore the last approved registry version,
  and require a new request and approval.
- **Evidence:** request schemas exist; authoritative registry implementation is
  `Target`.
- **Residual risk:** **High**. **Owner:** deployment-registry owner and Platform
  Security.

### TM-10: Artifact substitution or production rebuild

**Attacker story:** A release actor replaces an image after validation, deploys a
mutable tag, or rebuilds production and claims it is the validated artifact.

- **Preventive:** digest identity, signed release manifest, copy-and-verify
  promotion, pinned base image, production build prohibition, and Terraform
  consumption of manifest-bound digests.
- **Detective:** compare source, destination, manifest, and running digests;
  verify signatures and attestations.
- **Recovery:** block and quarantine the graph; promote the last-known-good
  complete graph without rebuilding.
- **Evidence:** digest controls exist locally; central promotion is `Target`.
- **Residual risk:** **Critical for production until Phase 6 is complete; target
  residual Medium**. **Owner:** Release Engineering and Platform Security.

### TM-11: Incomplete supply-chain graph or skipped gate

**Attacker story:** A release is promoted when an SBOM, scan, signature, or
provenance record is missing, skipped, stale, or bound to another digest.

- **Preventive:** complete graph required by the release manifest; missing tool
  or evidence fails the release; no partial approval.
- **Detective:** completeness, digest association, signature, scan, and
  attestation validation.
- **Recovery:** mark the release blocked and remove it from promotion eligibility;
  rebuild only in the approved build environment.
- **Evidence:** historical local tooling could report `SKIPPED`; ADR-032 now
  requires a non-zero failure for missing release tooling or evidence, while live
  enforcement is not
  implemented.
- **Residual risk:** **High**. **Owner:** Release Engineering and Platform
  Security.

### TM-12: Cross-customer ECR publication

**Attacker story:** A publisher pushes an approved image into the wrong customer
repository or uses another deployment's Environment and role.

- **Preventive:** deployment Environment, exact caller account/region/deployment
  checks, registry binding, and Promotion role limited to customer-local
  repositories.
- **Detective:** caller-account verification, destination digest readback, and
  ECR audit.
- **Recovery:** block the release, quarantine the destination artifacts, and
  reconcile metadata without deploying ECS.
- **Evidence:** current publication has local binding controls; the target
  Promotion flow is not live validated.
- **Residual risk:** **High**. **Owner:** Platform and Release Engineering.

### TM-13: ECS imperative drift or unreconciled automatic rollback

**Attacker story:** A pipeline updates ECS outside Terraform, or ECS rolls back
while Terraform and release evidence still claim the failed release.

- **Preventive:** Terraform sole ownership, no imperative service update, wave
  gates, and manifest digest binding.
- **Detective:** compare running task definition and digest to Terraform and the
  release manifest; monitor deployment-failure events and post-change drift.
- **Recovery:** stop later waves and create a new reviewed forward
  reconciliation plan for the known-good release.
- **Evidence:** ownership checks are local; live reconciliation is not exercised.
- **Residual risk:** **High**. **Owner:** SRE / Operations and Platform
  Engineering.

### TM-14: Partial release or non-transactional metadata

**Attacker story:** Some build matrix legs publish artifacts or metadata while
others fail, and the partial result is presented as a release.

- **Preventive:** one release decision over the complete service set and
  transactional manifest publication only after all requirements pass.
- **Detective:** manifest completeness and digest comparison across publication
  destinations and metadata.
- **Recovery:** mark the release incomplete and ineligible; reconcile metadata
  only after exact digest verification.
- **Evidence:** current publication can leave partial output; full release
  transaction is `Target`.
- **Residual risk:** **High**. **Owner:** Release Engineering.

### TM-15: Evidence overclaim

**Attacker story:** A local pass, dry-run, Terraform declaration, ADR status, or
synthetic fixture is used to claim AWS or production readiness.

- **Preventive:** mandatory taxonomy and evidence source/environment fields;
  phase gates cannot promote a state by inference.
- **Detective:** review commit, runner, environment, control, timestamp, source,
  and result; reject ambiguous evidence.
- **Recovery:** retract the claim, reopen the gate, and mark the missing evidence
  `Blocked`.
- **Evidence:** Phase 0 establishes the unified policy; CI and live use must be
  enforced later.
- **Residual risk:** **Medium**, with potentially High program impact. **Owner:**
  Technical Program Owner and independent Security reviewer.

### TM-16: Sensitive material in Git, CI, Linear, NotebookLM, or evidence

**Attacker story:** A contributor or automation publishes state, plans, real
manifests, identifiers, logs, credentials, PII, or customer data.

- **Preventive:** Git safety, sentinel checks, a sanitized evidence schema,
  explicit publication prohibitions, and a NotebookLM allowlist of curated
  derived sources.
- **Detective:** changed-scope scanning, publication-boundary review, and
  integrity-bound allowlist exceptions.
- **Recovery:** stop ingestion, quarantine the artifact, use the applicable
  incident process, and publish a sanitized replacement.
- **Evidence:** local checks exist; historical material is not trusted by
  default and requires classification outside this phase.
- **Residual risk:** **High**. **Owner:** Platform Security and repository owner.

### TM-17: Insider threat and single-maintainer concentration

**Attacker story:** One maintainer authors, approves, and enables a privileged
path without independent challenge.

- **Preventive:** independent reviewer, two-person production approval, separate
  release/security/operations authority, and no self-review or bypass.
- **Detective:** approval-graph audit and detection of one identity spanning
  incompatible functions.
- **Recovery:** suspend production authorization, appoint an independent
  reviewer, and re-review affected decisions and releases.
- **Evidence:** CODEOWNERS is concentrated; GUG-119 is unresolved.
- **Residual risk:** **High**. **Owner:** Technical Program Owner and
  organizational leadership.

### TM-18: Break-glass misuse

**Attacker story:** Diagnostic or StateRecovery is used for routine deployment,
approval bypass, or unproven state restore.

- **Preventive:** separate roles, incident ID, dual approval, short session, and
  no access to ordinary terminal roles.
- **Detective:** alarm on every use, SourceIdentity audit, and mandatory
  post-incident review.
- **Recovery:** terminate access, validate state/runtime consistency, reconcile
  through the normal orchestrator, and complete incident review.
- **Evidence:** design and local policies exist; live control and exercise
  evidence are absent.
- **Residual risk:** **High**. **Owner:** SRE / Operations and Platform Security.

### TM-19: M2M customer/deployment confused deputy

**Attacker story:** A valid machine token is mapped to a customer but is used
against another deployment, or a request-controlled identity field, legacy map,
or incomplete scope set is treated as sufficient authority.

- **Preventive:** a versioned `client_id`, customer, deployment, and required
  scope binding; exact comparison with the running deployment; binding-derived
  `read`/`write`/`admin` actions; explicit per-route authorization; typed
  internal authorization context; rejection of identity headers and payload
  fields; and distinct Terraform-owned customer/deployment variables.
- **Detective:** negative mismatch tests, startup configuration validation,
  task-definition schema checks, and sanitized reason-only authorization logs.
- **Recovery:** disable M2M, revert the reviewed implementation if necessary,
  correct the authoritative binding, and issue new credentials only through the
  separately approved identity control plane. Never re-enable the legacy
  customer-only map.
- **Evidence:** the repository implementation and local synthetic tests may
  establish fail-closed behavior. The edge-identity/services DAG, Cognito/API
  Gateway configuration, scope taxonomy, and two-deployment live isolation are
  blocked on GUG-93 and GUG-117.
- **Residual risk:** **High until non-production live validation; Critical if
  M2M is enabled with an ambiguous binding**. **Owner:** Application Security
  and Platform Engineering.

### TM-20: Document or batch object authorization bypass

**Attacker story:** An authenticated user or machine principal supplies a known
document, batch, artifact, or continuation identifier and receives another
customer's or deployment's data because a route checks only authentication,
action, a legacy tenant field, an accessible batch, or an unbound storage lookup.
The same bypass can expose a presigned URL, full-PII result, or batch export, or
can add a foreign document to an authorized batch.

- **Preventive:** centralized typed document, batch, and membership
  authorization; exact `customer_id` and `deployment_id` equality with the
  validated `AuthContext`; mandatory immutable ownership on new writes;
  ownership-bound DynamoDB keys, queries, conditions, and pagination; no
  protected scans or fetch-then-filter authorization; independent authorization
  of every batch member; stored-metadata-only S3 locators; authorization before
  presigning; and the GUG-102 `read+admin` requirement for export, full PII, and
  protected downloads.
- **Detective:** synthetic cross-customer, cross-deployment, missing-ownership,
  mixed-membership, query-boundary, presign, export, enumeration, and logging
  negative tests; route-policy inventory; conditional-write assertions; and
  reason-only authorization diagnostics without object or locator data.
- **Recovery:** disable the affected object path, preserve deny/quarantine
  treatment for unbound records, revert the reviewed application change if
  necessary, and reconcile ownership only through the approved report-only and
  migration procedure. Never restore legacy `tenantId`, infer ownership from a
  batch or S3 prefix, return a partial export, or weaken conditions.
- **Async/artifact boundary:** GUG-89 introduces strict stage-specific v2
  messages, exact customer/deployment reconciliation against the authoritative
  document, and stored-locator validation before worker side effects. Arbitrary
  prefixes and message-only authority remain denied. The control is effective
  only in the exact reviewed revision; task-definition activation, CI, live
  queue behavior, two-deployment proof, and recovery evidence remain separate
  and cannot be inferred from the repository change.
- **Concurrent child writes:** Employee Profile force regeneration never skips
  authorization of existing jobs/profiles. S3 creation and replacement use
  `If-None-Match`/`If-Match` preconditions so legacy, foreign, malformed, or
  concurrently replaced state cannot be silently adopted.
- **Evidence:** ADR-021 and the migration/quarantine runbook establish the
  repository decision only. The control is `Implemented` and `Locally validated`
  only for a reviewed revision containing the enforcement and passing named
  tests; passing PR checks are separate `CI validated` evidence. No live legacy
  inventory, migration, AWS behavior, or two-deployment isolation is established
  by repository artifacts. Those remain `Blocked` on GUG-117 and separately
  authorized non-production evidence.
- **Residual risk:** **High until reviewed CI and non-production isolation
  evidence; Critical if any normal path accepts foreign, ambiguous, or unbound
  ownership**. **Owner:** Application Security and Backend Engineering.

### TM-21: Async confused deputy, poison-message loss, or unsafe redrive

**Attacker story:** A producer or compromised message supplies a foreign owner,
legacy schema, conflicting stage/domain, or arbitrary artifact locator and a
worker performs a protected effect or forwards it without reconciling the
authoritative document. Alternatively, a poison message is acknowledged as
success, disappears without evidence, or is later redriven across a deployment
or stage, duplicating a partial effect.

- **Preventive:** exactly nine reviewed stage queues and paired Standard DLQs;
  strict stage-specific v2 envelopes; mandatory `customer_id`, `deployment_id`,
  and ownership schema v1; deployment-configured DynamoDB authority; exact
  owner/domain/locator comparison before protected effects; non-authoritative
  metadata allowlists; owner-bound conditional state transitions; required SQS
  `MessageId` before accepting a handoff; and exact `byQueue` DLQ source policy.
- **Detective:** synthetic missing/malformed/foreign/ambiguous-owner tests,
  stage/domain/locator conflict tests, duplicate and partial-handoff tests,
  topology/schema contract checks, reason-only worker diagnostics, per-stage
  retry/DLQ alarms, and sanitized count reconciliation.
- **Recovery:** retain the failed message in its exact stage path; classify it
  report-only as eligible, legacy, unbound, partial, ambiguous, foreign,
  orphaned, inconsistent, or partial-effect-unknown; require same-deployment
  revalidation, idempotency proof, dry-run, independent approval, rate limits,
  and stop criteria before any future redrive. Never infer or rewrite ownership,
  bypass the failed stage, cross deployments, or purge a queue.
- **Legacy behavior:** v1, missing, partial, malformed, conflicting, ambiguous,
  foreign, and unverifiable messages are denied and retained for reviewed
  quarantine/investigation. GUG-89 performs no automatic migration or redrive.
- **Evidence:** ADR-022, the async topology reference, worker/source tests, and
  Terraform/schema checks can establish repository implementation and local or
  CI evidence for an exact revision. They do not establish AWS resources,
  deployed task modes, live alarms, DLQ contents, failure injection, redrive, or
  no-loss/no-duplicate recovery. An S3 existence check alone does not prove a
  prior effect. The domain structured-artifact path now requires a conditional
  owner-bound reservation, exact writer/schema/checkpoint metadata, SHA-256
  content verification, and conditional finalization before a retry may recover.
  Deployment, IAM, live failure-injection, generalized idempotency, and redrive
  proof remain **Blocked** pending GUG-108's separately owned dependency and the
  GUG-118 runtime gate.
- **Residual risk:** **High until reviewed CI, deployment wiring, and authorized
  non-production failure/recovery evidence; Critical if any consumer accepts
  foreign authority, silently acknowledges poison work, or permits uncontrolled
  redrive**. **Owner:** Backend Engineering, Application Security, SRE, and
  Platform Engineering.

### TM-22: Enterprise privilege, stale-grant, or lifecycle bypass

**Attacker story:** A valid human token is accepted without proving a current
enterprise membership, exact customer/deployment binding, role/action policy,
or required authentication assurance. A stale token may survive a role change,
suspension, or offboarding; a provider group, email domain, request field, or
legacy claim may be treated as authority; or standing support/break-glass access
may bypass customer approval and object authorization. The result can be
cross-customer access, privilege escalation, unauthorized full-PII/export,
or an offboarded user continuing to act.

- **Preventive:** ADR-023's default-deny RBAC+ABAC decision; closed roles
  (`customer_admin`, `document_operator`, `document_reviewer`, `auditor`);
  exact `customer_id` and `deployment_id`; supported policy, role, scope, and
  membership/grant versions; access-token-only API use; explicit
  operation-to-action/resource mapping; ADR-021 object authorization; and
  phishing-resistant step-up plus `read+admin` for full-PII, export, and
  protected artifact operations. Provider group display names, email domains,
  headers, route/query parameters, payloads, and legacy tenant fields never
  establish authority.
- **Authentication/recovery:** credentials remain provider-managed; password
  authentication, when enabled, requires the portable password baseline and
  compromised-password detection. Reset/recovery is enumeration-safe, changes
  no authorization binding, revokes sessions, reconciles current membership,
  and never logs recovery secrets. Federation and SCIM remain disabled until a
  reviewed adapter preserves these invariants.
- **Lifecycle:** only `active` membership authorizes ordinary work. Role change,
  suspension, and revocation increment membership version and revoke sessions;
  expired and revoked memberships are terminal; the last administrator cannot
  be removed without an approved same-deployment replacement. Bootstrap is
  one-use, expiring, dual-approved, non-self-approved, strongly authenticated,
  and audited.
- **Privileged access:** exactly one membership or temporary-grant path may
  authorize a human. The authoritative temporary-grant store binds an active,
  current-version support/break-glass grant to one subject, customer,
  deployment, closed operation, and allowed data class; ABAC, object checks,
  and explicit denials prevail. The v1 catalog is read-only diagnostic access.
  Support expires within one hour and revokes on
  expiry/case closure. Break-glass expires within 15 minutes and alerts on use.
  Both unconditionally deny full-PII, export, and protected artifact access in
  v1 and cannot administer lifecycle, change ownership, or mint privilege.
- **Detective:** synthetic missing/foreign/conflicting tenant tests; unknown,
  future, and stale version tests; role/action/resource matrix tests; sensitive
  operation and step-up tests; self-elevation, last-admin, invitation replay,
  session-revocation, support-expiry, and emergency-expiry tests; complete route
  PEP inventory; and sanitized authorization/audit reason categories without
  tokens, claims, PII, object contents, or locators.
- **Recovery:** disable the affected human authorization path, revoke sessions
  and temporary grants, increment the authoritative membership/grant version,
  preserve sanitized audit evidence, and correct provider or membership
  mappings through a reviewed change. Never restore a default role, infer a
  group/tenant mapping, accept a stale token, create a shared administrator, or
  leave support/emergency access standing.
- **Portability:** one provider-neutral policy/schema and validator apply to
  every customer/account. Deployment adapters supply external exact bindings
  and may narrow authority, but cannot add roles/actions or reinterpret unknown
  versions. The source policy contains no customer, account, region, identity
  pool, client, or resource instance identifier.
- **Evidence:** GUG-92 / ADR-023 can establish only the repository policy
  decision, documentation, and offline conformance for an exact revision. It
  does not establish Cognito/API Gateway claims, route enforcement, session
  revocation, administrative workflows, provider state, live migration, or
  isolation. GUG-93 owns provider/IaC integration, GUG-153 owns backend PDP/PEP
  enforcement, GUG-94 owns administrative lifecycle APIs, GUG-95 owns UI/E2E,
  and GUG-117 remains the integrated two-deployment gate.
  No live user, provider, AWS, migration, or production action is authorized.
- **Residual risk:** **High until every protected route enforces the current
  policy and authorized non-production evidence proves lifecycle, revocation,
  sensitive operations, temporary privilege, and two-deployment isolation;
  Critical if a stale, foreign, or unbound human principal is accepted**.
  **Owner:** Application Security, Identity/Platform Engineering, Backend
  Engineering, and Customer Administration.

### TM-23: Identity-provider authority confusion, bootstrap replay, or credential-state disclosure

**Attacker story:** A provider group, ID token, client metadata value, legacy
tenant claim, or copied pool/client identifier is accepted as application
authority. A bootstrap request is replayed or approved by the target, two
workers execute the same effect, or a partial provider/membership effect is
retried without reconciliation. Alternatively, Terraform creates an M2M client
and stores the generated credential in plan/state/output, or a runtime adapter
returns or logs it. An unsafe import/replacement/deletion can also strand users,
cross deployment bindings, or destroy the only audit/recovery path.

- **Preventive:** ADR-024's dedicated identity-control-plane stage and exact
  customer/deployment/account/region/release/policy binding; a deletion-
  protected deployment-local provider; immutable customer/deployment
  attributes; admin-only human creation; non-authoritative provider groups;
  V2 pre-token lookup of one authoritative active membership; suppression of
  provider group/IAM-role claims; access-token-only route scopes; and exact
  contract gates before services and edge identity.
- **Bootstrap:** general human runtime provisioning and self-signup remain
  disabled. First-administrator bootstrap requires one supported exact record,
  exactly two independent non-target approvers, current assurance, lifetime no
  longer than 900 seconds, trusted idempotency, conditional claim and consume,
  idempotent provider/membership effects, sanitized audit, and SQS partial batch
  failures. Replay, expiry, ambiguity, stale versions, timeout, or conditional
  conflict denies.
- **M2M custody:** Terraform never creates or outputs a generated credential.
  The runtime provisioner conditionally claims one exact workload binding,
  calls an idempotent provider adapter, immediately escrows the credential in
  the approved credential store, conditionally completes the binding, and
  returns only non-sensitive client/credential references. Human principals,
  unknown/duplicate/default actions, foreign bindings, conflicting replays, and
  dependency failures deny. A fresh 300-second claim lease cannot be reused;
  recovery requires an expired lease and an exact conditional replacement of
  its token, timestamp, workload, environment, customer, deployment, and action
  set. Existing custody must read back under the exact deployment KMS key,
  secret name/ARN, binding tags, current version, and non-deleted state.
- **Detective:** synthetic group/client-metadata spoof tests; missing,
  malformed, foreign, inactive, stale-version/digest, unsupported-event, and
  dependency-timeout tests; bootstrap dual-approval/self-approval/TTL/replay/
  conditional-write tests; SQS partial failure tests; M2M idempotency and
  credential-redaction tests; Terraform mock tests for deletion protection,
  exact IAM, contract restrictions, and no credential output; and reason-only
  operational logging.
- **Deferred bootstrap audit closure:** the locally composed bootstrap primitive
  is unreachable while human runtime is disabled and the runtime role lacks
  human provider permissions. Its final audit currently follows conditional
  record consumption, so GUG-94 must add a recoverable outcome-audit protocol
  before enablement. This deferred item does not authorize bootstrap execution.
- **Deferred M2M command authority:** no principal in this package receives
  `sqs:SendMessage` to the provisioning queue. Before adding a producer, bind
  that permission to one exact reviewed identity and require the consumer to
  reload an authoritative approved provisioning record for the requested
  action set. The message body remains untrusted transport and cannot establish
  authority.
- **Legacy/migration:** report-only inventory classifies fully bound compatible,
  partial, ambiguous/shared, provider-only, state-only/orphaned, immutable-
  incompatible, and inconsistent resources. Only an exactly compatible
  resource may enter a reviewed replacement-free state-adoption plan. Immutable
  incompatibility uses an explicitly approved blue/green migration. Names,
  account proximity, domains, groups, and legacy customer-only claims never
  infer ownership.
- **Deferred identity-root adoption gate:** before any apply in an account with
  pre-existing identity resources, the identity root must require a reviewed
  `greenfield`, `adopted`, or `migration_required` disposition backed by a
  sanitized inventory digest. `adopted` also requires replacement-free plan
  evidence. The downstream edge handoff gate does not authorize creating a
  parallel pool first.
- **Recovery/decommission:** freeze new issuance, reconcile partial effects,
  retain old provider/audit/state resources, revoke sessions/grants, move every
  consumer through reviewed contracts, wait through retention, and prove
  successor/rollback independence. Deletion protection, state removal, import,
  pool deletion, credential disclosure, and legacy fallback are not rollback.
  Any destructive action is a separate approved change.
- **Provider-contract compatibility:** release manifests treat S3 VersionIds as
  opaque Unicode, reject the unversioned `null` sentinel, and require the
  operational consumer to enforce the 1,024 UTF-8 byte provider limit. The
  Identity Apply role can reconcile
  CloudWatch tags only on the exact deployment alarm family, while alarm
  deletion remains explicitly denied. Contract-schema drift can otherwise
  reject a valid immutable release, and missing tag permissions can leave a
  reviewed Terraform apply unable to converge.
- **Evidence:** repository runtime, Terraform, contracts, tests, ADR-024, and
  runbooks can establish `Implemented` and named offline results can establish
  `Locally validated` for an exact revision. Required PR checks remain separate
  `CI validated` evidence. No AWS/Cognito creation, provider upgrade,
  bootstrap, credential escrow/rotation, state adoption, user migration,
  decommission, rollback, or two-deployment isolation is `Live validated` by
  GUG-93 repository work. Those remain **Blocked**; production remains
  **NO-GO**.
- **Residual risk:** **High until reviewed CI and explicitly authorized
  non-production create/upgrade/bootstrap/M2M/consumer/rollback/isolation
  evidence; Critical if provider metadata grants authority, a credential enters
  Terraform/evidence, bootstrap can replay, or identity resources are replaced
  or deleted without migration proof**. **Owner:** Identity/Platform
  Engineering, Application Security, Backend Engineering, and SRE.

## Severity Calibration (Critical, High, Medium, Low)

| Severity | Repository-context calibration | Examples |
|---|---|---|
| **Critical** | Cross-customer access or mutation, unauthorized production change, broadly deployed artifact compromise, destructive state misuse, or regulated data disclosure | wrong-account apply; production artifact substitution; state recovery used to rewrite ownership; customer document exposure |
| **High** | One deployment can be materially compromised or a production control can be bypassed; identity, plan, contract, or artifact integrity is not assured | broad OIDC subject; Apply can re-plan; contract writer not isolated; independent approval absent |
| **Medium** | Control or evidence integrity is degraded but fail-closed behavior limits live impact and recovery is bounded | local evidence mislabeled before live enablement; diagnostic visibility gap with no mutation path |
| **Low** | Limited operational impact with no material authorization, confidentiality, integrity, or customer-isolation consequence | a sanitized metadata field is absent but the gate stops and no authority is granted |

Evidence-aware risk rules:

1. A `Target` control does not reduce current residual risk.
2. `Implemented` and `Locally validated` do not prove GitHub or AWS behavior.
3. `CI validated` proves only the identified commit and workflow execution.
4. `Live validated` requires an explicit non-production binding and reviewable
   sanitized evidence.
5. An accepted ADR alone is not a production-effective control.
6. Unknown evidence is absent; a blocked live path does not justify enabling it.

### Automatic NO-GO conditions

A condition below automatically blocks the gate whose capability would expose
the risk, every live use of that capability, and production. It does not block
an earlier, unprivileged implementation work package whose explicit purpose is
to remediate the condition. Such work remains `Target / Blocked`, cannot claim
the dependent gate's exit evidence, and must preserve the current live-disable
boundary. Phase 0 may therefore authorize only the next eligible remediation
package while the High risks assigned to later phases continue to block those
phases and production.

The dependent gate is automatically NO-GO when:

- any customer, deployment, account, region, environment, release, layer,
  change, or operation binding is absent or ambiguous;
- a privileged job can obtain OIDC without independently targeting a verified
  deployment Environment;
- required checks, exact OIDC trust, Plan/Apply separation, or independent
  review are not enforced;
- saved-plan digest, expiry, state freshness, or contract freshness is missing;
- raw state, plans, resolved manifests, or sensitive payloads enter a prohibited
  system;
- a contract lacks an authoritative owner, schema, digest, binding, or freshness
  check;
- the artifact graph is incomplete, mutable, unsigned, rebuilt, or has a
  skipped required gate;
- ECS can be updated outside Terraform;
- StateRecovery lacks a declared incident and independent approval;
- evidence does not distinguish local, CI, and live validation; or
- a Critical or High risk lacks approved, scoped, expiring treatment.

### Risk acceptance constraints

An accepted risk records the threat, phase, current and target risk, owner,
independent approver, scope, compensating controls, supporting evidence,
expiration, review date, containment action, and linked work package. It expires
no later than the next dependent gate and never later than 30 days without a
new independent review.

No exception may authorize ambiguous or cross-customer binding, CI or approval
bypass, static credentials, sensitive material in prohibited systems, mutable
production identity, production rebuild, routine state restore, or weakening a
required security gate.

Phase 0 baseline repository: sha256:80c9e3f626290491572781c3723a326dfed0f0d3430aee8493ac7a2383fb2f1c
Phase 0 baseline version: 7dd9647d93bbf2fd88dfdada97ece95f93e81eaf
