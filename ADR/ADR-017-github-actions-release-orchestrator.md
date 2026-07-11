# ADR-017: GitHub Actions Release Orchestrator

- **Status**: Accepted
- **Date**: 2026-07-10
- **Deciders**: César Guzmán, Platform Engineering
- **Scope**: Non-production orchestration formalization; production remains NO-GO
- **Refines**: ADR-012, ADR-013, ADR-016

## Context

The local deployment wrapper can validate Terraform roots, but it cannot safely
apply the platform in dependency order. Downstream plans currently rely on mock
inputs and are created before upstream resources and contracts exist. A saved
plan built from those mocks cannot become an authoritative live deployment
artifact.

Scanalyze also has two configuration classes that must not be conflated:

- a Git-safe deployment request that records non-sensitive desired intent; and
- a resolved deployment record and real manifest containing account-specific
  bindings, kept encrypted and access-controlled outside Git.

The platform therefore needs a CI control plane that can sequence Terraform
roots, validate explicit contracts, enforce approvals, and preserve sanitized
evidence without making operator laptops or GitHub job outputs an infrastructure
data bus.

## Decision

1. **GitHub Actions is the live deployment orchestrator.** Local tooling remains
   available for validation and dry-run preparation, but local `apply-all` is not
   an authoritative deployment path.
2. **`deployment/layers.yaml` is the canonical deployment graph.** Workflows,
   scripts, tests, and documentation must agree with it.
3. **One versioned SSM envelope per producer layer is the authoritative
   inter-layer contract.** `terraform_remote_state` and GitHub outputs are not
   contract transports.
4. **Terraform output is producer-local input only.** It may be consumed inside
   the producer job to construct and validate a candidate envelope; it is never
   exposed as a cross-job infrastructure API.
5. **Real manifests never enter Git.** Git may contain a schema-validated,
   non-sensitive deployment request and immutable release digest.
6. **Every deployable Terraform layer uses an exact saved plan.** The future live
   path is `plan -> policy gate -> plan digest verification -> apply saved plan ->
   contract validation` before the next layer can start.
7. **Authentication uses GitHub OIDC.** The target model is an OIDC-trusted
   orchestrator role followed by terminal roles scoped to operation and layer.
   The repository does not claim that this complete role model is deployed or
   live validated.
8. **Artifact publication is a distinct stage.** It runs after `cicd` provisions
   customer-local registries and before `services` consumes immutable image
   digests.
9. **Rollback is a forward deployment.** A known-good release is replanned and
   applied through the same gates. Terraform state restoration is a separate
   break-glass recovery procedure.
10. **Production is promotion-only and remains blocked.** A production workflow
    cannot be enabled until the same immutable release has reviewable live
    non-production evidence and the OIDC, contract, supply-chain, rollback, and
    approval controls are live validated.

## Canonical Stage Order

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

`account-ready-gate`, `artifact-publication`, and `synthetic-validation` are
control stages, not ordinary Terraform apply layers. The graph records that
distinction explicitly.

## Security Invariants

- Pull-request validation has no AWS credentials and no OIDC token permission.
- OIDC is available only to an approved live job, never globally to a workflow.
- The initial orchestrator role has no ambient infrastructure administration.
- Plan, Apply, Promotion, and Validation are separate authorization scopes.
- Contract identity is bound to deployment, account, region/scope, layer, and
  release before a consumer uses any output.
- Missing, stale, malformed, or digest-mismatched contracts fail closed.
- Raw plans, state, real tfvars, resolved manifests, and output payloads are not
  GitHub artifacts and are never committed.
- Evidence stored durably is sanitized and contains no customer data or secret
  values.
- Destroy operations are denied unless a future, separately approved policy and
  workflow explicitly authorizes them.

Repository merge governance is client-independent and uses only static required
check contexts. Dynamic matrix legs are evidence behind a stable aggregate gate;
they are never branch-protection interfaces. Deployment authorization is a
separate control plane: every deployment selects a protected GitHub Environment
whose non-secret deployment, logical-environment, and region bindings must match
the request. See ADR-018.

## This Change's Execution Boundary

The first implementation of this ADR is intentionally dry-run only:

- it validates the graph and Git-safe records;
- it renders candidate contract envelopes locally;
- it provides reusable workflow structure and explicit stage dependencies;
- it does not request OIDC credentials, initialize a live backend, publish to
  SSM/ECR, run `terraform apply`, or mutate AWS.

Any future live path must be enabled in a separate reviewed change. Environment
approval and a boolean workflow input are not, by themselves, sufficient proof
that the AWS role model and live controls are ready.

## Consequences

### Positive

- Dependency order and ownership become machine-checkable.
- A layer cannot plan against mock upstream infrastructure in the live path.
- GitOps intent remains reviewable without placing customer bindings in Git.
- Reusable workflows reduce drift between layer jobs and environments.
- Production promotion can reuse the exact artifacts validated in
  non-production instead of rebuilding them.

### Costs

- Contract schemas, producers, consumers, and compatibility tests must be kept in
  lockstep.
- The target terminal-role model and protected GitHub Environments still require
  independent IaC and live validation.
- Saved-plan storage, evidence retention, state locking, and recovery need an
  approved backend implementation before live enablement.

## Alternatives Rejected

1. **Repair local `apply-all`.** Rejected because downstream plans cannot be
   authoritative before upstream contracts exist and because operator laptops
   are not an auditable deployment control plane.
2. **Pass outputs through GitHub outputs or workflow artifacts.** Rejected because
   this creates an ephemeral, weakly typed infrastructure API and increases
   accidental disclosure risk.
3. **Use `terraform_remote_state`.** Rejected because it couples state ownership
   and broadens access to sensitive state.
4. **Enable production in the first workflow change.** Rejected because the role,
   contract, supply-chain, and non-production evidence gates are not live
   validated.

## Related Decisions

- [ADR-018: Stable CI Governance and Deployment-Scoped Environments](ADR-018-stable-ci-governance.md)
