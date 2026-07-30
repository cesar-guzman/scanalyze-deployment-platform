# ADR-018: Stable CI Governance and Deployment-Scoped Environments

- **Status**: Accepted
- **Date**: 2026-07-10
- **Deciders**: César Guzmán, Platform Engineering
- **Scope**: GitHub merge governance and multi-client deployment authorization
- **Refines**: ADR-011, ADR-017

## Context

The `main` branch protection rule required fourteen GitHub Actions contexts.
Seven were concrete expansions of the dynamic microservice matrix, for example
`Validate ingest-api`. An infrastructure-only pull request correctly selected
no services, so GitHub created no concrete matrix jobs. Branch protection kept
waiting for contexts that could never exist.

This exposed a control-plane mismatch: a required status check is a static name,
while a dynamic matrix is an implementation detail. GitHub does not associate a
required context with a particular workflow, event, or matrix definition. A
skipped job is successful for branch protection, but an absent context remains
pending.

The audit also found two adjacent sources of drift:

1. reproducibility ran for both a feature-branch push and its pull request,
   producing duplicate checks for one SHA, and used a Terraform version that did
   not match `.terraform-version`; and
2. `nonprod-release.yml` used the logical stage (`sandbox`, `dev`, or `staging`)
   as the protected GitHub Environment name, which cannot isolate approvals and
   variables for multiple deployments or clients.

## Decision

### 1. Required checks are a versioned compatibility API

`governance/github-policy.json` is the Git-safe, repository-global contract for
required status checks. `schemas/github-policy.schema.json` and
`tooling/validate_github_policy.py` validate that every target context:

- has one exact, static producer name;
- runs for every pull request targeting `main` without workflow path filters;
- is not a matrix job;
- cannot disappear after a dependency failure unless it uses `always()`;
- has no deployment Environment, write permission, OIDC permission, or dynamic
  failure tolerance in the required job or its transitive `needs` closure; and
- is unique against static and potentially colliding dynamic names across every
  workflow.

Client or deployment identifiers are prohibited in required check names.

### 2. Dynamic matrices report evidence; one stable gate enforces the result

For pull requests, the service matrix remains path-aware. Its concrete
`Service matrix evidence / <service>` jobs are diagnostic evidence and are not
branch-protection interfaces. A manual `workflow_dispatch` validates all seven
services before emitting the same stable gate; the operator's service selection
scopes only `publish_services`. Push selection and subset publication retain
their existing behavior.

`Microservices validation gate` always reports a result and passes only when:

- service selection and build-tool validation succeeded; and
- either services were selected and the complete matrix succeeded, or no
  services were selected and the matrix was skipped consistently.

Failure, cancellation, missing outputs, invalid booleans, and inconsistent
matrix state fail closed. Image publication depends on this gate.

### 3. Branch protection reconciliation is external and transactional

A workflow governed by the policy must never silently rewrite its own branch
protection. `scripts/governance/sync-required-checks.py` is an operator tool,
read-only by default. An apply requires an explicit repository, evidence SHA,
confirmation, and snapshot destination. It accepts only the canonical
repository-relative `governance/github-policy.json` and proves that the loaded
object and working file are identical to that path at the evidence SHA before
remote inspection and again immediately before mutation.

The migration order is:

1. publish the workflow change while the legacy rule still applies;
2. observe every target check succeeding on the same pull-request SHA and
   verify the `github-actions` app source;
3. revalidate the exact pull request and canonical manifest binding;
4. snapshot and hash the current required-status configuration;
5. revalidate both bindings, required checks, and effective rules immediately
   before the remote request;
6. atomically update only the dedicated required-status-check endpoint;
7. read back and verify the target state; and
8. compensate only while repeated readback proves no third-party drift.

Review requirements, admin enforcement, force-push/deletion controls, and all
other branch settings are outside this mutation and remain unchanged.

The immediate target requires six static contexts:

- `Lint, security, and schema checks`
- `Python tests`
- `Validate deployment manifest schema`
- `Terraform validate (no AWS)`
- `Verify clean clone reproducibility`
- `Microservices validation gate`

### 4. Repository governance and deployment authorization are separate

The monorepo has one client-independent merge policy. There are no customer
source forks and there are no customer-specific branch checks.

Every deployment uses a distinct protected GitHub Environment selected through
`github_environment`. The logical stage is a separate input named
`logical_environment`. Before orchestration continues, the selected Environment
must provide non-secret variables whose values match the request:

- `DEPLOYMENT_ID`
- `LOGICAL_ENVIRONMENT`
- `AWS_REGION`

The dry-run jobs still have no AWS credentials or OIDC permission. Any future
privileged job must independently target the same deployment-scoped Environment
and revalidate the bindings before requesting authority.

The current `vars` equality check is a dry-run consistency check, not proof of
variable provenance or Environment protection. GitHub configuration variables
can also exist at organization or repository scope, and referencing an unknown
Environment can create it without the intended protections. Before any live job
is enabled, an external onboarding/governance control must verify through the
GitHub API and the approved deployment registry that the Environment already
exists, has the required reviewers and `main`-only deployment policy, and owns
the exact three binding variables. Those variable names are reserved and must
not exist at organization or repository scope.

### 5. Reproducibility has one PR execution

The reproducibility workflow runs for pull requests, pushes to `main`, its
weekly schedule, and explicit manual dispatch. Feature-branch push duplication
is removed. Terraform is pinned to the repository version, `1.14.6`.

## Multi-Repository Direction

Normal Scanalyze scaling uses one source repository and many deployment-scoped
GitHub Environments. If governance later spans several platform repositories,
the same static context contract should be enforced through an organization
ruleset or an external controller using a short-lived GitHub App installation
token. Long-lived personal access tokens and self-modifying repository
workflows are rejected.

The current personal repository has classic branch protection and no rulesets.
Migrating the complete protection model to an organization ruleset is a separate
reviewed change because it changes more than the defective required contexts.

## Consequences

### Positive

- Infrastructure-only pull requests cannot deadlock on missing matrix contexts.
- Any service-matrix failure still blocks the stable gate.
- Branch-protection drift is machine-checkable and repeatable.
- Client onboarding does not copy workflows or create source forks.
- Deployment approval and variables are isolated per deployment.
- Remote governance changes have explicit evidence, rollback, and least-privilege
  boundaries.

### Costs

- A required job name is now an API and must be migrated deliberately when
  renamed.
- Every deployment-scoped GitHub Environment needs reviewed variables and
  protection settings.
- The classic branch rule remains an external GitHub object and therefore needs
  periodic drift auditing until organization-level policy is available.

## Alternatives Rejected

1. **Require all seven matrix jobs.** Rejected because matrix legs do not exist
   for unrelated changes and their names are not stable governance interfaces.
2. **Run all services for every pull request.** Rejected because it defeats
   path-aware CI and wastes runner capacity.
3. **Remove the seven checks without a replacement.** Rejected because service
   failures would no longer be guaranteed to block merges.
4. **Use one `dev` or `staging` Environment for every client.** Rejected because
   approvals, variables, and future OIDC subjects would cross deployment
   boundaries.
5. **Let CI update its own protection.** Rejected because compromised pull
   request code must not control its merge policy.

## References

- [GitHub: troubleshooting required status checks](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/collaborating-on-repositories-with-code-quality-features/troubleshooting-required-status-checks)
- [GitHub: protected branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
- [GitHub: branch-protection REST endpoints](https://docs.github.com/en/rest/branches/branch-protection)
- [ADR-011](ADR-011-monorepo-microservices-source.md)
- [ADR-017](ADR-017-github-actions-release-orchestrator.md)
