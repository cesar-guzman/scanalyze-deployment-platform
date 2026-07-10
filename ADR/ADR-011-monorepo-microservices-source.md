# ADR-011: Monorepo Microservices Source

> **Status**: Accepted
> **Date**: 2026-07-09
> **Decision maker**: César Guzmán
> **Scope**: Scanalyze Deployment Platform and application source
> **Depends on**: ADR-001, ADR-004, ADR-006, ADR-007, ADR-009, ADR-010

## Context

Scanalyze infrastructure and the seven application microservices were maintained
in separate source locations. The brownfield worker checkout also accumulated
dirty changes, Finder-numbered duplicates, archives, local backups, legacy
buildspecs, and account-specific base image references. That state was not a
safe or reproducible source for customer deployments.

The deployment platform already establishes account-per-deployment isolation,
customer-local ECR, immutable tags, KMS encryption, scan-on-push, release
metadata in SSM, and digest-based ECS image references. It also includes a
transitional CodeCommit/CodeBuild/CodePipeline path.

## Decision

1. `scanalyze-deployment-platform` is the canonical monorepo for infrastructure,
   contracts, policy, tooling, and all seven application services.
2. Service source lives at `backend/workers/scanalyze-<service>/`.
3. The migration baseline is the exact Git tree
   `9e6a14d240373ced4b23523097b1207982aa6004:scanalyze-micros/backend/workers`
   (tree `81535f1493c7b9719f10e38ea9ed72c386fc55bb`). This revision matches the
   recorded `brownfield_head` and GitHub `origin/main`.
4. Dirty working trees, the divergent CodeCommit main line, unmerged feature
   branches, numbered duplicates, archives, backups, and legacy buildspecs are
   not imported.
5. GitHub is the canonical source. Path-aware GitHub Actions and
   `scripts/microservices/build-push.sh` are the primary validation/build
   entrypoints.
6. The target state never delivers application source to a customer account.
   Customer accounts receive immutable OCI images through their local ECR.
   Existing CodeCommit mirrors may be retained only as a time-bounded,
   non-canonical migration exception until an approved retention/export step
   removes them.
7. Every Dockerfile requires a caller-supplied `BASE_IMAGE`. Production
   publication requires a digest-pinned base image from the target account ECR.
8. ECR and release metadata SSM remain Terraform-owned. Updating SSM metadata
   does not deploy ECS; the services layer remains the declarative runtime owner.
9. CodeCommit and CodePipeline controls are separated while preserving old
   resource-enablement defaults. Destructive retirement occurs only when
   operators set the new flag and approve a live plan; the independent
   CodeBuild repository-name correction can still be an in-place diff.

## Multi-client replication

There are no customer forks. A customer deployment supplies only reviewed
declarative inputs:

- deployment/account/region identity
- contract and Terraform inputs
- target ECR namespace
- digest-pinned base image
- runtime SSM parameters and approved feature configuration

GitHub Environment variables bind publishing to one deployment. Workflow inputs
must match those protected variables, and the assumed OIDC role must bind the
exact repository and environment subject. Both the workflow and Environment
deployment policy restrict publication to `main`.

## Security and supply chain

- Pull requests have read-only repository permission and no AWS OIDC token.
- Publish jobs receive `id-token: write` only when publication is explicitly
  enabled.
- No static AWS key is accepted or documented.
- The build script verifies caller account, region, repository existence, and
  immutable-tag absence before the first push.
- Publish builds reject `latest` and require a target-ECR base image by digest.
- ECR digest is read back after push; SSM digest is written last.
- The script has no ECS, Terraform apply, or deployment action.
- `.dockerignore`, `.gitignore`, the security sentinel, and the microservice
  policy check block credentials, state/plans, client material, caches,
  duplicate artifacts, and account-specific source.
- Synthetic identity-shaped test fixtures are documented by path and pattern in
  the sentinel allowlist; real customer data remains prohibited.

## Backwards compatibility and migration

`enable_codepipeline` is nullable. When omitted, it inherits
`enable_codecommit`, preserving the previous resource graph. The corrected
`ECR_REPO_NAME` value can still produce an in-place CodeBuild project update;
backwards compatibility does not mean a guaranteed zero-diff plan.

Recommended migration:

1. Establish and validate the GitHub OIDC role and protected Environment.
2. Validate all seven no-push builds.
3. Review compliance retention requirements and export any required historical
   CodeBuild/CodePipeline log evidence.
4. Set `enable_codepipeline=false` while retaining
   `enable_codecommit=true`; review the expected CodeBuild/CodePipeline/log/IAM
   removals in a live Terraform plan.
5. Publish and promote a digest-pinned release through the GitHub path.
6. Retain/export legacy source and obtain explicit approval.
7. In a separate change, set `enable_codecommit=false` and review deletion of
   the seven legacy repositories.

ECR repositories and SSM image metadata are independent of both legacy flags.
No step uses Terraform state manipulation as rollback.

## Consequences

### Positive

- Application and infrastructure changes can be reviewed atomically.
- Path-aware CI provides direct evidence for the affected services.
- Customer replication no longer requires source mirroring or forks.
- Base image and destination identity are explicit and fail closed.
- Legacy pipeline retirement can be staged without deleting ECR or SSM.

### Negative

- The repository is larger and CI ownership spans application and platform code.
- Customer publishing requires GitHub Environment and OIDC role provisioning.
- Existing unmerged feature branches require explicit reconciliation.
- The current flow performs a customer-scoped build against that account's
  approved base image. Byte-identical central build-and-promote is not yet
  implemented, and dependency ranges prevent deterministic rebuild claims.
- Some baseline Dockerfiles install mutable OS packages and keep build tooling
  in the runtime layer; multi-stage, approved-package-source hardening remains a
  follow-up that requires runtime validation.
- The current workflow produces build/test/digest evidence but does not yet
  implement every ADR-007 target such as SBOM, signing, provenance, or enhanced
  scan gating.

## Rejected alternatives

- **Copy a dirty working tree**: not reproducible and risks importing local
  artifacts or unreviewed changes.
- **Keep one repository per customer**: creates code forks and inconsistent
  security fixes.
- **Deploy source into customer accounts**: violates the artifact boundary.
- **Use a public base image implicitly in production**: weakens provenance and
  introduces uncontrolled registry dependency.
- **Delete CodeCommit/CodePipeline in the migration PR**: creates an unreviewed
  destructive Terraform transition.

## Follow-up

- Reconcile the excluded feature branches through normal PRs.
- Provision and review the least-privilege GitHub OIDC role per deployment.
- Add SBOM, signing, provenance, and vulnerability-gate stages required for the
  full ADR-007 target.
- Add locked, hash-verified Python dependencies and evaluate a signed central
  build plus verified cross-account image promotion model.
- Review existing tracked customer tfvars and move sensitive/local values to the
  approved configuration delivery mechanism without deleting files silently.
