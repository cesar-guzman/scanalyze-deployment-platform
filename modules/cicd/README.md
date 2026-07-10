# CI/CD Module

Customer-local ECR, release metadata, and optional legacy build-only pipelines
for Scanalyze microservices. Canonical source and the primary build workflow now
live in the GitHub monorepo.

## Ownership

| Resource | Owner |
|----------|-------|
| CodePipeline (optional Source+Build) | cicd |
| CodeBuild projects (optional) | cicd |
| CodeCommit repos (legacy/transitional) | cicd |
| ECR repositories | cicd |
| S3 artifact bucket | cicd |
| KMS artifact key | cicd |
| Release metadata SSM | cicd |

## Does NOT Own

- ECS task definitions (services)
- ECS services (services)
- ECS cluster (platform)

## Contract

Output: `cicd/v1` — see `schemas/cicd-contract.v1.schema.json`

## Safety Rules

- NO ECS Deploy stage in pipelines
- NO imagedefinitions.json as deploy artifact
- NO ecs:* in IAM policies
- NO iam:PassRole with Resource "*"
- ECR tag immutability enforced
- All image references must use @sha256: digest

## Source/build modes

| Mode | `enable_codecommit` | `enable_codepipeline` | Result |
|---|---:|---:|---|
| Existing legacy default | `true` | `null` | Preserves CodeCommit + CodeBuild + CodePipeline |
| GitHub migration stage 1 | `true` | `false` | Keeps legacy source for retention; removes legacy build pipeline |
| GitHub monorepo target | `false` | `false` | Keeps ECR + SSM; GitHub Actions owns source/build |
| Existing caller with CodeCommit disabled | `false` | `null` | Preserves the prior ECR + SSM-only behavior, including dormant legacy IAM |

`enable_codepipeline=null` intentionally inherits `enable_codecommit` so adding
the variable does not alter historical enablement decisions or resource
ownership. A plan may still show state-address moves and the in-place correction
of `ECR_REPO_NAME`; inspect it rather than assuming a zero diff. Do not flip
either live flag without reviewing the exact destroy set. ECR repositories and release metadata SSM
parameters are independent of both flags. Setting `enable_codepipeline=false`
also removes the now-unused CodeBuild/CodePipeline IAM roles, policies, build
projects, log groups, and pipelines; the artifact bucket and KMS key remain.
State `moved` blocks preserve the existing IAM objects when the new flag is
omitted or first enabled, avoiding name-collision replacements.

GitHub Actions assumes a separately provisioned, deployment-scoped OIDC role.
This module's CodeBuild and CodePipeline roles do not trust GitHub.
