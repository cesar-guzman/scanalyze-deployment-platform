# CI/CD Module

Build-only pipelines for Scanalyze microservices.

## Ownership

| Resource | Owner |
|----------|-------|
| CodePipeline (Source+Build) | cicd |
| CodeBuild projects | cicd |
| CodeCommit repos (sandbox) | cicd |
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
