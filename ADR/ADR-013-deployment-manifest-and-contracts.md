# ADR-013: Deployment Manifest and Contract Schemas

- **Status**: Accepted
- **Date**: 2026-07-10
- **Deciders**: César Guzmán, Platform Engineering

## Context

Each Scanalyze deployment requires customer-specific configuration: AWS account ID, region, ECR prefix, Cognito settings, feature flags, etc. Previously, these lived in ad-hoc `.tfvars` files with no schema validation, no cross-field consistency checks, and no machine-readable contract.

## Decision

1. **Deployment Manifest**: A single YAML file per deployment (`schemas/deployment-manifest.schema.json`) with strict JSON Schema validation including:
   - 12-digit AWS account ID (not `000000000000`)
   - Digest-pinned base images (`latest` forbidden)
   - ECR prefix must start with sanitized `deployment_id`
   - OIDC role ARN account must match `aws_account_id`

2. **SSM Contract Schema**: Formalizes the SSM Parameter Store interface between Terraform layers (`schemas/ssm-contract.schema.json`) with producer/consumer tracking.

3. **Identity Contract Schema**: Aligns Cognito, claims, authorization modes, and deployment binding (`schemas/identity-contract.schema.json`) with fail-closed restrictions (no cross-account, no cross-deployment, no passwords in docs).

4. **Frontend Config Schema**: Defines the exact shape of `config.json` that Terraform produces for the frontend (`schemas/frontend-config.schema.json`).

5. **Real manifests never enter Git**: Only synthetic examples are committed. Real deployment manifests live outside the repository.

## Consequences

- Every deployment is validated before any operation.
- Cross-field consistency is machine-verified.
- Inter-layer contracts are explicit, not implicit.
- Schema evolution is versioned via `schema_version`.

## Alternatives Considered

1. **`.tfvars` only**: Rejected — no cross-field validation, no schema versioning, no inter-layer contracts.
2. **JSON manifests**: Rejected — YAML is more readable for operators; JSON Schema validates both.
