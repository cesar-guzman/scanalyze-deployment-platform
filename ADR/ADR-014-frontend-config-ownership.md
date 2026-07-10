# ADR-014: Frontend Configuration Ownership

- **Status**: Accepted
- **Date**: 2026-07-10

## Context

Frontend applications need runtime configuration (API endpoint, Cognito pool, feature flags). In early development, these were hardcoded. They need to be deployment-specific and owned by infrastructure.

## Decision

Terraform is the single owner of frontend `config.json`. The schema is defined in `schemas/frontend-config.schema.json`. The config is rendered by the `edge` Terraform layer and deployed to S3. No manual editing.

## Consequences

- Frontend config is always consistent with the deployed backend.
- Changes require a Terraform plan/apply cycle.
- Config drift is detectable via schema validation.
