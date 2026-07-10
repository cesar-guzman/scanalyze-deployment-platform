# ADR-015: Identity Contract

- **Status**: Accepted
- **Date**: 2026-07-10

## Context

Scanalyze uses Amazon Cognito for authentication. The mapping between Cognito claims, deployment_id, customer_id, and allowed domains was implicit. Cross-deployment and cross-account access were not explicitly prevented by contract.

## Decision

Introduce `schemas/identity-contract.schema.json` that:

1. Binds `deployment_id` to Cognito via `custom:deployment_id` claim.
2. Enforces `enforce_deployment_binding: true` by default.
3. Explicitly forbids `cross_account_access`, `cross_deployment_access`, and `password_in_docs`.
4. Requires `customer_id_source` to be `claim`, `client_id_map`, or `static` — never `payload` (untrusted).
5. Lists `allowed_domains` per contract.

## Consequences

- Identity isolation is machine-verifiable.
- Misconfiguration is caught before deployment.
- Token validation rules are documented, not guessed.
