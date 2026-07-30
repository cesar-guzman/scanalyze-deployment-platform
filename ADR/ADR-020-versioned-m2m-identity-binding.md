# ADR-020: Versioned M2M Customer and Deployment Binding

- **Status**: Accepted
- **Date**: 2026-07-12
- **Scope**: GUG-102 WP1 repository implementation
- **Live enablement**: Blocked pending GUG-93 and non-production evidence

## Context

The ingest API historically resolved a machine principal with a
`client_id -> customer_id` map. That path did not prove that the customer was
the customer assigned to the running deployment, did not bind a deployment,
and did not require configured scopes before producing an authorization
context.

The infrastructure contract also substituted `deployment_id` for
`SCANALYZE_DEPLOYMENT_CUSTOMER_ID`. Existing public contracts disagree on the
customer identifier grammar: the identity v1 contract accepts a readable slug,
while deployment request and record v1 use `cust_<ULID>`. Tightening the v1
identity schema or silently accepting both formats would make the security
boundary ambiguous.

## Decision

1. Preserve the existing identity v1 schema as a legacy contract. Do not alter
   its identifier grammar in place.
2. Add an identity v2 schema that requires canonical `cust_<ULID>` and
   `dep_<ULID>` identities, explicit fail-closed restrictions, a versioned
   `read`/`write`/`admin` action-to-scope policy, and an M2M binding containing
   `client_id`, customer, deployment, and non-empty scopes.
3. Add the versioned runtime configuration
   `M2M_CLIENT_IDENTITY_BINDINGS_V1`. The legacy
   `M2M_CLIENT_TENANT_MAP` cannot authorize a machine principal.
4. Require a verified M2M access token, an allowed client, every scope declared
   by its binding, exact mapped-versus-runtime customer and deployment, and no
   contradictory signed identity claim.
5. Derive route actions only from the reviewed binding. Scopes present only in
   the token cannot elevate permissions. Bindings must include all or none of
   each configured action scope set, and export or full-PII operations require
   both `read` and `admin`.
6. Produce one typed internal authorization context. Downstream handlers may
   consume its read-only compatibility aliases but may not infer identity from
   a request header, query parameter, or payload.
7. Terraform services receive `customer_id` and `deployment_id` as distinct
   required inputs and render both canonical environment variables. Service
   extensions cannot override or duplicate those variables.
8. Reject legacy identity-bearing headers and top-level payload fields instead
   of treating them as authority or silently discarding them.

## Compatibility and migration

- No existing customer slug is converted automatically.
- No data, Cognito, or live task definition is migrated by this decision.
- A legacy M2M configuration is migration-required and remains disabled until
  a reviewed v2 binding exists.
- Object records without customer/deployment ownership remain the separate
  GUG-114 work package and must fail closed or follow an approved migration or
  quarantine procedure.

The current release DAG creates edge identity after services. It therefore
cannot yet deliver a newly created M2M client identifier to the services layer.
GUG-93 must establish the authoritative control-plane handoff and Cognito/API
Gateway audience and claim configuration. GUG-92/GUG-93 own the concrete scope
taxonomy; this work package deliberately consumes that taxonomy through
versioned configuration instead of hardcoding scope names. Until those inputs
exist, this ADR authorizes repository implementation and local validation, not
live M2M enablement.

## Security consequences

- A customer-only mapping is no longer evidence of deployment authorization.
- Missing, malformed, mismatched, unscoped, or request-controlled bindings are
  denied.
- A versioned contract makes migration explicit and reviewable.
- Every protected route declares one explicit `read`, `write`, or
  `read+admin` policy for M2M principals. Human and local-test behavior remains
  unchanged by this work package.
- The runtime enforces the configured action scope sets, but live configuration
  remains blocked until the canonical GUG-92/GUG-93 taxonomy is approved.

## Validation and evidence boundary

Required repository evidence includes positive and negative runtime tests,
v1/v2 schema tests, Terraform mock-provider tests, static security gates, and
the complete ingest API suite. Those results are local evidence only. No AWS,
Cognito, real token, live Terraform plan, deployment, or production evidence is
created by this ADR.

## Rollback

Revert the reviewed change as a normal Git change. Do not restore the legacy
customer-only map as a compatibility bypass. If the v2 path must be withdrawn,
M2M remains disabled while user-token behavior stays on its separately reviewed
contract.
