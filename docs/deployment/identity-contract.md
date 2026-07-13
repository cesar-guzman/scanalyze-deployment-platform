# Identity Contract Reference

## Overview

The identity contract aligns Cognito configuration, JWT claims, authorization logic, and deployment binding into a single validated document.

## Contract versions

| Version | Schema | Status | Identifier model |
|---|---|---|---|
| v1 | `schemas/identity-contract.schema.json` | Legacy, retained for compatibility | Readable customer slug and deployment ULID |
| v2 | `schemas/identity-contract.v2.schema.json` | Canonical for new M2M bindings | `cust_<ULID>` and `dep_<ULID>` |

Version selection is explicit. A v1 document is never reinterpreted as v2 and
a legacy customer-only M2M map never authorizes the v2 runtime path.

## Key Rules

1. **M2M v2 deployment binding is enforced**: a mapped or signed
   `custom:deployment_id` must match the running service's
   `SCANALYZE_DEPLOYMENT_ID`.
2. **Cross-account access is forbidden**: `restrictions.cross_account_access` must be `false`.
3. **Cross-deployment access is forbidden**: `restrictions.cross_deployment_access` must be `false`.
4. **No passwords in documentation**: `restrictions.password_in_docs` must be `false`.
5. **Customer ID source must be trusted**: never use a request header, query
   parameter, or payload as identity authority.
6. **Allowed domains are explicit**: Only `bank`, `personal`, `gov`.
7. **M2M is tuple-bound**: a verified access token must match one reviewed
   `client_id`, customer, deployment, and required-scope binding.
8. **Customer and deployment are distinct**: neither identifier can substitute
   for the other.
9. **Route permissions are binding-derived**: configured action scope sets are
   exact and disjoint; scopes present only in a token cannot elevate the
   reviewed client binding.

## Runtime v2 contract

The protected M2M path is:

```text
verified issuer and signature
  -> allowed client and access token
  -> versioned client identity binding
  -> token contains every binding scope
  -> binding scopes resolve to complete configured action sets
  -> mapped customer == expected customer
  -> mapped deployment == expected deployment
  -> any signed identity claims also match
  -> typed AuthContext with granted actions
  -> explicit route policy (read, write, or read+admin)
```

The runtime inputs are:

- `SCANALYZE_DEPLOYMENT_CUSTOMER_ID`
- `SCANALYZE_DEPLOYMENT_ID`
- `M2M_TENANT_RESOLUTION=client_identity_bindings_v1`
- `M2M_CLIENT_IDENTITY_BINDINGS_V1`
- `M2M_ACTION_SCOPE_SETS_V1`

The binding variable is a configuration object, not a secret. Evidence and
examples must still use synthetic identifiers and must never contain a real
client inventory. `M2M_ACTION_SCOPE_SETS_V1` contains exactly the externally
approved `read`, `write`, and `admin` scope sets. Each set is non-empty and the
sets are pairwise disjoint. A binding contains all or none of a set and must
grant at least one action. `M2M_CLIENT_TENANT_MAP` is legacy and cannot
authorize the new path.

ADR-023 / GUG-92 defines the concrete portable action catalog:

- `read` -> `scanalyze.api.v1/read`;
- `write` -> `scanalyze.api.v1/write`; and
- `admin` -> `scanalyze.api.v1/admin`.

GUG-93 owns provider and IaC realization of that catalog. A deployment may
narrow the action set, but must not rename the canonical scopes, embed a
customer-specific taxonomy, or enable the runtime before the provider and
services handoff is reviewed.

Terraform owns the two canonical deployment variables. A service's
`extra_environment` cannot override or duplicate them.

## Enterprise human authorization composition

Identity v2 proves a provider and deployment binding. It does not, by itself,
authorize a human role or resource. The additive
`enterprise-authorization/v1` contract in
[Enterprise Authorization Contract Reference](enterprise-authorization.md)
requires exactly one human path: an active versioned membership with one closed
role, or an active current-version temporary support/break-glass grant from the
authoritative grant store. Both bind the exact `subject`, `customer_id`, and
`deployment_id`; the temporary path also binds a closed operation, resource,
action, and data class. Object authorization, freshness, assurance, and
explicit-deny precedence remain mandatory.

The closed roles are `customer_admin`, `document_operator`,
`document_reviewer`, and `auditor`. Role claims, provider group display names,
and token scopes are not sufficient authority. Sensitive full-PII, export, and
protected artifact operations retain `read+admin` and require
phishing-resistant step-up for humans.

GUG-92 is a repository contract, not runtime enforcement. GUG-93 owns the
provider adapter and version claims; GUG-153 owns backend PDP/PEP enforcement;
GUG-94 owns membership and temporary-grant lifecycle administration; GUG-95
owns UI/E2E; GUG-117 remains the integrated isolation gate. Missing, stale, unknown,
conflicting, or legacy authorization versions fail closed without a default
role or group-name fallback.

## Authorization Modes

| Mode | Description |
|---|---|
| `cognito_jwt` | Default. JWT validation with Cognito User Pool. |
| `iam` | IAM-based authorization for service-to-service calls. |
| `api_key` | API key-based authorization (for external integrations). |

## Validation

```bash
python scripts/deployment/validate-identity-contract.py /path/to/contract.yaml
```

The validator selects the schema from `schema_version` and applies semantic
checks that JSON Schema cannot express by itself, such as binding equality and
unique client ownership.

## Evidence and live boundary

Passing local schema, runtime, or Terraform mock tests proves repository
behavior only. Live M2M and human enterprise enablement remain blocked until
GUG-93 provides the authoritative edge-identity-to-services handoff, Cognito
and API Gateway audiences/claims, canonical scope and policy version claims,
and sanitized non-production evidence. Production remains NO-GO.

Use [M2M Identity v2 Migration Inventory and Runbook](m2m-identity-v2-migration.md)
to migrate each deployment without accepting legacy fallback or storing live
identity inventories in Git.
