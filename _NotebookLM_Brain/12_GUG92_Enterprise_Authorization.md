# GUG-92 — Portable Enterprise Authorization and User Lifecycle

> **Sanitized source for NotebookLM**
> **Canonical decision:** ADR-023
> **Repository scope:** policy contract and documentation only
> **Production:** NO-GO

## Why this package exists

Authentication proves that a token was accepted. It does not prove that the
principal has a current enterprise grant for one action, one deployment, and
one object. GUG-92 closes the architecture and contract gap between identity,
enterprise roles, exact customer/deployment isolation, object authorization,
user lifecycle, and temporary privileged access.

The answer is portable by design. The source contract contains no real customer,
deployment, cloud account, region, identity pool, client, email domain, or
resource instance. Every deployment consumes the same role/action catalogs,
schema, validator, and fail-closed semantics through a reviewed identity-provider
adapter and external authoritative bindings.

## Canonical decision

Scanalyze combines:

- a closed RBAC catalog for understandable enterprise duties;
- mandatory ABAC for `customer_id`, `deployment_id`, object ownership, grant
  freshness, data classification, and authentication assurance;
- a policy decision point that denies by default;
- policy enforcement before every protected read, write, administration,
  full-PII, export, or artifact effect; and
- versioned membership and workload grants so stale tokens can be denied.

A human request selects exactly one authorization path: an active enterprise
membership or an active temporary support/break-glass grant. Temporary grants
come only from the authoritative grant store and bind the exact subject,
customer, deployment, type, state, version, and closed operation allowlist.
The v1 allowlist selects only read-only diagnostic entries and their explicit
metadata/masked/aggregated data classes. They do not assign or inherit a role;
ABAC, object authorization, and explicit denies always prevail.

An allow decision requires all applicable checks. A role or scope never
overrides exact tenant/deployment or object ownership.

## Actions and scopes

| Action | OAuth scope | Boundary |
|---|---|---|
| `read` | `scanalyze.api.v1/read` | Read an otherwise authorized resource at an allowed data classification |
| `write` | `scanalyze.api.v1/write` | Create or mutate an otherwise authorized resource/state transition |
| `admin` | `scanalyze.api.v1/admin` | Run one explicitly cataloged administrative or sensitive operation |

The action catalog is closed and has no wildcard. Scopes present only in a
token cannot elevate a human membership, temporary-grant allowlist, or M2M
workload binding. Human API access uses access tokens; an ID token is not an
API credential.

The supported v1 catalog values are
`enterprise-authorization.v1`, `scanalyze.api.v1`, and
`enterprise-roles.v1`. The reviewed policy digest uses RFC 8785 canonical JSON
and SHA-256; a request-provided digest is never authority.

## Credentials, reset, federation, and SCIM

The application stores no passwords. Provider-managed password authentication,
when enabled, uses a 14-character minimum, compromised-password detection, and
no static defaults. Privileged operations require phishing-resistant MFA.

Password reset/recovery returns a generic outcome, cannot change any
authorization binding, revokes sessions, reconciles the current membership,
emits sanitized audit evidence, and never logs recovery secrets. Federation
and SCIM remain future reviewed adapters and cannot directly grant authority.

## Human roles

| Role | Intended duty | Important denials |
|---|---|---|
| `customer_admin` | Administer deployment-local memberships and approved settings; use ordinary owned-resource operations | No cross-deployment access, object bypass, self-approval, shared support, or implicit full-PII/export |
| `document_operator` | Create, process, update, and organize owned documents/batches | No `admin`, lifecycle administration, full-PII, export, or protected artifact download |
| `document_reviewer` | Read owned resources and write explicit review decisions | No document/batch/profile mutation, `admin`, membership management, unmasked sensitive result, export, or protected artifact download |
| `auditor` | Read audit metadata, aggregate metrics, and approved audit evidence | Read-only; no masked/content/PII resource views, mutation, export, artifact download, or privileged grants |

There are no customer-specific roles in v1. A new role is a reviewed contract
version, not a source-code fork.

## Exact isolation and object authorization

Every protected resource decision proves both equalities:

```text
resource.customer_id == auth.customer_id
resource.deployment_id == auth.deployment_id
```

Both values come from validated internal context and authoritative records.
Headers, URLs, query parameters, payloads, cookies, email domains, group display
names, legacy tenant fields, route hints, and S3 prefixes do not establish
authority.

ADR-021 remains mandatory for documents, batches, every batch member, results,
exports, and artifacts. An accessible batch cannot carry a foreign document
across the boundary. `customer_admin` is not a cross-object or cross-deployment
superuser.

## Sensitive operations

These operations keep the strict `read` + `admin` policy and require
phishing-resistant step-up authentication for humans:

- `results.read_full`;
- `exports.execute`; and
- `artifacts.download`.

Every object or export member is authorized independently. A missing, unbound,
foreign, or conflicting member fails the complete operation. A protected
artifact locator comes from authorized stored metadata, never the request.

## Human lifecycle

The states are:

```text
invited -> active -> suspended -> active
invited -> expired
invited | active | suspended -> revoked
```

`expired` and `revoked` are terminal. Role change, suspension, and revocation
increment the membership version. Sensitive changes revoke sessions, and a
token with an older membership version is denied. A revoked member returns only
through a new reviewed invitation, never by reactivation.

Self-signup, self-promotion, and self-approval are forbidden. The last active
customer administrator cannot be removed without an approved replacement in
the same customer/deployment.

Invitations are single-use, bind the exact subject/customer/deployment, expire
within 24 hours, require recent phishing-resistant MFA, and deny replay.

## Bootstrap

First-administrator bootstrap is a one-use, expiring capability. It starts only
after the exact customer and deployment are known from an authoritative source,
requires two independent approvers, forbids self-approval, requires
phishing-resistant MFA, binds the exact subject, expires within 15 minutes,
consumes atomically with replay denial, is audited, and becomes invalid on use
or expiry.

Failure leaves the deployment blocked. It never falls back to a shared platform
administrator or self-signup.

## Temporary support

Support has no standing role. Each grant requires a case, customer approval,
exact subject/customer/deployment, purpose, allowlisted operations,
phishing-resistant MFA, expiry within one hour, current state/version, and
audit. It automatically revokes on expiry or case closure. Full PII, exports,
and protected artifacts are unconditionally denied in v1, and a service
principal cannot receive support access.

## Break-glass

Emergency access is human-only, incident-bound, dual-approved, exact to one
deployment and operation set, phishing-resistant, short-lived, alerted,
automatically revoked, and independently reviewed afterward. It is not a human
role, an M2M permission, or a substitute for support.

It binds the exact subject, expires within 15 minutes, checks state/version on
every use, and alerts on activation and use. Full PII, export, and protected
artifact download are unconditionally forbidden in v1. Break-glass cannot
administer lifecycle/roles, change ownership, or mint privileged grants.
Missing approval, audit, revocation, or policy dependencies cause denial, not a
standing emergency credential.

## Service principals

Service identities remain on ADR-020's M2M path. A binding is exact to workload,
customer, deployment, environment, and reviewed actions; the default action set
is empty. A service principal cannot inherit a human role, impersonate a user,
manage human lifecycle, or receive support or break-glass.

Read-only M2M cannot write, export, retrieve full PII, or download a protected
artifact. Token-only extra scopes cannot elevate the configured binding.

## Provider portability

A provider adapter validates signed access-token inputs and maps immutable
provider claims to the internal contract. It may narrow authority, but cannot:

- add a role or action;
- infer customer/deployment from a domain, display name, or request;
- treat an unknown or future policy version as current;
- accept stale membership/grant versions;
- bypass step-up or object authorization; or
- embed customer/account variants in the source policy.

This keeps the decision reproducible across customers, accounts, regions, and
supported identity providers while preserving fail-closed behavior.

## Migration boundary

GUG-92 performs no live migration. A future per-deployment process must:

1. inventory mappings, memberships, groups, scopes, grants, sessions, and route
   enforcement outside Git;
2. classify fully bound, partial, stale, ambiguous, conflicting, orphaned,
   legacy-only, and unsupported records;
3. keep access disabled for anything not fully and exactly bound;
4. create explicit memberships/provider mappings without inference;
5. issue new access tokens only after reviewed provider integration;
6. test two synthetic deployments and obtain separate authorization for live
   non-production isolation; and
7. revoke old sessions and mappings before allowlisting the deployment.

There is no group-name, email-domain, customer-only, ID-token, default-role, or
stale-token fallback.

## Downstream work

- **GUG-93** implements reusable Cognito/API Gateway/Terraform adapters, access
  token and version claims, services handoff, and session revocation without
  embedded customer/account values.
- **GUG-94** implements invitation, activation, role change, suspension,
  offboarding, bootstrap, support, break-glass, concurrency protection, and
  sanitized audit in administrative APIs.
- **GUG-153** implements the centralized backend PDP/PEP, exact route mapping,
  membership/temporary-grant resolution, freshness checks, and deny precedence.
- **GUG-95** implements the user/role console and privilege E2E without making
  UI state an authority.
- **GUG-117** remains the integration gate for complete route coverage,
  two-deployment isolation, stale-grant revocation, sensitive operations,
  recovery, and evidence review.

If no issue explicitly owns a runtime enforcement surface, enablement remains
blocked until ownership is assigned. GUG-92 does not absorb that implementation
silently.

## Evidence taxonomy

| State | Meaning for GUG-92 |
|---|---|
| **Implemented** | The exact reviewed revision contains the versioned portable contract, validator, synthetic fixtures, ADR, and reference. It does not mean runtime routes enforce it. |
| **Locally validated** | Named offline tests and repository gates pass for that revision. No provider or cloud behavior is implied. |
| **CI validated** | Required checks pass for the exact commit. It is not live identity, lifecycle, or isolation evidence. |
| **Live validated** | Explicitly authorized non-production evidence proves provider claims, lifecycle, revocation, tenant/object enforcement, and privileged workflows. This source contains no such evidence. |
| **Blocked** | Provider/IaC integration, runtime enforcement, administrative workflows, migration, and live isolation remain separately controlled. |

An ADR alone is a decision. A green local suite is not CI, and a green CI run is
not Live validated. Production remains **NO-GO**.

## Sanitization rules

NotebookLM may ingest this curated file, but not provider exports, real user or
group lists, tokens, invitation references, MFA material, customer/account
identifiers, logs, Terraform plans/state, documents, PII, extracted payloads,
screenshots, or operational evidence. Unknown information stays **Unknown** or
**Blocked**; it is never completed by inference.

## Canonical sources

- [ADR-023](../ADR/ADR-023-enterprise-authorization-and-user-lifecycle.md)
- [Enterprise Authorization Contract Reference](../docs/deployment/enterprise-authorization.md)
- [ADR-020](../ADR/ADR-020-versioned-m2m-identity-binding.md)
- [ADR-021](../ADR/ADR-021-object-level-authorization.md)
- [Production Readiness Threat Model](../docs/production-readiness/threat-model.md)

This file explains those sources; it does not override them or store execution
evidence.
