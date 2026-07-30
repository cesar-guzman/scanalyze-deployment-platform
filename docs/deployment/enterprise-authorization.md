# Enterprise Authorization Contract Reference

> **Decision:** ADR-023 / GUG-92
> **Contract:** `enterprise-authorization/v1`
> **Status:** portable repository contract; downstream runtime integration blocked
> **Production:** NO-GO

## Purpose

This reference explains the provider-neutral authorization and human membership
contract that every Scanalyze enterprise deployment must consume. The source
policy is reusable without editing customer-, account-, region-, identity-pool-,
or client-specific values into the repository.

The contract combines:

- a closed role-based access control catalog for enterprise duties;
- mandatory attribute-based checks for exact tenant, deployment, object,
  freshness, assurance, and data classification;
- versioned OAuth action scopes;
- a revocable human membership lifecycle;
- bounded bootstrap, support, and break-glass workflows; and
- explicit evidence and migration boundaries.

This file does not configure an identity provider or prove that a runtime route
enforces the policy. GUG-93 and GUG-94 are downstream consumers. GUG-117 remains
the integration and isolation gate.

## Canonical artifacts

| Artifact | Purpose |
|---|---|
| `ADR/ADR-023-enterprise-authorization-and-user-lifecycle.md` | Architectural decision, alternatives, trust boundaries, and downstream ownership |
| `schemas/enterprise-authorization.v1.schema.json` | Strict structural contract |
| `policies/authorization/enterprise-authorization.v1.json` | Canonical provider-neutral policy instance |
| `tooling/validate_enterprise_authorization.py` | Semantic and portability validation |
| `fixtures/valid/enterprise-authorization-v1-synthetic.json` | Sanitized positive conformance fixture |
| `fixtures/invalid/enterprise-authorization-v1-*.json` | Fail-closed negative fixtures |
| `tests/test_gug92_enterprise_authorization.py` | Contract, semantic, portability, and documentation regression suite |

All deployment-specific bindings remain outside the source policy. A live
inventory belongs only in the approved evidence system and must not be copied
into Git, CI logs, Linear, or NotebookLM.

## Decision algorithm

A policy enforcement point denies before a protected effect unless every step
succeeds:

1. Validate the access token using the expected provider adapter, issuer,
   audience, signature, algorithm, expiry, and token type.
2. Normalize the validated subject and principal type into an immutable internal
   authorization context.
3. Load exactly one authoritative path: membership, temporary human grant, or
   M2M workload binding.
4. Require a supported contract version and current policy, role, scope,
   membership/grant version, and policy digest.
5. Require an active/current membership or temporary grant, or a valid workload
   binding; conflicting paths deny.
6. Resolve the requested API operation to one closed resource/action rule.
7. Require the membership role, temporary-grant operation allowlist, or
   workload binding to contain every required action/operation.
8. Compare exact trusted `customer_id` and `deployment_id` values.
9. Authorize the object, batch, membership, export member, or artifact under
   ADR-021; a role never overrides ownership.
10. Enforce data-class and authentication-assurance requirements, including
    step-up for sensitive operations.
11. Apply explicit denies and temporary-grant restrictions.
12. Record a sanitized decision event and continue only on an explicit allow.

Missing, malformed, unknown, stale, conflicting, foreign, unsupported,
future-version, or legacy-only input is a denial. A dependency failure is not a
reason to infer authority or use a cached default role.

## Canonical identity attributes

The provider adapter constructs, and protected handlers consume, these logical
attributes:

| Attribute | Source and rule |
|---|---|
| `subject` | Immutable identifier in the GUG-102 `AuthContext`; never an email display value |
| `principal_type` | Closed type: `user` or `m2m`; `local_mock` is test-only and unknown types deny |
| `customer_id` | Authoritative membership/workload binding and validated internal context |
| `deployment_id` | Authoritative membership/workload binding and validated internal context |
| `role_id` | Exactly one role on the versioned active membership path; never a request field or provider group display name |
| `temporary_grant_type`, state, version, and reference | Required only on the exactly-one temporary path; values come from the authoritative grant store |
| `actions` | Derived from the reviewed role policy, temporary-grant operation allowlist, or M2M binding; not from token-only extra scopes |
| `authz_schema_version` | Supported canonical authorization schema version |
| `scope_catalog_version` | Supported action-to-scope catalog version |
| `role_catalog_version` | Required for a membership-path `user`; supported human role catalog version |
| `membership_version` | Required for a membership-path `user`; must equal the current authoritative membership |
| `grant_version` | Required for `m2m`; must equal the current authoritative workload grant |
| `policy_version` and `policy_digest` | Common fields that identify the exact reviewed policy |
| authentication assurance and time | Validated provider evidence used for step-up; never request-supplied |

The concrete provider claim names are adapter configuration. They are not part
of business authorization logic. Provider group names, headers, URL/query
parameters, payload fields, cookies, route hints, legacy tenant aliases, and
email domains never establish `customer_id`, `deployment_id`, role, action, or
assurance.

Human API requests use access tokens. An ID token describes an authentication
session and is not accepted as an API authorization credential.

The v1 catalog allowlist is exact:
`authz_schema_version=enterprise-authorization.v1`,
`scope_catalog_version=scanalyze.api.v1`, and
`role_catalog_version=enterprise-roles.v1`. `policy_digest` is SHA-256 over the
reviewed policy after RFC 8785 canonicalization, compared in constant time;
request-supplied digest values are never authority.

## Credential, reset, and provisioning lifecycle

Scanalyze stores no application password. Provider-managed password
authentication, when enabled, requires at least 14 characters, compromised
password detection, and no static default password. Privileged operations use
phishing-resistant MFA and the bounded authentication age in the policy.

Password reset and recovery return generic enumeration-safe outcomes. They
cannot change role, customer, deployment, membership, or grant authority; they
revoke sessions, reconcile the current membership before new access, emit
sanitized audit evidence, and never log recovery secrets or factors.

SAML/OIDC federation and SCIM remain future reviewed provider adapters. A
federated attribute or SCIM event is input for reconciliation, never direct
authorization, and unsupported adapters leave access disabled.

## Actions and scopes

The action universe is closed and pairwise disjoint:

| Action | OAuth scope | Use |
|---|---|---|
| `read` | `scanalyze.api.v1/read` | Read an authorized resource at an allowed data classification |
| `write` | `scanalyze.api.v1/write` | Create or mutate an authorized resource or state transition |
| `admin` | `scanalyze.api.v1/admin` | Execute an explicitly cataloged administrative or sensitive operation |

`admin` is not a wildcard or a cross-deployment superuser. Extra scopes in a
token cannot grant an action absent from the active membership, temporary-grant
operation allowlist, or workload binding. Partial, overlapping, wildcard,
unknown, or unversioned action sets are invalid.

## Human roles

The role universe is exactly:

### `customer_admin`

May administer memberships and deployment-local settings and may use ordinary
owned document/batch operations. Administrative operations remain individually
cataloged. This role cannot:

- cross `customer_id` or `deployment_id`;
- bypass document/batch ownership;
- approve its own elevation or privileged access request;
- silently remove the last active customer administrator;
- gain standing support or break-glass access; or
- reduce a sensitive operation below `read` + `admin` plus step-up.

### `document_operator`

May create, process, update, and organize owned documents and batches using
`read` and `write`. It has no `admin` and cannot manage memberships, execute an
export, retrieve full PII, or download a protected artifact.

### `document_reviewer`

May read owned resources and write explicit review decisions. It has no
document/batch/profile mutation, `admin`, membership administration, unmasked
result, export, or protected artifact permission.

### `auditor`

Uses `read` only for audit metadata, aggregate metrics, and approved audit
evidence. It cannot access masked/content/PII resource views, mutate resources,
exports, protected artifacts, role administration, support, or break-glass.

No custom customer role exists in v1. A new role or permission is a new reviewed
policy version, not a deployment-specific source edit.

### Exact v1 role matrix

The table below is normative with the JSON policy. A resource/action/data-class
combination not listed is denied; actions do not imply one another. Sensitive
operation, ABAC, object, freshness, and assurance checks still apply.

| Role | Resource(s) | Actions | Data classes |
|---|---|---|---|
| `customer_admin` | `documents`, `batches`, `employee_profiles` | `read`, `write`, `admin` | `metadata`, `masked`, `content`, `pii` |
| `customer_admin` | `results` | `read`, `admin` | `metadata`, `masked`, `content`, `pii` |
| `customer_admin` | `reviews` | `read`, `write`, `admin` | `metadata`, `masked`, `content` |
| `customer_admin` | `exports` | `read`, `admin` | `metadata`, `content`, `pii` |
| `customer_admin` | `deployment_configuration` | `read`, `admin` | `metadata` |
| `customer_admin` | `metrics` | `read`, `admin` | `metadata`, `aggregated` |
| `customer_admin` | `authorization_administration` | `read`, `admin` | `metadata` |
| `customer_admin` | `audit_log` | `read` | `metadata` |
| `document_operator` | `documents`, `batches` | `read`, `write` | `metadata`, `masked`, `content` |
| `document_operator` | `employee_profiles` | `read`, `write` | `metadata`, `masked` |
| `document_operator` | `results`, `reviews` | `read` | `metadata`, `masked` |
| `document_operator` | `metrics` | `read` | `metadata`, `aggregated` |
| `document_reviewer` | `documents`, `batches`, `employee_profiles`, `results` | `read` | `metadata`, `masked` |
| `document_reviewer` | `reviews` | `read`, `write` | `metadata`, `masked` |
| `auditor` | `audit_log` | `read` | `metadata` |
| `auditor` | `metrics` | `read` | `metadata`, `aggregated` |

## Mandatory tenant and object attributes

Every decision requires exact equality for both bindings:

```text
resource.customer_id == auth.customer_id
resource.deployment_id == auth.deployment_id
```

The running deployment binding and authoritative membership/workload binding
must also agree. Missing one field is not a partial success. A valid customer
with the wrong deployment, or a valid deployment with the wrong customer, is
foreign authority and must produce the same public not-found/denied behavior as
an absent resource when existence could otherwise be enumerated.

Documents, batches, every batch member, exports, results, and artifacts retain
ADR-021 authorization. Access to an authorized batch never authorizes an
unbound or foreign member. Lists, searches, and pagination must enforce both
bindings at the storage query boundary.

## Resource/action matrix

| Operation family | Required action | Additional conditions |
|---|---|---|
| Document/batch metadata read | `read` | Exact owner tuple and object authorization |
| Document/batch create or mutation | `write` | Owner tuple from trusted context, immutable ownership, allowed state transition |
| Employee-profile read or mutation | `read` / `write` | Exact owner tuple, ADR-021 authorization, and permitted data class |
| Masked result read | `read` | Exact object authorization and role data class |
| Review read or decision | `read` / `write` | Exact object authorization and review-state transition |
| Export metadata read | `read` | Same deployment; downloading/executing remains sensitive |
| Deployment configuration read/change | `read` / `admin` | Customer administrator and exact deployment; no ownership/IAM bypass |
| Metrics read/admin | `read` / `admin` | Deployment-scoped aggregate data only; no raw PII |
| Membership and role catalog read | `read` | Same deployment and permitted role |
| Invite or activate membership | `admin` | Authorized administrator, one-use invitation, exact binding, no self-approval, audit |
| Change role | `admin` | No self-elevation, last-admin rule, version increment, session revocation, audit |
| Suspend or revoke membership | `admin` | Exact membership, version increment, session revocation, enumeration-safe result |
| Read audit metadata/masked evidence | `read` | Data classification allowed for the role and same deployment |
| `results.read_full` | `read` + `admin` | Exact object authorization and phishing-resistant step-up authentication |
| `exports.execute` | `read` + `admin` | Every member authorized; no partial export; phishing-resistant step-up |
| `artifacts.download` | `read` + `admin` | Authorized stored locator; phishing-resistant step-up; never request-supplied key |

The first downstream route inventory must map every protected endpoint to one
of these canonical operation families. An unmapped route denies. New operations
require reviewed policy and regression tests before runtime enablement.

## Sensitive operations and step-up

`results.read_full`, `exports.execute`, and `artifacts.download` always require:

- both `read` and `admin`;
- the active membership or M2M workload binding and current versions; a
  temporary support/break-glass path always denies these operations;
- exact customer/deployment and object authorization;
- phishing-resistant MFA for human principals with a sufficiently recent
  authentication event;
- no support or break-glass restriction that forbids the operation; and
- a sanitized audit decision.

A standard authenticated session or the `customer_admin` role alone is
insufficient. The PEP must deny if step-up evidence is missing, stale,
unsupported, or cannot be verified.

## Human lifecycle

| State | Can authorize ordinary operations? | Allowed next state |
|---|---:|---|
| `invited` | No | `active`, `expired`, `revoked` |
| `active` | Yes, subject to all policy checks | `suspended`, `revoked` |
| `suspended` | No | `active`, `revoked` |
| `expired` | No | None; terminal |
| `revoked` | No | None; terminal |

Role change, suspension, and revocation increment `membership_version`.
Sensitive changes revoke sessions. Reusing a token with an older version fails
closed. A revoked membership is never reactivated; a reviewed new invitation is
required. The last active `customer_admin` cannot be removed unless an approved
replacement in the same deployment is ready.

### Invitation and activation

- Self-signup is disabled.
- The invitation is single-use, expires within 24 hours, binds the exact
  subject/customer/deployment, and carries no secret in logs.
- Customer and deployment are selected only from an authoritative record.
- Activation validates the immutable subject and required MFA.
- Consumption is atomic; a replay or conflicting subject denies.
- The provider and internal membership are reconciled before activation is
  reported as successful.

### Role changes and offboarding

- The requester must already hold the exact administrative permission.
- Self-promotion and self-approval are forbidden.
- Updates use expected current versions to prevent lost-update or replay.
- Suspension and revocation stop authorization before any protected effect.
- Session revocation and membership-version change are both required; neither
  is a substitute for the other.
- Provider deactivation or a future SCIM event is input to a reviewed adapter,
  not authority to infer another membership.

## Bootstrap

First-administrator bootstrap is a one-use, expiring capability created only
after an authoritative customer/deployment record exists. It requires two
independent approvers, forbids self-approval, binds the exact human subject,
expires within 15 minutes, requires phishing-resistant MFA no older than five
minutes, consumes atomically, denies replay, is audited, and is invalid after
use or expiry. It cannot grant support,
break-glass, cross-deployment access, or a role outside the closed catalog.

If bootstrap cannot complete safely, the deployment remains blocked. There is
no shared platform-admin or self-signup fallback.

## Temporary support access

Temporary access is an alternative capability path for an authenticated human,
not a role assignment or role inheritance. Exactly one path is evaluated. The
authoritative grant store supplies the active grant type/state/version and
exact subject/customer/deployment binding. Its allowlist can only reference the
closed read-only diagnostic catalog: document/batch metadata, masked results,
review metadata, deployment configuration, aggregate metrics, or audit metadata.
Unknown operations/data classes, conflicting paths, stale grants, ABAC failures,
object-authorization failures, or any explicit deny prevail.

Support has no standing role. A grant contains an approved case, customer
approval, exact subject/customer/deployment, purpose, operation allowlist,
phishing-resistant MFA no older than five minutes, issue/expiry times, current
grant version, and audit reference. It expires within one hour, checks current
state/version on every use, and automatically revokes on expiry or case closure.

Full PII, export, and protected artifact access are unconditionally denied to
support in v1. A service
principal cannot receive support access. Support cannot manage memberships,
alter ownership, or create another privileged grant.

## Break-glass

Break-glass is a human-only incident workflow with:

- a declared incident and exact required operations;
- two independent approvals;
- exact subject/customer/deployment binding;
- phishing-resistant MFA;
- expiry within 15 minutes, current state/version checks, and automatic revocation;
- alerting on issue and use; and
- mandatory independent post-event review.

There is no standing emergency role. Full PII, export, and protected artifact
download remain unconditionally forbidden in v1. Missing approval, audit, revocation, or
policy dependencies cause denial rather than creation of a reusable emergency
credential.

Break-glass cannot administer memberships or roles, mutate ownership, or mint
support/break-glass grants. Any identity recovery is a separate target-bound,
approved workflow and cannot be smuggled through this capability.

## Service principals

Service principals use the versioned M2M contract from ADR-020. The binding is
exact to workload, `customer_id`, `deployment_id`, and environment. Default
actions are empty. A service principal cannot receive a human role, administer
human lifecycle, impersonate a human, or receive support or break-glass access.

The action scopes in this reference are the canonical catalog consumed by the
M2M configuration. Token-only extra scopes never elevate the reviewed binding.

## Portable provider adapter

Every provider implementation must:

1. validate token signature, issuer, audience, algorithm, token type, times, and
   provider-specific revocation inputs;
2. map immutable signed claims to the canonical internal fields;
3. validate exact membership/workload and policy versions;
4. reject conflicting provider and authoritative values;
5. keep provider names and customer/account identifiers outside business policy;
6. narrow or deny authority when provider capabilities differ; and
7. expose sanitized reason categories only.

The adapter must not add roles, translate an unknown version as v1, infer a
customer from a domain, accept group display names as canonical, or copy a
request field into the authorization context.

## Fail-closed denial categories

Stable internal categories may include `missing`, `malformed`, `unknown`,
`stale`, `conflicting`, `foreign`, `legacy_only`, `unsupported_principal`,
`insufficient_action`, `insufficient_assurance`, and `explicit_deny`.

External errors remain generic where detail could reveal membership or resource
existence. Logs and general evidence never contain tokens, cookies, invitation
secrets, MFA values, documents, PII, extracted payloads, raw provider claims,
S3 locators, presigned URLs, or request bodies.

## Migration by deployment

1. Produce a report-only inventory outside Git for provider mappings,
   memberships, groups, scopes, grants, sessions, and route PEPs.
2. Classify records as fully bound, partially bound, stale, ambiguous,
   conflicting, orphaned, legacy-only, or unsupported.
3. Keep human authorization disabled where the provider adapter, versions,
   route mapping, or exact customer/deployment binding is incomplete.
4. Create explicit memberships and provider mappings; never infer from email
   domain, group display name, historical behavior, or adjacent deployment.
5. Issue new access tokens with supported version claims after GUG-93 is
   reviewed.
6. Validate positive and negative behavior using two synthetic deployments.
7. Revoke old sessions and legacy mappings before allowlisting a deployment.
8. Obtain separate authorization for sanitized non-production isolation proof.

No live user, group, token, client, grant, or session migration is authorized by
this reference.

## Downstream implementation checklist

### GUG-93: identity provider, API Gateway, and IaC

- reusable provider resources without embedded customer/account values;
- access-token-only API authorization;
- canonical action scopes and version claims;
- immutable subject and exact customer/deployment adapter mapping;
- protected services handoff and session revocation integration;
- short-lived token and step-up design appropriate to the assurance requirement;
- Terraform contract and negative provider tests; and
- no live apply without separate authorization.

### GUG-94: administrative API and workflows

- invitation, activation, role-change, suspend, and revoke workflows;
- bootstrap, support, and break-glass request/approval surfaces;
- atomic membership versions and safe concurrent updates;
- no self-approval, self-promotion, or last-admin removal;
- enumeration-safe responses and sanitized audit events; and
- no client-side authority: UI visibility is not enforcement.

ADR-026 implements this lifecycle subset with a canonical membership contract,
closed human-only API, conditional operation ledger, provider reconciliation,
transactional final-admin guard, session revocation, owner-bound list/query
patterns, durable lifecycle audit, and recoverable first-admin bootstrap.
Support/break-glass grant issuance remains a separately governed dependency;
live runtime installation and provider-backed assurance remain blocked.

### GUG-153: backend PDP/PEP enforcement

- centralized membership, temporary-grant, and M2M decision paths;
- exact route-to-resource/operation mapping with unknown-route denial;
- active state/version checks and deny precedence before protected effects;
- no request, group-name, legacy, or role-only authority fallback; and
- defensive cross-customer/deployment and stale-grant tests.

### GUG-95: frontend console and E2E

- user/role lifecycle console consuming only GUG-94 APIs;
- privilege and enumeration-safe E2E coverage;
- no client-side authority or hidden-control security assumption; and
- no enablement before GUG-153/GUG-94 enforcement is reviewed.

### GUG-117: integrated gate

- complete protected-route PEP inventory;
- user and M2M positive/negative matrix;
- cross-customer and cross-deployment isolation;
- stale grant/session revocation proof;
- object, export, full-PII, and artifact enforcement;
- support and break-glass expiry/revocation evidence;
- recovery/rollback evidence; and
- explicit separation of local, CI, and live results.

## Validation

Offline contract validation uses only synthetic data:

```bash
make enterprise-authorization-check
python -m pytest -q tests/test_gug92_enterprise_authorization.py
```

Run the repository safety, security, schema, and applicable preflight gates for
the exact revision. Do not place a live provider export or identity inventory in
a fixture to make a test realistic.

## Evidence status

| Classification | Current meaning |
|---|---|
| **Implemented** | The reviewed revision contains the provider-neutral contract artifacts. This does not mean Cognito, API Gateway, backend routes, or admin workflows enforce them. |
| **Locally validated** | Named offline tests and repository gates pass for the exact revision. It is not CI or provider evidence. |
| **CI validated** | Required checks pass for the exact commit and PR. It is not live identity or two-deployment evidence. |
| **Live validated** | Sanitized, explicitly authorized non-production evidence proves the provider, lifecycle, revocation, PEP, tenant/object, and privileged workflows. This is not established by GUG-92. |
| **Blocked** | Downstream runtime/IaC/admin implementation, live migration, and non-production isolation remain blocked on their own issues and approvals. |

Production remains **NO-GO**. A Proposed or Accepted ADR, passing local test, or
green PR cannot be promoted to Live validated by inference.

## Rollback

Revert the source contract through reviewed Git workflow and keep the human
enterprise path disabled. Never restore implicit group roles, shared
administrators, stale-token acceptance, customer-only binding, standing
support, or standing break-glass as a compatibility measure.

Any already deployed consumer requires a separate reviewed disable/revocation
plan. GUG-92 performs no live rollback, user mutation, provider mutation, data
migration, deployment, or production action.
