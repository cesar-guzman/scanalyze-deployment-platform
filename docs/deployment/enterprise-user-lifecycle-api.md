# Enterprise User Lifecycle API

> **Decision:** ADR-026 / GUG-94
> **Base authorization:** ADR-025 / GUG-153
> **Contract:** `enterprise-membership.v1`
> **Live validation:** No
> **Production:** NO-GO

## Purpose and boundary

This API administers deployment-local enterprise memberships without allowing
the request to select a customer, deployment, provider resource, role source,
or storage partition. It is portable across accounts and customers because all
authority comes from the validated `AuthContext` and deployment-installed
runtimes.

The routes are inert and fail closed unless trusted startup code installs both:

- `app.state.enterprise_authorization_runtime` for the GUG-153 PDP/PEP; and
- `app.state.enterprise_lifecycle_runtime` for membership, provider, approval,
  operation-ledger, audit, and clock ports.

No request header, query parameter, path parameter, or payload field may
replace either runtime. `HUMAN_ENTERPRISE_AUTHORIZATION_ENABLED=false` remains
the deployment default until an authorized rollout.

## Route catalog

| Method | Route | Operation | Role | Step-up | Idempotency |
|---|---|---|---|---|---|
| GET | `/api/v1/admin/roles` | `authorization.roles.read` | customer admin | no | no |
| GET | `/api/v1/admin/memberships` | `authorization.memberships.list` | customer admin | no | no |
| POST | `/api/v1/admin/invitations` | `authorization.invitations.create` | customer admin | yes | required |
| POST | `/api/v1/admin/memberships/{ref}/activations` | `authorization.memberships.activate` | customer admin | yes | required |
| POST | `/api/v1/admin/memberships/{ref}/role-changes` | `authorization.memberships.role_change` | customer admin | yes | required |
| POST | `/api/v1/admin/memberships/{ref}/suspensions` | `authorization.memberships.suspend` | customer admin | yes | required |
| POST | `/api/v1/admin/memberships/{ref}/reactivations` | `authorization.memberships.reactivate` | customer admin | yes | required |
| POST | `/api/v1/admin/memberships/{ref}/revocations` | `authorization.memberships.revoke` | customer admin | yes | required |
| POST | `/api/v1/admin/memberships/{ref}/session-revocations` | `authorization.sessions.revoke` | customer admin | yes | required |
| GET | `/api/v1/admin/audit-events` | `authorization_administration.audit.read` | customer admin or auditor | no | no |

All lifecycle administration policies set `m2m_allowed=false`. M2M `admin`
scope does not confer human identity administration.

## Request contracts

Invitation example using synthetic data:

```http
POST /api/v1/admin/invitations
Idempotency-Key: idem_11111111111111111111111111111111
Content-Type: application/json

{
  "principal_locator": "synthetic@example.invalid",
  "role_id": "document_operator",
  "expires_in_seconds": 3600,
  "approval_reference": "apr_11111111111111111111111111111111"
}
```

Transition example:

```json
{
  "expected_membership_version": 7,
  "approval_reference": "apr_22222222222222222222222222222222",
  "reason_code": "security_review",
  "replacement_membership_reference": null
}
```

Role changes add `role_id`. Removing or degrading an active customer admin
must provide `replacement_membership_reference` for a distinct owned active
customer admin. An approval must be active, unexpired, operation/target/owner
bound, issued by a subject distinct from both actor and target, and bound to the
exact canonical request digest. A changed role, reason, version, replacement,
or expiry therefore requires new approval evidence.

Payloads reject `customer_id`, `deployment_id`, `tenant_id`, `X-Tenant-ID`, and
normalized variants. Idempotency keys are bound to the actor and canonical
request digest and cannot be reused for different input.

## Responses and privacy

Membership list output includes only membership reference, state, role,
version, timestamps, and invitation expiry. It excludes subject, provider
principal, provider reference, locator, email, token, cookie, claims, and raw
payloads.

Foreign and absent membership references use the same sanitized not-found
response. Authorization and dependency failures contain no provider payload,
storage key, customer data, or enumeration detail.

## Storage contracts

Normal lists query `MEMBERSHIP#{deployment_id}#{customer_id}`. State-filtered
lists use `ownership-state-v1`; reference lookups use
`ownership-membership-reference-v1`. Both index keys contain the exact trusted
owner tuple. Cursors are accepted only after exact owner/state validation.

Mutations use conditional state/version updates. Active administrator removal
uses a DynamoDB transaction containing a condition check for the replacement
and an update for the target. No protected table scan is permitted.

## Provider behavior

The Cognito adapter is one reviewed implementation of the provider-neutral
port. Invitation derives a deterministic provider key from the locator digest,
sets exact immutable customer/deployment attributes, and reconciles any
existing user. Activation, enable/disable, and global session sign-out first
re-read the provider user and verify subject, provider reference, and immutable
owner binding.

Effect order is operation-specific and checkpointed. Activation/reactivation
prove provider enablement before active membership; suspension/revocation
commit the guarded membership restriction before provider disable; role change
and explicit session revocation commit membership state before invalidating
sessions. A missing or conflicting order marker fails unavailable. Raw provider
responses and secret delivery values are never returned or logged.

## Activation checklist

This checklist is documentary; it does not authorize execution:

1. PR is reviewed, CI-green, merged, and verified on `main`.
2. Membership/audit tables and exact indexes exist from reviewed Terraform.
3. Workload role grants only required item/index and provider administration
   actions for the exact deployment resources.
4. Both typed runtimes are installed from the verified deployment contract.
5. Approval producer and audit sink pass dependency and idempotency tests.
6. Human runtime is enabled only in an authorized non-production deployment.
7. GUG-95 UI/E2E and the two-deployment isolation proof are green.
8. Evidence distinguishes local, CI, non-production live, and production.

Until every required gate is met, human runtime remains disabled and
Production remains **NO-GO**.
