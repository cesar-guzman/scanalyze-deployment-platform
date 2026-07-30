# Enterprise User Console

> **Decision:** ADR-028 / GUG-95
> **Backend authority:** ADR-025 / GUG-153
> **Lifecycle contract:** ADR-026 / GUG-94
> **Live validation:** No
> **Production:** NO-GO

## Runtime boundary

The console is available at `/admin/users` only when
`features.user_administration=true` and the bounded access-token display
contract exactly matches the loaded `frontend-config.v2` customer, deployment,
policy digest, catalogs, active membership, role, scopes, and time bounds.

This browser check is not authority. Every API request is independently
authorized by the backend GUG-153 PDP/PEP and all storage/provider operations
remain bound to the trusted `AuthContext` owner tuple.

| Role | Membership list | Mutations | Lifecycle audit |
|---|---:|---:|---:|
| `customer_admin` | yes | yes, with step-up and approval | yes |
| `auditor` | no | no | yes |
| `document_operator` | no | no | no |
| `document_reviewer` | no | no | no |
| M2M, unknown, inactive, foreign, malformed | no | no | no |

## Supported workflows

- list and state-filter deployment-local memberships;
- invite a user with a closed role and approval reference;
- resend an invitation with a new expiry and membership version;
- activate an invited membership;
- change an active membership role;
- suspend or reactivate a membership;
- revoke an active membership;
- revoke sessions for active or suspended memberships; and
- read sanitized lifecycle audit events as an administrator or auditor.

The list deliberately excludes email, provider identifiers, subject, claims,
tokens, and customer data. Invitation email exists only in the transient form
and protected request.

## Browser request contract

Every mutation uses a new random `Idempotency-Key`. Transition bodies include
only expected membership version, approval reference, reason code, optional
replacement admin membership, and the operation-specific role or expiry.

The browser never sends `customer_id`, `deployment_id`, `tenant_id`, provider
keys, scopes, roles from arbitrary input, or legacy tenant headers as authority.

Responses are parsed against a closed shape. Error response bodies are not
shown. Public UX states are generic; an exact opaque response correlation
reference may be displayed when CORS exposes it.

## Invitation resend contract

```http
POST /api/v1/admin/memberships/{membership_reference}/invitation-resends
Idempotency-Key: <opaque-idempotency-key>
Content-Type: application/json

{
  "expected_membership_version": 3,
  "expires_in_seconds": 3600,
  "approval_reference": "<opaque-approval-reference>",
  "reason_code": "invitation_resend",
  "replacement_membership_reference": null
}
```

The route uses the existing invitation-create PEP. The service requires an
owned invited membership, exact version, current independent approval, and
provider reconciliation before notification. The subsequent DynamoDB update
is conditional on exact owner, provider binding, invited state, and version.
An ambiguous `provider_effect_reserved` record is quarantined rather than
automatically sending a duplicate notification.

## CORS contract

- allowed request headers: `Authorization`, `Content-Type`,
  `Idempotency-Key`, and edge-required `X-Amz-Date`;
- exposed response headers: `X-Correlation-ID`, `X-Request-ID`, and
  `X-Trace-ID`;
- exact HTTPS origins per deployment; and
- no wildcard origin or legacy identity header.

## Operator states

- **Loading:** data request is in flight.
- **Empty:** authorized query returned no membership/event.
- **Denied / 403:** generic unavailable message; no existence detail.
- **Session expired / 401:** sign-in is required again.
- **Conflict / 409:** refresh membership version and repeat approval if input
  changes.
- **Invalid / 400 or 422:** correct reviewed form fields.
- **Rate limited / 429:** wait before retrying.
- **Degraded / dependency failure:** no mutation is assumed successful.

## Activation checklist

This checklist does not authorize execution:

1. exact GUG-95 PR commit is CI-green, reviewed, merged, and verified on main;
2. runtime config enables the feature only for the authorized deployment;
3. human authorization runtime and lifecycle runtime are installed;
4. provider-backed assurance and approval/audit dependencies are verified;
5. response headers are exposed by the reviewed edge configuration;
6. synthetic and authorized non-production browser tests pass;
7. two distinct deployments prove deny-by-default isolation; and
8. rollback and support evidence are approved.

Until those gates are complete, human runtime remains disabled and Production
remains **NO-GO**.

## Local candidate evidence

The following results apply only to the uncommitted local GUG-95 candidate and
do not constitute CI or live validation:

- repository Python suite: `852 passed`;
- ingest API suite: `688 passed`;
- focused GUG-94/GUG-95 lifecycle and recovery suite: `47 passed`;
- frontend check: typecheck, lint, `36 passed`, build, and dependency audit with
  zero reported vulnerabilities;
- browser suite: `13 passed`, including eight GUG-95 authorization and
  lifecycle scenarios;
- edge authorization Terraform mock: `7 passed`;
- contract matrix: `114/114` scenarios passed;
- offline provider validation: `11/11` roots passed under the no-credentials
  guard;
- `git-safety`, `security-check`, `microservices-check`, `docs-check`,
  `preflight-m2b`, `compileall`, `terraform fmt -check`, and `git diff --check`
  passed.

No AWS API, Cognito provider, deployment, migration, or real customer data was
used. CI remains pending for the exact future commit.
