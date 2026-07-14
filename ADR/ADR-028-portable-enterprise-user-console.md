# ADR-028: Portable Enterprise User Console

- **Status:** Proposed; accepted only after reviewed merge and main verification
- **Date:** 2026-07-14
- **Work package:** GUG-95
- **Baseline:** `6ed7e34204c9f404c3d05a3dbdbef512000bd6ee`
- **Phase gate:** GUG-117
- **Upstream:** ADR-023, ADR-025, ADR-026, ADR-027
- **Live validation:** No
- **AWS activity:** None

Production: **NO-GO**

## Context

GUG-92 defines the portable enterprise role and lifecycle policy, GUG-153
enforces it at the backend PDP/PEP, GUG-94 provides recoverable lifecycle APIs,
and ADR-027 establishes one canonical SPA source. A browser console still needs
to expose those capabilities without becoming an authorization authority,
leaking identity data, allowing cross-deployment navigation, or silently
turning provider behavior into a second lifecycle contract.

The GUG-94 API intentionally returns opaque membership references instead of
email, subject, provider key, or provider response. The UI must preserve that
privacy boundary. It must also distinguish a local UX decision from backend
authority: hiding a button is useful defense in depth, but every request must
still pass GUG-153 and exact customer/deployment checks.

## Decision

### 1. Claims are display hints, never authority

The SPA decodes the access-token payload only to derive display capabilities.
It does not verify a JWT or authorize an API effect. It fails closed unless the
token is bounded, unexpired, recently authenticated, and exactly matches the
runtime customer, deployment, policy digest, catalog versions, active
membership state, closed role, and required scope.

Only `customer_admin` sees membership administration. `auditor` sees the
sanitized lifecycle audit view and cannot enumerate memberships. Operators,
reviewers, M2M principals, ID tokens, foreign deployments, unknown versions,
inactive memberships, stale authentication, and malformed claims receive the
same unavailable view and cause zero administration requests.

The backend remains authoritative for every request through the GUG-153 PEP.
Runtime configuration and route or payload values never establish identity.

### 2. Use one strict lifecycle API client

One typed client owns the complete admin route catalog, response parsing,
idempotency-key generation, error classification, and allowlisted UI telemetry.
Responses are rejected if their shape, role/state catalog, reference, cursor,
version, timestamp, or correlation field is malformed. Error bodies are never
rendered. Only an opaque `ref_...` response correlation header may reach the
operator.

Mutation bodies contain only the GUG-94 request fields. They never contain
customer, deployment, tenant, provider resource, subject, or authorization
claims. Every mutation receives a cryptographically random, request-local
`Idempotency-Key`.

### 3. Preserve privacy and usable failure states

The console renders opaque membership references, state, role, version, and
timestamps. It never receives or renders email from the membership list. Email
is accepted only inside the invitation form and sent directly to the protected
API; it is not stored in telemetry, logs, local storage, or audit views.

The UI has explicit loading, empty, denied, conflict, session-expired,
rate-limited, invalid, and degraded states. Mutation dialogs require explicit
confirmation, approval reference, reason code where applicable, and optimistic
membership version. Dialogs have semantic labels, keyboard dismissal, and
focus placement. Backend conflicts require refresh rather than an unsafe retry
with stale authority.

### 4. Add controlled invitation resend to the existing lifecycle contract

GUG-95 requires a resend control, but GUG-94 did not expose a resend route.
The extension reuses the existing closed `authorization.invitations.create`
PEP and introduces `membership.resend_invitation` as an approved, versioned,
audited lifecycle operation. It does not add a role, scope, provider group, or
IAM permission category.

The service loads the exact owned invited membership, rejects self-targeting or
version/state conflict, validates independent approval against the canonical
request digest, and checkpoints the effect order. The provider adapter re-reads
and reconciles subject, immutable customer/deployment attributes, provider key,
and provider reference before sending `RESEND`. DynamoDB then conditionally
refreshes expiry and increments membership version while binding the same
owner, membership reference, provider references, invited state, and previous
version. Retry recovery cannot duplicate the provider effect after its durable
checkpoint. Because Cognito provides neither an idempotency token nor a
delivery receipt for `RESEND`, a crash after the pre-effect reservation but
before the applied checkpoint is quarantined for manual review; it is never
retried automatically.

No invitation secret, email, subject, provider response, raw request, or token
enters audit or operation evidence.

### 5. Make browser diagnostics an explicit CORS contract

The edge CORS allowlist adds only `Idempotency-Key` for browser lifecycle
mutations. It exposes only `X-Correlation-ID`, `X-Request-ID`, and `X-Trace-ID`,
which the backend normalizes to opaque references. Legacy tenant headers remain
forbidden. The same exact contract is present in FastAPI for local and direct
service testing.

The reviewed API deployment trigger includes the CORS contract so changes are
not detached from the explicit deployment revision. This is repository-only
Terraform; no plan, apply, provider call, or live API change is authorized.

## Portability

All behavior is driven by the versioned runtime contract and protected API. It
contains no customer-specific fork, AWS account, real issuer, real origin,
email domain policy, or hard-coded deployment identifier. Each deployment
receives its exact runtime configuration and backend owner binding through the
existing reviewed contracts.

## Rollout and rollback

Merge alone does not publish the SPA, enable human authorization, create a
provider user, or change AWS. Activation requires reviewed CI, main
verification, an authorized non-production deployment, provider-backed
assurance, and the separate two-deployment isolation proof.

Rollback is a normal revert of the GUG-95 commit. Keep the backend human flag
disabled and do not remove lifecycle records. A resend already performed in a
future authorized environment is an external notification effect and is not
reversed by source rollback; its versioned audit evidence must be retained.

## Evidence classification

- **Implemented:** candidate branch code, schemas, UI, API extension, CORS
  contract, tests, and documentation.
- **Locally validated:** only named successful local gates.
- **CI validated:** pending the exact PR commit.
- **Live validated:** no.
- **Blocked:** CI, review/merge/main verification, authorized two-deployment
  proof, provider/live browser validation, and production authorization.
- **Production:** **NO-GO**.
