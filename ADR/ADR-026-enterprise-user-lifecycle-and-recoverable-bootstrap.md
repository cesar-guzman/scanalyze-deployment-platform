# ADR-026: Enterprise User Lifecycle and Recoverable Bootstrap

- **Status:** Proposed; accepted only after reviewed merge and main verification
- **Date:** 2026-07-13
- **Evidence snapshot:** GUG-94 locally validated candidate
- **Scope:** Versioned user lifecycle API, canonical membership persistence,
  provider reconciliation, audit, and first-admin bootstrap recovery
- **Phase gate:** GUG-117
- **Upstream decisions:** ADR-021, ADR-023, ADR-024, ADR-025
- **Downstream consumers:** GUG-95 console/E2E and the authorized
  two-deployment isolation proof
- **Live enablement:** Blocked pending reviewed merge, explicit non-production
  rollout authorization, workload IAM, runtime composition, and isolation proof

Production: **NO-GO**

## Context

GUG-92 defined portable enterprise roles and lifecycle invariants. GUG-93
created a deployment-bound provider control plane and a dual-approved
first-admin bootstrap, while deliberately leaving human runtime disabled.
GUG-153 placed a fail-closed PDP/PEP on every protected backend route, but left
provider and persistence ports to GUG-94.

Without this package, user administration has no versioned API, membership
mutations have no durable operation checkpoint, provider and application state
can diverge after partial failure, membership lists have no reviewed
ownership-bound access pattern, and the first-admin bootstrap can apply its
provider and membership effects before its audit checkpoint is recoverable.

The implementation must be reusable without source forks for every customer,
deployment, AWS account, region, and reviewed identity provider. HTTP input,
provider groups, email domains, legacy tenant aliases, resource names, and
request-supplied customer or deployment identifiers never establish authority.

## Decision

### Canonical membership

New authoritative records use `enterprise-membership.v1` and require:

```text
customer_id + deployment_id + subject
+ membership_reference + state + role_id + membership_version
+ provider_user_reference + provider_principal_key
+ created_at + updated_at
```

The primary key is derived only from trusted bindings:

```text
pk = MEMBERSHIP#{deployment_id}#{customer_id}
sk = SUBJECT#{subject}
```

`customer_id`, `deployment_id`, subject, provider binding, and membership
reference are immutable. Lifecycle changes increment a positive integer
`membership_version`. The pre-token adapter now reads this canonical shape and
converts the integer version to the signed string claim expected by the
authorization context. It has no fallback to the legacy `membership_state`
alias or string storage version.

Legacy, partial, foreign, ambiguous, unsupported, or inconsistent membership
records fail closed. GUG-94 performs no automatic inference or live migration.

### Versioned administration API

The ingest API exposes a closed `/api/v1/admin` surface for the role catalog,
membership list, invitations, activation, role changes, suspension,
reactivation, revocation, session revocation, and lifecycle audit reads.

Every route has exactly one GUG-153 `OperationId`. Lifecycle administration is
human-only; M2M principals cannot acquire it through the broad `admin` action.
Mutations require a fresh phishing-resistant step-up, a distinct approved
evidence reference, and `Idempotency-Key`. Approval evidence is bound to the
exact canonical request digest in addition to owner, operation, target, state,
expiry, and distinct approver. Customer and deployment come only from the
validated `AuthContext`.

The handler obtains an `EnterpriseLifecycleRuntime` from trusted application
state. Missing or incorrectly typed runtime dependencies return unavailable;
there is no local, permissive, or request-controlled fallback. Deployment-time
installation remains a separate explicit rollout action.

### Recoverable operation state machine

Each mutation reserves a canonical request digest under the exact
customer/deployment/idempotency partition. Reusing the same key for different
operation, actor, or request material is a conflict.

```text
reserved
  -> approval_validated
  -> provider_applied
  -> membership_applied
  -> sessions_revoked, when required
  -> audit_committed
  -> completed
```

Every checkpoint is conditional on the previous stage, operation reference,
actor, and request digest. An exact retry resumes from the stored checkpoint.
The operation stores an immutable `effect_order` marker. Activation and
reactivation reconcile the provider before making membership active. Suspension
and revocation commit the owner/version/replacement-guarded membership change
before disabling provider access. Role changes and explicit session revocation
do not require a membership-enable provider effect. Legacy or ambiguous
operations without the expected marker fail closed instead of guessing which
effect ran.

Provider calls use deterministic provider keys and re-read the exact principal
and immutable owner attributes before every enable, disable, activation, or
session-revocation mutation. Membership updates are conditional on exact owner,
reference, state, and version. A response is never successful until the
sanitized audit event has a matching durable receipt. Operation evidence uses
a closed typed allowlist and never contains free-form payloads.

Invitation payloads contain only a normalized locator, role, bounded expiry,
and approval reference. The locator is used by the provider adapter and stored
only as a digest in operation evidence. API responses, logs, audit records, and
operation records never contain raw locators, invitation secrets, temporary
passwords, tokens, cookies, JWTs, or provider payloads.

### State and session rules

The closed state transitions are:

```text
invited -> active
active -> suspended
suspended -> active
active -> revoked
```

`expired` and `revoked` are terminal in normal paths. An invited membership must
carry an aware, bounded invitation expiry and cannot activate after that time;
non-invited records cannot retain invitation expiry. Role changes require an
active membership. Role change, suspension, reactivation, revocation, and
explicit session revocation invalidate provider sessions before completion.
The actor cannot mutate their own role or membership state.

Removing or degrading an active `customer_admin` always requires a distinct,
owned, active replacement administrator. The persistence adapter performs the
replacement condition check and target update in one DynamoDB transaction,
binding both records to exact owner, state, role, and version. This conservative
rule avoids count-based eventual consistency and time-of-check/time-of-use
races.

### Query and pagination isolation

Membership lists query the exact owner primary partition. State-filtered lists
query a sparse `ownership-state-v1` GSI whose partition key contains the exact
deployment, customer, and state. Membership-reference lookup uses a separate
exact owner/reference binding and rejects duplicate results as ambiguous.

Cursors are opaque encodings of the exact DynamoDB continuation key. The
adapter validates the primary owner partition and, for filtered lists, the
state binding and membership-reference key before issuing the next query.
Foreign or malformed cursors fail before storage access. Protected scans and
post-query tenant filtering are prohibited.

### Audit and bootstrap ordering

Lifecycle audit is append-only, sanitized, owner-partitioned, idempotent for an
exact duplicate, and conflicting for the same decision key with different
content. Audit reads query only the exact owner partition and validate cursors.

First-admin bootstrap now checkpoints:

```text
approved -> claimed -> effects_applied -> audit_committed -> consumed
```

Provider and membership effects are idempotent. Their stable references are
durably checkpointed before audit. Audit is committed before the one-use
request is consumed. A retry after an audit or consume outage resumes from the
stored outcome without repeating provider or membership effects. A consumed
request cannot be replayed. Recovery is bounded by the reviewed recovery
window and exact claim/idempotency bindings.

## Consequences

Positive consequences:

- lifecycle behavior is provider-neutral, versioned, testable, and recoverable;
- list, lookup, mutation, cursor, and audit boundaries preserve exact tenant
  isolation;
- provider/application divergence is detected rather than silently accepted;
- final-admin safety is transactional; and
- audit failure cannot be reported as successful administration.

Trade-offs:

- administrator removal is intentionally more conservative and always needs a
  named active replacement;
- GSI reads are eventually consistent, so mutation paths always re-read the
  primary item consistently before effects;
- an approval producer remains a separately governed trusted dependency; and
- live runtime composition and least-privilege workload IAM remain disabled
  until an explicitly authorized non-production rollout.

## Rollout and rollback

Merge does not enable human runtime or authorize AWS changes. A later rollout
must install both GUG-153 and GUG-94 runtimes from the verified deployment
contract, attach reviewed least-privilege workload IAM, validate provider/table
bindings, and prove two-deployment isolation.

Rollback is code/configuration only: disable human runtime and remove lifecycle
route exposure from the service release while retaining membership, operation,
approval, audit, and bootstrap evidence. Do not delete or infer records, reset
versions, restore provider users automatically, or replay bootstrap requests.
Provider effects that occurred before a failed checkpoint require the recovery
runbook and reviewed reconciliation.

## Evidence classification

- **Implemented:** Domain/API/adapters/contracts, canonical bootstrap storage,
  recovery state machine, DynamoDB indexes, tests, and documentation.
- **Locally validated:** Focused and repository checks recorded in the PR.
- **CI validated:** Pending exact PR commit checks.
- **Live validated:** No.
- **Blocked:** AWS/provider/runtime activation and two-deployment proof.
- **Production:** **NO-GO**.
