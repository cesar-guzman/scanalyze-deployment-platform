# GUG-94 — Enterprise User Lifecycle and Recoverable Bootstrap

> **Sanitized NotebookLM source**
> **Canonical decision:** ADR-026
> **Related:** GUG-92, GUG-93, GUG-153, GUG-95, GUG-117
> **Live validation:** No
> **Production:** NO-GO

## Outcome

GUG-94 defines and implements a portable, fail-closed user lifecycle for every
Scanalyze customer deployment. It adds a human-only versioned administration
API, one canonical membership record, conditional idempotent orchestration,
provider reconciliation, session revocation, owner-bound list/query patterns,
append-only sanitized audit, and recoverable first-admin bootstrap.

The source contains no real customer, account, region, pool, user, email,
table, or credential value. Deployment bindings are supplied through trusted
runtime composition. Merge does not authorize live enablement.

## Core invariants

```text
authority = validated AuthContext.customer_id + AuthContext.deployment_id
membership owner = exact same customer_id + deployment_id
request identity fields = never authoritative
mutation = exact request-bound approval + step-up + idempotency + exact current version
success = provider + membership + session reconciliation + durable audit
```

Missing, malformed, foreign, ambiguous, stale, unsupported, legacy, or
unavailable evidence denies. Foreign and absent objects do not disclose
different enumeration detail.

## Canonical lifecycle

Membership states are `invited`, `active`, `suspended`, `expired`, and
`revoked`. Normal transitions are invited-to-active, active-to-suspended,
suspended-to-active, and active-to-revoked. Revoked and expired records are not
reactivated in normal paths. Role/state changes increment the membership
version and revoke sessions when applicable.

The actor cannot change their own role/state. An active customer administrator
can be removed only with a distinct owned active customer administrator named
as replacement. DynamoDB checks the replacement and updates the target in one
transaction, so no eventually consistent admin count is trusted.

## Recovery model

Lifecycle operations progress through reserved, approval validated, provider
applied/membership applied in the checkpointed safe order, sessions revoked,
audit committed, and completed. Enabling paths prove provider state before
active membership; restrictive paths commit the guarded membership restriction
before provider disable. Every transition is conditional. The same idempotency
key and exact request-bound approval resumes; different material conflicts.

Bootstrap progresses through approved, claimed, effects applied, audit
committed, and consumed. Provider/membership references are checkpointed before
audit; audit is checkpointed before consumption. Audit or consume outages can
recover without repeating identity creation. Consumed requests deny replay.

## Isolation and privacy

Membership primary/index keys include exact deployment and customer bindings.
State-filter pagination validates the full owner/state continuation key.
Protected scans and request-selected storage prefixes are prohibited.

Public membership responses omit subject, provider references, provider keys,
and locators. Operations and audit retain only digests, versions, states,
reason codes, and opaque references. No JWT, cookie, temporary password,
invitation secret, PII payload, provider response, storage key, or presigned URL
is logged or returned.

## Evidence states

- Implemented: code, contracts, tests, IaC indexes, ADR, API reference, recovery
  runbook, threat-model delta, and this source.
- Locally validated: recorded test/check commands for the candidate.
- CI validated: only after exact PR commit checks are green.
- Live validated: no.
- Production: NO-GO.

## Next order

1. Reviewed GUG-94 merge and `main` verification.
2. GUG-95 console and privilege E2E in a new branch/worktree/PR.
3. Explicitly authorized two-deployment isolation proof.
4. Close GUG-117 only after its complete evidence gate.
