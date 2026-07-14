# GUG-94 Enterprise User Lifecycle Threat-Model Delta

- **Scope:** Lifecycle API, canonical membership store, provider reconciliation,
  audit, and recoverable first-admin bootstrap
- **Base model:** `docs/production-readiness/threat-model.md`
- **Base decisions:** ADR-021, ADR-023, ADR-024, ADR-025
- **Decision introduced:** ADR-026
- **Baseline:** `a5b5ea9a52337110b1b627e08c81dbaaeb835d17`
- **Live validation:** No
- **Production:** NO-GO

## Overview

GUG-94 introduces the administrative boundary that changes a human's ability
to access Scanalyze. The assets are exact customer/deployment isolation,
membership and role integrity, provider/application consistency, active
session invalidation, first-administrator continuity, audit completeness, and
privacy of user locators and provider data.

The highest-impact failure is a valid administrator creating, activating, or
retaining a foreign or over-privileged identity, or a partial failure being
reported as successful without a durable audit trail.

## Threat Model, Trust Boundaries, and Assumptions

### Trust boundaries

1. **HTTP to AuthContext:** the client controls routes, references, payloads,
   headers, and cursors. Only the validated internal subject/customer/deployment
   tuple is authority.
2. **GUG-153 PDP/PEP to lifecycle service:** a closed human-only operation,
   current membership, scopes, step-up, and durable authorization decision must
   succeed before administration.
3. **Approval store to operation:** approval evidence is trusted only when
   exact owner, operation, target, state, expiry, distinct approver, and
   canonical request digest match.
4. **Lifecycle ledger to effects:** conditional stages and canonical request
   digest determine which provider, membership, session, and audit effect may
   run or resume.
5. **Application to identity provider:** provider output is evidence only after
   immutable owner attributes, subject, and stable provider reference reconcile.
6. **Application to DynamoDB:** primary keys, GSIs, continuation keys, and
   conditions derive from trusted owner data. A scan or post-fetch owner filter
   is outside the accepted design.
7. **Effects to audit:** success crosses the boundary only after an exact
   sanitized event receives a durable idempotent receipt.
8. **Bootstrap effects to consumption:** first-admin provider/membership effects
   must be checkpointed and audited before the one-use request is consumed.

Assumptions include correct access-token verification from GUG-102/GUG-93,
GUG-153 route enforcement, GUG-114 object authorization after role allow,
reviewed provider/table configuration, and least-privilege workload IAM. None
of these assumptions is live-validated by GUG-94.

## Attack Surface, Mitigations, and Attacker Stories

### IDOR and cross-deployment administration

An attacker supplies a foreign membership reference or continuation cursor.
The reference GSI key includes deployment, customer, and reference; the primary
item is re-read consistently and checked. Cursor validation rejects foreign
primary and state bindings before query. Not-found and foreign references share
sanitized responses.

### Payload authority spoofing

An attacker supplies customer, deployment, tenant, provider, or legacy identity
fields. Closed Pydantic models reject normalized authority field variants.
The service derives owner and actor only from `AuthContext`.

### Idempotency confusion and partial effects

An attacker or retry reuses an idempotency key with changed input, or triggers
failure between provider, membership, session, and audit steps. The operation
ledger binds key, owner, actor, operation, and request digest and advances only
through conditional stages. Exact retries reconcile; conflicting retries deny.

### Provider confused deputy

Provider groups, email/domain data, aliases, or request-supplied provider keys
attempt to create authority. The adapter derives a deterministic key from a
digest, writes immutable customer/deployment attributes, and re-reads exact
subject and owner attributes before activation, enable/disable, or sign-out.
Restrictive transitions commit the guarded membership restriction before the
provider mutation; enabling transitions prove provider state before exposing an
active membership. The immutable operation marker prevents ambiguous recovery.

### Last-administrator race

Concurrent requests attempt to remove the target and replacement admins. The
design does not rely on an eventually consistent count. It requires a named
replacement and performs replacement condition check plus target update in one
DynamoDB transaction with exact owner/state/role/version bindings.

### Membership list leakage

An attacker pages or filters across tenants. Normal and state-filtered queries
bind the owner at the key boundary; returned records are revalidated. Public
responses omit subject, locator, provider references, and storage keys.

### Audit suppression or poisoning

An attacker causes sink outage or reuses a decision key with different content.
The API never reports success before a durable receipt. Exact duplicates are
idempotent; content conflicts fail closed. Events contain opaque references and
no token, locator, PII, provider payload, key, URL, or secret. Operation
evidence is a closed typed allowlist, and completed operations require an audit
receipt reference at the schema boundary.

### Bootstrap replay

A consumed, expired, revoked, foreign, or changed bootstrap request is replayed.
Exact state/version/claim/idempotency conditions deny it. Partial recovery is
allowed only within the bounded recovery window and only with stored stable
effect references.

### Out-of-scope attacker stories

GUG-94 does not claim protection against compromise of the AWS account,
provider control plane, KMS root authority, CI signing/release authority, or an
independently approved malicious code release. Those controls remain governed
by repository IAM, release, and production-readiness gates. It also performs no
live data migration or production recovery.

## Severity Calibration

### Critical

- a path that lets an unauthenticated or foreign-deployment actor create an
  active administrator or consume first-admin bootstrap;
- a reusable provider or storage confused deputy that changes membership in
  arbitrary customer deployments; or
- exposure of live invitation/session credentials enabling broad account
  takeover.

### High

- bypass of approval, step-up, final-admin transactional guard, session
  revocation, or durable audit for privileged lifecycle changes;
- owner-unbound membership query/cursor permitting cross-customer enumeration;
- idempotency confusion that applies a different role or target than approved;
  or
- accepting a legacy/partial membership as active authority.

### Medium

- availability defects that leave a recoverable operation stuck without
  authorizing it;
- sanitized lifecycle metadata exposed to an authenticated role lacking audit
  permission; or
- incomplete operational evidence that makes safe recovery harder without
  enabling privilege escalation.

### Low

- documentation or diagnostics defects that reveal no sensitive identity,
  owner, provider, or storage material and do not alter a decision;
- malformed client input causing a bounded generic 4xx without state change.

Residual risk remains **High** until reviewed workload IAM/runtime composition
and an authorized two-deployment isolation proof are completed. Production is
**NO-GO**.
