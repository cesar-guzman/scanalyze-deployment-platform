# Terraform backend migration and recovery

> Report-only runbook for GUG-122. It does not authorize AWS access, state
> mutation, lock deletion, migration, plan, apply, or production activity.

## Inventory classes

| Class | Definition | Normal treatment |
|---|---|---|
| fully bound | v2 registry, independent anchor, ACCOUNT_READY v2, exact bucket/KMS/owner, canonical key, native lockfile | eligible for later gates |
| partially bound | one or more v2 bindings or controls missing | deny and quarantine |
| ambiguous | more than one customer/deployment/owner/key interpretation | deny; no inference |
| orphaned | storage or state exists without an approved registry owner | deny and quarantine |
| inconsistent | records exist but ownership, region, encryption, version, digest, or key disagree | deny and investigate |

Legacy manifest backend fields, DynamoDB lock-table configuration, naming
conventions, existing prefixes, previous AWS profiles, or accessible buckets
never establish ownership.

## Report-only inventory

An authorized read-only inventory must record only sanitized references and:

- approved registry version/digest and target lifecycle;
- ACCOUNT_READY schema/baseline/digest state;
- whether bucket versioning, SSE-KMS, bucket key, public access block, and
  Object Lock match the contract;
- whether state keys map one-to-one to canonical roots;
- whether a native lockfile or legacy lock record exists;
- owner and recovery authority evidence status; and
- classification, reviewer, and recommended disposition.

Do not copy state, plans, backend files, bucket listings, raw policies, customer
identifiers, or account identifiers into Git, Linear, NotebookLM, or chat.

## Reviewed migration

A migration change requires Platform Engineering and Platform Security review,
a non-production target, a verified recovery point, collision-free key mapping,
explicit source/destination ownership, no active execution lock, and a rollback
plan. Dry-run/report-only evidence must precede any write.

Migration must never:

- infer a customer or deployment from a bucket or prefix;
- copy state across ownership boundaries;
- overwrite an existing destination key;
- silently convert v1 to v2;
- reuse a legacy lock table as proof of exclusivity;
- disable encryption, versioning, or public access controls; or
- run concurrently with plan/apply/recovery.

## Stale execution lock

Expiry is evidence that the owner may have failed; it is not permission to
take over. Stop new executions, confirm the owner/run terminal state, inspect
the exact backend lock through an authorized read-only path, open an incident or
change, obtain dual review, and preserve sanitized evidence. The distributed
execution lock and Terraform `.tflock` are distinct and both must be reconciled.

Automatic lease stealing and automatic `force-unlock` are forbidden.

## State restoration

State restoration is allowed only after state corruption/loss is proven and an
exact known-good object version is approved. The short-lived StateRecovery
session must bind the operation and deployment tags, restore only the exact
state object with the approved KMS key, never delete state, and delete a
`.tflock` only under separate reviewed stale-lock approval.

After restoration, disable recovery authority and generate a new reviewed plan.
The restored version remains untrusted until state, infrastructure, contracts,
and runtime reconcile. An unexpected plan is a stop condition.

## Rollback

If migration or recovery evidence is incomplete or inconsistent, stop all new
execution, preserve the current state and every version, retain locks until
ownership is known, and return to report-only investigation. Never relax the
authorizer or re-enable a legacy fallback to restore availability.

## Current status

No inventory, migration, lock recovery, state restoration, or live backend
initialization was executed for GUG-122. Live proof belongs to an explicitly
authorized non-production phase after GUG-123 and GUG-124. Production remains
**NO-GO**.
