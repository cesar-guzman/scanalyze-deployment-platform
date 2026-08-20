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

Before any migration, compare every rendered state key across deployment,
region, and layer. Duplicate canonical templates, a key already owned by a
different root, a partially materialized baseline, or any existing destination
object is a stop condition. A deterministic second repository-only run must
produce byte-identical contract and sanitized manifest output; this no-change
check is not a Terraform plan and proves no live state.

## Stale execution lock

Expiry is evidence that the owner may have failed; it is not permission to
take over. Stop new executions, confirm the owner/run terminal state, inspect
the exact backend lock through an authorized read-only path, open an incident or
change, obtain dual review, and preserve sanitized evidence. The distributed
execution lock and Terraform `.tflock` are distinct and both must be reconciled.

Automatic lease stealing and automatic `force-unlock` are forbidden.

The single independent reviewer rule for GUG-379 applies only to its exact
repository head. It does not replace the dual review in this stale-lock
procedure, authorize a live recovery session, or permit a cloud mutation.

## State restoration

State restoration is allowed only after state corruption/loss is proven and an
exact known-good object version is approved. The short-lived StateRecovery
session must bind the operation and deployment tags, restore only the exact
state object with the approved KMS key, never delete state, and delete a
`.tflock` only under separate reviewed stale-lock approval.

Version inventory requires both `s3:ListBucket` and
`s3:ListBucketVersions` on the exact deployment-bound state bucket, constrained
to `${deployment_id}/*/terraform.tfstate` and the state-recovery session tags.
It does not authorize `ListAllMyBuckets`, wildcard bucket/prefix access,
`DeleteObjectVersion`, state deletion, or unreviewed `.tflock` deletion.

After restoration, disable recovery authority and generate a new reviewed plan.
The restored version remains untrusted until state, infrastructure, contracts,
and runtime reconcile. An unexpected plan is a stop condition.

## Rollback

If migration or recovery evidence is incomplete or inconsistent, stop all new
execution, preserve the current state and every version, retain locks until
ownership is known, and return to report-only investigation. Never relax the
authorizer or re-enable a legacy fallback to restore availability.

A failed or partial account-baseline materialization is quarantined. Do not
rerun by adopting a bucket, key, role, or alias that happens to exist; do not
emit ACCOUNT_READY from partial outputs; and do not delete retained resources
under this runbook. Reconciliation requires exact stack/resource provenance
and a separately reviewed forward-recovery or decommission plan.

The unattributed API Gateway access log group is not baseline evidence and is
not a migration candidate. Preserve it unchanged until ownership and
provenance are independently established.

## Current status

No registry write, inventory, migration, lock recovery, state restoration,
lock deletion, Terraform plan/apply, AWS operation, or live backend
initialization was executed for this GUG-122 repository remediation. All tests
are synthetic/offline. GUG-125 owns live conditional storage, two-deployment
isolation, authorized version inventory/recovery, and rerun/no-change proof.
Production remains **NO-GO**.
