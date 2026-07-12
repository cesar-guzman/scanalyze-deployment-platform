# Object Ownership Migration and Quarantine Runbook

> **Status:** repository decision and future migration procedure; no live
> inventory or migration authorized\
> **Owner issues:** GUG-114, GUG-117\
> **Related identity decision:** GUG-102 / ADR-020\
> **Production:** **NO-GO**

## Purpose

This runbook defines how documents and batches that do not yet satisfy the exact
`customer_id` plus `deployment_id` ownership contract are classified, denied,
quarantined, reviewed, and, only under later explicit authority, migrated. It
contains no real identifiers, object contents, S3 locations, customer data,
account data, or operational evidence.

Normal application paths never use this runbook to repair a record. They fail
closed and return the same sanitized external response used for an absent or
foreign object. Quarantine is a treatment state and evidence classification; it
does not authorize copying, deleting, or moving data.

## Inventory classes

| Class | Detection | Normal-path treatment | Migration disposition |
|---|---|---|---|
| Fully bound | Non-empty canonical `customer_id` and `deployment_id` are present, well-formed for their applicable contract, mutually consistent, and consistent with membership | Continue only after exact `AuthContext` authorization | No migration required; retain evidence of validation only |
| Partially bound | Exactly one canonical ownership field is missing, empty, or invalid | Deny and quarantine | Reviewed source reconstruction required; never fill from the surviving field |
| Ambiguous | Multiple candidate owners exist, aliases conflict, or authoritative sources disagree | Deny and quarantine | Escalate to data owner and Application Security; no automatic winner |
| Orphaned | No approved source can prove customer and deployment ownership | Deny and quarantine | Retain under approved policy or disposition through a separate data decision |
| Inconsistent | Batch and document ownership differ, membership is mixed, or artifact metadata contradicts the object contract | Deny the complete operation and quarantine the relationship | Repair only from reviewed authoritative evidence; never copy the batch owner onto documents automatically |
| Legacy-only | Only `tenantId`, a legacy tenant map, an inferred S3 prefix, or another deprecated field exists | Deny and classify as migration-required | Resolve both canonical fields independently from approved authority |

An inventory class is not authorization. A fully bound record still requires the
authenticated customer, authenticated deployment, required action, object, and
membership checks for each operation.

## Prohibited inference

The following values cannot create or repair ownership:

- request headers, query parameters, URL parameters, payload fields, or metadata;
- `tenantId` or customer-only mappings;
- a known batch owner applied to every referenced document;
- an accessible document applied to its batch;
- bucket names, S3 prefixes, object keys, filenames, or artifact locations;
- creator, uploader, email, display name, route, processing domain, or worker;
- account proximity, current runtime configuration, or the deployment performing
  the inventory; and
- statistical similarity, timestamps, or any best-effort guess.

If both canonical values cannot be proven independently from approved authority,
the record remains denied and quarantined.

## Report-only inventory procedure

No inventory may begin until a later task explicitly names the environment,
read-only identity, region, authoritative ownership sources, evidence
destination, retention, and approvers. Production remains read-only by default.

1. Confirm the exact revision, environment, and read-only execution identity.
2. Confirm authoritative customer and deployment sources with the data owner and
   Application Security. A current application record is not automatically its
   own ownership authority.
3. Run in report-only mode. Do not update tables, objects, indexes, memberships,
   S3 metadata, queues, or task definitions.
4. Classify each object and each batch-to-document relationship using the table
   above. Record opaque references and aggregate counts, not raw identifiers or
   contents.
5. Validate that pagination and retries preserve the same inventory boundary and
   do not omit or duplicate records. Record aggregate reconciliation counts.
6. Store protected detail only in the approved encrypted evidence system. Git,
   general CI artifacts, PRs, Linear, and NotebookLM receive sanitized counts and
   status only.
7. Have an independent reviewer confirm classification logic, source authority,
   unresolved ambiguity, and the absence of mutation.
8. Mark every unresolved record denied/quarantined. A report-only result never
   promotes an object to accessible state.

## Reviewed migration procedure

A live migration is outside GUG-114 repository implementation and requires a
separate approved task, change record, dry-run, rollback package, and exact
non-production scope before production can be considered.

1. Freeze the reviewed report and bind it to its source revision, inventory
   query, authoritative source versions, environment, and time.
2. Exclude every ambiguous, orphaned, inconsistent, or source-drifted record.
   Those records remain quarantined.
3. Produce a proposed mapping with both canonical fields and an opaque record
   reference. Do not include object contents or artifact locators in general
   evidence.
4. Require approval from the data owner, Application Security, and the authorized
   change owner. Approval of counts is not approval of individual ambiguous
   mappings.
5. Execute another report-only dry-run immediately before mutation. Any source,
   count, ownership, or membership drift blocks the migration.
6. Use per-record conditional writes that require the reviewed pre-migration
   state, reject existing conflicting ownership, and never overwrite a concurrent
   update. Preserve record version and audit linkage.
7. Migrate batches and documents only when every relationship is exact. A mixed
   batch is not partially released.
8. Verify canonical fields, conditions, membership, authorized positive access,
   cross-customer and cross-deployment denial, and enumeration-safe responses.
9. Reconcile attempted, changed, unchanged, condition-failed, and quarantined
   counts. Any unexplained difference blocks release.
10. Release a record from quarantine only after independent evidence review.
    Production enablement remains governed by GUG-117 and later gates.

## Failure, containment, and rollback

- A missing source, failed read, pagination uncertainty, malformed record, or
  unexplained count is **Blocked** and produces no ownership write.
- A conditional-write failure leaves the record denied and quarantined; it is not
  retried with a weaker condition.
- A discovered cross-boundary membership denies the entire batch operation and
  triggers review. It is not repaired by dropping the foreign member silently.
- A failed migration stops further writes and preserves the reviewed before-image
  in the approved evidence system. Do not delete records or artifacts.
- Rollback uses conditional writes tied to the migration change and verified
  post-migration version. It restores the prior data state, which remains denied
  or quarantined when ownership is absent.
- Never roll back by re-enabling `tenantId`, inferring prefixes, weakening object
  authorization, editing live data manually, or bypassing central authorization.

## Evidence checklist

- exact revision, tool, mode, environment, time, and reviewer recorded;
- report-only execution confirmed before any separately approved migration;
- authoritative sources and ownership mapping rules approved;
- classification and reconciliation counts complete;
- pagination, retry, and condition behavior validated;
- cross-customer, cross-deployment, mixed-membership, and enumeration negatives
  passed with synthetic or approved non-production fixtures;
- protected evidence stored only in the approved external system;
- no object contents, PII, tokens, S3 keys, presigned URLs, real identifiers,
  logs, state, plans, or customer data entered Git, PRs, Linear, or NotebookLM;
- rollback package and quarantine disposition reviewed; and
- GUG-117 and production remain **Blocked / NO-GO** until their separate exit
  evidence is accepted.

## Evidence state

This file's presence is only an **Implemented** repository procedure. A named
successful local validator may classify that validator as **Locally validated**.
An identified passing PR check is required for **CI validated**. No inventory,
migration, quarantine operation, AWS behavior, or two-deployment isolation is
**Live validated** by this document. Those activities remain **Blocked**, and
production remains **NO-GO**.
