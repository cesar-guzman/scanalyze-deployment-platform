# GUG-214 — Fail-closed authority recovery preflight

## Purpose

GUG-214 closes an evidence gap in the bootstrap of Scanalyze's dedicated
platform-authority account. An existing CloudFormation shell can be adopted
only when the canonical Plan identity proves that the exact stack is an empty
`REVIEW_IN_PROGRESS` shell, that every page contains zero active Change Sets,
and that account-level S3 Block Public Access is present and all true.

This source is sanitized. It contains no account IDs, principals, ARNs, Change
Set names, raw policies, AWS responses or operational receipts.

## Root cause

The earlier read-only path could prove zero stack resources but lacked
`ListChangeSets`. Zero resources is not the same fact as zero Change Sets, so
recovery could not continue without inferring absence. The founder PEP also
needed to repeat that inventory immediately before creation and its exact
ledger metadata permissions needed to match both runtime reads:
`DescribeTable` and `DescribeContinuousBackups`.

## Canonical recovery contract

The command is:

```text
platform-authority-bootstrap.py preflight-recovery
```

It requires the exact normal Plan SSO role and checks:

1. exact account and Region from STS;
2. exact stack status `REVIEW_IN_PROGRESS`;
3. canonical StackId and no service `RoleARN`, notification ARNs, `ParentId` or
   `RootId`;
4. zero stack resources;
5. zero active Change Sets across all pages;
6. present, all-true account S3 Block Public Access.

Any access denial, partial response, malformed pagination, returned Change Set
or missing account control is **Blocked**. The command never writes or repairs
AWS.

## Least-privilege boundaries

- Normal Plan receives `ListChangeSets` in a separate exact-stack statement.
- Founder Plan inventories Change Sets before its durable CAS and again
  immediately before `CreateChangeSet`.
- Founder Plan and Apply may read `DescribeTable` and
  `DescribeContinuousBackups` only on the exact ledger table.
- No path gains ListTables, Scan, restore, backup mutation or delete authority.
- A general ReadOnly profile is independent corroborating evidence, never Plan
  or Apply authority and never a managed policy attached to Scanalyze roles.

## No inference from an empty shell

An empty review shell has no trusted physical IDs or outputs. The workflow does
not guess KMS keys, S3 buckets or DynamoDB tables from names, templates or
requests. Those resource reads wait for trusted stack metadata. Account-level
S3 Block Public Access can be read because it is bound to the already validated
account; if absent, recovery stops.

An otherwise empty shell with a CloudFormation service role is not safe to
adopt. CloudFormation can reuse that persistent delegated role without a later
`iam:PassRole`, so recovery, normal Plan/Apply and founder Plan/Apply all reject
service-role, notification and nested-stack metadata and recheck before their
protected effect.

## Concurrency and residual risk

CloudFormation has no atomic operation that creates a Change Set only if zero
other Change Sets exist. The founder path checks twice and uses the durable CAS
ledger, exact role, exact stack and exact name. This narrows the TOCTOU window
but does not remove it. A foreign concurrent writer is a P0 stop; the consumed
attempt is not reset or retried.

`ListChangeSets` is an active inventory, not a complete historical audit.
Historical evidence remains in governed CloudFormation and audit records.

## Recovery and rollback

Rollback does not delete the shell, Change Sets, table, ledger, bucket or key.
An unexpected or ambiguous state permits read-only reconciliation only. Any
mutation or decommission requires a separate reviewed authorization.

## Evidence classification

| Class | Status |
|---|---|
| Implemented | Repository code, exact IAM contracts, tests, ADR and runbooks in the reviewed commit |
| Locally validated | Only named local gates on that commit |
| CI validated | Only required checks for the exact PR commit |
| Live validated | **Blocked** until merged policies are provisioned and the exact Plan role completes the canonical preflight |
| Production | **NO-GO** |

## Questions this source answers

1. Why are zero resources and zero Change Sets separate proofs?
2. Which identity is allowed to adopt an existing review shell?
3. Why can a general ReadOnly profile not replace Plan?
4. Why does missing Public Access Block stop instead of auto-remediate?
5. Which exact DynamoDB metadata reads prove table and PITR controls?
6. What TOCTOU risk remains and why is retry forbidden?
7. Why are KMS/S3/DynamoDB names never inferred from an empty shell?
8. Why does any retained CloudFormation service role block shell adoption?
