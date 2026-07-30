# ADR-040: Fail-closed Platform-Authority Recovery Preflight

- **Status:** Accepted for repository implementation; live recovery remains blocked
- **Date:** 2026-07-19
- **Work package:** GUG-214
- **Amends:** ADR-034 and ADR-039
- **Amended by:** [ADR-041](ADR-041-retained-change-set-retirement.md)
- **Production:** **NO-GO**

## Context

The normal platform-authority Plan role could describe the exact bootstrap
stack but could not enumerate its Change Sets. A read-only recovery attempt
therefore proved that the retained stack shell was `REVIEW_IN_PROGRESS` and
contained zero resources, but could not prove that it contained zero active,
foreign or stale Change Sets. Continuing from that partial observation would
make absence an inference instead of evidence.

The durable founder PEP had two related gaps. Its Plan path did not repeat a
paginated Change Set inventory immediately before the ledger claim and again
immediately before `CreateChangeSet`. Its Plan and Apply policies allowed
`dynamodb:DescribeTable` for the exact ledger table while the reviewed runtime
also calls `DescribeContinuousBackups` to prove point-in-time recovery. A broad
managed read-only policy could observe those facts, but it would not prove that
the operational Plan or Apply principal had the exact authority required by
the PEP.

## Decision

### 1. Recovery has one canonical read-only command

`platform-authority-bootstrap.py preflight-recovery` is the only normal-flow
command for adopting an existing bootstrap review shell. It accepts only the
canonical Plan SSO principal in the exact authority account and Region. It
fails closed unless all of the following are proved from AWS responses:

- the exact bootstrap stack exists in `REVIEW_IN_PROGRESS`;
- `ListStackResources` returns exactly zero resources;
- every page of `ListChangeSets` returns zero active Change Sets;
- the account-level S3 Block Public Access configuration is present and all
  four settings are true.

Malformed pages, missing or repeated pagination tokens, unknown summaries,
partial account controls, access denied, timeout or an ambiguous response are
authorization failures. Output is limited to sanitized state classes and
counts; stack IDs, Change Set names, ARNs and raw AWS responses remain private
operational evidence.

The shell is also rejected if CloudFormation reports a service `RoleARN`, any
notification destination, or nested-stack `ParentId`/`RootId` metadata. A
service role is durable stack authority that CloudFormation can reuse without
the caller presenting `iam:PassRole` again; adopting such a shell would turn a
later exact Change Set execution into a confused-deputy path. The same shared
metadata contract is re-evaluated in normal and founder Plan/Apply immediately
before their protected CloudFormation effects.

### 2. List authority is separate and exact-stack

The normal Plan policy receives a separate `cloudformation:ListChangeSets`
statement scoped to the canonical bootstrap stack ARN. It is not added to an
existing `Resource: "*"` read statement and does not authorize Create, Delete
or Execute. The CLI paginates until AWS provides no continuation token and
treats any returned active summary as a stop condition.

`ListChangeSets` reports active Change Sets; it is not evidence that no deleted
or historical Change Set ever existed. Historical evidence remains in the
approved audit and CloudFormation records. The recovery decision requires
zero *active* Change Sets at the instant of each check.

### 3. Empty shells do not authorize inferred resource reads

An empty `REVIEW_IN_PROGRESS` shell has no trusted physical resource IDs or
stack outputs. Recovery must not derive KMS keys, S3 buckets or DynamoDB tables
from naming conventions, request fields, prior receipts or expected template
names. KMS, S3 and DynamoDB resource inspection begins only after the exact
resource locator is obtained from trusted stack metadata or another reviewed
contract.

Account-level S3 Block Public Access is different: it is bound to the already
validated account and is therefore safe to read. If the account control is
absent, the recovery preflight blocks; it does not create or repair it.

### 4. Founder Plan closes the inventory race as far as AWS permits

Founder Plan enumerates every page of active Change Sets while validating the
empty shell and repeats that inventory after the durable Plan CAS, immediately
before `CreateChangeSet`. A non-empty or ambiguous inventory before the CAS
denies without consuming an attempt. A non-empty or ambiguous inventory after
the CAS closes the consumed attempt as failed or uncertain according to the
existing no-retry state machine; it never creates a second Change Set.

This double check reduces, but cannot eliminate, time-of-check/time-of-use
risk. CloudFormation does not offer an atomic "create only if the stack has no
Change Sets" primitive. The durable CAS serializes reviewed PEP clients, exact
IAM scoping limits the permitted stack and name, and any foreign concurrent
writer remains a P0 governance failure requiring read-only reconciliation.

### 5. Ledger control reads match runtime behavior

Founder Plan and Apply may call both `dynamodb:DescribeTable` and
`dynamodb:DescribeContinuousBackups`, scoped only to the canonical durable
ledger table ARN. Neither role receives ListTables, Scan, backup mutation,
restore or table deletion authority. The runtime requires ACTIVE status,
deletion protection, encryption, the exact key schema and enabled point-in-time
recovery before a protected effect.

### 6. General ReadOnly is independent corroboration only

A separately assigned read-only SSO profile may corroborate inventory during a
review. It is never the Plan or Apply authority, never satisfies the exact-role
check, never repairs an access denial in the operational permission set and is
never attached as a managed policy to a Scanalyze permission set. Findings from
that profile are classified separately from PEP execution evidence.

### 7. A retained Change Set requires the separate GUG-215 path

If the canonical inventory returns one retained active Change Set and its
original private bootstrap Plan receipt cannot be proved, this recovery
preflight remains blocked. The historical `cancel` command is not weakened and
the receipt is never reconstructed from live metadata.

[ADR-041](ADR-041-retained-change-set-retirement.md) defines a separate
version-pinned Lambda PEP. Human permission sets can only establish exact
Identity Center context and assume their account-local invoker roles; those
roles invoke qualified `classify`, `retire` or `reconcile` aliases. Humans
receive no `DeleteChangeSet` or DynamoDB write authority. The broker execution
role is the only ledger writer and the only principal permitted to delete the
exact retained metadata object.

The deployment binds two different immutable Identity Store UserIds, exact
assignments and invoker-policy digests, reviewed broker code and effective
broker-policy digests, and a resource-policy-protected durable ledger. The
request payload is empty; aliases and immutable configuration establish
authority. Live deletion remains blocked until the broker stack and two
genuinely independent operators are provisioned and read back. Only the live
broker configuration and durable ledger establish retirement authority.

Missing or partial account Public Access Block may coexist with verified
retirement of the unexecuted metadata object, but GUG-214 recovery readiness
remains blocked until the all-true PAB invariant is proved. The retirement path
does not repair PAB and never emits `READY`; temporary role/session revocation
must also be proved.

## Consequences

- A retained shell cannot be silently adopted while active Change Sets exist.
- Exact operational roles can prove the controls their code enforces without a
  broad read-only attachment.
- Missing account Public Access Block remains an explicit blocker.
- A retained unexecuted Change Set with no provable original Plan is routed to
  GUG-215; it is not canceled by inference or silently adopted.
- A legacy shell with inherited service-role, notification or nesting metadata
  remains quarantined and cannot be adopted.
- The implementation adds no AWS mutation, auto-remediation or delete path.
- A concurrent foreign Change Set between the last inventory and create remains
  a residual TOCTOU risk and a stop condition on subsequent readback.

## Alternatives rejected

- **Use a general ReadOnly managed policy for Plan:** observation is not
  operational authority and would hide least-privilege drift.
- **Trust an empty resource list alone:** resources and Change Sets are distinct
  CloudFormation inventories.
- **Inspect expected KMS/S3/DynamoDB names:** naming is not ownership evidence.
- **Delete the review shell and retry:** deletion hides evidence and can affect
  retained resources or a concurrent plan.
- **Ignore pagination:** the first page cannot prove global absence.
- **Trust an existing CloudFormation service role:** stack service roles are
  persistent delegated authority and violate the terminal Plan/Apply boundary.

## Rollback and recovery

Repository rollback removes the new command and exact read grants, but does not
delete or mutate AWS resources. Operational rollback is always read-only
reconciliation: retain the shell, active Change Sets, ledger and account
controls until a separately reviewed action authorizes a specific change.
Never auto-delete a stack, Change Set, bucket, key, table or ledger attempt.

If a separately authorized GUG-215 retirement is attempted later, ambiguous
deletion is never retried. Its rollback is invocation of the broker's
non-delete `reconcile` alias against the original immutable deployment binding;
a replacement requires a new normal Plan.

## Evidence classification

| Class | Status |
|---|---|
| Implemented | Only after the reviewed commit contains the command, exact IAM statements, founder double inventory, table-control reads, tests and documentation |
| Locally validated | Only after named focused and repository gates pass on that commit |
| CI validated | Pending required checks for the exact PR commit |
| Live validated | **Blocked** until the merged policies are provisioned and the canonical command succeeds under the exact Plan identity |
| Production | **NO-GO** |
