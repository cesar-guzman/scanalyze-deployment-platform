# ADR-039: Durable one-shot founder bootstrap PEP

- **Status:** Accepted for repository implementation; live seed and execution pending review
- **Date:** 2026-07-17
- **Work package:** GUG-211
- **Supersedes:** the future-PEP placeholder in ADR-037; it does not supersede the normal GUG-206 two-person flow

## Context

The dedicated platform-authority account initially has one qualified operator.
GUG-209 modeled that exceptional risk explicitly, but deliberately remained
offline-only: a local JSON ledger could not prove freshness, serialize an AWS
effect, or prevent a retry after an ambiguous response.

The authority backend cannot provide its own pre-bootstrap ledger. Putting the
ledger in Audit, shared-services, or either customer destination would create a
standing cross-account authority and the wrong ownership boundary. The root of
trust therefore must be seeded from the AWS Organizations management account
before temporary founder Plan or Apply authority exists.

## Decision

### 1. Management seeds only two preventive controls

The management account may perform a separately reviewed, one-time seed:

1. attach an Amazon S3 organization policy with
   `public_access_block_configuration = all` only to account `042360977644`;
2. use a service-managed CloudFormation StackSet with account-filter
   `INTERSECTION` to deploy one retained DynamoDB table in `us-east-1`.

The StackSet has automatic deployment disabled, failure tolerance zero,
concurrency one, and no foreign stack instances. Its template creates no IAM,
Lambda, S3, KMS, workload, customer, or production resources. The table uses
on-demand billing, AWS-managed KMS encryption, point-in-time recovery, deletion
protection, and retain policies.

The seed is not founder authorization. It cannot create permission sets,
assign users, create the authority backend Change Set, or execute it.
The reviewed management-session policy grants only the exact Organizations
S3-policy and service-managed StackSet APIs; it contains no IAM, Identity
Center, customer-account, backend Change Set, or production permission.
Because AWS Organizations requires `organizations:TagResource` when
`CreatePolicy` carries tags, that action is authorized only in the same
create-bound statement and under the exact `S3_POLICY`, request-tag values and
tag-key set. The seed cannot independently retag, untag or update an existing
policy.
The live seed CLI accepts only the management-account SSO permission set
`ScanalyzeFounderPepSeed`; a generic administrator session is rejected.

### 2. A typed intent precedes every effect

The private PEP intent binds:

- exact authority account and Region;
- literal non-production classification and `production=false`;
- explicit absence of independent approval;
- one operator subject digest and two distinct live SSO principal digests;
- one template digest, canonical Change Set name, and four-resource inventory;
- normal-Plan revocation plus twelve-hour quarantine;
- disjoint bounded Plan and Apply windows;
- one Plan attempt, one Apply attempt, and twelve-hour deny retention.

Raw Identity Center IDs, ARNs, policy documents, plans, Change Set IDs, ledger
documents, and AWS responses remain private mode-0600 evidence outside Git,
Linear, NotebookLM, and general CI artifacts.

### 3. DynamoDB is the authoritative PEP ledger

The partition key is the exception ID. Initial creation requires
`attribute_not_exists(exception_id)`. Every transition is a full-document
compare-and-swap on version, digest, state, Plan count, and Apply count. There
is no Scan, GSI, DeleteItem, batch write, or request-selected table.
State, counters, version, binding presence and timestamps are validated as one
invariant: versions 1 through 6 map exactly to the allowed lifecycle, Apply
terminal states retain the reviewed Change Set evidence, and time may never
move backwards.

State transitions are:

```text
PREPARED
  -> PLAN_ATTEMPTED
  -> PLAN_REVIEWED
  -> APPLY_ATTEMPTED
  -> SUCCEEDED | FAILED | UNCERTAIN

PLAN_ATTEMPTED -> FAILED | UNCERTAIN
```

The PEP commits `PLAN_ATTEMPTED` before `CreateChangeSet` and
`APPLY_ATTEMPTED` before `ExecuteChangeSet`. A lost response, timeout,
unverifiable readback, or storage conflict becomes `UNCERTAIN`; retry is
forbidden. A lost final CAS response is accepted only when a fresh consistent
read returns the exact intended terminal digest; otherwise the claimed record
is closed as `UNCERTAIN` or explicitly requires reconciliation. Only read-only
reconciliation may follow.

### 4. Temporary roles cannot administer their own authority

The founder Plan and Apply policies bind AWS time, Identity Center subject,
Region, exact Change Set, exact stack, and exact DynamoDB leading key. They
contain no Organizations, IAM Identity Center, IAM, customer, or production
authority.

Plan can consume its ledger item and create/review/cancel only the exact Change
Set. It cannot execute. Apply can consume its ledger item and execute only the
reviewed Change Set. It cannot create/cancel Change Sets, mutate account-level
S3 Block Public Access, delete the stack, retarget KMS aliases, scan/delete the
ledger, or create customer resources. Both policies deny all calls outside the
AWS-side time window or authenticated subject binding.

A separately authenticated management-account Identity Center administrator
may manage only tagged GUG-211 permission sets in the exact Identity Center
instance and provision/assign them only to authority account `042360977644`.
Read-only inventory is broader only to prove the normal Plan assignment count.
The workflow creates no groups or memberships: each temporary permission set
has exactly one direct `USER` assignment to the intent-bound subject. Plan and
Apply assignment windows cannot overlap.
That administrator must use `ScanalyzeFounderPepIdentityAdmin` with the
reviewed least-privilege policy; `AWSAdministratorAccess` is not accepted by
the CLI. Creating and assigning the seed and identity-admin permission sets is
a separately reviewed management-account bootstrap step and is not performed
by this repository package.

### 5. Success requires authoritative readback and revocation

Immediately before each effect, the PEP re-reads STS identity, effective S3
Block Public Access, table controls, stack state, Change Set ARN/name/status,
tags, the `Original` template body and its exact approved SHA-256, and complete
resource inventory. Apply success requires
`CREATE_COMPLETE`, exactly the four reviewed resources, exact stack outputs,
account and bucket Block Public Access, bucket owner enforcement, versioning,
KMS/bucket-key encryption, lifecycle, non-public deny-only bucket policy,
exact tags, KMS metadata/policy/tags, and enabled rotation.

Execution success does not close the exception. Temporary Plan/Apply
assignments must be removed, absence read back by the management administrator,
and the expired deny retained for twelve hours. The Apply session may close the
ledger only after AWS reports zero normal Plan/founder assignments and before
its own bounded window expires. The final `SUCCEEDED -> REVOKED` transition is
another exact DynamoDB CAS and stores the revocation digest. Only after the
retention timestamp may the two tagged permission sets be retired. Until that
receipt is `REVOKED`, GUG-206 and production remain blocked.

## Consequences

- There is a narrow, auditable founder exception without silently degrading
  normal two-person approval.
- The management account is a bootstrap root of trust, not a runtime authority.
- Customer onboarding remains account-per-deployment and does not reuse this
  table or founder roles.
- The durable ledger is retained; rollback never deletes or resets attempts.
- Enabling Organizations S3 policy type and StackSets trusted access are live
  governance changes requiring exact review and authorization.

## Trust boundary and residual administrator risk

The compare-and-swap is enforced by the reviewed PEP client and DynamoDB
condition expressions. DynamoDB IAM can restrict the table and partition key,
but it cannot require a caller to include a specific `ConditionExpression` or
prove the semantic contents of an arbitrary `PutItem`. Consequently, this
design does not claim resistance to a malicious or compromised
authority-account administrator or founder session that deliberately bypasses
the reviewed CLI.

Before any live window, the operator must use only the task-specific Identity
Center permission sets and any standing broad administrator assignment capable
of bypassing the workflow must be removed or placed outside the reviewed
session window. This residual is acceptable only for the explicitly recorded,
single-operator, non-production founder event. It is not a production approval
model. Eliminating administrator bypass requires a separately reviewed trusted
compute PEP and independent administration; that is a later hardening package,
not an implicit property of GUG-211.

## Alternatives rejected

- Local files or S3 objects as locks: no atomic conditional state transition.
- Audit/shared-services/customer ledger: wrong owner and cross-boundary
  standing authority.
- Create the table from founder Apply: circular trust.
- Retry after timeout: can duplicate an unobserved protected effect.
- Remove the GUG-209 offline deny in place: turns a safe review artifact into
  hidden live authority.
- Direct account-level PAB from founder Apply: lets the exception change its own
  precondition.

## Rollback

Before a Plan claim, revoke temporary assignments and leave the seed controls
in place. After a Plan or Apply claim, never reset/delete the ledger or reuse
the exception. On uncertainty, run read-only reconciliation. Retain the S3
organization policy and protected table; removing either is a separate
governance change, not routine rollback.

## Evidence classification

| Class | Status |
|---|---|
| Implemented | Repository contracts, seed template, PEP core/CLI, IAM templates, schemas, tests, ADR and runbooks in the reviewed commit |
| Locally validated | Only after named local gates pass |
| CI validated | Only after required checks pass for the exact commit |
| Live validated | No; the seed and founder windows have not run from this branch |
| Production | **NO-GO** |
