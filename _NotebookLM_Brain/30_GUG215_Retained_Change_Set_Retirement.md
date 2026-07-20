# GUG-215 — Brokered retirement of one retained Change Set

## Purpose

GUG-215 defines a fail-closed way to retire one exact unexecuted
CloudFormation Change Set retained on the empty platform-authority review shell
when the original bootstrap Plan cannot be proved.

This source is sanitized. It contains no account/principal identifiers,
Identity Store UserIds, assignments, ARNs, UUIDs, Change Set names, Lambda
artifact locators, templates, ledger documents, AWS responses or screenshots.

The repository implementation did not deploy or invoke the PEP. It did not
delete or execute a Change Set, delete a stack, create customer infrastructure,
run Terraform, seed an account or enable production.

## Why historical cancellation is not reused

The historical bootstrap `cancel` path requires the original typed Plan. Live
metadata cannot prove its initiator, review, timestamps or evidence lineage.
Reconstructing the Plan would fabricate provenance.

GUG-215 therefore uses a separate service-owned ledger and broker. Nothing it
produces can satisfy the historical Plan schema or authorize bootstrap Apply.

## One service principal owns every mutation

The GUG-215 CloudFormation template defines:

- one dedicated DynamoDB ledger;
- one code-signed Lambda function;
- one immutable published version;
- aliases `classify`, `retire` and `reconcile` pinned to that version;
- one broker execution role;
- two identity-enhanced human invoker roles.

Only the broker execution role can write the ledger or call
`DeleteChangeSet`. Human identities can only assume/set Identity Center context
into an exact invoker role. That role can invoke only its qualified alias; the
reviewed CLI forces synchronous `RequestResponse`, while any separately
authorized asynchronous path blocks live use.

The Lambda payload must be exactly `{}`. The alias chooses the operation;
immutable configuration and fresh AWS reads choose every target. A request can
never supply an action, account, stack, Change Set, ledger key or identity.

## Independent operators are immutable Identity Store users

The deployment binds two different actual IAM Identity Center
`IdentityStore UserId` values: classifier and approver. Equality is rejected by
CloudFormation and runtime configuration.

The invoker-role trust and invoke policies require identity-enhanced sessions
with exact UserId, Identity Store, Identity Center Instance and Application.
There is no session-name or `IfExists` fallback.

The source permission sets are exactly `ScanalyzeAuthorityRetireClass` and
`ScanalyzeAuthorityRetireApprove`. The classifier may invoke only `classify`.
The approver may invoke only `retire` and `reconcile`. Profiles and terminals
do not establish this identity boundary.

Repository configuration does not prove the users and assignments exist.
Until two genuinely independent operators, provisioning and identity-enhanced
session readback are established, live retirement remains blocked.

An ordinary SSO profile is not identity-enhanced. The repository does not yet
provide the reviewed `CreateTokenWithIAM` plus STS `ProvidedContexts` adapter,
so the command surface is not live-ready. Lambda also does not receive the
direct caller identity: IAM enforces the UserId boundary before invocation,
and a live preflight must prove no foreign alias-invoke authority exists.

## Version and effective-authority binding

The broker requires a reviewed versioned S3 artifact, expected code SHA,
code-signing configuration, published version and reserved concurrency of one.
It rejects `$LATEST` and alias drift.

Before every operation it reads back its execution-role trust, inline-policy
inventory, attached policies and canonical effective broker-policy digest. It
also binds configured assignment and invoker-policy digests into the durable
identity record. Actual Identity Center provisioning readback remains an
external prerequisite; the human CLI accepts no policy input.

## Resource-policy-protected ledger

The table is keyed by:

```text
gug215#sha256:<64-hex-sha256-of-full-change-set-id>
```

It is deletion-protected, KMS encrypted, point-in-time recoverable and tagged
as non-production control metadata. Its resource policy denies DynamoDB writes
from every principal except the exact broker execution role.

The state machine is:

```text
CLASSIFIED -> APPROVED -> ATTEMPTED -> RETIRED_RECONCILED
```

- `classify` performs live target proof and create-only `CLASSIFIED`.
- `retire`, invoked by the independent approver, creates the durable approval,
  then consumes the one attempt before deletion.
- `reconcile` writes the terminal state only after exact target absence.
- An ambiguous delete leaves `ATTEMPTED` and never permits a second delete.

Local files, terminal output and copied digests cannot manufacture or reset
this authority.

## Exact target authorization

The broker proves:

- canonical empty `REVIEW_IN_PROGRESS` shell;
- zero stack resources and no inherited service role or nesting;
- complete paginated Change Set inventory;
- exact full Change Set ARN/UUID and expected state/type;
- exact original template, parameters, tags and four resource additions;
- exact broker runtime and ledger controls.

The broker execution role can delete only the configured Change Set name on
the canonical stack. It cannot execute the Change Set, delete/update the stack,
create another Change Set, mutate IAM or access a customer deployment.

## Human command surface

The only human CLI operations are:

```text
broker-classify  -> invoke alias classify
broker-retire    -> invoke alias retire
broker-reconcile -> invoke alias reconcile
```

The CLI validates the exact invoker role, invokes synchronously with an empty
payload and prints only sanitized status, ledger digest and next-required
control. Direct CloudFormation and DynamoDB mutation adapters are disabled.

## One attempt and reconciliation only

`retire` moves the durable item through `APPROVED` and `ATTEMPTED` before the
one delete request. After the claim, it requires the same retirement key and
all target digests, then uses the full Change Set and Stack IDs. SDK retries
are disabled. Any exception or lost response returns reconciliation required.

A later `retire` invocation sees `ATTEMPTED` and cannot issue another delete.
The `reconcile` alias has no delete path. It binds every inventory to the
classified full Stack ID digest and writes `RETIRED_RECONCILED` only after two
consecutive proofs of exact absence, zero active Change Sets and the preserved
empty shell, with the second proof immediately before the terminal CAS.

## Recovery readiness remains separate

GUG-215 never returns `READY`. Terminal reconciliation requires revocation of
both temporary assignments and sessions. Missing or partial account-level S3
Public Access Block adds an independent PAB remediation requirement. A fresh
GUG-214 preflight must prove the complete recovery state.

## Current evidence status

| Class | Status |
|---|---|
| Implemented | Only on the exact reviewed commit containing broker, aliases, identity-enhanced invokers, resource-policy ledger, CLI, tests and docs |
| Locally validated | Only named local gates on that commit |
| CI validated | Pending required checks for the exact PR commit |
| Live inventory | Sanitized read-only observation only |
| Live broker deployment | **Not performed** |
| Live alias invocation | **Not performed** |
| Identity-enhanced credential adapter | **Not implemented; live blocker** |
| Account-wide foreign invoke inventory | **Not performed; live blocker** |
| Live retirement | **Blocked** |
| Production | **NO-GO** |

## Questions this source should answer

1. Why can the retained Change Set not reconstruct the original bootstrap Plan?
2. Which principal is the only ledger writer and Change Set deleter?
3. Why do human permission sets and invoker roles have invoke-only authority?
4. How do two immutable Identity Store UserIds establish the technical
   separation boundary?
5. Why does the human CLI accept no identity or policy input?
6. How do published version, aliases, code digest and code signing bind the PEP?
7. What does the DynamoDB resource policy prevent?
8. Why must the Lambda event be empty?
9. When are `APPROVED` and `ATTEMPTED` written?
10. Why can an ambiguous outcome never issue a second delete?
11. What can the `reconcile` alias write, and when?
12. Why does successful retirement still not mean recovery `READY`?
