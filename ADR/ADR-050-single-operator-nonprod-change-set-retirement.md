# ADR-050: Single-Operator Non-Production Change Set Retirement

- **Status:** Proposed repository contract; not deployed
- **Date:** 2026-08-11
- **Issue:** GUG-215
- **Amends:** ADR-041, ADR-043, ADR-044 and ADR-045 only for the bounded mode below

## Decision

Scanalyze may retire the one exact GUG-215 retained, unexecuted CloudFormation
Change Set with one human only when an immutable
`SINGLE_OPERATOR_NONPROD_EXCEPTION` is deployed into the existing broker
boundary. This is an additive emergency path. The normal two-human path and
its negative tests remain unchanged.

The exception does not assert independent review. Every receipt and ledger
record must state:

```text
authorization_mode = SINGLE_OPERATOR_NONPROD_EXCEPTION
two_human_status = NOT_PROVEN
independent_approval_present = false
production = false
```

It never authorizes production, customer accounts, `ExecuteChangeSet`,
`DeleteStack`, `CreateChangeSet`, Terraform, stack deployment, Identity Center
provisioning or an additional delete attempt.

## Immutable exception artifact

Before deployment, the owner produces one canonical digest-only v1 artifact.
It binds:

- the exact authority account digest, `us-east-1`, stack and `retirement_id`;
- the full Change Set ID digest, original-template digest and resource-inventory
  digest;
- the exact Identity Center binding and single immutable operator UserId
  digest;
- the exact Lambda runtime pin where
  `RuntimeManagementConfig.UpdateRuntimeOn = Manual`, plus the reviewed
  `RuntimeVersionArn` digest;
- the canonical `BrokerVersionBindingSha256` covering every published function
  property and environment input;
- the exact owner-authorization digest;
- the owner-reviewed expected `authorization_digest` of the complete exception
  artifact;
- a not-before time, expiry and maximum fifteen-minute effect window;
- one allowed CloudFormation effect: `cloudformation:DeleteChangeSet`;
- only the broker's required ledger `PutItem` and `UpdateItem` effects;
- the explicit forbidden mutation set;
- `single_execution = true`, `request_selectable = false` and
  `deployment_authorized = false`.

The artifact may be created no more than one hour before activation. Missing,
unknown, malformed, stale, future or digest-drifted fields fail closed before
an AWS client is used. The owner-reviewed expected `authorization_digest`
prevents deployment
parameters from silently minting a different internally valid exception. The
artifact is evidence and a deployment input; it is not by itself deployment or
execution authorization.

The broker code is built only from the exact clean reviewed commit by
`platform-authority-change-set-retirement-package.py`. Its fixed-metadata ZIP
contains the closed seven-member source/import set. The strict public manifest
binds commit, handler, Python runtime, architecture, manually pinned runtime
digest, `BrokerVersionBindingSha256`, every member digest, archive digest and
Lambda `CodeSha256`. GUG-219 v2 accepts candidate A only when the observed
`CodeSha256` equals this manifest and its expected `manifest_digest` arrived
through the owner's separate review channel.

## Exclusive transport

The CloudFormation template deploys exactly one of two alias families:

```text
TWO_HUMAN                         SINGLE_OPERATOR_NONPROD_EXCEPTION
classify                          single-classify
retire                            single-retire
reconcile                         single-reconcile
```

The families are mutually exclusive. The authorization mode is immutable
function configuration; the request remains unable to choose an operation,
mode, identity or target. A normal deployment cannot invoke `single-*`, and an
exception deployment cannot invoke the normal aliases.

Both technical invoker roles remain least-privilege and distinct, but the
exception requires their Identity Store bindings to name the same one human.
That fact is recorded as non-independent; it is never reclassified as duty
separation.

## Durable one-attempt state machine

Normal two-human ledger v2 is unchanged. The exception uses ledger v3:

```text
CLASSIFIED v1, attempts=0
  -> EXCEPTION_ACCEPTED v2, attempts=0
  -> ATTEMPTED v3, attempts=1
  -> RETIRED_RECONCILED v4, attempts=1
```

The same immutable user must provide separate, fresh proof receipts through
`single-classify`, `single-retire` and `single-reconcile` for classification,
exception acceptance and reconciliation. The broker binds the
exception digest and owner-authorization digest before it advances the ledger.
It rechecks the effect window immediately before the sole
`DeleteChangeSet` call.

If the window expires before that call, deletion is not attempted. If outcome
is ambiguous after the durable `ATTEMPTED` claim, `single-retire` cannot be
retried. `single-reconcile` remains available after expiry only to prove
absence or preserve the uncertain state; it cannot call delete.

## Deployment and live-use checkpoint

Repository code, tests or this ADR do not authorize AWS changes. Before live
use, the owner must separately authorize the exact reviewed commit and:

1. the CloudFormation/IAM/Lambda/DynamoDB/Identity Center mutations needed to
   deploy this exact exception mode;
2. the exact exception artifact digest and immutable deployment parameters;
3. one broker invocation sequence against the one full Change Set ID digest;
4. mandatory readback, post-attempt reconciliation and exception revocation.

Direct `aws cloudformation delete-change-set` remains prohibited. The only
effect principal is the version-pinned broker execution role, and its policy
continues to deny `ExecuteChangeSet` and `DeleteStack`.

## Rollback and recovery

Before any live deployment, repository rollback is a reviewed revert of this
exception implementation and has no AWS effect. After a separately authorized
deployment but before `ATTEMPTED`, rollback revokes the exact temporary human
assignments and `single-*` invocation authority, reads back their absence and
invalidates the exception. Removing IAM, Lambda, DynamoDB or Identity Center
resources is a separate mutation package; this ADR never authorizes
`DeleteStack` as cleanup.

After the ledger reaches `ATTEMPTED`, rollback never recreates the Change Set,
resets or deletes the ledger, re-enables `single-retire`, or issues another
delete. Revoke the temporary assignments/sessions, retain the ledger and private
evidence, and use only the original version-pinned `single-reconcile` path for
read-only observation and the terminal CAS after exact absence. Read back every
revocation and preserve an uncertain `ATTEMPTED` state when absence cannot be
proved.

If the effect window expires before the durable attempt, no delete is permitted;
revoke and read back the exception path. Any later attempt requires a fresh
artifact, owner-reviewed digest and separately authorized live checkpoint.

## Consequences

- The project no longer waits for a nonexistent second human for this one
  non-production retirement.
- The loss of independent approval is explicit, bounded and auditable.
- Normal two-human controls are not weakened or silently repurposed.
- Production remains **NO-GO**.
- Current status remains **repository-only / AWS mutations none** until the
  separate live checkpoint is approved and read back.
