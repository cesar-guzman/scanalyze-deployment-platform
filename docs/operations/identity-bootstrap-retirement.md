# Identity Bootstrap and Retirement Runbook

> **Status:** target operational procedure; repository implementation only\
> **Decision:** ADR-024 / GUG-93\
> **Lifecycle owner:** GUG-94\
> **Live execution:** **Blocked**\
> **Production:** **NO-GO**

## Purpose

This runbook defines the controlled lifecycle for:

- creating the first deployment-local customer administrator;
- containing failed, expired, replayed, or ambiguous bootstrap requests;
- retiring a consumed bootstrap capability;
- adopting or migrating a compatible legacy identity provider; and
- retaining, disabling, and eventually decommissioning an old identity control
  plane.

It contains no live identifiers, provider exports, user lists, addresses,
credentials, tokens, state, plans, or execution evidence. It does not authorize
AWS access, Cognito operations, queue redrive, Terraform apply, state import,
user migration, client creation, credential rotation, or deletion.

## Non-negotiable invariants

1. One bootstrap request binds one target subject to one exact customer and
   deployment.
2. General human runtime provisioning and self-signup remain disabled.
3. Exactly two independent approvers authorize the same request; the target
   cannot approve it.
4. Required assurance is phishing-resistant and current according to the
   reviewed policy.
5. The request lifetime is no longer than 900 seconds.
6. A conditional claim prevents concurrent execution; conditional consume makes
   the request single-use.
7. Provider and membership effects use the same trusted idempotency key.
8. Provider groups do not establish the role; the authoritative membership
   record does.
9. Enrollment values, client credentials, tokens, raw claims, message bodies,
   and provider responses never enter logs, audit events, Terraform, contracts,
   Git, CI summaries, Linear, or NotebookLM.
10. Missing, malformed, stale, foreign, conflicting, replayed, expired,
    unavailable, or unknown state denies.

## Authority and separation of duties

| Activity | Requester | Approvers | Executor | Reviewer |
|---|---|---|---|---|
| Initial administrator bootstrap | Authorized onboarding owner | Two distinct approved humans; neither is target or sole executor | Lifecycle runtime under its dedicated identity | Application Security plus customer/deployment owner |
| Report-only legacy inventory | Identity/Platform Engineering | Security and data/identity owner | Read-only inventory identity | Independent reviewer |
| State adoption | Platform Engineering | Identity/Security and state owner | Dedicated reviewed Terraform change | Independent reviewer; production requires production authority |
| Blue/green migration | Identity/Platform Engineering | Security, Application, Operations, and customer owner | Approved migration identities | Independent reviewer and gate owner |
| Decommission | Platform Engineering | Security, Operations, identity/data owner, and required production authority | Dedicated destructive change identity | Independent evidence reviewer |

Repository ownership, an AI response, the target subject, or a successful test
is not independent approval.

## Bootstrap record contract

The queue message is not the authority. It carries a reference to an
authoritative record with at least:

- supported request schema version;
- opaque request reference and conditional record version;
- exact target subject, customer, and deployment;
- initial reviewed role;
- `approved` state;
- issue and expiry timestamps;
- trusted idempotency key;
- exactly two approval records with distinct approvers, common binding,
  approved decision, assurance, authentication time, and opaque approval
  reference; and
- current authorization schema, scope catalog, role catalog, policy version,
  and policy digest.

The command repeats the request reference, expected version, and binding only
for conflict detection. Repeated fields do not become authority. The processor
loads the record and requires equality.

## Pre-execution gate

The GUG-93 repository state cannot pass this gate. Terraform configures
`HUMAN_RUNTIME_ENABLED=false`, `USER_POOL_ID=UNBOUND`, and an empty human-client
allowlist; the processor denies before it reads an authoritative request or
invokes provider/membership effects. GUG-93 also does not supply an enabled
human-create adapter or lifecycle authority. Those are deliberate fail-closed
boundaries, not operator values to override.

Before a future authorized bootstrap execution, all answers must be yes:

- Is the deployment tuple authoritative and immutable?
- Is the identity control-plane contract current and exact?
- Has a separately reviewed GUG-94/GUG-153 promotion bound the generated pool
  and SPA client and enabled the exact human path without a Terraform cycle?
- Is the approved provider adapter present under its dedicated least-privilege
  execution identity?
- Is self-signup disabled?
- Is no active administrator already present for this bootstrap purpose?
- Is the target subject bound explicitly rather than inferred from an address,
  domain, group, or existing provider record?
- Are there exactly two independent current approvals?
- Are both approvals bound to the same request/customer/deployment?
- Is neither approver the target?
- Is the request within its 900-second lifetime?
- Are policy/catalog versions and digest current?
- Are conditional claim, idempotent provider operation, conditional membership
  creation, conditional consume, and sanitized audit available?
- Does the reviewed implementation make the final outcome audit recoverable if
  record consumption succeeds but audit persistence fails? The disabled GUG-93
  primitive does not yet satisfy this condition.
- Is the SQS source/DLQ pairing exact and the consumer configured for partial
  batch failures?
- Is a rollback/containment owner available?

Any no, unknown, unavailable, or ambiguous answer is **Blocked**. Do not create
or repair a record manually to bypass the gate.

## Processing sequence

```text
receive message reference
  -> validate message identifier and supported command
  -> load authoritative request
  -> verify exact binding, versions, approvals, assurance, and expiry
  -> conditionally claim expected approved record/version
  -> idempotently ensure provider subject with immutable bindings
  -> idempotently ensure active initial membership
  -> conditionally consume the claimed record
  -> append sanitized audit
  -> return non-sensitive references only
```

The provider adapter may create or reconcile an enrollment state, but the
processor does not return a password, invitation value, recovery value, token,
or raw provider response. Enrollment delivery and first-login verification are
separate GUG-94 responsibilities.

Successful processing changes only the exact approved target and membership.
It does not create support access, emergency access, an M2M client, a second
administrator, an account-wide role, or a cross-deployment mapping.

## Conditional and idempotent behavior

The trusted idempotency key comes from the authoritative record. Request data
cannot replace it.

- A second worker cannot acquire the same expected state/version claim.
- Provider and membership adapters must treat the same key as the same intended
  effect and compare every binding before returning an existing result.
- A conflicting existing provider subject or membership is a denial, not an
  update.
- The request is consumed only after both bounded effects succeed.
- A consume conflict after idempotent effects remains failed/unknown until
  reconciled. Do not create another bootstrap record as a shortcut.
- A consumed request is a replay denial even if the incoming message is an SQS
  retry.

Idempotency prevents duplicate effects. It does not make a stale, foreign,
expired, revoked, or conflicting request valid.

## SQS and DLQ behavior

The consumer returns `batchItemFailures` for each failed message identifier so
successful records are not retried. A malformed record without a usable message
identifier rejects the invocation because a precise retry cannot be expressed.

Operational logs contain only reason categories and aggregate outcomes. They do
not contain the message body, provider exception, target, customer, deployment,
approval data, enrollment material, or membership record.

The DLQ is containment, not a work queue. GUG-93 authorizes no redrive. A future
redrive requires:

1. report-only classification;
2. proof that the same exact deployment and request remain valid;
3. reconciliation of conditional state and prior provider/membership effects;
4. idempotency proof;
5. independent approval, rate limit, and stop criteria; and
6. sanitized before/after counts.

Never purge, copy across deployments, rewrite binding, extend expiry, reset the
record version, or bypass the failed stage.

## Failure classification

| Class | Examples | Treatment |
|---|---|---|
| Invalid | Missing/malformed field, unsupported schema, unknown role/version | Deny; fix source workflow through a reviewed change |
| Foreign/conflicting | Tuple, subject, approval, role, provider, or membership disagrees | Deny and quarantine; no inference |
| Expired/replayed | Request expired, consumed, revoked, or conditional claim lost | Deny permanently; investigate if an effect may have occurred |
| Dependency unavailable | Membership, provider, credential, audit, or store timeout | Fail closed; retain message and reconcile before retry |
| Partial-effect unknown | Provider or membership effect may exist but consume/audit did not complete | Stop automatic retry until idempotent readback proves state |
| Poison message | Repeated deterministic denial reaches paired DLQ | Retain and classify; no automatic redrive |
| Evidence incomplete | Missing approval/audit/readback or uncertain count | Status remains Blocked |

External responses and general evidence use generic categories. They never
reveal whether a foreign subject, request, or membership exists.

## Bootstrap retirement

The bootstrap capability is retired immediately after successful consume or
expiry:

1. confirm the authoritative record is `consumed`, `expired`, or `revoked`;
2. confirm the created membership has the expected exact binding and current
   version;
3. confirm no second pending bootstrap record exists for the same purpose;
4. preserve the append-only sanitized audit event;
5. revoke or expire any provider enrollment mechanism that was not used;
6. leave self-signup and general human runtime provisioning disabled;
7. keep failed messages in their reviewed retention path;
8. record only sanitized status and opaque evidence references; and
9. transfer all subsequent lifecycle work to GUG-94's invitation and
   membership-administration controls.

Retirement does not delete the request or audit record before its approved
retention period. A completed bootstrap cannot be reset to approved.

## Legacy identity inventory

No live inventory is authorized by this runbook. A future report-only inventory
uses a named read-only identity and protected evidence destination, then
classifies:

| Class | Required disposition |
|---|---|
| Fully bound and compatible | Candidate for state adoption after independent review |
| Partially bound | Deny/quarantine; prove all missing fields from authority |
| Ambiguous or shared | Deny/quarantine; no inferred customer/deployment |
| Provider-only/unmanaged | Deny until ownership, policy, and state are proven |
| State-only/orphaned | Stop; reconcile as state/recovery issue |
| Immutable-schema incompatible | Retain and prepare a blue/green migration |
| Inconsistent | Deny; reconcile provider, membership, contract, registry, and state |

Protected inventory details remain outside Git, CI artifacts, Linear, chat, and
NotebookLM. Durable summaries contain aggregate counts and opaque references
only.

## State adoption procedure

State adoption is not an ordinary bootstrap or deployment step. It requires a
separate change and all of the following:

1. exact provider resource identity and ownership proven by the report-only
   inventory;
2. exact tuple and immutable attribute compatibility;
3. current encrypted state backup/version evidence and state-owner approval;
4. versioned import configuration or equivalent reviewed adoption mechanism;
5. a plan that contains no replacement, deletion, ownership drift, or unrelated
   action;
6. independent Platform, Identity, and Security review;
7. approved non-production apply and immediate readback;
8. separate validation of provider behavior, memberships, token claims,
   consumers, and two-deployment denial; and
9. a retained rollback/recovery boundary.

Importing a resource into state proves neither user authorization nor migration
success. If any immutable attribute or binding is incompatible, stop adoption
and use blue/green migration.

## Blue/green migration

For incompatible provider schema or unsafe legacy bindings:

1. retain the old identity resources and disable new authority expansion;
2. create a new isolated control plane through a reviewed saved plan;
3. publish a new versioned contract without replacing the old contract
   silently;
4. migrate only explicitly approved subjects and memberships, with no group,
   domain, pool-name, or customer-only inference;
5. issue new access tokens and reject old versions;
6. move services and edge consumers through reviewed contract gates;
7. prove positive behavior and cross-deployment denial with synthetic data;
8. revoke old sessions/clients only after successor validation;
9. observe through the approved retention window; and
10. obtain a separate retirement decision.

A partial migration leaves both sides retained and production **NO-GO**. It
does not justify accepting both contracts broadly or falling back to legacy
claims.

## Retain-first decommission

Decommission is destructive and is never part of GUG-93 execution. The default
sequence is:

### 1. Freeze

- stop new bootstrap/M2M provisioning and human invitations;
- prevent policy/group/client expansion;
- record the exact successor contract and cutover owner.

### 2. Revoke and drain

- revoke/expire sessions, grants, bootstrap requests, and old clients through
  approved lifecycle controls;
- wait through the required token, retry, queue, audit, and customer retention
  windows;
- keep alarms and audit available.

### 3. Prove successor independence

- all services and edge consumers validate only the successor contract;
- no rollback path, active session, workload, queue, or operator process
  depends on the old provider;
- two-deployment isolation and customer acceptance evidence are complete.

### 4. Retain evidence and protected data

- preserve required authorization audit and state/version history;
- document the legal/security retention decision in the approved system;
- keep general evidence sanitized.

### 5. Separately authorize deletion

Only a new destructive saved plan with Identity, Security, Operations,
identity/data-owner, and required production approval may disable deletion
protection or remove resources. Unexpected destruction, state removal, or
retention change is a stop condition.

The standard Identity Apply role cannot perform these operations: explicit
deny statements cover identity resource deletion, queue purge, key disable or
scheduled deletion, Lambda permission removal, and monitoring/retention
deletion. `s3:DeleteObject` is limited to the exact Terraform `.tflock` object.
The approved destructive procedure must use a separate short-lived change
identity and is outside GUG-93.

## Rollback and uncertain outcomes

Rollback uses a new reviewed forward plan and contract transition. It does not:

- restore Terraform state as routine rollback;
- manually edit/import/remove state;
- delete a pool or table to force recreation;
- re-enable ID tokens, group authority, self-signup, or legacy tenant mapping;
- expose a credential for manual recovery; or
- reset a consumed bootstrap record.

On timeout or unknown apply/runtime result:

1. stop downstream stages and issuance expansion;
2. preserve protected evidence externally;
3. read back state, contract, provider, queue, membership, and audit through
   authorized read-only paths;
4. classify not-started, complete, partial, failed, or unknown;
5. create a new plan only after state and provider reality reconcile; and
6. keep production NO-GO.

## Evidence checklist

- exact revision, change, tuple, execution identity, and environment recorded
  in the approved evidence system;
- two independent approvals and assurance validated;
- no self-approval;
- request TTL no longer than 900 seconds;
- conditional claim/consume and trusted idempotency verified;
- provider/membership effects reconciled;
- sanitized audit appended;
- no credential, token, enrollment value, claim, message body, provider response,
  live identifier, state, plan, or customer data copied to a prohibited surface;
- retries, partial batch failures, DLQ containment, and alarms validated;
- rollback/retirement owner identified; and
- GUG-117 and production gate status preserved.

## Evidence status

| Evidence class | Status |
|---|---|
| **Implemented** | Repository runtime, Terraform topology, contracts, tests, ADR, and this procedure may establish implementation for an exact reviewed revision |
| **Locally validated** | Named offline tests can establish fail-closed logic and configuration shape only |
| **CI validated** | Pending exact-commit required checks |
| **Live validated** | **Blocked**; no bootstrap, M2M credential, inventory, adoption, migration, redrive, retirement, or decommission executed |
| **Production** | **NO-GO** |

## Related sources

- [ADR-024](../../ADR/ADR-024-identity-control-plane-and-provider-boundary.md)
- [Identity control-plane reference](../deployment/identity-control-plane.md)
- [Enterprise authorization](../deployment/enterprise-authorization.md)
- [M2M identity v2 migration](../deployment/m2m-identity-v2-migration.md)
- [Object ownership quarantine](../deployment/object-ownership-migration-quarantine.md)
- [Rollback and recovery boundaries](rollback-recovery-boundaries.md)
- [Evidence policy](../production-readiness/evidence-policy.md)
