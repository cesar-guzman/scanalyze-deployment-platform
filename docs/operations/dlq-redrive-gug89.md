# GUG-89 DLQ Investigation and Controlled Redrive Runbook

> **Status:** repository procedure; no live execution authorized
>
> **Default mode:** report-only and fail-closed
>
> **Scope:** the nine GUG-89 stage DLQs only
>
> **Live validation:** not performed
>
> **Production:** **NO-GO**

## Safety statement

This runbook defines the evidence and approvals required before a future DLQ
redrive. It does not grant AWS access and does not authorize message retrieval,
payload export, resource mutation, migration, redrive, purge, deployment, or
production. No live redrive or data migration is performed by GUG-89.

A DLQ message is untrusted incident evidence. It may be malformed, foreign,
ambiguous, duplicated, stale, attacker-controlled, or connected to a partially
completed side effect. Its presence never proves that replay is safe.

## Covered queues

The only covered source/DLQ pairs are:

1. `ingest`
2. `ocr`
3. `classify`
4. `bank-extract`
5. `personal-extract`
6. `gov-extract`
7. `validate`
8. `persist`
9. `notify`

Every queue and DLQ is Standard. Each source queue uses a 300-second visibility
timeout and a maximum receive count of three. Each DLQ is configured with an
exact `byQueue` source allowlist. A message must return only to the source stage
that owns its schema; it cannot be redirected to a later stage to bypass failed
validation.

## Absolute prohibitions

- Do not use a default AWS profile or an unreviewed account, region, queue URL,
  ARN, task definition, or deployment binding.
- Do not print, copy into a ticket, or place in general evidence any message
  body, document content, customer identifier, PII, JWT, S3 key, Textract output,
  extracted financial data, credential, or presigned URL.
- Do not infer ownership from `tenantId`, route, queue name, S3 prefix, customer
  stack, neighboring record, or operator knowledge.
- Do not change `customer_id`, `deployment_id`, ownership version, document ID,
  stage, processing domain, or artifact locator to make a message pass.
- Do not replay a v1, partially bound, conflicting, ambiguous, foreign, or
  unverifiable message.
- Do not redrive across deployments, accounts, regions, environments, queue
  pairs, or stages.
- Do not purge a source queue or DLQ. Purge destroys evidence and can conceal
  loss or partial processing.
- Do not acknowledge, delete, or rewrite messages as an inventory shortcut.
- Do not treat a successful API response as proof that downstream work completed
  once and only once.

## Roles and approvals

No person may request, approve, execute, and validate the same redrive alone.
Before any live read or write, the incident/change record must identify:

| Role | Required responsibility |
|---|---|
| Incident or service owner | Defines impact, affected stage, time boundary, and stop condition |
| Application Security reviewer | Approves ownership, schema, locator, and cross-deployment controls |
| Backend/worker owner | Proves the fix and stage-specific idempotency behavior |
| SRE/Platform operator | Confirms exact deployment/account/region and executes only the approved operation |
| Independent validator | Reviews sanitized counts, effects, alarms, and remaining DLQ state |
| Data owner/compliance reviewer | Required when message classification may include regulated or customer-sensitive material |

Production requires the program's explicit production approval in addition to
these roles. This document records no such approval.

## Required change record

The record must use opaque, sanitized references and contain:

- incident and change identifiers;
- exact source commit/release and worker image digests;
- exact non-production deployment binding, account, region, and environment;
- one stage and its exact source/DLQ pair;
- report-only time window and immutable inventory reference;
- root cause and reviewed remediation commit;
- schema version and allowed ownership version;
- expected message count, size distribution, age buckets, and reason categories;
- idempotency proof and known partial-effect analysis;
- rate/concurrency limits, observation window, alarms, and cost boundary;
- executor, approvers, independent validator, and approval timestamps;
- stop conditions, rollback/containment owner, and evidence destination; and
- explicit confirmation that purge, cross-stage routing, field rewriting, and
  ownership inference are prohibited.

If any binding, approver, evidence location, or stop condition is missing, the
operation is **Blocked**.

## Phase 0: Contain and preserve

1. Stop additional unsafe production of the affected schema through the normal
   incident/change process. Do not mutate a live service merely because this
   runbook says to contain it.
2. Preserve source and DLQ retention. Never purge.
3. Record only sanitized approximate counts and age/size distributions until a
   protected evidence workspace is approved.
4. Determine whether messages may have created a partial S3, DynamoDB, Textract,
   extraction, persistence, notification, or downstream-enqueue effect.
5. If cross-customer/deployment exposure or data corruption is plausible,
   escalate as a security incident and keep replay disabled.

## Phase 1: Report-only inventory

This phase has two evidence levels that must not be conflated.

### Phase 1A: Queue-metadata inventory

Queue attributes, CloudWatch metrics, alarms, age/depth trends, and deployment
bindings can be inspected through separately authorized read-only APIs without
receiving a message. This level can report queue-level counts and health only.
It cannot classify schema, ownership, domain, locator, duplicate, or
partial-effect state inside a message body.

### Phase 1B: Protected payload inventory — BLOCKED

Amazon SQS has no non-destructive message-body `peek`. `ReceiveMessage` changes
message visibility even when no delete or redrive follows, so payload inspection
is not a read-only operation and must not be mislabeled as one. GUG-89 provides
no command or authorization for that action.

Message-level inventory remains **Blocked** until a separate change procedure
defines and approves one protected mechanism, such as an explicitly quiesced DLQ
with bounded receive and visibility restoration, or an already approved
immutable evidence capture created before the investigation. That procedure
must name the exact profile, region, caller identity, account, deployment,
queue, visibility behavior, concurrency, evidence system, stop conditions, and
rollback/containment owner. It must prove that inspection cannot delete,
redrive, reorder across a stage boundary, or expose a body outside the protected
evidence workspace.

If that mechanism or approval is absent, only Phase 1A may run and no message may
be classified as `eligible_candidate`.

Once Phase 1B is separately authorized, its output must contain only aggregate,
sanitized facts:

- stage and schema-version counts;
- ownership classification counts without owner values;
- missing/invalid/ambiguous/foreign categories;
- processing-domain and stage-consistency counts;
- age and receive-count buckets;
- suspected partial-effect and duplicate categories;
- root-cause reason category; and
- an opaque protected-evidence reference for exceptional review.

Message bodies remain in the approved protected evidence system and are not
copied to Git, CI logs, Linear, NotebookLM, chat, or general-purpose artifacts.
Hashing a sensitive value does not automatically make it safe to publish.

### Inventory classification

| Class | Criteria | Normal treatment |
|---|---|---|
| `eligible_candidate` | Strict v2 schema, complete owner tuple, same exact deployment, authorized record and locators, reviewed fix, idempotency proof | May proceed to dry-run; not yet authorized for redrive |
| `legacy` | v1 or unsupported schema | Deny; quarantine/investigation; no inference or rewrite |
| `unbound` | Missing or malformed customer/deployment/ownership version | Deny; quarantine/investigation |
| `partial` | Only part of the canonical owner tuple is present | Deny; quarantine/investigation |
| `ambiguous` | Conflicting aliases, ownership candidates, stage, domain, or locators | Deny; quarantine/investigation |
| `foreign` | Owner or deployment does not equal the authoritative deployment/record | Deny; security review; never cross-deployment redrive |
| `orphaned` | Authoritative document or required artifact is absent | Deny; investigation; no reconstruction by inference |
| `inconsistent` | Stored state, schema, stage, domain, or locator disagrees | Deny; investigation; preserve evidence |
| `partial_effect_unknown` | An effect may have occurred but cannot be proven | Deny until reconciled; redrive blocked |

Only `eligible_candidate` messages can enter a dry-run report. The inventory
does not modify the message or confer eligibility by majority, similarity, age,
or operator expectation.

## Phase 2: Remediation readiness

Before dry-run, prove on the exact candidate revision that:

1. the root cause has a reviewed fix and synthetic regression test;
2. the consumer rejects missing, malformed, ambiguous, foreign, and legacy
   ownership before protected side effects;
3. the consumer validates the message against the authoritative document and
   exact stored locators;
4. the stage only publishes its exact next-stage v2 contract;
5. enqueue requires a non-empty `MessageId` and owner-bound state transition;
6. duplicate delivery with the same owner/stage returns one proven outcome;
7. an unverifiable prior effect is a conflict, not idempotent success;
8. alarms and sanitized diagnostics distinguish retry, DLQ, and terminal state;
9. the rollback/containment path has been exercised without customer data; and
10. required CI checks pass for the exact commit.

If durable idempotency or partial-effect reconciliation is insufficient for the
stage, redrive remains **Blocked** for GUG-118 even if parsing tests pass.

## Phase 3: Dry-run decision report

Dry-run validates eligibility without sending, deleting, rewriting, or changing
visibility for a message. For each candidate, the protected evaluator must:

1. parse the body under the exact stage v2 schema;
2. reject unknown fields and schema versions;
3. compare the complete owner tuple with the same-deployment authoritative
   document record;
4. compare processing domain, pipeline stage, and all required locators;
5. inspect idempotency and partial-effect state under the same owner binding;
6. simulate the consumer decision without invoking S3, Textract, Bedrock,
   DynamoDB writes, downstream SQS, notifications, or external services; and
7. emit only `eligible`, `denied`, or `blocked` plus a stable reason category.

The report must reconcile:

```text
inventoried = eligible + denied + blocked
```

Counts must also reconcile by stage and original reason category. Any mismatch,
unknown category, evaluator error, evidence gap, owner ambiguity, or partial
effect blocks live execution.

## Phase 4: Live redrive approval gate

Live redrive is a separate, explicit write authorization. Approval must name the
exact deployment, account, region, stage pair, protected candidate set, maximum
count, rate, concurrency, observation window, executor, and expiry. A blanket
approval such as “replay the DLQ” is invalid.

The approval gate requires:

- phases 0-3 complete and independently reviewed;
- exact same-deployment proof for every candidate;
- no legacy, foreign, ambiguous, orphaned, inconsistent, or unknown candidates;
- durable idempotency and partial-effect reconciliation accepted under GUG-118;
- alarm, backpressure, downstream capacity, and cost limits ready;
- a tested stop control that does not purge or delete evidence;
- an immutable approved candidate manifest in protected storage; and
- rollback/containment and post-operation validation owners present.

GUG-89 does not satisfy or execute this gate. No live command is provided here
because the account-, tool-, and authorization-specific procedure must be
reviewed at execution time.

## Phase 5: Controlled execution requirements

If a later package authorizes execution, the operator must:

1. re-confirm caller identity, account, region, deployment, stage, source/DLQ
   pair, approval validity, and candidate-manifest digest;
2. begin with the smallest approved canary;
3. enforce the approved rate and concurrency below downstream capacity;
4. monitor source depth, DLQ depth, age, errors, throttles, duplicate conflicts,
   handoff counts, terminal counts, latency, and cost;
5. stop at the first ownership, schema, locator, idempotency, count, alarm, or
   downstream-health discrepancy;
6. preserve denied and blocked messages; and
7. expand only after the independent validator accepts the canary evidence.

No step may purge a queue, edit a message, change ownership, bypass the failed
stage, or use another deployment as a destination.

## Stop conditions

Stop immediately and retain remaining messages when:

- caller, account, region, deployment, queue pair, or approval differs;
- a candidate is missing from the approved manifest or its protected digest
  differs;
- any owner, schema, stage, domain, or locator comparison fails;
- a duplicate or partial effect is not reconciled deterministically;
- source, DLQ, handoff, or terminal counts do not reconcile;
- errors, retries, age, latency, throttling, or cost exceed the approved bound;
- an alarm is absent, stale, or firing unexpectedly;
- a downstream service is unhealthy or backpressured;
- logs or evidence expose protected data; or
- the stop/rollback control cannot be verified.

## Rollback and containment

Redrive cannot be “undone” by moving messages back after side effects occur.
Rollback therefore means stopping additional movement and reconciling effects,
not purging or reversing ownership.

1. Stop further approved redrive using the pre-reviewed control.
2. Preserve the remaining DLQ and source messages; do not purge or mass-delete.
3. Disable only the affected path through the separately approved incident
   procedure if safe owner-bound behavior cannot be maintained.
4. Reconcile canary message, handoff, artifact, conditional-write, and terminal
   state using protected evidence and the canonical owner tuple.
5. Quarantine unverifiable, foreign, legacy, or partially effected items. Do not
   infer or rewrite ownership.
6. Revert the application release through the normal reviewed deployment path
   only if the previous release preserves fail-closed authorization. Never
   restore acceptance of v1 or ambiguous ownership.
7. Record the uncertain outcome, retain evidence, and require a new reviewed
   candidate manifest and approval before any retry.

## Post-operation evidence

The independent validator must produce a sanitized report containing:

- exact change/release reference and approved deployment binding;
- stage and approved candidate count;
- canary and total processed counts;
- one-effect/idempotency reconciliation;
- downstream handoff and terminal count reconciliation;
- remaining source/DLQ counts by reason category;
- alarm, error, throttle, latency, backpressure, and cost outcome;
- denied/blocked/quarantined counts without owner or payload data;
- stop or rollback events; and
- final decision: accepted, partially accepted, failed, or blocked.

Evidence must distinguish repository implementation, local tests, CI, and live
execution. A successful local dry-run is not live validation. A live
non-production redrive is not production approval.

## Evidence status for GUG-89

| Evidence class | GUG-89 status boundary |
|---|---|
| **Implemented** | The repository can define strict message/topology/DLQ and fail-closed worker behavior for an exact revision. |
| **Locally validated** | Synthetic tests and offline gates may validate that revision. |
| **CI validated** | PR checks may validate the exact commit; this does not inspect a live queue. |
| **Live validated** | Not established by GUG-89 or this runbook. |
| **Blocked** | Live inventory, message retrieval, migration, redrive, purge, failure injection, and production. |

GUG-108 remains a separate program dependency. GUG-118 must accept runtime
idempotency, quarantine, controlled redrive, and no-loss/no-duplicate evidence
before this procedure can be considered operationally complete. Production
remains **NO-GO**.
