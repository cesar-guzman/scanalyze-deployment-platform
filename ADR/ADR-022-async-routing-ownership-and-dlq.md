# ADR-022: Ownership-Bound Async Routing and DLQ Topology

- **Status**: Proposed; accepted only after reviewed merge
- **Date**: 2026-07-12
- **Scope**: GUG-89 asynchronous messages, worker routing, queue topology, and
  fail-closed dead-letter behavior
- **Phase gates**: GUG-117 dependency; GUG-118 remains a later runtime gate
- **Live enablement**: Blocked pending reviewed CI and explicitly authorized
  non-production evidence
- **Production**: NO-GO

## Context

GUG-102 and GUG-114 establish authenticated customer/deployment identity and
object-level authorization for synchronous document and batch operations. The
pre-existing asynchronous path did not carry the same proof consistently across
every producer and consumer. Messages used mixed versions and aliases, some
workers could treat route or locator fields as authority, and the infrastructure
contract did not expose one complete producer-to-consumer queue and DLQ map.

That mismatch creates a confused-deputy boundary. A valid message identifier,
customer-like route, request-supplied S3 location, incomplete legacy envelope,
or message from a different deployment could otherwise cause a worker to read,
transform, write, or forward an object outside the exact authenticated owner
boundary. A poison message that is acknowledged or discarded silently would
also destroy the evidence needed for diagnosis and safe recovery.

SQS Standard queues provide at-least-once delivery. Therefore a successful send
does not prove a single effect, and a received message does not prove authority.
Authorization, validation, idempotency, acknowledgement, and dead-letter
treatment are separate decisions.

## Decision

1. The canonical asynchronous topology contains exactly these stages:
   `ingest`, `ocr`, `classify`, `bank-extract`, `personal-extract`,
   `gov-extract`, `validate`, `persist`, and `notify`. Each stage has one
   Standard source queue and one Standard DLQ.
2. Every source queue uses a 300-second visibility timeout and
   `max_receive_count = 3`. Each DLQ accepts redrive only from its exact source
   queue through `redrivePermission = byQueue`. The repository contract exposes
   source and DLQ URLs, ARNs, and the topology metadata; these values do not
   prove that the resources exist in AWS.
   Existing `data-foundation/v1` worker-oriented resources and outputs remain
   unchanged in address, physical name, and value source; they are not aliases
   to the new queues. The additive `data-foundation/v2` contract exposes the
   stage resources. Legacy removal or any live queue transition requires the
   separately approved GUG-118 migration and drain plan.
3. Messages use a strict versioned v2 contract for their stage. The exact
   canonical ownership tuple is:

   ```text
   customer_id
   deployment_id
   ownership_schema_version = 1
   ```

   Both identifiers must be present, valid, and equal to the authoritative
   document record. Missing, malformed, partial, contradictory, ambiguous,
   legacy-only, or foreign ownership fails closed.
4. `pipeline_stage` and, when classified, `processing_domain` are explicit
   contract fields. They are not derived from customer identity. A processing
   domain may be selected only by reviewed deployment configuration or by the
   classifier and then reconciled with the authoritative stored record.
5. Message attributes and `_metadata` are non-authoritative. Correlation and
   trace identifiers may be propagated through an allowlist, but metadata,
   headers, aliases, legacy `tenantId`, queue names, S3 prefixes, payload route
   hints, and request fields never establish customer, deployment, domain, or
   object authority.
6. Before a protected side effect, each consumer validates the strict envelope,
   loads the minimum document metadata through the configured deployment-owned
   DynamoDB table, and proves exact customer, deployment, ownership version,
   stage/domain, and stored artifact locator compatibility. A message locator
   alone is never trusted.
7. S3 bucket and key values are accepted only after they match the authorized
   document contract. New structured artifacts use the reviewed owner-bound
   prefix. A worker never accepts an arbitrary request or message prefix as an
   authorization boundary.
8. A producer treats enqueue as successful only when SQS returns a non-empty
   `MessageId`. State is not advanced to a completed handoff on an exception or
   ambiguous response. Handoff state changes retain ownership-bound conditional
   writes.
9. A consumer acknowledges a message only after its authorized, idempotent stage
   outcome and required downstream handoff have succeeded. Invalid, foreign,
   ambiguous, legacy, or poison messages are not acknowledged as success; normal
   retry behavior retains them and eventually sends them to the stage's DLQ.
10. Logs and general evidence contain stable stage, reason category, counters,
    and synthetic references only. They never contain message bodies, document
    contents, PII, JWTs, customer identifiers, S3 keys, presigned URLs, Textract
    results, extracted financial data, or credentials.
11. DLQ presence is an incident/evidence signal, not authorization to replay.
    Redrive requires the companion runbook, independent approval, report-only
    inventory, dry-run classification, same-deployment proof, revalidation of
    every message, idempotency evidence, and an explicit stop/rollback plan.
    Purge is prohibited.
12. GUG-89 does not authorize AWS access, deployment, live queue inspection,
    message retrieval, migration, redrive, DLQ purge, data repair, Terraform
    provider operations, merge, or production.

## Canonical topology

| Stage | Producer(s) | Consumer | Consumer mode | Queue | DLQ |
|---|---|---|---|---|---|
| `ingest` | `ingest-api` | `ocr-worker` | `INGEST` | Standard | Exact `ingest` DLQ |
| `ocr` | `ocr-worker` | `ocr-worker` | `OCR_POLL` | Standard | Exact `ocr` DLQ |
| `classify` | `ocr-worker` | `classifier-worker` | `CLASSIFY` | Standard | Exact `classify` DLQ |
| `bank-extract` | `ocr-worker`, `classifier-worker` | `bank-worker` | `BANK_EXTRACT` | Standard | Exact `bank-extract` DLQ |
| `personal-extract` | `ocr-worker`, `classifier-worker` | `personal-worker` | `PERSONAL_EXTRACT` | Standard | Exact `personal-extract` DLQ |
| `gov-extract` | `ocr-worker`, `classifier-worker` | `gov-worker` | `GOV_EXTRACT` | Standard | Exact `gov-extract` DLQ |
| `validate` | domain extraction workers | `postprocess-worker` | `VALIDATE` | Standard | Exact `validate` DLQ |
| `persist` | `postprocess-worker` | `postprocess-worker` | `PERSIST` | Standard | Exact `persist` DLQ |
| `notify` | `postprocess-worker` | `postprocess-worker` | `NOTIFY` | Standard | Exact `notify` DLQ |

The OCR worker has two explicitly separated consumer modes. `INGEST` validates
the owner-bound source record and starts OCR; `OCR_POLL` validates the stored job
and source/artifact bindings before it publishes to `classify` or to a trusted
pre-classified domain stage. A queue URL or worker command must select exactly
one reviewed mode. There is no generic stage dispatcher controlled by the
message.

## Stage contract requirements

| Contract | Required stage | Additional trusted binding |
|---|---|---|
| `scanalyze.ingest.v2` | `ingest` | Stored raw locator; configured domain may be absent before classification |
| `scanalyze.ocr-poll.v2` | `ocr` | Stored Textract job, raw locator, OCR artifact locator, and route decision |
| `scanalyze.classify.v2` | `classify` | Authorized raw and OCR locators; domain is not supplied as authority |
| `scanalyze.extract.v2` | one exact domain extract stage | Exact `processing_domain` plus authorized raw and OCR locators |
| `scanalyze.validate.v2` | `validate` | Exact domain and authorized structured locator |
| `scanalyze.persist.v2` | `persist` | Exact domain, validation result, and authorized structured locator |
| `scanalyze.notify.v2` | `notify` | Exact domain and terminal result consistent with validation |

Stage-specific models reject unknown authority-bearing fields. Compatibility is
explicit by schema version; an unknown version is poison and follows retry/DLQ
treatment rather than being coerced into a known shape.

## Authority and acknowledgement sequence

For every stage, the order is:

1. decode the SQS body without logging it;
2. validate the exact stage and schema version;
3. reject unknown, malformed, or authority-bearing extra fields;
4. load the authoritative document metadata from deployment configuration;
5. compare the exact ownership tuple and expected domain/stage/locators;
6. check the stage's idempotency state;
7. perform the protected side effect;
8. publish the complete next-stage envelope and require `MessageId`;
9. conditionally record the handoff or terminal state; and
10. acknowledge only the proven outcome.

An idempotent replay must prove that the earlier effect belongs to the same
customer, deployment, document, schema, and stage. A key collision or pre-existing
effect without that proof is a conflict, not success.

The repository has two distinct evidence levels. Owner-bound conditional
DynamoDB transitions prove selected stage checkpoints. Bank, personal, and
government structured-artifact writes additionally use a two-phase binding: an
exact owner/deployment/document/domain reservation precedes the create-only S3
write; the object carries the reservation token, writer/schema metadata, and a
SHA-256 content digest; and finalization is conditioned on the unchanged
reservation. A retry may recover the S3-to-Dynamo partial-commit window only
after reading the object and proving the complete metadata and digest binding.
Legacy, unbound, mismatched, oversized, or unverifiable objects remain conflicts.

This closes the repository-level partial-commit contract for those three domain
artifacts only. It does not prove deployed IAM, live task wiring, cross-stage
handoffs, runtime failure injection, no-loss/no-duplicate behavior, or controlled
redrive. Those environment and end-to-end claims remain **Blocked** on GUG-118.

## Legacy and quarantine behavior

- v1 messages and records without the full canonical ownership tuple are denied
  in the normal pipeline.
- Partial ownership, conflicting aliases, foreign customer/deployment, invalid
  schema, domain disagreement, locator mismatch, and unrecognized stage are
  migration- or investigation-required.
- No ownership field is repaired, inferred, normalized into authority, or copied from a
  queue name, S3 prefix, `tenantId`, customer stack, route hint, or neighboring
  record. The structured-artifact recovery path may only finalize an existing
  owner-bound reservation whose S3 metadata and content digest match exactly.
- Retry and the exact stage DLQ retain the original operational evidence. A
  quarantine classification is a reviewed disposition; this ADR does not create
  or claim a live quarantine resource.
- No live inventory, migration, delete, purge, or redrive is part of GUG-89.

The `v2` label identifies both the asynchronous message family and the new,
additive `data-foundation/v2` output contract. The existing
`data-foundation/v1` schema, fixture, resource addresses, names, and deprecated
outputs remain preserved. Repository authoring is not proof that v2 was
published, applied, or selected by a task definition, or that any live queue
contains v1 or v2 messages. V1 message denial applies only when the reviewed v2
consumer is actually selected; it is not a claim about live cutover state.

## Boundaries with GUG-108 and GUG-118

GUG-89 owns the repository message, producer/consumer, routing, queue/DLQ, and
fail-closed handoff contracts described here. It does not claim task-definition
activation, a deployed consumer path, or live runtime proof. GUG-108 remains a
separate dependency identified by the production-readiness program; its exact
acceptance criteria are not absorbed or marked complete by this ADR.

GUG-118 remains the Phase 2 runtime gate. It owns acceptance of the complete
runtime behavior, including the reviewed FIFO decision or migration, durable
idempotency/ledger behavior, outbox or lease/heartbeat controls where selected,
failure injection, alarm verification, quarantine implementation, controlled
redrive, and no-loss/no-duplicate recovery evidence. Standard queues in GUG-89
are an explicit current contract, not a claim that the future FIFO decision is
closed.

## Security consequences

- Customer and deployment identity survive every asynchronous boundary and are
  re-authorized rather than trusted transitively.
- The reviewed consumer invariant requires foreign or malformed messages to
  stop before S3, Textract, DynamoDB, extraction, persistence, or downstream
  enqueue side effects. This is an implementation claim only where the exact
  worker revision and negative tests demonstrate that order; it is not inferred
  from this ADR or from publication of a JSON Schema.
- Exact producer/consumer mappings reduce confused-deputy routing and make
  unexpected queues or modes a configuration error.
- Poison messages are retained for investigation instead of disappearing as
  successful work.
- Standard at-least-once delivery retains duplicate risk. Owner-bound
  conditional-write tests reduce that risk for the reviewed code, but S3
  existence alone does not prove a prior effect. Only GUG-118 can accept durable
  idempotency and live no-duplicate/no-loss evidence.

## Validation and evidence boundary

| Evidence class | Meaning for this decision |
|---|---|
| **Implemented** | The exact reviewed revision contains the v2 contracts, owner-bound workers, canonical topology, and DLQ policies. Documentation alone is not implementation. |
| **Locally validated** | Named synthetic tests and repository gates pass for that exact revision without AWS or customer data. |
| **CI validated** | Required PR checks pass for the exact commit. This is not live queue evidence. |
| **Live validated** | An explicitly authorized non-production deployment proves queue, worker, ownership, retry, DLQ, and recovery behavior with sanitized evidence. No such claim is made here. |
| **Blocked** | AWS inspection, deployment, migration, redrive, live failure injection, two-deployment proof, and production remain blocked until separately authorized gates close. |

The PR or Linear evidence for GUG-89 must list the exact commit and named test
results. It must not upgrade skipped or blocked provider/live checks to passed.
GUG-117 and GUG-118 remain in progress or blocked according to their own exit
criteria. Production remains **NO-GO**.

## Rollback

Revert the reviewed repository change through the normal Git workflow and keep
the affected asynchronous path disabled if the exact owner-bound contract cannot
be preserved. Do not roll back to accepting v1, missing ownership, a request
locator, customer-only routing, silent poison acknowledgement, a shared queue
without an exact consumer contract, or unrestricted DLQ redrive.

Queue and message changes already applied live would require a separately
approved compatibility and drain plan. This ADR does not authorize that plan or
any live action. Messages or records encountered during an uncertain rollback
remain denied and retained; they are not deleted or inferred into compatibility.
