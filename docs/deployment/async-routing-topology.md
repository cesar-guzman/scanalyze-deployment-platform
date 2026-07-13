# Asynchronous Routing and Ownership Contract

> **Status:** GUG-89 repository contract; effective only in the exact reviewed
> revision and deployed only through a separately authorized change
>
> **Related decisions:** ADR-020, ADR-021, ADR-022
>
> **Live validation:** not performed
>
> **Production:** **NO-GO**

## Purpose

This reference defines the one supported asynchronous path between Scanalyze
producers and consumers. It is the deployment-facing companion to ADR-022. It
does not authorize Terraform provider operations, AWS inspection, task-definition
changes, deployment, migration, message replay, redrive, purge, or production.

The core invariant is that asynchronous transport never grants authority. Every
protected worker operation must prove that the message and the authoritative
document record have exactly the same canonical ownership tuple:

```text
message.customer_id == document.customer_id
message.deployment_id == document.deployment_id
message.ownership_schema_version == document.ownership_schema_version == 1
```

The authoritative record is loaded through the deployment-owned DynamoDB table
selected by reviewed configuration. A message body, message attribute, queue
name, URL, legacy field, S3 prefix, or `_metadata` value cannot replace that
lookup or comparison.

## Canonical queue matrix

All queues in this GUG-89 contract are SQS Standard queues. Each source queue has
one same-type DLQ, a 300-second visibility timeout, a maximum receive count of
three, a 14-day retention period, long polling, KMS encryption, and an exact
`byQueue` redrive allow policy. A DLQ accepts messages only from its paired source
queue.

| Stage key | Producer(s) | Consumer | Mode | Source queue type | DLQ source policy |
|---|---|---|---|---|---|
| `ingest` | `ingest-api` | `ocr-worker` | `INGEST` | Standard | only `ingest` source ARN |
| `ocr` | `ocr-worker` | `ocr-worker` | `OCR_POLL` | Standard | only `ocr` source ARN |
| `classify` | `ocr-worker` | `classifier-worker` | `CLASSIFY` | Standard | only `classify` source ARN |
| `bank-extract` | `ocr-worker`, `classifier-worker` | `bank-worker` | `BANK_EXTRACT` | Standard | only `bank-extract` source ARN |
| `personal-extract` | `ocr-worker`, `classifier-worker` | `personal-worker` | `PERSONAL_EXTRACT` | Standard | only `personal-extract` source ARN |
| `gov-extract` | `ocr-worker`, `classifier-worker` | `gov-worker` | `GOV_EXTRACT` | Standard | only `gov-extract` source ARN |
| `validate` | `bank-worker`, `personal-worker`, `gov-worker` | `postprocess-worker` | `VALIDATE` | Standard | only `validate` source ARN |
| `persist` | `postprocess-worker` | `postprocess-worker` | `PERSIST` | Standard | only `persist` source ARN |
| `notify` | `postprocess-worker` | `postprocess-worker` | `NOTIFY` | Standard | only `notify` source ARN |

There are exactly nine source queues and nine DLQs. Adding, renaming, sharing,
or omitting a stage requires a reviewed contract and corresponding schema/test
change; runtime configuration must not invent an unreviewed alias.

The module retains `worker_queue_urls`, `worker_queue_arns`, and `dlq_arns` as
deprecated `data-foundation/v1` compatibility outputs backed by the preserved
legacy resources. They do not map to, or authorize routing through, the new
stage queues. New consumers use the additive `data-foundation/v2` stage-oriented
source/DLQ maps and `queue_topology`; removing legacy resources or changing live
bindings requires GUG-118.

## Processing graph

```text
ingest-api
  -> ingest / ocr-worker:INGEST
  -> ocr / ocr-worker:OCR_POLL
     -> classify / classifier-worker:CLASSIFY
        -> bank-extract / bank-worker:BANK_EXTRACT
        -> personal-extract / personal-worker:PERSONAL_EXTRACT
        -> gov-extract / gov-worker:GOV_EXTRACT
     -> trusted pre-classified domain extract stage
  -> validate / postprocess-worker:VALIDATE
  -> persist / postprocess-worker:PERSIST
  -> notify / postprocess-worker:NOTIFY
```

The OCR worker may bypass `classify` only when a trusted configuration or an
already authorized stored contract establishes the domain. A customer identifier,
request field, route hint, queue name, or S3 prefix is not a processing domain.

## Versioned message matrix

Every model rejects unexpected fields. Optional trace metadata is allowlisted
and remains non-authoritative.

| Source stage | Schema version | Required authority and object bindings |
|---|---|---|
| `ingest` | `scanalyze.ingest.v2` | canonical ownership tuple, `documentId`, `pipeline_stage=ingest`, stored raw locator; configured domain may be absent |
| `ocr` | `scanalyze.ocr-poll.v2` | canonical ownership tuple, `pipeline_stage=ocr`, authorized source and OCR artifact locators, stored Textract job and route decision |
| `classify` | `scanalyze.classify.v2` | canonical ownership tuple, `pipeline_stage=classify`, authorized raw and OCR locators; message cannot choose domain authority |
| domain extract | `scanalyze.extract.v2` | canonical ownership tuple, exact domain stage, exact `processing_domain`, authorized raw and OCR locators |
| `validate` | `scanalyze.validate.v2` | canonical ownership tuple, `pipeline_stage=validate`, exact domain, authorized structured locator |
| `persist` | `scanalyze.persist.v2` | canonical ownership tuple, `pipeline_stage=persist`, exact domain, structured locator and consistent validation result |
| `notify` | `scanalyze.notify.v2` | canonical ownership tuple, `pipeline_stage=notify`, exact domain and terminal result consistent with validation |

### Fields that never establish authority

- `_metadata`, message attributes, correlation IDs, and trace IDs;
- legacy `tenantId`, customer stack names, headers, URL/query parameters, or
  payload identity aliases;
- queue URLs, ARNs, names, worker mode, or deployment display names;
- arbitrary `bucket`, `key`, `prefix`, `route`, `stage`, or domain hints; and
- a neighboring record, batch membership, prior successful message, or an
  inferred relation between customer and processing domain.

Metadata forwarding must use an allowlist. Producers and consumers must not log
the body or serialize rejected fields into diagnostics.

## Producer contract

A producer must:

1. receive customer and deployment from a previously validated internal
   authority or from the already authorized stored document;
2. build the exact schema for the destination stage;
3. derive `pipeline_stage` and queue URL from reviewed code/configuration, never
   from an untrusted payload selector;
4. resolve artifact locators from authorized stored metadata or construct the
   reviewed owner-bound output prefix;
5. include the complete canonical ownership tuple and applicable domain;
6. send one complete message and require a non-empty SQS `MessageId`;
7. conditionally record the handoff with the same owner tuple; and
8. leave the current item retryable or explicitly failed when send or state
   reconciliation is ambiguous.

The ingest API accepts a request stage only as confirmation of the configured
first stage. The configured first stage is `ingest`; a request cannot skip OCR,
select `classify`, or route directly to a domain worker.

## Consumer contract

A consumer must execute these gates before S3, Textract, extraction, persistence,
or downstream enqueue:

1. parse JSON without logging the body;
2. validate the exact v2 schema and stage;
3. require the canonical ownership tuple;
4. load the authoritative document through deployment configuration;
5. compare both owner fields and ownership schema version;
6. compare the expected processing domain when classification exists;
7. compare the raw, OCR, or structured locator with stored metadata;
8. evaluate stage-local idempotency under the same binding; and
9. proceed only when every proof succeeds.

The consumer acknowledges only after its required local effect and downstream
handoff are proven. Missing `MessageId`, conditional-write conflict, document
not found, owner mismatch, domain mismatch, locator mismatch, malformed body,
unknown version, or unrecognized stage is not a successful acknowledgement.

## Storage boundary

- DynamoDB table identity comes from reviewed deployment configuration.
- Reads and sensitive updates use the exact document key plus owner-bound
  validation or conditions.
- Updates never assign or repair customer/deployment ownership.
- An idempotent readback is valid only when the existing result is bound to the
  same customer, deployment, document, schema, stage, and domain.
- S3 reads use the authorized stored raw/OCR/structured locator.
- S3 writes use the canonical owner-bound prefix defined by the object contract.
- A transport field is input to validation, not trusted storage authority.

An S3 existence check is not an idempotency proof. A successful `HeadObject` at
the canonical key does not establish the artifact writer, content schema,
digest, stage checkpoint, or downstream handoff. The current domain-worker
exact-key retry optimization is locally observable behavior, but it is not
accepted as durable prior-effect evidence. Production enablement and redrive
remain blocked until GUG-118 supplies a reviewed content/checkpoint binding or
durable ledger and corresponding duplicate/partial-effect tests.

## Failure and DLQ behavior

| Condition | Required treatment |
|---|---|
| Missing/malformed owner tuple | Fail closed; do not perform protected side effects; retry then exact stage DLQ |
| Foreign customer or deployment | Same external/operational category as unavailable authority; no existence disclosure; retry then exact stage DLQ |
| Legacy v1 or unknown schema | No coercion or fallback; retain through retry/DLQ for reviewed disposition |
| Ambiguous/conflicting ownership | Deny and classify as quarantine-required; no inference |
| Domain or stage conflict | Deny before artifact access; retain through retry/DLQ |
| Stored locator mismatch | Deny before S3/Textract; retain through retry/DLQ |
| Duplicate with exact prior effect | Return only the reviewed idempotent outcome; never repeat a side effect merely because delivery is duplicated |
| Duplicate with unverifiable or foreign prior effect | Conflict and retain; never adopt the prior effect |
| Downstream send lacks `MessageId` | Handoff is unproven; do not advance as success |
| Unexpected exception | Sanitized reason-only diagnostic; no message body or protected locator; retry/DLQ |

A DLQ is not a migration queue. The message remains denied until a separately
approved review proves that it is safe to replay. See
`docs/operations/dlq-redrive-gug89.md`.

## Deployment configuration and outputs

The data-foundation contract exports four closed maps for the exact stage set:

- source queue URLs;
- source queue ARNs;
- DLQ URLs; and
- DLQ ARNs.

It also exports the producer, consumer, consumer-mode, queue-type, visibility,
and receive-count topology. A service layer must consume those reviewed outputs
without reconstructing queue names or accepting request-supplied URLs. The
presence of a Terraform resource or output is **Implemented** repository intent,
not evidence that a live resource exists or is wired to a task definition.

## Compatibility and rollout boundary

There is no automatic v1-to-v2 compatibility path. A v1, partially bound, or
foreign message is denied and retained. Any future live cutover must use a
separately reviewed compatibility/drain plan that proves:

- consumers compatible with the approved producer contract are active before
  producer cutover;
- no cross-deployment queue or task binding exists;
- in-flight legacy messages are inventoried without inference or deletion;
- retries and duplicates cannot create a second effect;
- alarm and DLQ behavior is verified; and
- rollback keeps unsafe messages denied.

`scanalyze.*.v2` is the version family for message bodies. The repository also
authors an additive `data-foundation/v2` Terraform output contract for the nine
stage queues while preserving `data-foundation/v1` and its legacy resources.
Repository code for either v2 contract is not evidence that Terraform was
applied, the contract was published, a task definition selected that consumer
mode, a live producer cut over, or an in-flight v1 message was handled. Those
activation facts require separately authorized GUG-108/GUG-118 evidence.

GUG-89 does not execute that rollout. GUG-108 remains a separate program
dependency and is not marked complete here. GUG-118 owns the later runtime gate,
including FIFO decision/migration, durable ledger/outbox/lease controls,
failure-injection evidence, quarantine implementation, controlled redrive, and
no-loss/no-duplicate acceptance.

## Evidence classification

| Classification | Required proof |
|---|---|
| **Implemented** | Exact commit contains the topology, v2 models, producer/consumer gates, conditional storage behavior, and DLQ policy. |
| **Locally validated** | Named synthetic tests and offline repository gates pass for the exact commit. |
| **CI validated** | Required checks pass on the exact PR commit. |
| **Live validated** | Explicitly authorized non-production evidence proves queues, task modes, owner isolation, retries, DLQs, and recovery. Not established by this document. |
| **Blocked** | AWS/provider validation, deployment, live inventory, redrive, migration, two-deployment runtime proof, and production remain blocked unless separately authorized and accepted. |

Skipped or blocked checks stay skipped or blocked. Documentation, local tests,
and CI do not prove AWS behavior. Production remains **NO-GO**.
