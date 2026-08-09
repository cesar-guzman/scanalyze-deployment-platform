# ADR-049: Versioned, Idempotent Critical Document Journey

- **Status:** Proposed; accepted only after independent P0 review, merge, and main verification
- **Date:** 2026-08-08
- **Issue:** GUG-354
- **Scope:** repository contract only; no AWS or live-service claim

## Context

The historical `/api/v1` create endpoints allocate a new random resource for
every request. They do not bind a durable operation to an idempotency key, and
a caller that loses a successful response cannot discover the resource without
already knowing its identifier. Historical status, error, and result responses
also contain open strings or transport locators that are not a closed public
journey contract.

GUG-354 must close that gap without changing worker orchestration (GUG-118),
the frontend journey (GUG-103), pilot work (GUG-269), or any live deployment.
This decision is repository-only: it authorizes no AWS write, deployment,
database/data migration, historical backfill, customer-data access, staging
exercise, pilot, production change, or production verification claim.

The execution boundary is explicit:

- No live DynamoDB access.
- No live API Gateway access.
- No live Cognito access.
- No live upload.
- No live OCR, Textract, or Bedrock execution.
- No AWS access or mutation.
- No deployment.

## Decision

### Public authority and versioning

- The additive canonical namespace is `/api/v2`.
- The contract identifier is `scanalyze.document-journey.v1`.
- Every v2 operation requires the exact
  `X-Scanalyze-Contract-Version` header. Missing, unknown, or downgraded values
  fail closed.
- Historical `/api/v1` routes remain explicit compatibility endpoints; they
  are not aliases for v2 and acquire no implied idempotency guarantee.
- The same-origin `/api` facade continues to route historical calls to v1;
  explicit `/api/v2` calls remain v2.

The committed
`schemas/scanalyze-document-journey.openapi.v1.json` file is the sole OpenAPI
authority for v2. FastAPI's generated `/openapi.json` remains legacy,
noncanonical operational metadata and intentionally excludes the v2 routes;
clients and generators must not infer the v2 contract from that endpoint.

### Strict input and canonical digest

The v2 boundary accepts one BOM-less UTF-8 JSON object and rejects alternative
encodings, duplicate keys, non-finite numbers, unknown fields, unsupported
MIME types, and identity-authority fields.
The canonical projection is the validated request model only. It is encoded as
compact UTF-8 JSON with sorted keys and no NaN/Infinity, then hashed with
SHA-256 over this exact domain-separated byte sequence:

```text
UTF8("scanalyze.document-journey.canonical-request.v1") || 0x00 ||
UTF8(compact_sorted_JSON({
  "contractVersion": "scanalyze.document-journey.v1",
  "operation": <batches.create|documents.create>,
  "request": <validated alias-keyed request projection>
}))
```

The stored value is `sha256:<lowercase-hex>`. The NUL byte is part of the
domain; there are no newline or unit-separator frames around the fields.

Filename is semantic for document creation and therefore contributes to the
digest, but neither the filename nor the request body is stored in the ledger.

### Idempotency key and owner scope

`Idempotency-Key` is exactly a lowercase RFC 4122 UUID string compatible with
`crypto.randomUUID()` (36 ASCII characters). Spaces, control characters, path
separators, email/filename-shaped values, uppercase/non-canonical UUIDs, and
oversized values are rejected. The raw key is used only in request memory. The
ledger stores `sha256:<hex>` for the key.

The owner scope is derived only from verified authentication:

- user/local actor: `subject`;
- M2M actor: `client_id`;
- customer: verified `AuthContext.customer_id`;
- deployment: verified `AuthContext.deployment_id`.

Missing or ambiguous actor/deployment authority fails closed. A bounded digest
of that tuple is stored on the ledger and business resource. Request payload,
headers, and query parameters cannot establish customer, deployment, or actor.

### Ledger placement and keys

`OPERATION_LEDGER_TABLE_NAME` must explicitly equal the Terraform-managed
documents table. The ledger uses that table's `pk`/`sk` without populating the
document ownership GSIs:

```text
owner-digest    = SHA256(UTF8(customer-id || 0x1f || deployment-id))
contract-digest = SHA256(UTF8(contract-version))

pk = GUG354#OWNER#<owner-digest-lowercase-hex>
sk = CONTRACT#<contract-digest-lowercase-hex>
     #OPERATION#<batches.create|documents.create>
     #ACTOR#<actor-digest-lowercase-hex>
     #KEY#<idempotency-key-digest-lowercase-hex>
```

The digest components embedded in `pk`/`sk` omit the persisted `sha256:`
prefix. Actor and idempotency digests retain their own reviewed domain
separation before their lowercase hex components are placed in the key.

The closed record contains schema/contract version, operation, bounded owner
and key digests, request digest, state, stable resource type/id, a small
allowlisted durable response projection, safe failure code, timestamps,
logical expiry, and an exact CAS version. It never contains raw keys, request
bodies, filenames, email, tokens, provider responses, signed URLs, storage
locators, document data, or stack traces.

### Reservation-first atomicity and ambiguity

The first conditional reservation selects and durably stores one stable
resource ID before any business write. Only the reservation winner may issue a
create-only business write for that ID. The resource stores the exact contract,
operation, owner-scope digest, request digest, and operation reference.

The sequence is:

1. conditional `PENDING` reservation;
2. one create-only business write using the reserved ID;
3. strong consistent read after a conditional or ambiguous response;
4. exact owner/request/operation/resource verification;
5. conditional versioned transition to `SUCCEEDED`.

The closed ledger states are `PENDING`, `SUCCEEDED`, `FAILED_RETRYABLE`,
`FAILED_TERMINAL`, `UNKNOWN_OR_QUARANTINED`, and `EXPIRED`. Every transition is
CAS-guarded. An ambiguous business result is never replayed blindly: the
service reconciles the reserved ID, and either completes the original record
or quarantines the outcome. This proves one logical batch/document effect
without `TransactWriteItems`, a new table, or ownership of the externally
configured batches table.

`FAILED_RETRYABLE` is resumable and therefore has no `completedAt`.
`SUCCEEDED`, `FAILED_TERMINAL`, `UNKNOWN_OR_QUARANTINED`, and `EXPIRED` require
one. Non-expired observations satisfy `updatedAt < expiresAt`. An `EXPIRED`
observation satisfies `expiresAt <= updatedAt`, while `completedAt` remains
between `createdAt` and `updatedAt` and may preserve the original terminal
completion from before logical expiry.

### Replay, conflict, and response loss

- Same scope/key/digest: return the same durable resource and response
  projection; `replayed=true` identifies replay. A document replay includes a
  fresh upload capability only when the document remains uploadable; a replay
  after lifecycle advancement may omit that ephemeral field.
- Same scope/key but another payload digest: stable HTTP 409
  `IDEMPOTENCY_CONFLICT` without exposing either payload.
- Another operation, actor, customer, deployment, or contract version has a
  distinct lookup scope and cannot retrieve or mutate the original record.
- `POST /api/v2/operations/{operation}/reconciliation` uses the original key
  header. It never requires a resource ID and returns a closed operation state.
- Missing and foreign records share enumeration-safe not-found behavior.
- A timeout/unknown write instructs reconciliation with the same key; clients
  must not create with a new key.

### Retention and expiry

The minimum logical retention is 30 days and is deployment-configurable within
bounded limits. The record is retained as a tombstone after logical expiry;
DynamoDB TTL deletion is not enabled. Expiry never authorizes key reuse or a
second business effect. No historical resource receives a synthesized ledger
record.

### Upload capability

The document resource identity and input locator are durable. A presigned PUT
is an ephemeral capability minted only after exact owner/resource/state
authorization. It is returned separately from the durable response, may differ
on replay or refresh, and is never persisted in the ledger, result, logs, or
evidence. `POST /api/v2/documents/{documentId}/upload-capabilities` refreshes it
only while the document remains uploadable. `replayed=false` always carries the
first capability. `replayed=true` may carry a newly authorized capability or
omit it after the document leaves the uploadable state.

The replay guarantee is:

```text
same durable business resource
+ same durable response projection
+ separately authorized fresh ephemeral capability when state permits
```

### Public state, errors, and results

The v2 adapter explicitly maps every supported current internal document/stage
value to closed lifecycle, stage, stage-state, processing-condition, and
failure-disposition enums. Unknown values, impossible timestamp ordering, and
stage/overall mismatches map to the public `UNSUPPORTED_STATE` error; a
status response never invents a quarantine lifecycle. Neither maps to success
or indefinite processing.

The exact reachable status values are lifecycles `UPLOAD_PENDING`, `SUBMITTED`,
`PROCESSING`, `COMPLETED`, and `FAILED`; stages `INGEST`, `OCR`, `CLASSIFY`,
`BANK_EXTRACT`, `PERSONAL_EXTRACT`, `VALIDATE`, and `TERMINAL`; stage states
`PENDING`, `RUNNING`, `SUCCEEDED`, and `FAILED`; and processing conditions
`ACTIVE` and `NOT_APPLICABLE`. Internal persisted/notify evidence is validated
without becoming a public `PERSIST` or `NOTIFY` stage. Unwritten or unsupported
received, uploaded, government-extraction, skip, delay, stall, and quarantine
projections fail closed instead of enlarging the public enum surface.

Repeated observations of the same lifecycle are valid self-transitions. They
do not authorize a repeated business effect or bypass any stage-transition CAS.

Errors use a closed `scanalyze.error.v1` envelope with safe code/message,
opaque correlation reference, retry class, allowlisted details, and
`Retry-After` only when meaningful. The envelope deliberately does not repeat
the request contract version. Provider text is never reflected.

`GET /api/v2/documents/{documentId}/result` selects a result family from the
owner-authorized document record before storage access. Version 1 requires
exact `processing_domain=documentRoute=bank`, the bank worker's closed,
completed, owner-bound `bank_extract` checkpoint, a matching structured
locator, and a SHA-256 match against the retrieved bytes. It then validates a
closed discriminated `bank_statement` envelope. Coherent personal/gov routes
fail explicitly as unsupported before an S3 read; inconsistent route/stage
evidence fails closed. A terminal `COMPLETED` record without a trusted locator
or checkpoint is malformed/unsupported, not indefinitely result-not-ready.
Download URLs remain separate transport capabilities.

The v2 result consumer intentionally enforces a 5 MiB maximum even though the
current bank producer permits structured artifacts up to 10 MiB. This tighter
consumer boundary is defense in depth, not a promise that every producer-sized
artifact is publicly consumable. Before live enablement, review observed
artifact sizes and explicitly align the producer limit or deployment
`JOURNEY_RESULT_MAX_BYTES`; never raise the consumer bound silently.

The public projection is the allowlisted subset already emitted by the bank
worker, excludes arbitrary model/provider payload, binds document/result
identity, and moves bounded confidence evidence into closed quality fields.
It regenerates account/CLABE masks and deterministically masks
separator-tolerant identifier tokens containing 8 through 18 ASCII digits in
any projected producer text (bank name, holder, summary, transaction
description/reference, and category input) before public model validation.

Any public account/CLABE mask is regenerated server-side as four asterisks plus
one to four final digits. A statement with both dates must satisfy
`periodStart <= periodEnd`.

### Edge, abuse, and observability

CloudFront, API Gateway CORS, FastAPI CORS, and the committed v2 OpenAPI use the
exact reviewed names for `Authorization`, `Content-Type`, `Idempotency-Key`,
`X-Correlation-ID`, `X-Scanalyze-Contract-Version`, `Retry-After`, and opaque
response correlation headers. The legacy `x-tenant-id` is not forwarded as
authority. Origins and credentials are not broadened.

Logs contain route templates, operation/state, opaque correlation references,
and bounded failure codes only. They omit bodies, filenames, raw keys, identity
values, capabilities, results, and provider text. Repository code defines the
rate-limit/error contract; live WAF/throttle values require separate authorized
verification and are not claimed here.

The upload-capability refresh limiter is process-local. It constrains bursts
inside one running process but is not a distributed quota and is reset by
restart or scale-out. It cannot substitute for separately reviewed edge/WAF
and service-level throttles; no live throttle effectiveness is claimed.

`api_authorization_routes` remains an external root-module input. The
checked-in synthetic Terraform fixture and executable edge-composition test
prove the reviewed route-map shape, JWT binding, and scopes in repository code
only. They do not prove root-stack wiring, a deployed API Gateway route set, or
any live edge state.

## Compatibility and migration

- `/api/v2` is additive and strict.
- `/api/v1` remains historical and is never silently upgraded/downgraded.
- Existing batches/documents/statuses/results are not reinterpreted or
  backfilled. A v2 replay without its exact ledger record fails closed.
- Frontend generated/contract-derived types are evidence of schema parity, not
  completion of GUG-103.
- Worker retry/orchestration remains owned by GUG-118.
- Pilot/acceptance remains owned by GUG-269.

## Rollback

Rollback is one reviewed revert of the complete GUG-354 repository package.
Do not delete tables, ledger tombstones, resources, or keys; do not rewrite
records; do not fall back to retrying an ambiguous create. If the v2 route is
withdrawn, preserve ledger data so delayed requests cannot reopen duplicate
effects. No rollback action in this ADR authorizes AWS or production mutation.

## Consequences and known limits

- The documents table carries non-indexed operation rows; scans remain
  forbidden and lookups use exact keys.
- The batches table is still externally configured rather than Terraform-owned.
  Reservation-first stable IDs avoid asserting or changing that ownership.
- Repository validation proves implementation and contracts only. The
  externally supplied `api_authorization_routes` root input, edge/live routing,
  throttles, deployed IAM, historical-record prevalence, and customer behavior
  require separately authorized evidence.
- No step in this ADR deploys code, migrates/backfills data, reads customer
  data, exercises staging or a pilot, changes production, or proves any
  staging/pilot/production outcome.
