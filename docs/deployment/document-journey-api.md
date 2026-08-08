# Critical document journey API v2

This runbook describes the repository contract introduced by GUG-354. It is
not deployment evidence and does not authorize an AWS write, deployment,
database/data migration, historical backfill, customer-data access, staging
exercise, pilot, production change, or production verification claim.

Explicit execution boundary:

- No live DynamoDB access.
- No live API Gateway access.
- No live Cognito access.
- No live upload.
- No live OCR, Textract, or Bedrock execution.
- No AWS access or mutation.
- No deployment.

## Authority

- Namespace: `/api/v2`
- Contract: `scanalyze.document-journey.v1`
- Contract header: `X-Scanalyze-Contract-Version`
- Create/reconciliation key header: `Idempotency-Key`
- Authoritative schema:
  `schemas/scanalyze-document-journey.openapi.v1.json`
- Architecture decision:
  `ADR/ADR-049-versioned-idempotent-document-journey.md`

The committed schema above is the sole OpenAPI authority for v2. FastAPI's
generated `/openapi.json` is legacy, noncanonical operational metadata and
intentionally excludes v2; do not use it for v2 client generation or parity
claims.

Every request is authenticated. Actor, customer, and deployment are derived
from the verified authentication context. Never send customer, tenant,
deployment, or owner authority in a payload, query string, or custom header.

## Client algorithm

Generate one lowercase UUID with `crypto.randomUUID()` for each user intent.
Retain it in client operation state until the intent reaches a terminal
reconciliation state. Do not derive it from a filename, email, document, or
other user data.

For batch or document creation:

1. Send the exact contract-version and idempotency headers.
2. If the response arrives, retain the durable resource ID.
3. If the request times out or the connection is lost, do **not** create a new
   key and do **not** automatically issue another POST with a different key.
4. Call the operation reconciliation endpoint with the original operation and
   original key.
5. While the state is `PENDING`, use the declared bounded backoff. Do not run a
   second create.
6. On `SUCCEEDED`, continue with the returned durable resource.
7. On `FAILED_RETRYABLE`, follow only the server-declared retry contract.
8. On `FAILED_TERMINAL`, stop that intent.
9. On `UNKNOWN_OR_QUARANTINED`, stop automation and preserve the correlation
   reference for operator reconciliation.
10. On `EXPIRED`, do not reuse the key.

`FAILED_RETRYABLE` has no `completedAt`, because the operation remains
resumable. Terminal outcomes require it. For non-expired states,
`updatedAt < expiresAt`; for `EXPIRED`, `expiresAt <= updatedAt` and
`createdAt <= completedAt <= updatedAt`. An expired tombstone may retain the
original terminal `completedAt` from before `expiresAt`.

The same key and exact request return the same durable batch/document. The
same key with any semantically changed request returns HTTP 409
`IDEMPOTENCY_CONFLICT`. JSON member order is not semantic; JSON types and
field values are semantic. Duplicate keys, non-finite numbers, and unreviewed
fields are rejected.

## Routes

| Method | Route | Purpose |
|---|---|---|
| `POST` | `/api/v2/batches` | Reserve and create one batch |
| `POST` | `/api/v2/documents` | Reserve and create one durable upload intent |
| `POST` | `/api/v2/operations/{operation}/reconciliation` | Resolve response loss using the original key |
| `POST` | `/api/v2/documents/{documentId}/upload-capabilities` | Mint a fresh owner-authorized upload capability |
| `POST` | `/api/v2/documents/{documentId}/submit` | Submit to the existing canonical `ingest` boundary |
| `GET` | `/api/v2/documents/{documentId}` | Read the closed public journey state |
| `GET` | `/api/v2/documents/{documentId}/result` | Read the typed terminal result |

The only create operation identifiers are `batches.create` and
`documents.create`.

## Durable response versus capability

The batch/document ID, closed status, contract/operation, and creation time are
durable. A document upload URL is not. It is a short-lived transport capability
minted only after the server reauthorizes the exact owner and verifies the
document remains uploadable.

An exact document replay therefore guarantees the same durable response but
may carry a newly minted upload capability with a different URL/expiry. The
first response (`replayed=false`) always carries a capability. An exact replay
(`replayed=true`) may omit it after the document advances beyond an uploadable
state; use the refresh route only while owner and state authorization still
permit upload. Never compare or persist capabilities as business identity.
Never place a capability in logs, analytics, tickets, screenshots, or durable
client storage.

## Status contract

The response separates:

- overall document lifecycle;
- current pipeline stage;
- stage state;
- processing condition;
- failure disposition.

The exact public lifecycles are `UPLOAD_PENDING`, `SUBMITTED`, `PROCESSING`,
`COMPLETED`, and `FAILED`. Public stages are `INGEST`, `OCR`, `CLASSIFY`,
`BANK_EXTRACT`, `PERSONAL_EXTRACT`, `VALIDATE`, and `TERMINAL`; stage states are
`PENDING`, `RUNNING`, `SUCCEEDED`, and `FAILED`; processing conditions are
`ACTIVE` and `NOT_APPLICABLE`. Internal persist/notify evidence does not create
public `PERSIST` or `NOTIFY` stages. Unwritten or unsupported received,
uploaded, government-extraction, skipped, delayed, stalled, and quarantined
status projections fail closed. An unknown internal value is a contract error,
never success and never indefinite processing.

Valid public values and transitions are enumerated in the authoritative
OpenAPI document. Client code must treat an unrecognized enum as a hard
contract mismatch, not a default processing state.

Every lifecycle permits a same-state observation. A self-transition represents
polling or an idempotent observation, not permission to repeat the underlying
business effect.

`SUBMITTED` with `INGEST`/`FAILED`, `NOT_APPLICABLE`, `RETRYABLE`, and
`ENQUEUE_FAILED` is the one reviewed nonterminal failure projection. It means
the existing enqueue boundary did not accept work and a later authorized
submit may retry. All other failure projections are terminal or quarantined.

## Error and retry contract

Errors use `scanalyze.error.v1` and include a stable code, safe message, opaque
correlation ID, and closed retry class:

- `NOT_RETRYABLE`: correct the request or stop;
- `RETRYABLE_WITH_BACKOFF`: retry only after the declared delay;
- `RETRY_ONLY_AFTER_RECONCILIATION`: query the original operation first;
- `TERMINAL`: stop the intent;
- `UNKNOWN_OR_QUARANTINED`: stop automation and escalate safely.

`Retry-After` is present only when a bounded delay is meaningful. The body and
header are contract-tested together. Never surface raw provider messages,
stack traces, tokens, ARNs, queue URLs, signed URLs, document content, raw keys,
or customer data.

## Typed bank statement result

Version 1 supports the `bank_statement` discriminator only. The result binds
the authorized source document, deterministic result identity/version,
producer schema evidence, closed data, warnings, and bounded quality. It
projects only fields already emitted by the current bank worker.

Full account number and full CLABE are intentionally not part of the minimum
public v1 projection. When present, either masked value is server-produced as
exactly four asterisks followed by one to four final digits; producer-provided
mask labels and full numeric values are never trusted as public masking.
Separator-tolerant numeric identifiers containing 8 through 18 ASCII digits
are also remasked in every producer text field before projection. Arbitrary
model/provider output and arbitrary JSON objects are rejected. A transport
download locator is not a result envelope. Unsupported document families fail
explicitly.
When both statement-period dates are present, `periodStart` must not be later
than `periodEnd`.

The public result consumer deliberately caps the fetched structured artifact
at 5 MiB, while the current bank producer has a 10 MiB maximum. The tighter
consumer limit is a defense-in-depth boundary: a producer-valid artifact above
5 MiB is rejected rather than partially parsed. Before live enablement, review
observed artifact sizes and explicitly align the producer limit or
`JOURNEY_RESULT_MAX_BYTES`; do not silently raise the public consumer bound.

## Compatibility and historical records

`/api/v1` is historical. It is not an alias for v2 and does not gain v2 replay
claims. Existing batches/documents are not backfilled and cannot be presented
as v2 replays without their exact operation ledger. Existing open status or
result records are adapted only when every value, timestamp, identity, and
artifact binding is explicitly supported; otherwise v2 fails closed.

The frontend contract files are derived/parity-checked artifacts for GUG-354.
They do not implement polling, UX, or the GUG-103 journey.

## Operation retention and recovery

Operations have a bounded logical expiry with a 30-day default minimum
retention. Expired records remain tombstones; there is no DynamoDB TTL deletion
and expiration never authorizes key reuse. If an operation remains
`UNKNOWN_OR_QUARANTINED`, preserve it and investigate through separately
authorized, non-sensitive evidence.

Upload-capability refresh has a process-local burst limiter. It resets when a
process restarts and is independent in each replica, so it is not a distributed
abuse-control guarantee. Separately reviewed edge/WAF and service throttles are
required before any live effectiveness claim.

Repository rollback is a reviewed revert of the entire GUG-354 package. Never
delete or rewrite ledger/resource rows, reset keys, deploy a historical
non-idempotent route as a fallback for an ambiguous operation, or execute a
cloud change from this runbook.

## Local validation boundary

All GUG-354 tests use synthetic fakes, disable EC2 metadata lookup, clear AWS
credential/profile variables, and make no application network call. Terraform
validation uses `-backend=false` and is never applied. Local/CI success proves
repository behavior only; inspect exact deployed edge/runtime state separately
under explicit authorization.

The application-generated `/openapi.json` intentionally remains a legacy-only
view. Validate all v2 routes, schemas, enums, and response shapes against the
committed `schemas/scanalyze-document-journey.openapi.v1.json` authority.

The reusable edge-identity module receives `api_authorization_routes` from an
external root module. Its checked-in synthetic fixture and executable rewrite
composition test prove only that the reviewed map shape resolves `/api` to
explicit JWT-protected `/api/v1` routes, preserves all seven `/api/v2` routes,
and binds the expected scopes. They do not prove root-stack wiring or deployed
API Gateway/CloudFront state.

This runbook performs no deploy, cloud mutation, database or historical-data
migration/backfill, customer-data inspection, staging exercise, pilot, or
production action. Those boundaries remain NO-GO without a separate exact
authorization and evidence lane.

## Lane boundaries

- GUG-354 owns this backend/edge/schema contract.
- GUG-103 owns frontend journey behavior after this contract is merged.
- GUG-118 owns broader worker/orchestration idempotency.
- GUG-269 owns pilot evidence and acceptance.
- GUG-105/PR #66 and GUG-291 remain separate OCR-worker lanes.
