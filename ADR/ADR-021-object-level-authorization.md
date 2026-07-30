# ADR-021: Object-Level Authorization and Ownership Binding

- **Status**: Accepted
- **Date**: 2026-07-12
- **Scope**: GUG-114 documents, batches, memberships, artifacts, and exports
- **Phase gate**: GUG-117
- **Live enablement**: Blocked pending reviewed CI and non-production isolation evidence
- **Production**: NO-GO

## Context

Authentication and route-level action policy do not by themselves prove that a
principal may act on one specific document or batch. GUG-102 produces a typed,
validated `AuthContext` with customer and deployment identity and preserves the
stricter `read+admin` policy for export and full-PII operations. Object records,
however, also need an exact, immutable ownership contract before any read,
mutation, membership operation, artifact access, or asynchronous handoff can be
authorized.

Legacy records may contain only `tenantId`, partially populated ownership,
conflicting aliases, or no ownership at all. Treating those records as if they
belonged to the current deployment would create an IDOR/BOLA boundary failure.
Similarly, authorizing a document only because its batch is accessible, querying
an index by an unbound identifier, or accepting an S3 prefix from a request would
allow one authorization decision to be reused outside its exact object scope.

## Decision

1. The canonical ownership fields for every new document and batch are
   `customer_id` and `deployment_id`. Both values come only from the validated
   internal `AuthContext`; request headers, path or query parameters, payloads,
   metadata, legacy tenant maps, and S3 prefixes never establish authority.
2. One centralized typed authorization layer evaluates documents, batches, and
   batch membership. Handlers pass the complete `AuthContext` and do not infer,
   normalize, repair, or duplicate ownership logic.
3. Authorization requires exact equality for both bindings:

   ```text
   object.customer_id == auth.customer_id
   object.deployment_id == auth.deployment_id
   ```

   Missing, empty, non-string, malformed, contradictory, partially bound, or
   legacy-only ownership fails closed. A missing `AuthContext`, missing
   deployment identity, or unsupported principal type also fails closed before
   a protected object is dereferenced.
4. Object authorization is evaluated in addition to the GUG-102 action policy.
   A user or M2M principal succeeds only when the object is owned by the exact
   authenticated customer and deployment. Export, full-PII, and protected
   downloads continue to require `read+admin`; a read-only M2M principal cannot
   mutate, export, retrieve full PII, or generate a protected download.
5. New writes persist both canonical fields from `AuthContext`. Conditional
   writes prevent overwrite and ownership conflict. Updates include the expected
   customer and deployment in their condition and never change either field.
6. A batch is authorized independently from every member document. Adding a
   document requires exact ownership equality across the principal, batch, and
   document. Reading or exporting a batch fails as one operation when any
   referenced document is missing, unbound, malformed, foreign, or inconsistent;
   partial results are not returned.
7. List and search operations enforce ownership in the DynamoDB key/query access
   pattern. A GSI or primary-key query that cannot bind customer and deployment
   is not an authorization boundary. Protected table scans and fetch-then-filter
   designs are rejected for normal request paths.
8. An S3 bucket and key are resolved only from the already authorized stored
   object contract. A request may select only a reviewed artifact alias; it may
   not provide a bucket, key, or prefix. Authorization completes before
   `generate_presigned_url`, and a URL is bound to that exact bucket and key with
   the configured minimal expiry, attachment disposition, and restricted content
   type where the artifact contract defines one.
9. Object absence and authorization failure use the same sanitized external
   not-found contract where object existence could otherwise be enumerated.
   Logs record stable reason categories and counts only; they never include
   object contents, PII, JWTs, S3 keys, presigned URLs, or request payloads.
10. Admin, support, analytics, add-on, export, and asynchronous paths do not
    receive a bypass. Any path that dereferences a document or batch must consume
    the same centralized authorization and ownership-bound repository contract.
11. The two canonical fields are the ownership contract for this version. A
    future representation change requires explicit versioning and a new reviewed
    compatibility decision; it cannot reinterpret legacy fields in place.
12. GUG-114 does not authorize AWS access, Cognito changes, Terraform provider
    operations, deployment, data migration, redrive, merge, or production.

## Compatibility and legacy behavior

- `tenantId` may remain in an API response only as a deprecated presentation
  alias. It is not canonical stored ownership and never authorizes access.
- A record that contains only `tenantId`, or whose aliases disagree with the
  canonical fields, is migration-required and denied in normal paths.
- Existing route shapes need not change solely to carry authority because the
  authority is the internal `AuthContext`, not a new public request field.
- Local and CI fixtures must provide explicit synthetic customer and deployment
  bindings. `local_mock` requires an explicit valid `SCANALYZE_DEPLOYMENT_ID`;
  no shared local deployment is inferred. Local mode is not an ownership bypass.
- No record is automatically migrated, inferred, deleted, or reassigned by this
  decision. The companion migration and quarantine runbook governs future work.

## Storage and artifact consequences

- The versioned record shape is defined by
  `schemas/object-ownership.v1.schema.json`. The documents table exposes sparse
  `OwnershipIndex` and `BatchOwnershipIndex` partitions; records without the
  canonical attributes are intentionally absent from those indexes.
- Repository reads and sensitive updates accept the trusted ownership binding,
  not only an object identifier.
- Conditional updates preserve existing idempotency while also requiring exact
  ownership. An idempotent retry never converts an ownership mismatch into
  success.
- Batch membership and pagination remain inside one customer/deployment query
  boundary. A continuation token cannot select or resume another boundary.
- Existing indexes that do not bind both ownership fields are insufficient for
  protected list, membership, or export operations until a reviewed storage
  contract provides that binding.
- Stored artifact metadata is still untrusted until its owning object passes
  authorization and the locator satisfies the reviewed artifact contract.
- Employee Profile jobs, manifests, and individual profiles authorize any
  pre-existing record even during `force=true` regeneration. Writes use S3
  `If-Match` for replacement or `If-None-Match: *` for creation so concurrent
  replacement, malformed legacy state, and ownership reassignment fail closed.
- The currently deployed worker-v1 producers write only the exact keys
  `platform|bank|personal|gov/<documentId>/ocr.json` in the configured OCR
  bucket and `bank|personal|gov/<documentId>/result.json` in the configured
  structured bucket. GUG-114 preserves those exact producer contracts after
  object authorization so existing legitimate results remain accessible. This
  is not a legacy ownership fallback: route, document id, filename, and
  deployment-configured bucket must all match exactly, and arbitrary prefixes
  remain denied. GUG-89 owns migration of the asynchronous producers to the
  canonical owner-bound prefix.

The baseline has a pre-existing IaC drift: the ingest API consumes a separately
configured batches table, but `modules/data-foundation` does not declare that
table. GUG-114 does not invent, import, replace, or cut over a live table because
doing so without environment and ownership evidence could collide with existing
data. Batch authorization is implemented and locally tested against the typed
repository contract, while IaC reconciliation and any live proof remain
**Blocked** pending a separately reviewed inventory and change. This limitation
prevents live-validation and production-readiness claims; it does not permit a
customer-only fallback.

The asynchronous consumers also predate the ownership-v1 message contract. The
ingest producer emits the exact ownership tuple, but the OCR worker does not yet
make that tuple mandatory or fail closed when its authoritative DynamoDB lookup
fails. Changing the routing/message/worker/DLQ contract belongs to GUG-89 and is
not started in this worktree. Until GUG-89 binds and verifies owner plus stored
bucket/key before processing, the async boundary is **Blocked**, GUG-114 cannot
be treated as end-to-end live proof, and production remains **NO-GO**.

## Security consequences

- Cross-customer and cross-deployment object access is denied even when an
  identifier is known or a related batch is accessible.
- Legacy ambiguity becomes visible as migration-required instead of silently
  expanding authority.
- A single authorization implementation reduces route-to-route policy drift.
- Fail-closed membership prevents a foreign document from entering an otherwise
  authorized batch export.
- Generic external errors reduce object enumeration while reason-only internal
  diagnostics retain operational value without exposing protected material.

## Validation and evidence boundary

The control is **Implemented** only for a reviewed revision that contains the
central authorization layer, protected route integration, ownership-bound
storage behavior, and protected artifact generation. It is **Locally validated**
only after named synthetic positive and negative tests and repository gates pass
for that revision. **CI validated** requires the identified PR checks to pass for
the exact commit. No repository test is **Live validated**.

Live two-deployment isolation, legacy inventory, and migration remain
**Blocked** until separately authorized non-production work produces sanitized,
reviewed evidence. GUG-117 remains in progress and production remains **NO-GO**.

## Rollback

Revert the reviewed application change as a normal Git change and keep protected
object paths disabled if exact authorization cannot be preserved. Do not restore
legacy `tenantId` authorization, remove canonical ownership from records, weaken
conditions, or expose a customer-only fallback. New records that already contain
canonical ownership remain data; rollback of code is not permission to delete or
rewrite them. Any future migration rollback returns affected records to denied or
quarantined treatment under the companion runbook.
