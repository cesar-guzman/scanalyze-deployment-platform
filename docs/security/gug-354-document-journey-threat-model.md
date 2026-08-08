# GUG-354 document journey threat-model delta

## Scope and evidence boundary

This delta covers the repository implementation of `/api/v2` batch/document
create, operation reconciliation, upload capability refresh, public status,
and the typed `bank_statement` result. It assumes the existing verified-auth
and object-authorization boundaries. It does not assert deployed IAM, edge,
WAF, throttling, data quality, live records, or production behavior.
It authorizes no AWS write, deploy, database/data migration, historical
backfill, customer-data access, staging exercise, pilot, production change, or
production verification claim.

Explicit execution boundary:

- No live DynamoDB access.
- No live API Gateway access.
- No live Cognito access.
- No live upload.
- No live OCR, Textract, or Bedrock execution.
- No AWS access or mutation.
- No deployment.

## Assets and trust boundaries

- verified actor/customer/deployment authority;
- idempotency-key and canonical-request binding;
- one-effect batch/document identity;
- operation ledger state and durable response projection;
- document/object ownership and final-artifact binding;
- ephemeral upload capability;
- public state/error/result integrity;
- logs and correlation evidence free of secrets/PII.

Request JSON, headers, CloudFront/API Gateway, FastAPI parsing, DynamoDB ledger,
business tables, S3 transport capabilities, stored structured results, and
frontend consumers are distinct trust boundaries. A digest proves only its
canonical projection; it never creates authority.

The committed `schemas/scanalyze-document-journey.openapi.v1.json` is the sole
v2 OpenAPI authority. FastAPI's `/openapi.json` is legacy, noncanonical
metadata and intentionally excludes v2, preventing a generated framework view
from silently broadening or replacing the reviewed contract.

## Threats and controls

| Threat | Repository control | Residual boundary |
|---|---|---|
| Cross-actor/customer/deployment replay | Lookup keys include contract, operation and verified owner scope; resource records repeat the binding | Current deployed auth/claims require separate evidence |
| Same key with changed payload | Domain-separated canonical request digest and stable 409 conflict | Client must preserve the original key/request |
| Duplicate-key or JSON smuggling | Raw-body duplicate-key/non-finite rejection plus closed models | Edge/body-size enforcement is deployment evidence |
| Type/coercion/canonicalization mismatch | Pydantic strict fields, compact sorted encoding, SHA-256 domain separation, parity tests | Producer formats outside v2 remain historical |
| Concurrent identical/conflicting writers | Conditional reservation selects one stable ID; only winner writes; create-only resource | Dynamo service behavior is not live-verified here |
| Lost/ambiguous write response | Strong read of ledger and reserved resource; exact binding; no blind retry; quarantine otherwise | Operator remediation for quarantined records is separate |
| Partial ledger/business commit | Reservation precedes resource; stable ID; PENDING reconciliation; exact CAS | No cross-table transaction is claimed |
| TTL/key reuse duplicate | Logical expiry retained as tombstone; no Dynamo TTL | Storage lifecycle changes require separate review |
| Operation-key enumeration | Authenticated exact scope, key digest lookup, common not-found behavior, bounded headers | WAF/rate values require live verification |
| Signed URL persistence/leak | Capability minted after authorization and separated from durable projection/result/logging | Browser/client handling is GUG-103 |
| Capability reuse/wrong owner/state | Exact resource owner+actor binding and uploadable-state check on every mint | S3 policy and live expiry require separate evidence |
| Distributed capability-refresh abuse | Process-local limiter bounds one process and the route retains owner/state authorization | Limiter resets on restart and is per replica; edge/WAF and distributed quotas require separate live review |
| Client identity-authority injection | Closed requests reject tenant/customer/deployment/owner fields; authority comes from auth context | Existing identity-control-plane assumptions apply |
| Unknown or unproduced state treated as public | Exact writer-derived enums plus exhaustive adapter and transition/timestamp validation fail closed | Broader worker normalization remains GUG-118 |
| Malformed/foreign result accepted | Owner-bound bank domain/route, exact completed extraction checkpoint, locator/content-digest binding, size-bounded strict JSON, and document/result/discriminator/version validation | Bank extraction quality is not certified by structure |
| Producer-sized artifact exhausts the public consumer | Consumer rejects structured artifacts above 5 MiB even though the bank producer permits 10 MiB | Review observed sizes and explicitly align producer or deployment limit before live enablement |
| Account/CLABE copied into public text | Server regenerates identifier masks and deterministically remasks separator-tolerant tokens containing 8 through 18 ASCII digits in every projected producer text field | Private worker artifacts remain restricted and unmodified |
| Sensitive/public error leakage | Closed code/message/retry mapping and allowlisted details; provider text ignored | Operational log sinks need separate assessment |
| Correlation spoofing | Middleware hashes inbound values into opaque references | Edge forwarding must match the checked-in contract |
| Retry storm/downgrade | Explicit reconciliation-only class, Retry-After, required version header, no silent alias | Client implementation and WAF remain separate lanes |
| Historical record reinterpretation | No ledger backfill; unsupported/missing v2 evidence fails closed | Any live migration requires its own issue/authorization |
| Rollback reopens duplicates | Tombstones retained; rollback is package revert, not data/key deletion | Deployed rollback requires explicit review |
| Cross-agent ownership overlap | PR #66 exact path manifest is frozen; GUG-354 uses disjoint paths | Re-fetch before publication and review |

## Security invariants

1. No GUG-354 ledger, public response, or logging path persists or exposes a
   raw idempotency key, request body, upload URL, document content, token,
   provider response, full account number, or full CLABE, including when a
   producer places an identifier in holder, summary, bank-name, description,
   reference, or category text. The public adapter remasks separator-tolerant
   identifier tokens containing 8 through 18 ASCII digits. Existing private
   worker artifacts remain a separate restricted trust boundary.
2. No create occurs before a durable reservation fixes the resource ID.
3. A reservation loser never issues the business create.
4. An ambiguous write never triggers an automatic second create.
5. No reconciliation lookup succeeds outside the exact verified scope.
6. A public bank result requires exact `processing_domain=documentRoute=bank`,
   a completed owner-bound `bank_extract` checkpoint, matching structured
   locator, and matching stored-content SHA-256 before projection. Coherent
   personal/gov routes fail as `UNSUPPORTED_RESULT_TYPE` before an S3 read.
7. A terminal `COMPLETED` record without that trusted locator/checkpoint is a
   malformed/unsupported internal result, never indefinite `RESULT_NOT_READY`.
8. No unknown internal state/result field is projected as valid public data.
9. No missing/unsupported contract version silently falls back to v1.
10. Public status values are limited to writer-reachable outputs: five
    lifecycles, seven stages, four stage states, two processing conditions, two
    failure dispositions, and three safe failure codes. Persist/notify evidence
    remains internal, and unsupported received/uploaded/government/skip/delay/
    stall/quarantine projections fail closed.
11. The 5 MiB public result-consumer bound is intentionally tighter than the
    producer's 10 MiB limit until an explicit live-enablement size review.

## Explicit NO-GO boundary

This delta does not deploy, mutate AWS, migrate or backfill data, read customer
data, exercise staging, run a pilot, change production, or prove a
staging/pilot/production outcome. Repository/CI evidence must not be relabeled
as any of those activities.

It also performs no live DynamoDB, API Gateway, Cognito, upload, OCR, Textract,
or Bedrock operation and makes no AWS access or mutation.

## Verification requirements

Focused synthetic tests must cover exact/conflicting replay, concurrent winner
and loser, partial/ambiguous writes, response loss without resource ID, expiry,
cross-scope isolation, capability separation, every state/error/result enum,
strict JSON, OpenAPI/runtime/frontend parity, CORS/headers, and existing
GUG-89/GUG-102/GUG-114 regressions. Run the exact-diff Codex Security workflow
and block review readiness on any unresolved P0/P1.

Parity evidence must also prove that `/openapi.json` excludes v2 and remains
noncanonical, while the committed schema contains every v2 route and only the
writer-reachable public status values.
