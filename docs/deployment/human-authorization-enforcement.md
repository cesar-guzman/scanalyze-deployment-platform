# Human Authorization Enforcement

> **Decision:** ADR-025 / GUG-153
> **Policy:** `enterprise-authorization.v1`
> **Runtime scope:** Scanalyze ingest API human PDP/PEP
> **Evidence snapshot:** 2026-07-13 locally validated candidate
> **Live validation:** No
> **Production:** NO-GO

## Purpose

This reference defines how every protected ingest API route maps to the
portable human authorization policy. It is reusable for any customer,
deployment, account, region, and reviewed provider because no deployment
identifier or provider resource name is embedded in the operation catalog.

GUG-153 consumes an already validated internal `AuthContext`. It does not use
headers, query parameters, payloads, route identifiers, provider group names,
email domains, or legacy tenant maps as authorization inputs. It does not
perform AWS changes, identity migration, user lifecycle actions, deployment, or
live validation.

## Runtime architecture

```text
API Gateway access-token validation
        |
        v
GUG-102/GUG-153 AuthContext adapter
  - exact customer + deployment
  - principal type + subject
  - human authorization snapshot, or M2M actions
        |
        v
require_operation(OperationId) route PEP
        |
        +-- user --> enterprise human PDP
        |             role + scopes + resource + data class
        |             versions + digest + signed-snapshot age
        |             exact current authority-state resolver
        |             explicit deny + proven step-up
        |             trusted opaque audit-reference bindings
        |             durable audit receipt before effect
        |
        +-- m2m ---> GUG-102 explicit granted actions
        |
        +-- other --> deny
        |
        v
service handler
        |
        v
GUG-114 object/batch/member/trusted-locator authorization
        |
        v
protected effect
```

The route PEP and object authorization are both mandatory. A successful route
decision does not prove that a supplied object ID belongs to the caller.

The human branch additionally requires an `EnterpriseAuthorizationRuntime`
installed by trusted application startup code at
`app.state.enterprise_authorization_runtime`. It contains three ports: a
current authoritative-state resolver, a typed
`authorization-audit-references.v1` resolver, and a durable
authorization-audit sink.
The HTTP request cannot supply or replace either port. With no runtime, human
authorization denies; M2M remains on the unchanged GUG-102 path.

## Human snapshot contract

### Membership path

The normal human path is a provider-validated snapshot from the GUG-93
pre-token membership adapter. Required logical fields are:

| Field | Rule |
|---|---|
| `schema_version` | Exactly `human-authorization-context.v1` |
| `authorization_path` | Exactly `membership` |
| `authorization_source` | Exactly `pre_token_membership_v1` |
| `subject` | Non-empty signed immutable subject; equal to `AuthContext.subject` |
| `customer_id` | Exact signed customer; equal to deployment and AuthContext binding |
| `deployment_id` | Exact signed deployment; equal to runtime and AuthContext binding |
| `membership_state` | Exactly `active` |
| `role_id` | One canonical role; no aggregation |
| `membership_version` | Non-empty current authoritative version |
| `authz_schema_version` | `enterprise-authorization.v1` |
| `scope_catalog_version` | `scanalyze.api.v1` |
| `role_catalog_version` | `enterprise-roles.v1` |
| `policy_version` | Exact reviewed version configured for the deployment |
| `policy_digest` | Exact reviewed lowercase SHA-256 digest, compared in constant time |
| `issued_at_epoch` | Not future and no more than 300 seconds old |
| authentication time | Required, valid, and no later than snapshot issue time |
| assurance | Optional for ordinary operations; sensitive use also requires the exact reviewed source/version/event reference |

The valid signed-snapshot age interval is inclusive: `0..300` seconds. A value
of 301 seconds, a future timestamp, a missing timestamp, or a non-integer value
denies. Snapshot age is not current authority. The runtime resolver must also
return `authorization-authority-state.v1` membership evidence observed at the
exact decision second, sourced from `authoritative_membership_store_v1`, with
exact subject/customer/deployment/active-state/version/role equality.

The current GUG-93 token adapter emits no trusted phishing-resistant assurance.
It ignores arbitrary configurable custom claims for elevation. Sensitive human
operations remain denied until a reviewed adapter supplies the indivisible
tuple `phishing_resistant_mfa` + `authoritative_authentication_event_v1` +
`phishing-resistant-mfa.v1` + an opaque event reference.
`ENTERPRISE_ASSURANCE_CLAIM_NAME` is retained only as inert configuration
compatibility; setting it never establishes assurance or authorizes an
operation.

### Temporary-grant path

Temporary grants are an internal normalized path, not a public token or request
format. The only accepted source is
`authoritative_temporary_grant_store_v1`. Required fields include exact
subject/customer/deployment binding, active state, grant type, version,
operation allowlist, data-class allowlist, expiry, immutable grant issue time,
and current
policy versions/digest.

The path contains no role or membership version. Membership plus grant fields,
or neither set, deny. An expired or stale grant denies. Only operations in the
GUG-92 temporary-grant catalog can be allowed. Full results, exports, and
protected downloads always deny for temporary grants. The GUG-153
exposure-specific artifact-list and full-profile operations also deny them.

Support and break-glass grants also require exact phishing-resistant assurance
and an authentication age from zero through 300 seconds for their otherwise
allowlisted ordinary operations.

The complete grant lifetime is measured from `grant_issued_at_epoch` to
`expires_at_epoch`: support is limited to 3,600 seconds and break glass to 900
seconds. A fresh token snapshot cannot renew or hide an overlong underlying
grant. Current grant evidence must match the complete normalized grant at the
exact decision second.

No current request route may supply or override a grant. A future GUG-94
adapter must construct this snapshot from its authoritative internal store
before the path can be enabled.

Support requires an opaque case reference, an opaque purpose reference, and at
least one unique independent approval reference. Break glass requires an
opaque incident reference, an opaque purpose reference, and exactly two unique
independent approval references. Case and incident bindings are mutually
exclusive; the grantee cannot self-approve. The complete reference set must
match current authoritative grant evidence at the decision second.

## Trusted runtime adapter contracts

The runtime ports are provider-neutral and have no live implementation in this
package:

| Contract | Required proof | Failure behavior |
|---|---|---|
| `authorization-authority-state.v1` | Exact path, source, checked time, subject, customer, deployment, active state, version, plus role or complete grant fields | Deny before policy allow |
| `authorization-audit-references.v1` | Stable opaque principal, customer, deployment, and current correlation binding; exact grant reference only on the temporary path | Deny before allow-event emission |
| `authorization-audit-receipt.v1` | `durable_authorization_audit_sink_v1`, sink version `1.0.0`, exact decision id, opaque receipt reference, acknowledgement time | Deny before handler effect |

GUG-94 must install all three adapters from trusted startup code, perform lookups only
from the validated snapshot tuple, use ownership-bound and conditional storage
access, and return these exact immutable records. Do not install a logger,
request callback, header-derived resolver, post-response queue, or best-effort
collector as any port. Until those adapters and the assurance provider are
reviewed, human operations deny by construction.

## Decision algorithm

For each request the PDP performs these checks in order:

1. Resolve the operation through the closed `OperationId` enum.
2. Dispatch by exact principal type; unknown and `local_mock` deny.
3. For a user, require one human snapshot and exact subject/customer/deployment
   equality with `AuthContext` and runtime binding.
4. Require exactly one membership or temporary-grant path and its trusted
   internal source.
5. Require active state, path version, supported catalog versions, reviewed
   policy version, and constant-time digest equality.
6. Require a signed snapshot age from zero through 300 seconds.
7. Call the trusted current-state resolver and require exact evidence at the
   decision second; unavailable, cached, foreign, or conflicting evidence
   denies.
8. Resolve required resources, actions, data classes, scopes, and explicit
   denies from the immutable operation registry.
9. Require every OAuth scope; extra scopes do not add role permission.
10. Require the role matrix or temporary-grant operation/data allowlist.
11. For a sensitive operation, require membership path, `read` + `admin`, exact
    proven phishing-resistant assurance, and authentication age from zero
    through 300 seconds.
12. Resolve the trusted typed opaque audit references and require exact
    request/path binding; missing, malformed, mismatched, or raw references deny.
13. Emit the sanitized decision and require a matching typed durable receipt;
    missing/malformed/mismatched acknowledgement denies before the handler.
14. Continue to the service and require GUG-114 object authorization before the
    protected effect.

Any missing, malformed, stale, future, unsupported, unknown, foreign,
conflicting, unavailable, or legacy-only value denies. There is no default
role, operation, data class, or allow.

## Exact protected route inventory

The following 30 routes are the complete protected API v1 business inventory.
`M2M` records the unchanged GUG-102 action requirement. `Human policy`
describes the additional GUG-153 decision; object checks remain mandatory where
an object is involved. Public `/health` and `/api/v1/health` liveness routes
carry no customer data and are intentionally excluded.

| # | Method and route | `OperationId` | M2M | Human policy |
|---:|---|---|---|---|
| 1 | `POST /api/v1/documents` | `documents.create` | `write` | Admin/operator; documents write/content |
| 2 | `POST /api/v1/documents/{document_id}/submit` | `documents.submit` | `write` | Admin/operator; documents write/content; owned document |
| 3 | `GET /api/v1/documents/{document_id}` | `documents.read_metadata` | `read` | Admin/operator/reviewer or exact temporary grant; metadata; owned document |
| 4 | `GET /api/v1/documents/{document_id}/result` | `results.read_full` | `read+admin` | Sensitive; admin membership only; PII; step-up; owned document |
| 5 | `GET /api/v1/documents/{document_id}/artifacts` | `artifacts.list_metadata` | `read` | Privileged; admin membership only; `read+admin`; step-up; owned document |
| 6 | `GET /api/v1/documents/{document_id}/download` | `artifacts.download` | `read+admin` | Sensitive; admin membership only; step-up; trusted locator |
| 7 | `GET /api/v1/documents/{document_id}/artifacts/{artifact_id}/download` | `artifacts.download` | `read+admin` | Sensitive; admin membership only; step-up; trusted stored alias/locator |
| 8 | `POST /api/v1/batches` | `batches.create` | `write` | Admin/operator; batches write/metadata |
| 9 | `GET /api/v1/batches/{batch_id}` | `batches.read_metadata` | `read` | Admin/operator/reviewer or exact temporary grant; owned batch; closed non-identifying envelope |
| 10 | `GET /api/v1/batches/{batch_id}/documents` | `batches.read_metadata` | `read` | Same role/grant; batch and every returned member must be owned |
| 11 | `GET /api/v1/batches/{batch_id}/manifest` | `exports.execute` | `read+admin` | Sensitive; admin membership only; step-up; every member authorized |
| 12 | `GET /api/v1/batches/{batch_id}/exports/json` | `exports.execute` | `read+admin` | Sensitive; admin membership only; step-up; all-or-nothing export |
| 13 | `GET /api/v1/batches/{batch_id}/exports/csv` | `exports.execute` | `read+admin` | Sensitive; admin membership only; step-up; all-or-nothing export |
| 14 | `GET /api/v1/batches/{batch_id}/exports/zip` | `exports.execute` | `read+admin` | Sensitive; admin membership only; step-up; all-or-nothing export |
| 15 | `GET /api/v1/analytics/dashboard` | `metrics.read_identified` | `read` | Explicit human deny; response includes identified user dimensions |
| 16 | `GET /api/v1/analytics/overview` | `metrics.read` | `read` | Admin/operator/auditor or exact temporary grant; aggregated only |
| 17 | `GET /api/v1/analytics/pages-by-user` | `metrics.read_identified` | `read` | Explicit human deny; user ID/display identity is not aggregated data |
| 18 | `GET /api/v1/analytics/by-day` | `metrics.read` | `read` | Admin/operator/auditor or exact temporary grant; aggregated only |
| 19 | `GET /api/v1/analytics/by-batch` | `metrics.read` | `read` | Admin/operator/auditor or exact temporary grant; deployment-scoped aggregate |
| 20 | `GET /api/v1/analytics/by-doc-type` | `metrics.read` | `read` | Admin/operator/auditor or exact temporary grant; aggregated only |
| 21 | `GET /api/v1/analytics/costs` | `metrics.read` | `read` | Admin/operator/auditor or exact temporary grant; aggregated only |
| 22 | `GET /api/v1/analytics/export-ine` | `exports.execute` | `read+admin` | Sensitive; admin membership only; PII; step-up; every document owned |
| 23 | `GET /api/v1/addons/employee-profiles/status` | `deployment_configuration.read` | `read` | Admin or exact temporary grant; deployment metadata only |
| 24 | `GET /api/v1/addons/employee-profiles/export/csv` | `exports.execute` | `read+admin` | Sensitive; admin membership only; PII; step-up; every profile/batch owned |
| 25 | `POST /api/v1/addons/employee-profiles/generate` | `employee_profiles.generate` | `write` | Admin membership; write creates PII and exceeds operator masked-data permission |
| 26 | `GET /api/v1/addons/employee-profiles/jobs/{job_id}` | `employee_profiles.read_job` | `read` | Admin/operator/reviewer; closed non-identifying status/count/timestamp projection; owned job and batch |
| 27 | `GET /api/v1/addons/employee-profiles` | `employee_profiles.list_masked` | `read+admin` | Admin/operator/reviewer; masked only; owned profiles/batches |
| 28 | `GET /api/v1/addons/employee-profiles/{profile_id}/export/json` | `exports.execute` | `read+admin` | Sensitive; admin membership only; PII; step-up; owned profile/batch |
| 29 | `GET /api/v1/addons/employee-profiles/{profile_id}/export/csv` | `exports.execute` | `read+admin` | Sensitive; admin membership only; PII; step-up; owned profile/batch |
| 30 | `GET /api/v1/addons/employee-profiles/{profile_id}` | `employee_profiles.read_full` | `read+admin` | Sensitive equivalent to full result; admin membership only; PII; step-up |

The route test must assert both:

- exactly one typed operation dependency per protected route; and
- exactly one unchanged GUG-102 action dependency with the expected M2M action
  set.

A new route intentionally breaks this inventory until its resource, action,
data class, ownership, temporary-grant, sensitive-operation, and M2M behavior
are reviewed.

## Role summary

| Role | Ordinary operations relevant to current routes | Denied examples |
|---|---|---|
| `customer_admin` | Owned documents/batches, deployment status, aggregate metrics, profile generation/list; stepped-up artifact locator listing | Identified metrics; privileged/sensitive operations without step-up |
| `document_operator` | Document/batch create/read, aggregate metrics, masked profile list/job | Admin, exports, full PII, protected download, identified metrics |
| `document_reviewer` | Owned document/batch metadata, profile job/masked list | Create/mutate documents, aggregate metrics, export, full PII, download |
| `auditor` | Aggregate metrics and approved audit metadata | Document/profile content, mutation, identified metrics, export, download |

The normative complete role/resource/data-class matrix remains the versioned
GUG-92 policy. This route summary cannot expand it.

## Sensitive and exposure-specific step-up enforcement

The canonical GUG-92 sensitive catalog remains `results.read_full`,
`exports.execute`, and `artifacts.download`. GUG-153 additionally marks
`artifacts.list_metadata` and `employee_profiles.read_full` as
exposure-specific privileged operations because their current responses contain
locator material or full PII. All five require:

```text
authorization_path == membership
required scopes == {read, admin}
assurance == phishing_resistant_mfa
0 <= now_epoch - authenticated_at_epoch <= 300
0 <= now_epoch - issued_at_epoch <= 300
audit allow persisted before effect
GUG-114 object/member/locator authorization succeeds
```

Missing assurance is not inferred from a configured MFA policy. A password,
provider group, token scope, old authentication, future timestamp, or client-
supplied claim is not phishing-resistant evidence.
Temporary grants deny every canonical sensitive and exposure-specific
privileged operation.

## Identified metrics deny

`dashboard` and `pages-by-user` currently return a user identifier and may
derive a display value from a display name or email. The policy grants metrics
only as `metadata` or `aggregated`; it contains no identified-person metric
class. `metrics.read_identified` therefore has an explicit human deny for every
role and temporary grant.

Future enablement requires a reviewed API contract that either:

- removes person-level fields and uses a minimum aggregation/privacy rule; or
- introduces a separately reviewed resource/data class and policy version.

Fetching the current response and filtering fields after authorization is not
an acceptable control.

## Artifact locator boundary

The current artifact-list response includes internal locator material. Human
`artifacts.list_metadata` is therefore limited to a customer-administrator
membership with `read` + `admin`, documents/content permission, current
phishing-resistant step-up, audit, and exact document ownership. Document
operators, reviewers, auditors, and temporary grants deny. M2M retains the
reviewed GUG-102 `read` action; the human policy does not alter that workload
grant.

A future opaque alias-only response could justify a separately reviewed lower-
privilege policy. The current response must not be silently reclassified as
ordinary metadata.

Download routes never accept a request bucket, key, prefix, or URI as
authority. The service must:

1. authorize the document under GUG-114;
2. resolve the artifact alias from stored metadata;
3. validate the locator against the exact customer/deployment/document prefix;
4. complete sensitive step-up and audit; and
5. generate a short-lived URL for only the approved object.

Full URLs, keys, prefixes, and locators are not logged or placed in audit
events.

## Metadata and masked-response boundaries

`documents.read_metadata` never returns the stored stage dictionary verbatim.
The service projects each canonical stage onto a strict allowlist of closed
status values, timezone-aware timestamps, and bounded non-negative counters.
Nested objects and free-form values are dropped, including buckets, keys,
prefixes, locators, hashes, queue URLs, message IDs, payloads, and raw errors.
Uploader subject identifiers and stored correlation values are also suppressed;
their legacy response fields remain null-only to avoid a breaking schema
removal.

`batches.read_metadata` returns only batch identity, timestamps, status, and
compatibility fields. Stable creator identity is null-only. Arbitrary stored
`metadata` is returned as an empty object because its legacy free-form values
have no reviewed data-class contract; no live data is migrated or deleted.

`employee_profiles.read_job` returns an allowlist of job identity, closed
status, bounded counts, recognized error code, and valid timestamps. It never
returns creator identity, source fingerprints, raw error text/type, profile
IDs, ownership internals, or newly stored fields by default.

`employee_profiles.list_masked` returns the existing `fullName` response field
as the fixed marker `[REDACTED]`. The `q` name filter is unsupported and returns
a stable 400 response without evaluating names or revealing whether a match
exists. Full names remain available only through the separately authorized
`employee_profiles.read_full`/export path with its full PII controls.

Masked list, JSON-export, and CSV-export paths all rebuild their output through
the same closed `project_masked_profile` projection. Stored masked fields and
unknown future fields are ignored; supported scalar identifiers are remasked
from canonical values, so poisoned stored masks cannot become output.

Document creation accepts only `application/pdf`, `image/jpeg`, `image/png`, or
`image/tiff`. Legacy or poisoned stored content types normalize to `Unknown`
before public metadata, batch-document listing, or analytics aggregation.
Employee-profile generation accepts only the boolean options `force` and
`includeIncomplete`; unknown, nested, or non-boolean options deny before
storage lookup, logging, or effects. Every complete or masked CSV generator
uses the shared formula-cell neutralizer before `csv.writer`, including formula
prefixes hidden behind whitespace or control characters.

## Audit behavior

An allow event is written before the protected handler effect. It carries only
the versioned event type, timestamp, opaque decision/correlation reference,
principal type, operation, action/resource classification, allow/deny reason,
policy version/digest, and assurance category when applicable.

The trusted `authorization-audit-references.v1` resolver first returns stable
opaque references bound to the exact validated principal, customer, deployment,
and current correlation. Temporary-grant decisions additionally require an
opaque grant reference; membership decisions reject one. Validated temporary
grant decisions carry only their already current-matched opaque case/incident,
purpose, and approval references.

For an `allow`, `authorization-decision.v1` requires exactly one mutually
exclusive provenance branch: membership, support, break-glass, or M2M. An
early denial can omit authority that was never established; it cannot turn
missing evidence into an allow.

Forbidden audit/log content includes:

- JWTs, cookies, raw claims, OAuth credentials, and recovery factors;
- names, emails, document/profile contents, and identifiers containing PII;
- request bodies, extracted bank or government records;
- S3 buckets, keys, prefixes, artifact locators, and presigned URLs; and
- raw dependency exceptions or store responses.

For human authorization the sink must return
`authorization-audit-receipt.v1`, exact sink source/version, the same decision
id, an opaque receipt reference, and a valid acknowledgement time. A fire-and-
forget log call or `None` is failure. If an allow cannot obtain that receipt,
the request is denied. Audit retry must never execute the protected effect.

External `x-request-id`, correlation, and trace headers are never logged or
echoed raw. Their values are hashed into fixed-format opaque references before
context binding and response propagation; absent values receive fresh random
references.
Dynamic URL values are logged only through code-owned route templates. Human
subjects are not bound into request context, and a request-supplied stage is
never bound; only the canonical stage is recorded after service validation.
The global structured-log sanitizer pseudonymizes known customer, deployment,
tenant, document, batch, profile, job, uploader, and user identifier fields even
when a call supplies them directly instead of using the context helper.

## Required local and CI validation

At minimum, classify each result as PASSED, FAILED, SKIPPED, or BLOCKED:

```text
python -m compileall backend/workers/scanalyze-ingest-api
(
  cd backend/workers/scanalyze-ingest-api
  python -m pytest tests/test_gug153_human_auth_context.py
  python -m pytest tests/test_gug153_human_authorization.py
  python -m pytest tests/test_gug153_route_pep.py
  python -m pytest tests/test_gug153_route_privacy.py
  python -m pytest tests
)
python -m pytest tests/test_gug153_human_authorization_contract.py
make git-safety
make security-check
make microservices-check
make preflight-m2
make provider-check
make preflight-m2b
git diff --check
```

The focused suite must cover:

- all four roles and negative permission combinations;
- required-but-not-sufficient OAuth scopes;
- missing/unknown/conflicting path, role, version, digest, binding, or source;
- stale/future signed snapshots plus missing, stale, foreign, or conflicting
  current authority-state evidence;
- 299/300/301-second step-up boundaries;
- temporary-grant allowlists, 3,600/3,601 and 900/901 lifetime boundaries, and
  sensitive-operation denial; support case/purpose/independent approval and
  break-glass incident/purpose/two-independent-approval bindings;
- audit sink failure and missing/malformed/mismatched durable receipts;
- missing/malformed/mismatched typed audit-reference resolution and exact
  principal/customer/deployment/correlation/grant bindings;
- raw-assurance-claim non-elevation and exact assurance provenance;
- M2M regression and human-role non-crossover;
- `local_mock` denial;
- all 30 route mappings;
- foreign/malformed object and mixed batch-member denial; and
- identified metrics, artifact locator, document-stage, closed masked list/JSON/
  CSV projections, content-type/option validation, global identifier-log
  sanitization, masked-name, and correlation-header privacy boundaries.

No skipped test is reported as passed. CI green is not live validation.

## Rollout and rollback

### Rollout

1. Keep human runtime disabled.
2. Validate contracts, PDP, PEP, route inventory, current-state/audit adapters,
   response privacy, object regressions, and sensitive-operation negatives
   locally with synthetic adapters only.
3. Obtain exact-commit CI and independent security review.
4. Merge and verify `main` without enabling human runtime.
5. Complete GUG-94 lifecycle/bootstrap and install the reviewed authoritative
   state, typed audit-reference, and durable audit adapters; complete GUG-95
   UI/E2E and provider-backed phishing-resistant assurance.
6. Request separate authorization for non-production provider promotion and a
   two-deployment isolation proof.
7. Close GUG-117 only after all gate evidence exists.

### Rollback

- Restore or retain both `HUMAN_RUNTIME_ENABLED=false` at the identity adapter
  and `HUMAN_ENTERPRISE_AUTHORIZATION_ENABLED=false` at the ingest API; verify
  denial before changing code.
- Never remove the operation PEP while either human gate is active.
- If code rollback is required, use a targeted revert that preserves response
  projections, masked exports, content-type/option validation, and global
  identifier-log sanitization. Do not blanket-revert privacy hardening.
- Preserve GUG-102 M2M and GUG-114 object authorization.
- Do not infer legacy roles, extend snapshot age, bypass audit, migrate users,
  mutate data, deploy, redrive, or delete resources as rollback shortcuts.

## Evidence classification

| Evidence | Status at document authoring time |
|---|---|
| Implemented | Candidate branch `feat/gug-153-human-authorization-enforcement` |
| Locally validated | PASSED: focused 439; contract/storage 102; ingest API 641; repository 813; compileall; git-safety; security-check; microservices 7/7; preflight-m2 contracts 114/114; providers 11/11; preflight-m2b |
| CI validated | No |
| Live validated | No |
| Skipped | Wrong-digest fixture without schema mapping; replicated-data outside M2 scope. Neither is counted as passed. |
| Blocked | Runtime enablement, GUG-94/GUG-95, authorized isolation proof |
| Production | **NO-GO** |

Customer runtime enablement, AWS/Cognito mutation, Terraform apply, deployment,
data migration, queue redrive, production access, and merge are outside this
document and outside GUG-153's local implementation evidence.

## GUG-94 handoff status

ADR-026 now supplies the canonical membership record, lifecycle service ports,
reviewed DynamoDB/Cognito adapters, owner-bound indexes, conditional admin
guard, append-only lifecycle audit, and bootstrap recovery protocol. These are
locally validated candidate artifacts, not live runtime installation evidence.
`HUMAN_RUNTIME_ENABLED` and `HUMAN_ENTERPRISE_AUTHORIZATION_ENABLED` remain
false until separately authorized workload IAM/runtime composition, GUG-95,
and the two-deployment isolation proof are complete.
