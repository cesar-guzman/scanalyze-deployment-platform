# GUG-153 — Fail-Closed Human Authorization Enforcement

> **Sanitized NotebookLM source**
> **Canonical decision:** ADR-025
> **Related controls:** GUG-102, GUG-114, GUG-92, GUG-93, GUG-117
> **Evidence snapshot:** 2026-07-13 locally validated candidate
> **Live validation:** No
> **Production:** NO-GO

## Why this package exists

Authentication proves who presented a valid token. It does not prove that a
human's current enterprise role may execute one specific backend operation.

Earlier packages established complementary controls:

- GUG-102 binds a principal to an exact customer and deployment and enforces
  explicit M2M actions.
- GUG-114 binds documents, batches, members, and trusted artifact locators to
  the same customer/deployment tuple.
- GUG-92 defines the portable roles, actions, resources, data classes,
  temporary grants, lifecycle, and sensitive-operation policy.
- GUG-93 normalizes a reviewed membership into signed access-token claims while
  keeping human runtime disabled until downstream enforcement is ready.

GUG-153 closes the backend human gap with one typed policy decision point (PDP)
and one route policy enforcement point (PEP) for every protected API v1 route.
It does not deploy or enable humans in a live environment.

## Core rule

Every protected request is denied unless all applicable proofs succeed:

```text
valid access-token AuthContext
+ exact customer and deployment
+ one bounded signed human authorization path
+ exact current authoritative state/version proof at decision time
+ supported policy/catalog versions and digest
+ snapshot age no greater than 300 seconds
+ closed route operation
+ required OAuth scopes
+ permitted role/resource/action/data class
+ no explicit deny
+ proven sensitive step-up source/version/event when required
+ matching durable audit receipt before effect
+ exact GUG-114 object/member/locator ownership
= explicit allow
```

Missing, malformed, unknown, stale, future, foreign, conflicting, unsupported,
legacy-only, or unavailable evidence produces a denial. There is no default
role, route policy, tenant, deployment, object prefix, or admin fallback.

## Portable architecture

```text
Identity provider adapter
    -> verified access token
    -> immutable AuthContext
    -> typed OperationId PEP
    -> human PDP or separate M2M action path
    -> exact current-state resolver for human decisions
    -> trusted typed opaque audit-reference resolver
    -> sanitized decision plus durable receipt
    -> handler
    -> object/batch/member/trusted-locator authorization
    -> protected effect
```

The source contains no customer, deployment, account, region, pool, client,
user, email, bucket, or key instance. Each deployment supplies its exact
bindings through reviewed contracts. This makes the same implementation
replicable across customers and dedicated accounts without source forks.

## Bounded human membership snapshot

The ordinary human path consumes a pre-token snapshot created from the
authoritative membership. It contains:

- one signed subject, customer, and deployment;
- active membership state;
- one canonical role and membership version;
- supported authorization, role, and scope catalog versions;
- reviewed policy version and digest;
- issue time; and
- validated authentication time and assurance when the adapter established it.

The ingest API accepts the signed snapshot only for an inclusive maximum of 300
seconds. A future timestamp or an age of 301 seconds denies. Snapshot age alone
is not current authority: one centralized trusted runtime resolver must return
`authorization-authority-state.v1` at the exact decision second and match the
complete subject/customer/deployment/state/version/role or grant tuple. Missing,
cached, foreign, or conflicting evidence denies; handlers never perform their
own request-derived lookup.

Authentication time is required and cannot be later than the snapshot issue
time. Assurance may be absent for ordinary membership operations. The current
GUG-93 adapter does not promote configurable custom claims to assurance.
Sensitive human access needs the exact reviewed assurance source, version, and
opaque authentication-event reference; until that adapter exists, it denies.

## Human roles

The closed v1 role universe is:

- `customer_admin`: deployment-local cataloged administration; never an
  ownership or step-up bypass.
- `document_operator`: owned document/batch processing and approved aggregate
  metrics; no admin, export, full PII, or protected download.
- `document_reviewer`: owned metadata/masked review work; no ordinary mutation,
  admin, export, full PII, or protected download.
- `auditor`: aggregate metrics and approved audit metadata only.

OAuth scopes are necessary but not sufficient. Extra `read`, `write`, or
`admin` scopes cannot add a permission absent from the role. `admin` is not a
wildcard or a cross-deployment superuser.

## Temporary grants

Temporary grants are a mutually exclusive human path. They are accepted only
from the exact internal source
`authoritative_temporary_grant_store_v1` after it has been normalized into the
validated `AuthContext`.

A grant binds one subject, customer, deployment, type, state, version, immutable
issue time, expiry, operation allowlist, and data-class allowlist. Support is
limited to 3,600 seconds and break glass to 900 seconds. Request headers, payloads,
provider groups, and client metadata cannot create a grant. A grant never
inherits a role.

Support also requires an opaque case, an opaque purpose, and at least one
unique independent approval reference. Break glass instead requires an opaque
incident, an opaque purpose, and exactly two unique independent approval
references. Case and incident bindings are mutually exclusive, the grantee
cannot self-approve, and the exact complete reference set must match current
authoritative evidence at the decision second.

The sensitive operations `results.read_full`, `exports.execute`, and
`artifacts.download` always deny for temporary grants, even if a claimed
allowlist contains them. The GUG-153 exposure-specific artifact-list and
full-profile operations also deny temporary grants. The public lifecycle that
creates and revokes grants belongs to GUG-94 and is not enabled by this package.

Otherwise allowlisted support and break-glass operations still require exact
phishing-resistant assurance and authentication no more than 300 seconds old.

## M2M remains separate

M2M workloads retain the reviewed GUG-102 `granted_actions` path. They do not
receive a human role, temporary support access, or human step-up semantics.
Attaching human-looking fields to an M2M context cannot elevate it.

Every route therefore carries both:

- a typed operation mapping for the GUG-153 human PDP; and
- the unchanged GUG-102 M2M action requirement.

`local_mock` is test-only and is denied by the enterprise PDP unless a test
uses an explicit dependency override with a synthetic validated user context.

## Object authorization remains mandatory

A route-level allow answers whether the principal may attempt an operation. It
does not answer whether a document or batch belongs to that principal.

GUG-114 continues to require:

```text
object.customer_id == auth.customer_id
object.deployment_id == auth.deployment_id
```

Batch operations validate the batch and every member. One foreign, malformed,
or legacy member denies the complete list/export. Artifact access resolves a
trusted stored locator only after document authorization. A request-supplied
bucket, key, prefix, or URI is never authority.

## Sensitive and exposure-specific privileged operations

The canonical GUG-92 sensitive catalog remains full results, exports, and
protected downloads. GUG-153 additionally applies the same step-up gate to
artifact locator listings and full employee-profile reads because their current
responses contain locator material or full PII. All five require:

- membership path, not a temporary grant;
- the role's PII/content permission;
- both `read` and `admin` scopes;
- a signed snapshot no more than 300 seconds old plus exact current authority;
- exact `phishing_resistant_mfa` with reviewed provenance;
- authentication no more than 300 seconds old;
- a typed durable audit receipt bound to the decision before the effect; and
- exact object/member/locator authorization.

Authentication ages 299 and 300 seconds meet the boundary; 301 seconds does
not. Missing assurance is never inferred from provider configuration.
Temporary grants deny all five operations.

## Complete route inventory

The protected API v1 business inventory is exactly 30 routes. Public `/health`
and `/api/v1/health` liveness endpoints carry no customer data and are outside
the authorization catalog:

1. create document → `documents.create`
2. submit document → `documents.submit`
3. read document metadata → `documents.read_metadata`
4. read full document result → `results.read_full`
5. list document artifacts → `artifacts.list_metadata`
6. download document → `artifacts.download`
7. download selected artifact → `artifacts.download`
8. create batch → `batches.create`
9. read batch metadata → `batches.read_metadata`
10. list batch documents → `batches.read_metadata`
11. read batch manifest → `exports.execute`
12. batch JSON export → `exports.execute`
13. batch CSV export → `exports.execute`
14. batch ZIP export → `exports.execute`
15. analytics dashboard → `metrics.read_identified`
16. analytics overview → `metrics.read`
17. pages by user → `metrics.read_identified`
18. analytics by day → `metrics.read`
19. analytics by batch → `metrics.read`
20. analytics by document type → `metrics.read`
21. analytics costs → `metrics.read`
22. identity-document data export → `exports.execute`
23. employee-profile feature status → `deployment_configuration.read`
24. employee-profile batch export → `exports.execute`
25. generate employee profiles → `employee_profiles.generate`
26. read profile-generation job → `employee_profiles.read_job`
27. list masked profiles → `employee_profiles.list_masked`
28. export one profile as JSON → `exports.execute`
29. export one profile as CSV → `exports.execute`
30. read one full profile → `employee_profiles.read_full`

Tests fail if a protected route is added, removed, duplicated, or lacks exactly
one typed operation mapping. Operations are not inferred from HTTP methods.

## Exposure-specific controls

### Identified metrics

The current dashboard and pages-by-user responses contain person-level user
identifiers and display-derived values. The v1 metrics policy permits only
metadata and aggregates. `metrics.read_identified` is therefore denied to every
human role and temporary grant until a reviewed privacy-safe response or a new
policy version exists.

### Artifact locator listing

The current artifact-list response exposes internal locator details.
`artifacts.list_metadata` is therefore limited to a customer-administrator
membership with `read` + `admin`, documents/content permission, current
phishing-resistant step-up, audit, and exact document ownership. Other human
roles and temporary grants deny. M2M preserves its reviewed GUG-102 `read`
action. Protected downloads remain a separate sensitive operation using trusted
stored locators.

An opaque alias-only response may support a lower-privilege policy only after a
separate API and policy review.

### Weaker response paths

Document metadata projects stage records through a strict status/time/counter
allowlist and excludes all artifact, queue, payload, digest, and free-form error
fields. Uploader subject and stored correlation response fields remain null-only
for compatibility. The masked employee-profile list returns `[REDACTED]` for
`fullName` and rejects name search without evaluating a match. Full identity
remains on the separately authorized full-profile/export paths.

Batch metadata responses keep stable creator identity null and return an empty
compatibility metadata object because legacy free-form values lack a reviewed
data-class schema. Profile-job status uses a closed identity/status/count/
timestamp projection and drops creator identity, fingerprints, raw errors,
profile IDs, ownership internals, and unknown future fields.

Masked profile lists, JSON exports, and CSV exports all rebuild output through
one closed projection. Stored masks and unknown future fields are ignored;
supported scalar identifiers are deterministically remasked. Document creation
accepts only PDF, JPEG, PNG, or TIFF MIME values; poisoned legacy values become
`Unknown` before public metadata, batch-document listings, or aggregates.
Profile generation accepts only the boolean options `force` and
`includeIncomplete` and rejects every unknown, nested, or non-boolean option
before lookup, logging, or effect. All CSV paths share a formula-cell
neutralizer that detects `=`, `+`, `-`, or `@` after leading whitespace/control
characters before standard CSV quoting. Human tokens with any noncanonical
identity alias, including matching or conflicting `custom:` variants, deny.

## Audit and privacy

An explicit human allow is audited before the protected effect. The sink must
return `authorization-audit-receipt.v1` from the reviewed durable sink,
version `1.0.0`, bound to the exact decision id. Logging-only, missing,
malformed, mismatched, or failed acknowledgement denies. Audit and logs contain
closed reason categories, operation/resource classifications, policy version,
and opaque references.

Before the allow event, the trusted `authorization-audit-references.v1`
resolver must return stable opaque references bound to the exact validated
principal, customer, deployment, and current correlation. Temporary-grant
events additionally require the exact opaque grant reference and carry only
their current-matched opaque case/incident, purpose, and approval references;
membership events reject a grant reference.

Every allow event validates against one and only one authority branch:
membership, support, break-glass, or M2M. Early denials can omit provenance not
yet established, but missing or conflicting provenance can never validate an
allow.

They do not contain tokens, cookies, raw claims, names, emails, request bodies,
document/profile contents, bank or government data, S3 buckets/keys/prefixes,
artifact locators, presigned URLs, credentials, or raw dependency exceptions.
External request/correlation/trace values are SHA-256-derived into fixed opaque
references before logging or response propagation; raw header text is never
bound. Logs use code-owned route templates rather than dynamic paths, never bind
the human subject, and record a pipeline stage only after canonical validation.
The global structured-log sanitizer pseudonymizes known customer, deployment,
tenant, document, batch, profile, job, uploader, and user identifier fields in
both context-bound and directly supplied structured events.

## Rollout sequence

1. Keep `HUMAN_RUNTIME_ENABLED=false` and
   `HUMAN_ENTERPRISE_AUTHORIZATION_ENABLED=false`.
2. Implement and locally validate the typed snapshot, current-state/audit
   runtime ports, PDP, route PEP, contracts, response privacy, complete route
   inventory, audit failure behavior, and negative tests.
3. Preserve and rerun GUG-102 M2M and GUG-114 ownership regressions.
4. Obtain green CI and independent security review for the exact commit.
5. Merge and verify `main` without enabling human runtime.
6. Complete GUG-94 lifecycle/bootstrap plus current-state, typed
   audit-reference, and durable-audit adapters, and GUG-95 UI/E2E plus
   provider-backed phishing-resistant assurance.
7. Under separate authorization, validate non-production behavior and prove
   isolation between two deployments.
8. Close GUG-117 only after every required evidence class is present.

## Rollback

First retain or restore `HUMAN_RUNTIME_ENABLED=false` and
`HUMAN_ENTERPRISE_AUTHORIZATION_ENABLED=false`, then verify denial. Never remove
the operation PEP while either gate is active. If code rollback is still
required, use a targeted revert that preserves response/masked-export privacy,
MIME/option validation, global identifier-log sanitization, GUG-102 M2M, and
GUG-114 object authorization. A blanket privacy regression is not rollback.
Rollback never means accepting stale snapshots, assigning a default role,
skipping audit, inferring a legacy tenant, migrating users, changing cloud
resources, redriving queues, deploying, or deleting data.

## Evidence boundary

At authoring time:

- **Implemented:** candidate branch
  `feat/gug-153-human-authorization-enforcement`.
- **Locally validated:** PASSED: 439 focused PDP/PEP/privacy/object tests, 102
  contract/storage tests, 641 ingest API tests, 813 repository tests,
  compileall, git-safety, security-check, 7/7 microservices, preflight-m2
  114/114, provider-check 11/11, and preflight-m2b.
- **Skipped:** the unmatched wrong-digest fixture and replicated-data outside
  M2 scope; neither is represented as passed.
- **CI validated:** no.
- **Live validated:** no.
- **Blocked:** human enablement, GUG-94/GUG-95, provider promotion, and the
  authorized two-deployment proof.
- **Production:** **NO-GO**.

No live customer, token, identifier, document, credential, provider resource,
bucket, key, log, or audit record is included in this source.
