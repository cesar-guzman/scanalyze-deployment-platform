# ADR-025: Fail-Closed Human Authorization Enforcement

- **Status:** Proposed; accepted only after reviewed merge and main verification
- **Date:** 2026-07-13
- **Evidence snapshot:** 2026-07-13 locally validated candidate state
- **Scope:** GUG-153 backend human PDP/PEP enforcement
- **Phase gate:** GUG-117
- **Upstream decisions:** ADR-020, ADR-021, ADR-023, ADR-024
- **Downstream consumers:** GUG-94 lifecycle APIs, GUG-95 console/E2E, and the
  authorized two-deployment isolation proof
- **Live enablement:** Blocked pending reviewed integration, non-production
  authorization, lifecycle readiness, and isolation evidence

Production: **NO-GO**

## Context

GUG-102 established a deployment/customer-bound `AuthContext` and explicit M2M
action checks. GUG-114 independently established exact object ownership for
documents, batches, their membership, and trusted artifact locators. GUG-92
then defined the portable enterprise role, action, resource, data-class,
lifecycle, temporary-grant, and sensitive-operation policy. GUG-93 created the
provider adapter and a pre-token boundary that can issue a versioned human
authorization snapshot from an authoritative membership.

Those controls do not by themselves enforce a human role at every backend
route. The pre-GUG-153 route dependency deliberately applies logical actions
only to M2M principals. Enabling human requests without a separate policy
decision would therefore authenticate a user without proving that the user's
role may execute the requested operation.

The solution must remain portable for every customer, deployment, AWS account,
region, and reviewed identity provider. Request headers, route values, query
parameters, payloads, provider group names, email domains, account IDs, object
keys, and legacy tenant aliases cannot establish authority.

## Security objectives

1. Deny every protected human request unless a closed operation policy produces
   an explicit allow.
2. Consume only the immutable, validated internal `AuthContext`; handlers never
   parse authorization claims or infer a role.
3. Bind every decision to the exact signed subject, customer, deployment,
   catalog versions, policy version, policy digest, and authorization path.
4. Bound the signed pre-token snapshot to at most 300 seconds and independently
   require an exact current-state/version proof from the authoritative
   membership or grant adapter for every human decision.
5. Preserve GUG-102 M2M action authorization as an independent path.
6. Preserve GUG-114 object ownership as a mandatory check after route policy
   authorization and before every protected effect.
7. Require current phishing-resistant step-up and durable sanitized audit for
   the canonical sensitive catalog and GUG-153 exposure-specific privileged
   locator/full-profile operations.
8. Make an unregistered route, operation, role, version, digest, assurance,
   path, or dependency failure a denial.

## Decision

### 1. Use one typed PDP and one closed route PEP

The ingest API owns one provider-neutral policy decision point exposed through
the typed `authorize_operation` function. FastAPI routes use a single
`require_operation(OperationId)` policy enforcement dependency. The operation
registry is closed; free-form strings, wildcards, missing mappings, and default
HTTP-method inference are invalid.

The protected request flow is:

```text
verified access token
  -> immutable AuthContext
  -> exact route OperationId PEP
  -> principal-path dispatch
       user -> enterprise human PDP
       m2m  -> GUG-102 granted actions
       other -> deny
  -> exact current authority-state resolver
  -> trusted typed pseudonymous audit-reference resolver
  -> durable sanitized authorization audit receipt
  -> service handler
  -> GUG-114 object/batch/member authorization
  -> protected read, write, export, or artifact effect
```

An explicit route allow is necessary but not sufficient for object access. A
role never overrides `customer_id`, `deployment_id`, object ownership, batch
membership, stored artifact metadata, or storage-boundary conditions.

### 2. Consume a bounded snapshot plus current authoritative state

The human `AuthContext` carries one immutable `HumanAuthorizationSnapshot`.
For the normal membership path, the snapshot is produced by the reviewed
pre-token adapter from the authoritative membership and is marked
`pre_token_membership_v1`. The snapshot alone is never current authority.

Every human PEP also requires an immutable `EnterpriseAuthorizationRuntime`
installed in application state by trusted startup code. Its resolver receives
the already validated snapshot and closed operation; it never receives a
request-supplied customer, deployment, subject, object id, prefix, or role. It
must return `authorization-authority-state.v1` evidence observed at the exact
decision second from `authoritative_membership_store_v1` or
`authoritative_temporary_grant_store_v1`. Missing runtime, resolver failure,
older/cached evidence, foreign bindings, version/state/role drift, or partial
evidence denies. GUG-153 defines this portable port but introduces no IAM,
Terraform, table, or live provider mutation; GUG-94 owns its reviewed adapter.

The runtime also contains a typed `authorization-audit-references.v1` resolver
and the durable audit sink. The reference resolver receives only the validated
`AuthContext`, closed operation, and current opaque correlation reference. It
must return stable opaque bindings for the exact principal, customer,
deployment, and correlation, plus the exact grant reference only for the
temporary-grant path. Missing, malformed, mismatched, path-conflicting, or raw
identity values deny before an allow event is accepted.

The membership snapshot contains, at minimum:

- exact `human-authorization-context.v1` envelope version;
- exact subject, customer, and deployment bindings;
- authorization path and trusted internal source;
- active membership state, one closed role, and membership version;
- authorization, scope, and role catalog versions;
- policy version and canonical policy digest;
- issue time; and
- provider-validated authentication time and, where established, assurance.

The PDP accepts the signed snapshot only when:

```text
0 <= now_epoch - issued_at_epoch <= 300
```

A missing issue time, a future issue time, an age of 301 seconds, a malformed
binding, an inactive membership, an unknown role, a missing or conflicting
field, an unsupported version, or a non-matching digest denies. Digest
comparison is constant-time. There is no stale-token grace period, cached role,
legacy membership inference, or fallback to provider groups.

It then requires current authoritative evidence with exact equality for subject,
customer, deployment, active state, membership version, and role at the
decision time. A 300-second-old signed token with a different current version
is denied.

Authentication time must be present, valid, and no later than the snapshot issue
time for every human snapshot. Assurance may be absent for an ordinary
membership operation. The current GUG-93 adapter deliberately does not promote
any configurable custom claim to phishing-resistant assurance. Sensitive human
operations therefore remain denied until a reviewed provider adapter can
populate `authoritative_authentication_event_v1`,
`phishing-resistant-mfa.v1`, and an opaque authentication-event reference. The
snapshot-age, current-state, and sensitive authentication-age checks are
independent and all must pass where applicable.

### 3. Keep authorization paths mutually exclusive

A human snapshot selects exactly one path:

- `membership`: active membership, exactly one canonical role, and no temporary
  grant fields; or
- `temporary_grant`: no role or membership version, and one active, unexpired,
  versioned internal grant.

Temporary grants are accepted only when their internal source is exactly
`authoritative_temporary_grant_store_v1`. A header, query, payload, provider
claim outside the validated adapter, or a source label supplied by a client is
not trusted. The grant must bind the exact subject/customer/deployment, allowed
operation IDs, allowed data classes, state, version, immutable issue time, and
expiry. Support lifetime may not exceed 3,600 seconds; break-glass lifetime may
not exceed 900 seconds. The current resolver must reproduce the complete grant
record at the exact decision time. An operation
not present in the closed GUG-92 temporary-grant catalog denies.

A support grant additionally requires an opaque case reference, an opaque
purpose reference, and at least one unique independent approval reference. A
break-glass grant instead requires an opaque incident reference, an opaque
purpose reference, and exactly two unique independent approval references.
Case and incident paths are mutually exclusive, and an approval reference that
matches the grantee's opaque subject reference is rejected as self-approval.
The exact case/incident, purpose, and approval set is part of the current-state
equality proof; stale or changed approval evidence denies.

Temporary grants never authorize `results.read_full`, `exports.execute`, or
`artifacts.download`, even if a malformed grant claims those operations. A
snapshot containing both a role and temporary grant, or neither path, denies.
An ordinary temporary grant also requires the phishing-resistant assurance and
authentication-age controls defined for support/break-glass access.
The exposure-specific `artifacts.list_metadata` and
`employee_profiles.read_full` operations also deny temporary grants.

### 4. Enforce roles, scopes, resources, and data classes together

The role catalog remains exactly:

- `customer_admin`
- `document_operator`
- `document_reviewer`
- `auditor`

The action catalog remains exactly `read`, `write`, and `admin`, paired with the
versioned OAuth scopes in ADR-023. A required scope is necessary but never
sufficient. Extra scopes and the M2M `granted_actions` field cannot elevate a
human role. `admin` is an explicitly cataloged action, not a wildcard or
cross-deployment superuser.

Every `OperationId` binds required actions, resources, data classes, sensitive-
operation controls, temporary-grant eligibility, and the legacy GUG-102 M2M
action set. Missing registry data denies at startup or at the PEP; it is never
derived from the HTTP verb.

### 5. Preserve M2M without human-role crossover

M2M principals continue to use the exact GUG-102 `granted_actions` contract.
They do not acquire a human role, membership path, temporary support grant, or
human step-up semantics. A human snapshot attached to an M2M context cannot
elevate its explicit workload actions. Conversely, human scopes do not become
M2M granted actions.

The existing route action dependencies remain present as a regression contract
while the operation dependency adds the human PDP. The reviewed M2M action set
for every operation is documented in the deployment reference.

`local_mock` is test-only and receives no implicit administrator role. Tests
that need a human principal must provide an explicit synthetic validated
snapshot through dependency overrides.

### 6. Preserve object and membership authorization

After a route PEP allows a request, GUG-114 still requires exact object equality:

```text
object.customer_id == auth.customer_id
object.deployment_id == auth.deployment_id
```

Batch access validates the batch and every referenced document. Exports are
all-or-nothing. Artifact access uses the trusted stored locator after document
authorization; request-supplied buckets, keys, prefixes, aliases, or URIs never
establish authority. Absent and foreign objects retain enumeration-safe public
behavior.

### 7. Treat sensitive and exposure-specific privileged operations separately

The canonical GUG-92 sensitive-operation catalog is exactly:

- `results.read_full`
- `exports.execute`
- `artifacts.download`

For a human membership they require all of the following:

- the role permits the relevant resource and PII/content data class;
- both `read` and `admin` scopes are present;
- the signed snapshot passes its 300-second bound and the resolver proves the
  exact current membership state/version at decision time;
- assurance is exactly `phishing_resistant_mfa` with the reviewed source,
  version, and authentication-event reference;
- authentication time is present, not future, and at most 300 seconds old;
- GUG-114 authorizes every object/member/locator; and
- the sanitized audit event receives a matching durable receipt before the
  protected effect.

The 300-second authentication-age boundary is inclusive: 299 and 300 seconds
are eligible; 301 seconds denies. A customer administrator without valid
step-up is denied. Temporary grants always deny these operations.

GUG-153 applies the same membership-only `read` + `admin`, current-state,
phishing-resistant step-up, audit, and object-ownership controls to two
additional exposure-specific operations without changing the GUG-92 catalog:

- `artifacts.list_metadata`, because the current response contains locator
  material; and
- `employee_profiles.read_full`, because the response contains full PII.

Temporary grants also deny both exposure-specific privileged operations.

### 8. Add exposure-specific identified-metrics and locator controls

Exposure-specific controls prevent weaker endpoints from bypassing the reviewed
operation policy:

1. `metrics.read_identified` includes user identifiers and display-name/email
   derived values. The v1 metrics policy permits only metadata and aggregated
   data. Human access is explicitly denied until a separately reviewed response
   contract removes or properly classifies those identifiers.
2. `artifacts.list_metadata` currently exposes stored locator details. It is
   therefore a privileged customer-administrator operation requiring
   `read` + `admin`, the documents/content permission, phishing-resistant
   step-up, current snapshot/authentication time, audit, and exact document
   ownership. Other roles and temporary grants deny. M2M retains its reviewed
   GUG-102 `read` action.
3. `documents.read_metadata` projects stored stage records through a strict
   allowlist of state, timestamp, and bounded counter fields. It never returns
   buckets, keys, prefixes, locators, digests, queue URLs, message IDs, payloads,
   free-form error content, uploader subject identifiers, or stored correlation
   values. Legacy response fields remain null-only for compatibility.
4. `employee_profiles.list_masked` returns a fixed redacted name marker and
   rejects name-search input. Full identity remains available only through the
   separately authorized full-profile operation.
5. `batches.read_metadata` returns a closed status envelope. Stable creator
   identity is null-only and arbitrary stored metadata is represented by an
   empty compatibility object until a versioned safe metadata schema exists.
6. `employee_profiles.read_job` uses a closed status/count/timestamp projection
   and excludes creator identity, source fingerprints, raw errors, profile IDs,
   ownership fields, and unknown future fields.
7. Every masked employee-profile list, JSON export, and CSV export is rebuilt
   from one closed `project_masked_profile` projection. Stored masks and unknown
   fields are ignored; canonical scalar identifiers are deterministically
   remasked and identity fields outside the projection remain absent or empty.
8. Document creation accepts only the reviewed MIME catalog
   (`application/pdf`, `image/jpeg`, `image/png`, `image/tiff`). Stored legacy or
   poisoned content types normalize to `Unknown` before metadata or aggregate
   responses and never become a new analytics dimension verbatim.
9. Employee-profile generation accepts only the closed boolean options `force`
   and `includeIncomplete`. Unknown, nested, or non-boolean options deny before
   storage access, logging, or generation behavior.
10. Every CSV writer neutralizes spreadsheet formula prefixes (`=`, `+`, `-`,
    `@`) even after leading whitespace or control characters, while retaining
    standard CSV quoting. Stored or extracted strings never become active
    spreadsheet expressions on export.
11. Human tokens carrying any legacy customer/deployment alias, including
    prefixed `custom:` variants, deny even when the alias matches the canonical
    value. Only the two exact canonical claims may bind identity.

These are explicit operation decisions, not post-fetch filtering or accidental
omissions. Protected downloads remain available only through
`artifacts.download` after the full sensitive and object checks.

### 9. Require a durable audit receipt before allow

An allow decision emits one sanitized, versioned authorization decision event
before the protected handler effect. Human authorization requires a typed
`authorization-audit-receipt.v1` acknowledgement from
`durable_authorization_audit_sink_v1`, version `1.0.0`, bound to the exact
decision id and an opaque receipt reference. A plain `logger.info`, filtered
stdout, missing sink, `None`, malformed receipt, mismatched decision, or sink
exception is not acceptance and produces a generic denial. A denial remains
denied if its diagnostic audit cannot be persisted; it must never retry by
executing the protected operation. Existing GUG-102 M2M semantics remain
separate and unchanged.

Events use closed reason codes and opaque correlation references. They exclude
JWTs, raw claims, emails, names, request bodies, document contents, PII, S3
buckets/keys/prefixes, presigned URLs, credentials, and dependency exception
messages.

Before an allow event is emitted, the trusted
`authorization-audit-references.v1` resolver must produce the exact opaque
principal/customer/deployment/correlation bindings for the validated request
and, for a temporary grant, its opaque grant binding. Membership events reject
a grant reference. Temporary-grant events also carry only the validated opaque
case or incident, purpose, and approval references whose exact set matched
current authoritative evidence.

The closed decision schema requires every `allow` to select exactly one
provenance branch: membership, support grant, break-glass grant, or M2M
binding. Conflicting branch evidence is invalid. Early `deny` events may omit
authority fields that were unavailable at the point of rejection and never
fabricate provenance.

Inbound request, trace, and correlation headers are never echoed or bound raw.
When present, they are reduced to fixed-format SHA-256-derived opaque
references; when absent, a fresh opaque reference is generated.
Human subjects and request-supplied stage confirmations are never bound to the
logging context. Only the code-owned canonical stage is bound after validation.
The global structured-log processor pseudonymizes known customer, deployment,
tenant, document, batch, profile, job, uploader, and user identifier keys even
when a caller supplies them directly instead of using the context helper.

## Closed operation inventory

The protected API v1 business surface contains exactly 30 routes mapped to 16
operation IDs. The public `/health` and `/api/v1/health` liveness endpoints
carry no customer data and are explicitly outside this authorization catalog.
The normative route-by-route inventory is maintained in
`docs/deployment/human-authorization-enforcement.md`. CI must fail if a route is
added, removed, duplicated, or left without exactly one typed operation PEP.

The closed operation IDs are:

```text
documents.create
documents.submit
documents.read_metadata
results.read_full
artifacts.list_metadata
artifacts.download
batches.create
batches.read_metadata
exports.execute
metrics.read_identified
metrics.read
deployment_configuration.read
employee_profiles.generate
employee_profiles.read_job
employee_profiles.list_masked
employee_profiles.read_full
```

## Alternatives considered

### Authorize humans with OAuth scopes only

Rejected. Scopes express requested API capability but do not establish one
current role, membership state, data-class permission, or explicit deny.

### Use Cognito groups as runtime roles

Rejected. Provider groups are adapter metadata, can drift independently, and
make the policy provider- and deployment-specific.

### Query a membership store from each handler

Rejected. It duplicates policy, creates inconsistent failure semantics, and
permits request identifiers to influence lookups. One central runtime port at
the PEP/PDP boundary performs the current-state proof from the already validated
snapshot. Its concrete store and IAM adapter belong to GUG-94.

### Let `customer_admin` bypass ownership or step-up

Rejected. It creates a cross-deployment and full-PII superuser path contrary to
ADR-021 and ADR-023.

### Filter identified metrics or foreign objects after retrieval

Rejected. Authorization must occur at the policy/storage boundary; post-fetch
filtering is not a primary security control.

## Consequences

### Positive

- One reviewable policy path covers every human backend route.
- The route inventory is statically testable and fails closed on drift.
- Provider, customer, account, and region details remain outside policy source.
- M2M and object authorization retain their reviewed independent controls.
- Sensitive reads have explicit assurance, freshness, audit, and locator gates.

### Costs and limitations

- Human tokens older than 300 seconds require refresh, while every request also
  needs a current authoritative state result and durable audit acknowledgement.
- Sensitive operations may require an additional user authentication ceremony.
- Human requests deny until GUG-94 installs the authoritative-state and durable
  audit adapters; the current provider adapter establishes no
  phishing-resistant assurance.
- Identified metrics remain unavailable to humans; artifact locator listings
  remain restricted to a stepped-up customer administrator until their response
  contracts are hardened.
- GUG-153 does not implement user lifecycle, bootstrap, provider promotion,
  deployment, migration, or live isolation evidence.

## Rollout

1. Keep both human runtime gates disabled for customer deployments.
2. Land the typed snapshot parser, PDP, operation registry, PEP markers,
   sanitized decision contract, and negative tests.
3. Validate the exact 30-route inventory and preserve GUG-102/GUG-114 suites.
4. Obtain independent security review and green CI for the exact commit.
5. Merge and verify `main`; do not enable human runtime as part of the merge.
6. Complete GUG-94 lifecycle/bootstrap and GUG-95 UI/E2E dependencies.
7. Under separate authorization, validate in non-production and prove isolation
   between two deployments before GUG-117 can close.

## Rollback

The immediate rollback is to keep or restore both human gates to false:
`HUMAN_RUNTIME_ENABLED=false` at the identity adapter and
`HUMAN_ENTERPRISE_AUTHORIZATION_ENABLED=false` at the ingest API. Verify denial
before any code rollback. The operation PEP must never be removed while either
human gate is active.

If code rollback remains necessary, use a targeted revert that preserves the
response projections, content-type/option validation, identifier-log
sanitization, GUG-102 M2M, and GUG-114 object authorization. A blanket revert
that re-exposes metadata, PII, locators, or raw identifiers is not an acceptable
rollback. Rollback does not loosen policy, infer legacy roles, accept stale
snapshots, alter data, migrate identities, delete resources, or redrive queues.

## Evidence classification

| Class | GUG-153 status at ADR authoring time |
|---|---|
| Implemented | Candidate branch `feat/gug-153-human-authorization-enforcement` |
| Locally validated | PASSED: 439 focused PDP/PEP/privacy/object tests; 102 contract/storage tests; 641 ingest API tests; 813 repository tests; compileall; git-safety; security-check; 7/7 microservices; preflight-m2 with 114/114 contract scenarios; provider-check 11/11; preflight-m2b |
| CI validated | Not established |
| Live validated | No |
| Skipped | Reviewed preflight exclusions: unmatched wrong-digest fixture and replicated-data outside M2 scope; neither is reported as passed |
| Blocked | Human enablement, lifecycle/provider promotion, and isolation proof |
| Production | **NO-GO** |

Documentation and local tests are not deployment evidence. Only exact-commit
CI, reviewed merge, main verification, explicitly authorized non-production
execution, and separately reviewed live evidence may advance those classes.

### GUG-94 integration note

ADR-026 implements the provider-neutral lifecycle runtime, canonical
membership adapter, owner-bound queries, conditional mutations, durable
lifecycle audit, and recoverable bootstrap expected by this decision. It does
not by itself install the GUG-153 authoritative-state/audit runtime or enable
either human gate in a deployment. The remaining live boundary is explicit
workload IAM/runtime composition, provider-backed assurance, GUG-95 E2E, and
the authorized two-deployment isolation proof.
