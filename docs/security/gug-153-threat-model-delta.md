# GUG-153 Human Authorization Threat-Model Delta

- **Scope:** Human PDP/PEP enforcement for the 30 protected ingest API v1 routes
- **Base decisions:** ADR-020, ADR-021, ADR-023, ADR-024
- **Decision introduced by this delta:** ADR-025
- **Baseline reviewed:** `477965ae7d77fe93bb257df3cb2d40cfbc3f81b8`
- **Evidence snapshot:** 2026-07-13 locally validated candidate
- **Live validation:** No
- **Production:** NO-GO

## Overview

Scanalyze processes customer documents and derived financial, bank,
government, employee-profile, and identity data. GUG-153 adds the backend human
authorization boundary between a validated access-token identity and each
protected route. The delta does not replace authentication, M2M workload
authorization, object ownership, storage isolation, provider lifecycle, or
deployment controls.

The assets protected by this change are:

- exact customer and deployment isolation;
- document, batch, employee-profile, result, export, metric, and artifact
  confidentiality;
- document/batch/profile mutation integrity;
- role and membership integrity;
- authorization policy/version integrity;
- phishing-resistant step-up state;
- audit completeness without sensitive-data disclosure; and
- availability that fails closed rather than silently authorizing on a
  dependency failure.

The highest-impact failure is a validly authenticated human reaching a foreign
deployment, full PII, export, or protected artifact without the exact current
role, scopes, object ownership, assurance, and audit evidence.

## Threat Model, Trust Boundaries, and Assumptions

### Actors

| Actor | Legitimate capability | Security boundary |
|---|---|---|
| Enterprise user | Operations granted by one active membership | Cannot select role, customer, deployment, snapshot source, assurance, or ownership |
| Customer administrator | Explicit deployment-local administrative operations | Not a platform superuser; cannot bypass ownership or step-up |
| Document operator/reviewer/auditor | Closed role duties | No permission aggregation, standing admin, or implicit sensitive access |
| Temporary support/emergency user | Exact internal grant allowlist | No standing role and no sensitive operations |
| M2M workload | GUG-102 explicit actions | No human role, support grant, or human assurance crossover |
| Identity provider adapter | Authentication and signed claim normalization | Provider groups and display attributes are not policy authority |
| Malicious or compromised client | Controls HTTP inputs and referenced IDs | No request field establishes identity or object authority |
| Developer/operator | Changes route registry, policy/configuration, or rollout state | Changes require review, tests, CI, and separate live authorization |

### Trust boundaries

#### 1. Provider token to validated AuthContext

The token verifier must establish issuer, audience/client, signature,
algorithm, expiry, token type, exact customer/deployment, subject, and
principal type before GUG-153 runs. Human authorization consumes only the
internal immutable snapshot. ID tokens, unsigned metadata, headers, cookies,
provider groups, and request claims are outside the trusted boundary.

#### 2. Pre-token membership to bounded snapshot

The membership source is trusted only through the reviewed GUG-93 pre-token
adapter. The runtime snapshot is bound to all canonical versions and is usable
for at most 300 seconds. The ingest API does not infer an updated role after
issuance or accept a stale/future snapshot.

Temporary grants cross this boundary only through the exact internal source
`authoritative_temporary_grant_store_v1`. No external request format creates a
temporary grant.

#### 3. Route to closed operation policy

Every protected route must carry exactly one typed `OperationId`. A route path,
HTTP verb, function name, or caller-selected operation cannot create a default
policy. Adding or changing a route breaks the closed 30-route inventory until a
reviewed mapping exists.

#### 4. PDP decision to PEP and audit

The PEP continues only after an explicit allow, successful typed
`authorization-audit-references.v1` resolution, and successful required audit.
The trusted resolver binds opaque principal, customer, deployment, and current
correlation references, plus a grant reference only for the temporary path.
Exceptions, timeouts, malformed or mismatched references/events, unknown
operations, and missing registry data deny. Handlers cannot call a permissive
fallback dependency.

#### 5. Route authorization to object/storage authorization

A role-level allow does not establish ownership. GUG-114 independently checks
the exact customer/deployment on the document, batch, every member, employee
profile, and trusted artifact locator. Storage/query boundaries must avoid
cross-deployment retrieval; post-fetch filtering is not a substitute.

#### 6. Stored artifact metadata to presigned access

The requester controls the document/artifact identifiers but never the bucket,
key, prefix, URI, or presigned URL. A trusted stored locator is resolved and
validated only after route, step-up, and object authorization.

### Assumptions

- GUG-102 token verification and M2M bindings remain intact.
- GUG-114 exact object ownership and enumeration-safe errors remain intact.
- The canonical GUG-92 policy and configured digest are reviewed artifacts.
- Server time used for freshness is monotonic enough for the 300-second bound;
  material clock failures deny rather than widen freshness.
- Provider assurance is trusted only after adapter validation. A configured MFA
  policy alone is not proof of the current authentication method.
- Human runtime remains disabled until exact-commit review, downstream
  lifecycle readiness, and authorized isolation evidence exist.

### Attacker-controlled inputs

- document, batch, profile, job, and artifact identifiers;
- route, method, headers, cookies, query parameters, and payload fields;
- legacy tenant/deployment aliases and identity-looking headers;
- valid tokens with extra scopes, stale claims, foreign bindings, unexpected
  roles, or conflicting path data;
- operation-like strings in request data;
- file/document content processed after authorization; and
- repeated or concurrent requests intended to exploit stale membership or
  audit failure.

### Operator- and developer-controlled inputs

- expected policy/catalog versions and canonical digest;
- human runtime gates and provider adapter configuration;
- operation registry and route dependency wiring;
- assurance claim mapping and clock configuration; and
- code, tests, CI, and deployment promotion.

These inputs are privileged configuration, not request authority. Misconfiguration
must fail closed and is not corrected by accepting legacy/default values.

## Attack Surface, Mitigations, and Attacker Stories

| Threat / attacker story | Potential impact | Required mitigation and verification |
|---|---|---|
| A valid user adds `admin` scope or a provider group and calls an export | Full PII disclosure | Scope necessary but insufficient; role/resource/data class required; provider groups ignored; negative role/scope tests |
| A suspended user's old token is replayed | Continued access after revocation | Signed snapshot bounded to 300 seconds plus exact current authoritative state/version/role proof at each decision; missing or older evidence denies |
| A client supplies another deployment in a header, payload, or path | Cross-deployment access | Signed AuthContext binding only; conflicting legacy fields deny; GUG-114 object equality |
| A developer adds a route with a generic read dependency | Unreviewed authorization bypass | Closed 30-route inventory; exactly one typed operation PEP and one preserved M2M action dependency |
| A human snapshot contains both a role and support grant | Permission union/elevation | Exactly one authorization path; conflicting fields deny |
| A request labels itself as a temporary support grant | Standing or forged support access | Accept only `authoritative_temporary_grant_store_v1` inside validated AuthContext; request data ignored |
| A grantee self-approves support or supplies incomplete break-glass evidence | Unauthorized privileged support path | Support requires case+purpose+at least one unique independent approval; break glass requires incident+purpose+exactly two unique independent approvals; exact reference set must match current authority |
| A temporary grant lists export/download/full-result operations | Sensitive data disclosure | Global sensitive-operation deny takes precedence over grant allowlist |
| A customer administrator calls a sensitive route without recent MFA | Full PII/artifact disclosure | `read+admin`, exact phishing-resistant assurance, auth age `0..300`, audit, object authorization |
| An audit sink is unavailable or stdout is dropped | Unrecorded privileged effect | Human allow requires a typed durable receipt bound to the exact decision id; logger return/`None`/mismatch/failure denies before effect |
| A valid role references a foreign object ID | BOLA/IDOR | GUG-114 exact object and batch-member authorization after the route PEP; enumeration-safe response |
| An authorized batch contains one foreign document | Cross-deployment export contamination | Validate batch and every member; all-or-nothing denial |
| Dashboard/read-by-user is treated as aggregate metrics | Identified user disclosure | `metrics.read_identified` explicit human deny until a reviewed privacy-safe contract exists |
| Artifact list is treated as harmless metadata | Bucket/key/prefix disclosure and targeting | Customer-admin membership only; `read+admin`, content permission, step-up, audit, and owned document; other human roles/grants deny |
| Document status returns stored stages or identity/correlation fields verbatim | Artifact/queue locator or stable-identifier disclosure through weaker metadata policy | Strict allowlist projects only closed status, timestamp, and bounded counter fields; uploader and stored correlation fields are null-only |
| Batch metadata returns creator identity or arbitrary legacy payloads | Same-deployment PII/locator disclosure through a metadata-only policy | Closed response envelope; creator is null-only and unclassified metadata is an empty compatibility object |
| Profile-job status returns the complete stored job | Creator, fingerprint, raw-error, ownership, or future-field disclosure | Closed job identity/status/count/timestamp projection; unknown and identifying fields are dropped |
| Masked employee list returns or searches exact names | Same-deployment PII enumeration | Fixed name redaction; name search rejected without evaluation; full identity requires full-profile policy |
| Poisoned stored masks, unknown profile fields, or a weaker masked export path return PII | Same-deployment PII disclosure | One closed projection rebuilds masked list, JSON, and CSV output from reviewed scalar fields and deterministically remasks identifiers |
| Request or legacy metadata supplies an arbitrary document content type | PII in aggregates, unsafe upload handling, or unbounded dimensions | Closed four-value MIME catalog for writes; unreviewed stored values normalize to `Unknown` before responses/aggregation |
| Generation options contain unknown, nested, or non-boolean controls | Hidden behavior, log injection, or unreviewed storage access | Closed `force`/`includeIncomplete` boolean contract validated before lookup, logging, or effect |
| Stored or extracted text begins a spreadsheet formula, including after whitespace/control characters | Formula execution when an administrator opens an authorized CSV | One central cell neutralizer covers profile, batch stream, batch ZIP, analytics, and masked CSV writers before standard CSV quoting |
| A token adds a matching or conflicting legacy identity alias, including `custom:` variants | Ambiguous customer/deployment authority or parser differential | Reject every noncanonical identity alias; only exact canonical customer and deployment claim names are accepted |
| A configurable custom claim asserts strong MFA | Sensitive-operation step-up bypass | Current token adapter never elevates custom assurance; future evidence requires exact reviewed source/version/event reference |
| Audit references are random, raw, foreign, or not request-bound | Untraceable or misattributed privileged effect | Trusted typed resolver; exact opaque principal/customer/deployment/current-correlation binding and path-consistent grant reference required before allow audit |
| An allow decision omits provenance or combines membership and grant/M2M evidence | Ambiguous audit trail hides the authority actually used | Decision schema requires exactly one membership, support, break-glass, or M2M allow branch; early denies remain a separate partial-evidence contract |
| Correlation headers contain token-like or personal text | Sensitive log/response retention | Raw external values are SHA-256-derived into fixed opaque references before binding/echo |
| URL object IDs, human subject, or request stage reach log context | Stable-identity or payload retention | Code-owned route templates, no subject binding, canonical stage only after validation, and a global sanitizer for direct/context identifier fields |
| Request supplies an S3 key or prefix for a download | Arbitrary object access | Resolve only trusted stored locator after authorization; exact prefix validation; short-lived URL |
| M2M token is decorated with a human admin snapshot | Workload privilege escalation | Principal-path separation; M2M uses only GUG-102 granted actions; human snapshot cannot elevate |
| `local_mock` reaches a deployed or ordinary authorization path | Test bypass in runtime | Environment protections plus PDP denial; explicit synthetic dependency overrides only in tests |
| Unknown policy version/digest is treated as latest | Silent policy upgrade/downgrade | Exact allowlisted versions; constant-time digest equality; no compatibility fallback |

### Existing mitigations retained

- GUG-102 rejects client-supplied tenant identity and binds M2M actions.
- GUG-114 uses immutable ownership records and generic foreign/not-found errors.
- GUG-92 defines closed roles, resources, data classes, temporary operations,
  sensitive operations, and deny precedence.
- GUG-93 separates provider authentication from canonical policy authority and
  keeps human runtime disabled by default.
- GUG-153 adds typed route coverage, signed-snapshot bounds, exact per-decision
  current-state evidence, role/data enforcement, proven step-up, receipt-backed
  audit-before-effect, typed opaque audit-reference binding, response/header
  privacy controls, closed masked exports, MIME/option normalization, global log
  identifier sanitization, an identified-metrics deny, and privileged
  artifact-locator/full-profile gates.

### Out-of-scope attacker stories

This delta does not claim to solve identity-provider account takeover,
application XSS/CSRF, document parser vulnerabilities, AWS control-plane
compromise, malicious Terraform apply, lifecycle/bootstrap replay, or live
network/IAM isolation. Those remain covered by their owning packages and the
GUG-117 integration gate. GUG-153 must not weaken their boundaries.

## Security Invariants and Negative Evidence

The following invariants must have synthetic negative tests:

1. No human authorization snapshot means deny.
2. Unknown, missing, stale, future, malformed, or conflicting path, role,
   source, version, digest, binding, state, or operation means deny.
3. A role plus every OAuth scope cannot exceed the role's resource/data class.
4. An OAuth scope absent from an otherwise permitted role means deny.
5. Signed snapshot age 300 seconds may pass; 301 seconds and future time deny;
   current authority evidence must match the exact decision second and complete
   state/version/role or grant record.
6. Sensitive authentication age 299/300 may pass; 301 denies.
7. Missing/non-phishing-resistant assurance or partial/unknown source, version,
   or authentication-event provenance denies sensitive operations.
8. Temporary grants may use only their exact operation/data allowlist, must
   remain within 3,600-second support or 900-second break-glass lifetime, and
   never authorize the three canonical GUG-92 sensitive operations or the two
   GUG-153 exposure-specific privileged operations.
   Support requires case, purpose, and at least one unique independent approval;
   break glass requires incident, purpose, and exactly two unique independent
   approvals. The grantee cannot self-approve and the exact set must match
   current authoritative evidence.
9. Missing sink, sink failure, logging-only sink, malformed receipt, or
   mismatched decision receipt prevents an otherwise allowed human effect.
10. Missing, malformed, raw, foreign, correlation-mismatched, or path-conflicting
    `authorization-audit-references.v1` evidence prevents human allow; temporary
    grants require an opaque grant reference and memberships forbid one.
11. The exact GUG-102 M2M required-action sets and valid route outcomes remain
    regression-tested; GUG-153 does not reinterpret them as human roles.
12. Human fields cannot elevate M2M; `local_mock` cannot become admin.
13. Every one of the 30 routes has exactly one closed operation PEP.
14. A foreign or malformed object still denies after a route-level allow.
15. Identified metrics deny for humans; artifact locator listing and full
    employee-profile reads require stepped-up customer-admin membership and
    deny other roles/grants.
16. Document metadata excludes internal stage locators, queue bindings,
    uploader identity, and stored correlation values; batch and profile-job
    metadata use closed non-identifying projections; masked profile lists redact
    names and reject name search.
17. Masked profile list/JSON/CSV output uses one closed projection; unsupported
    stored content types become `Unknown`; unknown or non-boolean generation
    options deny before lookup/logging/effect.
18. Request correlation/trace headers, dynamic paths, human subjects, and
    request-supplied stages are never logged or echoed raw; known identifier
    keys are globally pseudonymized in context and direct structured events.

## Residual Risks and Deferred Boundaries

| Residual risk | Current treatment | Owner / exit condition |
|---|---|---|
| Human provider issuance and runtime gates remain disabled | Fail closed; no runtime means deny | GUG-94 installs reviewed current-state, typed audit-reference, and durable-audit adapters; provider promotion supplies proven assurance |
| Temporary-grant producer is not an enabled public workflow | Deny absent exact internal source, complete current evidence, and bounded issue/expiry | GUG-94 lifecycle/grant implementation |
| Dashboard and pages-by-user expose identified dimensions | Human explicit deny | New privacy-safe API contract and policy review |
| Artifact-list and full-profile responses contain locator material or full PII | Customer-admin `read+admin` plus step-up, audit, and ownership; other humans/grants deny | Opaque alias-only/artifact and separately reviewed full-profile contracts before any privilege reduction |
| No live two-deployment proof exists | Production NO-GO | Separately authorized isolation exercise |
| Documentation/local/CI cannot prove deployed IAM/provider behavior | Evidence classes remain separate | GUG-117 phase-gate evidence |

## Severity Calibration

### Critical

- A path that permits cross-customer or cross-deployment full document/profile
  access or export with realistic production reach.
- A default-allow or route bypass that exposes protected artifacts or PII to an
  arbitrary authenticated user across deployments.

### High

- A valid user can exceed their role within the same deployment to retrieve
  full PII, execute exports, or download protected artifacts.
- Stale/suspended membership, forged temporary source, missing step-up, or audit
  failure still permits a sensitive effect.
- One foreign batch member can be included in an otherwise authorized export.

### Medium

- Identified metrics or internal artifact locators are exposed to a broader
  same-deployment role without direct document contents.
- A denial/audit reason leaks existence or stable sensitive identifiers but
  does not itself grant access.
- Route inventory drift causes denial or availability loss without bypass.

### Low

- Sanitized reason categories or documentation drift that does not change
  authority, expose sensitive values, or weaken a gate.
- Test-only ergonomics failures where runtime `local_mock` remains impossible.

Severity is increased when exploitation crosses customer/deployment boundaries,
reaches PII/artifacts, changes authorization state, or avoids audit. It is
reduced when the human runtime gate is demonstrably disabled and no deployed
path exists, but the underlying flaw must still be fixed before enablement.

## Evidence and Production Boundary

At this delta's authoring time:

- implementation evidence is limited to the candidate branch;
- local evidence is PASSED: 439 focused PDP/PEP/privacy/object tests, 102
  contract/storage tests, 641 ingest API tests, 813 repository tests,
  compileall, git-safety, security-check, 7/7 microservices, preflight-m2 with
  114/114 contract scenarios, provider-check 11/11, and preflight-m2b;
- the preflight wrong-digest fixture without schema mapping and
  replicated-data module outside M2 scope remain explicitly SKIPPED, not passed;
- exact-commit CI is not established;
- live validation has not occurred;
- AWS, Cognito, deployment, migration, redrive, and production actions are not
  authorized; and
- production remains **NO-GO**.

Rollback first keeps `HUMAN_RUNTIME_ENABLED=false` and
`HUMAN_ENTERPRISE_AUTHORIZATION_ENABLED=false` and verifies denial. The PEP is
never removed while either gate is active. Any targeted code rollback preserves
response/masked-export privacy, MIME/option validation, global identifier-log
sanitization, GUG-102 M2M, and GUG-114 object authorization; a blanket privacy
regression is not an acceptable recovery action.

Repository: cesar-guzman/scanalyze-deployment-platform
Version: 477965ae7d77fe93bb257df3cb2d40cfbc3f81b8
