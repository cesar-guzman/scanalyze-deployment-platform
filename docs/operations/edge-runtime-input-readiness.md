# Edge identity runtime input readiness

**LOCAL AUDIT — two authority inputs remain unavailable for a live plan.** The
affected root is `edge-identity`, not the separate `edge` root. This assessment
reads public repository source only on `fix/production-runtime-readiness`, base
`16dec52b2522e80f2a85ad9551ee3a0cdafbb4a8`. It creates no route map, transport,
handoff receipt, state operation, gateway change or cloud authorization.

The two required inputs are declared at
[`roots/edge-identity/variables.tf`](../../roots/edge-identity/variables.tf):
`api_authorization_routes` and `legacy_identity_handoff_complete`. The module
requires a nonempty exact method/path map, exactly one canonical scope per key,
no `$default`, wildcard, query string or greedy proxy route. Its
[`identity_handoff_gate`](../../modules/edge-identity/cognito.tf) requires a
reviewed state-adoption or no-legacy-state assertion before the authorizer can
use the verified identity-control-plane contract.

## Source-derived route inventory

The inventory below is derived without importing or starting the application:
parse the mounted router decorators and `Depends(require_operation(...))`
bindings with Python AST, then resolve `OperationId` and `OPERATION_POLICIES` in
[`enterprise_authorization.py`](../../backend/workers/scanalyze-ingest-api/app/enterprise_authorization.py).
The router hierarchy is explicit in
[`main.py`](../../backend/workers/scanalyze-ingest-api/app/main.py) and
[`api/v1/router.py`](../../backend/workers/scanalyze-ingest-api/app/api/v1/router.py).
There are 52 decorated method/path entries: 48 with operation metadata and four
without it. Generated documentation endpoints are recorded separately.

`Operation` below is the value supplied to `require_operation`. `Human` lists
the policy's required action scopes; it does not imply a role grant, membership,
permitted data class, or satisfied step-up. `M2M` lists the separate existing M2M
requirements. An AND is preserved as `R + A` and must not become an API Gateway
scope array: API Gateway evaluates arrays as OR. These columns are evidence for
a reviewed prefilter decision, not a ready-to-deploy map.

| Symbol | Exact canonical scope |
| --- | --- |
| R | `scanalyze.api.v1/read` |
| W | `scanalyze.api.v1/write` |
| A | `scanalyze.api.v1/admin` |
| DENIED | The operation explicitly forbids M2M; no empty/public scope is implied. |

### Document journey v2

Source: [`api/v2/router.py`](../../backend/workers/scanalyze-ingest-api/app/api/v2/router.py).
All seven method/path pairs match the committed
[`scanalyze-document-journey.openapi.v1.json`](../../schemas/scanalyze-document-journey.openapi.v1.json).
The OpenAPI operations do not contain per-operation OAuth scope lists; the
operation policy supplies those requirements. Reconciliation explicitly selects
one of two operation IDs from the constrained path parameter; both require W.

| Method/path | Operation | Human | M2M |
| --- | --- | --- | --- |
| `POST /api/v2/batches` | `batches.create` | W | W |
| `POST /api/v2/documents` | `documents.create` | W | W |
| `POST /api/v2/documents/{documentId}/submit` | `documents.submit` | W | W |
| `GET /api/v2/documents/{documentId}` | `documents.read_metadata` | R | R |
| `POST /api/v2/documents/{documentId}/upload-capabilities` | `documents.create` | W | W |
| `POST /api/v2/operations/{operation}/reconciliation` | `batches.create` or `documents.create` | W | W |
| `GET /api/v2/documents/{documentId}/result` | `results.read_full` | R + A | R + A |

Full-result access additionally requires the existing fresh step-up and data
permissions. Selecting a gateway prefilter never removes that backend gate.

### Legacy document and batch APIs

Sources: [`documents.py`](../../backend/workers/scanalyze-ingest-api/app/api/v1/documents.py),
[`batches.py`](../../backend/workers/scanalyze-ingest-api/app/api/v1/batches.py).

| Method/path | Operation | Human | M2M |
| --- | --- | --- | --- |
| `POST /api/v1/documents` | `documents.create` | W | W |
| `POST /api/v1/documents/{document_id}/submit` | `documents.submit` | W | W |
| `GET /api/v1/documents/{document_id}` | `documents.read_metadata` | R | R |
| `GET /api/v1/documents/{document_id}/result` | `results.read_full` | R + A | R + A |
| `GET /api/v1/documents/{document_id}/artifacts` | `artifacts.list_metadata` | R + A | R |
| `GET /api/v1/documents/{document_id}/download` | `artifacts.download` | R + A | R + A |
| `GET /api/v1/documents/{document_id}/artifacts/{artifact_id}/download` | `artifacts.download` | R + A | R + A |
| `POST /api/v1/batches` | `batches.create` | W | W |
| `GET /api/v1/batches/{batch_id}` | `batches.read_metadata` | R | R |
| `GET /api/v1/batches/{batch_id}/documents` | `batches.read_metadata` | R | R |
| `GET /api/v1/batches/{batch_id}/manifest` | `exports.execute` | R + A | R + A |
| `GET /api/v1/batches/{batch_id}/exports/json` | `exports.execute` | R + A | R + A |
| `GET /api/v1/batches/{batch_id}/exports/csv` | `exports.execute` | R + A | R + A |
| `GET /api/v1/batches/{batch_id}/exports/zip` | `exports.execute` | R + A | R + A |

The metadata/export distinction is policy-specific: a GET is not automatically
read-only authorization. Human artifact metadata and M2M artifact metadata also
have intentionally different requirements in the current policy.

### Analytics and employee profiles

Sources: [`analytics.py`](../../backend/workers/scanalyze-ingest-api/app/api/v1/analytics.py),
[`employee_profiles.py`](../../backend/workers/scanalyze-ingest-api/app/api/v1/addons/employee_profiles.py).

| Method/path | Operation | Human | M2M |
| --- | --- | --- | --- |
| `GET /api/v1/analytics/dashboard` | `metrics.read_identified` | R | R |
| `GET /api/v1/analytics/overview` | `metrics.read` | R | R |
| `GET /api/v1/analytics/pages-by-user` | `metrics.read_identified` | R | R |
| `GET /api/v1/analytics/by-day` | `metrics.read` | R | R |
| `GET /api/v1/analytics/by-batch` | `metrics.read` | R | R |
| `GET /api/v1/analytics/by-doc-type` | `metrics.read` | R | R |
| `GET /api/v1/analytics/costs` | `metrics.read` | R | R |
| `GET /api/v1/analytics/export-ine` | `exports.execute` | R + A | R + A |
| `GET /api/v1/addons/employee-profiles/status` | `deployment_configuration.read` | R | R |
| `GET /api/v1/addons/employee-profiles/export/csv` | `exports.execute` | R + A | R + A |
| `POST /api/v1/addons/employee-profiles/generate` | `employee_profiles.generate` | W | W |
| `GET /api/v1/addons/employee-profiles/jobs/{job_id}` | `employee_profiles.read_job` | R | R |
| `GET /api/v1/addons/employee-profiles` | `employee_profiles.list_masked` | R | R + A |
| `GET /api/v1/addons/employee-profiles/{profile_id}/export/json` | `exports.execute` | R + A | R + A |
| `GET /api/v1/addons/employee-profiles/{profile_id}/export/csv` | `exports.execute` | R + A | R + A |
| `GET /api/v1/addons/employee-profiles/{profile_id}` | `employee_profiles.read_full` | R + A | R + A |

For example, `metrics.read_identified` requires an identified/PII data class
that the current v1 human roles do not grant; R alone does not authorize it.
`employee_profiles.generate` likewise retains its PII permission requirement.

### Human administration

Source: [`user_lifecycle.py`](../../backend/workers/scanalyze-ingest-api/app/api/v1/user_lifecycle.py).
Every operation below has `m2m_allowed=False`. The empty M2M action metadata must
not be interpreted as no authorization required or converted into a public route.

| Method/path | Operation | Human | M2M |
| --- | --- | --- | --- |
| `GET /api/v1/admin/roles` | `authorization_administration.roles.read` | R | DENIED |
| `GET /api/v1/admin/memberships` | `authorization_administration.memberships.list` | R | DENIED |
| `POST /api/v1/admin/invitations` | `authorization_administration.invitations.create` | A | DENIED |
| `POST /api/v1/admin/memberships/{membership_reference}/invitation-resends` | `authorization_administration.invitations.create` | A | DENIED |
| `POST /api/v1/admin/memberships/{membership_reference}/activations` | `authorization_administration.memberships.activate` | A | DENIED |
| `POST /api/v1/admin/memberships/{membership_reference}/role-changes` | `authorization_administration.memberships.change_role` | A | DENIED |
| `POST /api/v1/admin/memberships/{membership_reference}/suspensions` | `authorization_administration.memberships.suspend` | A | DENIED |
| `POST /api/v1/admin/memberships/{membership_reference}/reactivations` | `authorization_administration.memberships.reactivate` | A | DENIED |
| `POST /api/v1/admin/memberships/{membership_reference}/revocations` | `authorization_administration.memberships.revoke` | A | DENIED |
| `POST /api/v1/admin/memberships/{membership_reference}/session-revocations` | `authorization_administration.sessions.revoke` | A | DENIED |
| `GET /api/v1/admin/audit-events` | `authorization_administration.audit.read` | R | DENIED |

### Explicit review decisions

Source: [`authentication_assurance.py`](../../backend/workers/scanalyze-ingest-api/app/authentication_assurance.py),
[`health.py`](../../backend/workers/scanalyze-ingest-api/app/api/health.py), and the
explicit documentation configuration in `main.py`.
Every row in this section remains **REVIEW_DECISION_REQUIRED**. None has an
assigned gateway prefilter scope in this audit.

| Method/path or surface | Observed action metadata | Required decision |
| --- | --- | --- |
| `POST /api/v1/auth/passkey/initiate` | No `require_operation` / action binding | Review the precise authenticated step-up prefilter and authority; do not infer W from POST. |
| `POST /api/v1/auth/passkey/respond` | No `require_operation` / action binding | Same; a Bearer header and verified gateway issuer do not supply a missing route policy. |
| `GET /health` | None | Decide internal health exposure separately; do not add a public route or scope automatically. |
| `GET /api/v1/health` | None | Review whether this facade is published; do not derive R from GET. |
| `GET /docs`, `GET /openapi.json` | Framework documentation, no action binding in `main.py` | Explicit exposure decision; generated legacy OpenAPI does not replace the committed v2 contract. |
| Human bootstrap | No dedicated bootstrap HTTP route mounted by the inspected `main.py` | Keep the separate reviewed bootstrap/Lambda workflow and its runtime gate; do not invent a bootstrap endpoint or mark activation complete. |

## Phantom fixture routes and path composition

The initial `variables.api_authorization_routes` block in
[`api_authorization.tftest.hcl`](../../modules/edge-identity/tests/api_authorization.tftest.hcl)
is a synthetic ten-route conformance fixture, not the mounted API inventory.
Two of its route keys have no current corresponding endpoint:

- `GET /api/v1/documents`: the actual document GET takes `/{document_id}`.
- `POST /api/v1/batches/{batch_id}/export`: the actual export routes are the GET
  `/manifest` and `/exports/json`, `/exports/csv`, `/exports/zip` routes listed above.

The fixture also omits both passkey endpoints and many mounted v1 endpoints.
Its later intentionally invalid `GET /documents?admin=true` test input is not a
candidate publication route and must not be counted as a third phantom baseline
entry. The existing Node composition test passed four cases before the rewrite
correction despite those inventory gaps: it proves its fixture composition only.

The separately corrected
[`api_path_rewrite.js`](../../modules/edge/api_path_rewrite.js) now preserves both
canonical `/api/v1` and `/api/v2` namespaces while retaining the historical
`/api/...` facade. Root reproduced two failing cases before the correction and
reported six passing rewrite cases afterward. This audit read back the changed
function. No method or authorization scope changes are implied by the rewrite.
The coordinated root checkpoint also reported 70 Python schema/frontend-config
tests, 82 frontend unit tests and the frontend production build passing. The
three missing-domain negative fixtures now supply the earlier layer-authority
argument pairs and retain their exact domain-error assertions; the complete
27-test frontend-config file passed in this audit. These checks do not establish
the missing route policy or handoff authority.

| Browser path | Gateway/backend path after current rewrite |
| --- | --- |
| `/api/v1/auth/passkey/initiate` | `/api/v1/auth/passkey/initiate` |
| `/api/auth/passkey/initiate` | `/api/v1/auth/passkey/initiate` |
| `/api/documents` | `/api/v1/documents` |
| `/api/v2/documents` | `/api/v2/documents` |

Before the correction, the first example became
`/api/v1/v1/auth/passkey/initiate`; preserving canonical v1 fixes that composition
without requiring the client to depend on a proxy-only alias. Route policy must
describe the exact gateway keys after rewriting. A missing handler remains
missing even when a rewrite is correct.

## Handoff authority remains missing

The five legacy Cognito declarations in
[`modules/edge-identity/cognito.tf`](../../modules/edge-identity/cognito.tf) use
`removed { lifecycle { destroy = false } }`. They retain the resources when the
old state ownership is forgotten; they do not prove import into the identity
root, absence of legacy state, or authorized adoption.

Follow the existing
[`Legacy inventory and state adoption`](../deployment/identity-control-plane.md#legacy-inventory-and-state-adoption)
requirements: exact tuple, provider/state ownership, immutable compatibility,
approved inventory disposition, protected backup/version evidence, reviewed
import and replacement-free plan, and independent Identity/Security review.
No state, production inventory or migration evidence was read in this audit.
No existing complete handoff receipt/verifier was found in the inspected public
deployment/tooling/schema authority paths. A new deployment ID, an absent pool
listing, a successful login, a newly published identity contract, or a receipt
self-digest alone cannot establish `legacy_identity_handoff_complete=true`.

## Minimum proposed interface for review

Implement this only after the missing route and handoff authority is supplied
and reviewed. Preserve all existing sealed-request versions and coordinate a
new closed transport extension with other runtime-authority work. Do not place
these fields in the infrastructure-selection document.

1. A closed, reviewed `edge-route-policy.v1` artifact contains an explicit
   publication set of exact `method`, `path`, `operation_ids` and one
   `prefilter_scope` per route. Pin the mounted route inventory/source commit,
   committed v2 OpenAPI digest, authorization policy RFC 8785 digest/version and
   CloudFront rewrite source digest. Check each selected route against the real
   mounted inventory and its operation requirements. Selection and the single
   prefilter for multi-action or metadata-free routes require an explicit
   reviewed decision. Empty/default/wildcard routes, phantom endpoints, scope
   arrays with OR widening and changed source/policy pins must fail closed.
2. A separate closed `identity-handoff-receipt.v1` uses exactly one disposition:
   `NO_LEGACY_STATE` or `ADOPTED`. Bind the exact customer/deployment/account/
   partition/region/environment, the verified identity-control-plane/v1
   envelope's full document digest and its existing outputs `contract_digest`,
   selected signed release manifest digest, inventory/evidence digests and
   immutable evidence references, review authority and bounded observation time.
   Do not confuse this installed identity contract with identity-contract/v2 M2M
   registry authority. NO_LEGACY_STATE needs complete reviewed ownership
   coverage; ADOPTED needs exact legacy addresses, verified destination import
   and compatible resource bindings plus backup/version and replacement-free
   import-plan evidence. The later edge forget plan remains independently
   reviewed; do not create a cycle by requiring that same plan's completed
   forget operation as evidence before it can be planned.
3. One closed `edge-runtime-authority.v1` bundle carries the route artifact and
   handoff receipt with their independent expected digests. A fixed reviewed
   path under the claim's release/environment/deployment namespace and a
   protected outer document pin provide custody, following the completed
   identity transport pattern. Existing upstream resolution must verify the
   installed identity envelope's tuple, producer, outputs digest, release and
   freshness before the handoff adapter compares its anchor. Reviewed
   provenance/evidence is mandatory; a free-text approver field or incoming
   hash is not authority. Expired, missing or ambiguous evidence yields no output.
4. A later caller extension could use only `--edge-authority` and
   `--expected-edge-authority-digest`, forwarding the same protected pin through
   materializer, controller, orchestrator, wrappers and real validator. It emits
   exactly the reviewed `api_authorization_routes` plus
   `legacy_identity_handoff_complete=true` **only after** the receipt verifier
   establishes the asserted disposition. An explicit false/incomplete decision
   remains blocked; no successful test, new resource or code default promotes it.

Required tests should use the real caller and validator: phantom/missing routes,
path rewrite mismatch, policy/source changes, scopes with OR widening, missing
metadata decisions, wrong identity tuple/digest, stale/ambiguous handoff,
unproved no-legacy-state/adoption, outer and inner mutations under unchanged
pins, and replacement pins against the original claim. No mocked handoff
verifier or synthetic fixture may establish live authority. Reverting this
audit document has no runtime effect; there is no deployed change to roll back.
