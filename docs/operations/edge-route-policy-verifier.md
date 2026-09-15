# Offline edge route policy verifier

Status: local implementation, not a published production route policy or runtime
authority. Only an explicitly reviewed subset is projected. No cloud, app startup,
identity handoff, wrapper transport or gate activation is implemented here.

The CLI requires a policy document, its independently expected digest, a separate
closed pins document, and the reviewed source root:

```sh
python3 -m tooling.edge_route_policy verify \
  --policy-path "$REVIEWED_ROUTE_POLICY" \
  --expected-record-digest "$EXPECTED_ROUTE_POLICY_DIGEST" \
  --expected-pins-path "$REVIEWED_SOURCE_PINS" \
  --source-root "$REVIEWED_SOURCE_ROOT"
```

Expected values must come from trusted release/review custody. Computing them
from submitted input is not approval. The verifier checks the independent
digest against both the embedded digest and canonical policy content; re-sealing
an altered document cannot replace that external pin. It uses the fixed schema
in this repository and accepts no caller-supplied schema. Duplicate JSON keys,
non-finite constants, extra fields, empty selections and scope arrays are denied.

The pins document contains exactly `source_commit`, `source_tree_digest`,
`inventory_digest`, `openapi_digest`, `authorization_policy_digest`,
`authorization_policy_version`, `authorization_source_digest` and
`rewrite_source_digest`. These equal the artifact fields and the observed source
digests. `source_commit` is compared with the independent supplied commit pin;
this offline tool does not inspect Git or certify that files belong to HEAD.
The release caller must authenticate that commit-to-source provenance.

`source_tree_digest` hashes a sorted mapping of repository-relative mounted
source paths to SHA-256 hashes of their exact bytes, including main, router
containers, mounted endpoint modules and enterprise authorization source. The
metadata-owning `authorization.py` dependency wrapper is also included. The
inventory separately binds sorted method/path/operation-value rows. OpenAPI and
rewrite digests hash exact file bytes. `authorization_source_digest` hashes the
Python implementation, while `authorization_policy_digest` uses the existing
RFC 8785 policy helper on `policies/authorization/enterprise-authorization.v1.json`.
The published JSON must pass its fixed schema and semantic validator; the AST's
policy version/digest and action-scope map must agree. These two digests are not
interchangeable. JSON whitespace changes do not change the policy's RFC digest.

The AST walker follows the explicit `app = create_app()` factory and direct
relative `include_router` imports, checking the exact receiving router and
literal constructor/mount/decorator prefixes. It never imports app modules or
reads their configuration dependencies. Unmounted routers do not become routes;
conditional or nested mounts, early factory exits, unresolved imports, dynamic
prefixes/registration, router rebinding, dependency-bearing mount options and
duplicate method/path templates fail closed. Unsupported syntax requires an
explicit reviewed parser extension rather than a guessed inventory.
Parsed framework and authorization names require unique canonical imports;
shadowing those names, reassigning operation dependencies, or aliasing route
registration methods is rejected.

Both sync and async handlers are included. Operation identities use the actual
`OperationId` string values. The finite reconciliation selector and its
`ROUTE_OPERATION_POLICY_ATTRIBUTE` declaration preserve both alternatives.
Current source produces **52 unique routes, 48 with operation metadata**, matching
[the source audit](edge-runtime-input-readiness.md). Health and the two passkey
routes have no operation metadata and cannot be published by this artifact.
Generated docs/OpenAPI routes are outside the decorated inventory; no framework
exposure or missing-metadata authorization decision is made automatically.

Human requirements remain an AND of all required actions. The selected single
gateway scope must be necessary for every allowed principal type and every
alternative operation. M2M-denied administration uses human requirements only;
it never becomes public. For example, human `R+A` with M2M `R` admits only the
`R` prefilter. The backend continues to enforce full scopes, membership, tenant,
data-class and assurance requirements; this prefilter cannot replace them.

Success writes only JSON of the form `{"api_authorization_routes":{...}}`, with
exact reviewed method/path keys and one scope per key. Failure returns exit 2,
empty stdout and a fixed stderr reason; no partial projection or input content
is emitted. The artifact alone does not authorize deployment or establish the
separate legacy identity handoff.

The transport interface remains pending: a separately reviewed caller must bind
the external policy digest and source pins to authenticated release custody,
then consume this exact projection. No wrapper currently invokes this verifier.
Passkey route metadata and its reviewed gateway policy also remain pending;
their absence must not be filled by inventing an operation or selecting scopes
automatically. No complete production route policy is approved by these tests.

Validation uses `python3 -m pytest -q tests/test_deployment/test_edge_route_policy.py`.
The local checkpoint passes **67 tests** plus Python syntax, JSON Schema and
four-file whitespace checks.
An independent read-only review reproduced all 67 tests, closed the dependency
rebinding finding with six regressions before the route decorator, and found no
remaining P1/P2 issue within these four files.
Tests copy only named public source files to temporary trees, use explicit
synthetic route selections, and exercise the real verifier/CLI. No Antigravity
scratch inventory, production policy, app import or cloud call is required.
Rollback removes these four local verifier/schema/test/document files; it has no
runtime or state effect because no caller integration or publication occurred.
