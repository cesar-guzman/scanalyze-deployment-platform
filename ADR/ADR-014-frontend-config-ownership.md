# ADR-014: Frontend Runtime Configuration Ownership

- **Status:** Accepted; amended for frontend-config/v3
- **Original date:** 2026-07-10
- **v3 amendment:** 2026-08-05
- **Work package:** GUG-101
- **Live validation:** No
- **Production:** NO-GO

## Context

The SPA must be one portable build promoted across environments. Its public
runtime values come from deployment contracts, but public input remains
untrusted and must not start OIDC before complete validation. Historical v1/v2
schemas, a hand-maintained TypeScript shape and documentation that referenced a
missing renderer allowed contract drift. The edge module also needs a single
reviewable projection and config-specific cache behavior.

## Decision

`schemas/frontend-config.v3.schema.json` is the canonical closed public shape.
The edge Terraform root owns one non-sensitive `frontend_runtime_config`
projection. `scripts/deployment/validate-frontend-config.py` is the offline
boundary between captured `terraform output -json` and publishable
`config.json`; it verifies the typed object, canonical compact JSON bytes and
their SHA-256 output agree, validates schema and semantic bindings, and writes
the exact verified bytes to a new mode-`0600` file outside the repository.

The v3 document requires:

- explicit schema and release/config versions;
- exact customer, deployment, account, environment and Region bindings;
- same-origin API `/api`, callback `/callback` and logout `/` URLs;
- exact Cognito Region, pool, issuer and full hosted-UI HTTPS origin;
- Authorization Code plus PKCE and no client secret;
- access-token-only canonical scopes and reviewed policy digest;
- non-authoritative public identity values; and
- a closed boolean feature allowlist.

The serialized v3 document is capped at 65,536 UTF-8 bytes and
`config_version` at 128 characters. Terraform, the offline renderer and the
browser loader enforce the same contract.

The identity control plane and edge share the same reviewed `deployment_id`,
`region`, `aws_partition` and `domain_name` authority. Cognito registration is
plan-gated to the singleton callback `https://<domain_name>/callback` and
logout URI `https://<domain_name>/`; the edge derives those same URIs and the
hosted-UI origin from the same inputs. This preserves the content-addressed
`identity-control-plane/v1` and `edge-identity/v2` contracts unchanged while
removing an independently configurable URI path.

Deployment-manifest v1/v2 remains immutable and backward compatible when
`domain` is absent. Domain-owning plans require `deployment-target/v2`, whose
closed `runtime_origin/v1` contains the exact domain. The target record digest,
independently retrieved anchor and existing execution-lock v1 registry digest
bind that value across identity, API-edge and frontend-edge plans. Manifest and
CLI values are assertions only; Terraform receives the environment and domain
read back from the authorized backend binding v2. A one-step CAS migration may
add `runtime_origin/v1` to a v1 target without changing status or any existing
binding; the changed target digest requires a fresh anchor and execution lock.

The public same-origin API base remains `/api`. CloudFront matches only `/api`
and `/api/*`, then removes that exact prefix in a viewer-request function so the
existing API Gateway routes continue to receive `/` or `/documents` rather than
an undeclared `/api/...` path. Method, query, headers and origin selection are
preserved.

The API origin is not accepted as an arbitrary HTTPS host. The edge consumer
projects both the API Gateway ID and endpoint from `edge-identity/v2`, requires
the endpoint to equal the ID/Region/partition-derived execute-api origin, and
derives the CloudFront origin hostname from those bound fields.

HTTPS is mandatory except for an explicit sandbox-only localhost/loopback
development rule. Unknown fields, duplicate JSON keys, non-finite values,
secret-like keys, ambiguous origins and binding mismatches fail closed before
OIDC construction.

Callback state lives only in `sessionStorage` and is checked before provider
processing for exact issuer/client/redirect bindings, PKCE verifier presence
and a maximum age of 300 seconds. Invalid callback queries are scrubbed from
browser history before the terminal safe error is shown.

The SPA build never contains deployment config. One build-tree digest is reused
with distinct external config digests. `/config.json` receives an exact
no-store cache behavior; immutable assets retain long-lived caching. The edge
Terraform module owns `${deployment_id}/config.json` in the exact
account-scoped frontend bucket, with the canonical JSON bytes, SHA-256 upload
algorithm and no-store object metadata. The Promotion role remains limited to
immutable release assets and cannot replace runtime config.

## Compatibility

v1 and unknown versions are unsupported. v2 is not generally accepted. A
bounded deterministic migration may handle only a v2 document that already has
the same-origin `/api`, exact derived hosted UI, exact identity/authorization
bindings and a valid `config_version`. Migration derives callback and logout
paths from that already proven origin and then revalidates as v3. External API
Gateway endpoints, bare hosted domains, missing versions, aliases, conflicts or
other ambiguity return `RUNTIME_CONFIG_UPGRADE_REQUIRED`; no fallback or value
guessing is permitted.

The v1 and v2 schema files remain immutable historical evidence. They are not
edited to reinterpret old documents as v3.

## Consequences

Positive:

- runtime, IaC projection, fixtures and publication share one versioned shape;
- invalid config cannot silently start OIDC;
- output is reproducible without AWS and contains no secret material;
- one build can be promoted by changing only validated external config; and
- cache and rollback behavior are explicit and reviewable.

Trade-offs:

- existing v1 and most v2 documents require a reviewed v3 re-render;
- live object publication, readback and CloudFront/S3 cache headers require
  separate authorized non-production proof; and
- repository validation does not prove a live provider, callback or session.

## Deployment and rollback

An authorized orchestrator publishes immutable build assets, prepares the exact
saved edge plan and records the v3 digest. That Terraform plan writes the
canonical runtime-config bytes and no-store metadata to the exact config key.
The offline renderer independently reproduces and verifies those same outputs;
it is not a manual publication path. No config edit, direct promotion-role
replacement or ad-hoc invalidation is allowed.

Rollback restores the last proven compatible build/config versions as a pair.
If their binding or cache state is uncertain, deployment stops and a new v3
document is rendered. Merge, green CI or local validation grants no AWS or
production authority.
