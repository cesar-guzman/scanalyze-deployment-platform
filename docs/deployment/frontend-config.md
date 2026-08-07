# Frontend Runtime Configuration

## Status and boundary

`frontend-config/v3` is the canonical public runtime contract for the SPA. The
v1 and v2 schemas remain immutable historical contracts; they are not alternate
current deployment formats. Production remains **NO-GO** until a separately
authorized non-production deployment proves publication, cache headers, OIDC
integration and rollback.

`config.json` is public routing configuration, never an authorization boundary.
It must not contain credentials, tokens, authorization codes, private keys,
client secrets, customer documents or server-side configuration. Customer and
deployment identifiers are non-authoritative bindings; backend token and
deployment enforcement remains authoritative.

## Canonical v3 contract

The machine-readable source is
[`schemas/frontend-config.v3.schema.json`](../../schemas/frontend-config.v3.schema.json).
The document is closed: unknown fields, missing fields and incompatible values
are rejected before OIDC construction, discovery, callback processing or
session verification.

`frontend_runtime_config_json` is the canonical compact UTF-8 byte sequence
emitted by Terraform; `frontend_runtime_config_sha256` binds those exact bytes.
The offline renderer verifies that the object, bytes and digest agree, then
writes those verified bytes without reserialization.

Required top-level fields are:

- `schema_version`, exactly `3`;
- `config_version`, the reviewed semantic release/config version, such as
  `v2.1.0` or `2026.07.14`, limited to 128 characters;
- `customer_id`, `deployment_id`, `account_id`, `region` and `environment`;
- `api_endpoint`, bound to the deployment origin and exact `/api` path;
- `cognito`, including pool, SPA client, issuer, full hosted-UI HTTPS origin,
  exact callback and post-logout URIs, Authorization Code flow and PKCE;
- `authorization`, bound to the reviewed access-token-only scope and policy
  digest contract; and
- `identity_values_authoritative`, exactly `false`.

`features` is optional and accepts only `document_upload`, `batch_processing`,
`audit_view` and `user_administration`, each boolean.

The canonical serialized document limit is 65,536 UTF-8 bytes. The schema,
Terraform gate, offline renderer and browser loader share and test this limit,
so a config accepted for publication cannot be too large for browser startup.

The API, callback and logout URLs must share one exact origin, with paths
`/api`, `/callback` and `/`. Public deployments require HTTPS without
credentials, port, query or fragment. Only `environment=sandbox` may use
`http://localhost:<port>` or `http://127.0.0.1:<port>`, with those same exact
paths. Cognito issuer, pool, Region and hosted UI are cross-bound and cannot be
substituted independently.

The identity control plane accepts the same reviewed `domain_name` used by the
edge and rejects Cognito app-client registration unless its callback and logout
lists are exactly the singleton values `https://<domain_name>/callback` and
`https://<domain_name>/`. Both owners derive the hosted-UI prefix from the same
deployment ID and use the same Region/partition suffix mapping. The existing
content-addressed `identity-control-plane/v1` and `edge-identity/v2` contract
shapes and digests remain immutable; no new URI field is grafted onto them.

CloudFront selects only the exact `/api` and `/api/*` behaviors for the API
origin. Their viewer-request function removes the public `/api` prefix before
API Gateway route matching (`/api/documents` becomes `/documents`) without
changing the method, query string, headers or selected origin. No `/api*`
catch-all is allowed.

The `edge-identity/v2` projection supplies both `api_gateway_id` and
`api_gateway_endpoint`. Terraform requires the endpoint to equal the
ID/Region/partition-derived execute-api origin, and CloudFront derives its
origin hostname from those exact bound fields; an arbitrary HTTPS endpoint is
rejected before planning can publish or route runtime traffic.

Historical deployment-manifest v1/v2 documents and schemas remain unchanged;
they are intent, not runtime-origin authority. Domain-owning plans require an
approved `deployment-target/v2` record with closed `runtime_origin/v1`. Its
record digest covers the exact lowercase domain and is matched by the
independently retrieved target anchor and the existing execution-lock v1. The
manifest and CLI domain/environment are assertions only. The plan wrapper reads
the authorized values from `terraform-backend-binding/v2` before constructing
Terraform variables, so separate layer runs under one lock cannot substitute a
different origin.

Existing v1 targets migrate through one compare-and-swap transition that adds
only `runtime_origin/v1`, increments `registry_version`, preserves status and
all existing target fields, and computes a new record digest. A fresh anchor
and execution lock are mandatory for that new digest. No in-place v1 schema
edit or stale-lock reuse is accepted.

## Offline validation and rendering

The validator consumes either a config document or previously captured
`terraform output -json`. It does not execute Terraform, contact AWS, call a
live OIDC provider or read a Terraform backend.

```bash
python scripts/deployment/validate-frontend-config.py \
  validate fixtures/valid/frontend-config-v3-synthetic-a.json
```

To reproduce rendering without AWS, use the tracked synthetic Terraform-output
fixture and an output directory outside the repository:

```bash
RUNTIME_CONFIG_TMP="$(mktemp -d)"
python scripts/deployment/validate-frontend-config.py render \
  --terraform-output fixtures/gug101/terraform-output-frontend-config-v3.json \
  --output "${RUNTIME_CONFIG_TMP}/config.json"
```

The renderer selects the three non-sensitive `frontend_runtime_config`,
`frontend_runtime_config_json` and `frontend_runtime_config_sha256` outputs. It
requires the typed object, canonical compact bytes and digest to agree exactly.
It rejects empty, corrupt, duplicate-key and non-finite JSON, secret-like keys,
schema drift, noncanonical bytes, digest mismatch and cross-field binding drift.
It writes mode `0600`, refuses paths inside the repository and does not
overwrite an existing file unless the operator explicitly supplies
`--overwrite`. Standard output contains only a stable result code and SHA-256
digest; rejected values and paths are never printed.

An authorized deployment orchestrator may capture the exact reviewed edge-root
output and invoke this renderer for offline/readback evidence. Publication is
owned by the edge Terraform module: `aws_s3_object.frontend_runtime_config`
writes those canonical bytes to the exact account/deployment config key with
SHA-256 upload checking and no-store metadata. The edge session policy permits
only `GetObject`/`PutObject` on that key; the Promotion role can publish only
immutable release assets. Manual editing, copying values from a console,
selecting an AWS resource from a list, or committing generated `config.json` is
not an accepted deployment step.

## Build once and promote configuration separately

Build the frontend once. Do not place `config.json` in `dist`, source, Vite
environment variables or compiled assets. The proof harness verifies that two
valid, distinct external configs use one unchanged build tree:

```bash
cd frontend/scanalyze-frontend-ui
npm ci
npm run build
cd ../..
python scripts/deployment/validate-frontend-config.py prove-build-once \
  --artifact-dir frontend/scanalyze-frontend-ui/dist \
  --config-a fixtures/valid/frontend-config-v3-synthetic-a.json \
  --config-b fixtures/valid/frontend-config-v3-synthetic-b.json
```

The recorded build digest must remain identical. Config digests must differ.
Promotion copies the same immutable build; a reviewed edge Terraform plan owns
the validated external config for each target. Neither step rebuilds or forks
the SPA by environment or customer.

## Compatibility policy

Normal startup accepts v3 only. v1 fails closed with
`RUNTIME_CONFIG_UPGRADE_REQUIRED`; unknown schema versions fail closed with
`RUNTIME_CONFIG_UNSUPPORTED_VERSION`.

One v2 subset may be migrated deterministically during the bounded transition:

- `api_endpoint` already uses the deployment frontend origin with exact `/api`;
- `config_version` is present and valid;
- issuer, Region and user-pool bindings are exact;
- `hosted_ui_domain` is the full HTTPS origin derived from the deployment ID
  and Region; and
- all authorization and non-authoritative identity invariants already match v3.

For that subset only, migration adds `redirect_uri=<origin>/callback` and
`post_logout_redirect_uri=<origin>/` inside `cognito`, then validates the full
v3 result. No value is guessed. A v2 config with an external API Gateway URL,
bare or ambiguous hosted domain, missing version, legacy alias, conflicting
canonical value or any unsupported field fails
`RUNTIME_CONFIG_UPGRADE_REQUIRED`. It must be re-rendered from reviewed IaC.

## Runtime and OIDC failure states

The browser loads `/config.json` once per page lifecycle with `cache: no-store`,
a five-second timeout and a 64 KiB incremental byte limit. There is no automatic
retry. Retrieval errors terminate as `RUNTIME_CONFIG_UNAVAILABLE`, timeouts as
`RUNTIME_CONFIG_TIMEOUT`, invalid content as `RUNTIME_CONFIG_INVALID`, v1 as
`RUNTIME_CONFIG_UPGRADE_REQUIRED`, and unknown versions as
`RUNTIME_CONFIG_UNSUPPORTED_VERSION`. The user may explicitly reload after the
terminal error.

Only a validated config can construct the OIDC provider. OIDC transport uses a
five-second request timeout and the UI has a six-second terminal guard for
bounded bootstrap/callback/logout work. Authorization state and user state are
kept in `sessionStorage`; callback state is bound to issuer, client, redirect,
PKCE verifier and a maximum age of 300 seconds before any token exchange.
Missing, unknown, stale, corrupt or mismatched state becomes
`AUTH_CALLBACK_INVALID`, and the callback query is removed from browser history
before the terminal safe UI is shown. Discovery, callback and logout errors are
projected only as stable codes; tokens, authorization codes, raw config and raw
provider responses are never rendered. Retry is user-initiated and cannot
automatically replay callback processing.

## Cache, deployment and rollback

Immutable build assets use long-lived immutable caching. `/config.json` is a
separate exact behavior and object with `Cache-Control: no-store, max-age=0,
must-revalidate`; it must not inherit the static-asset cache policy. Browser
`fetch(..., {cache: "no-store"})` is defense in depth and does not replace the
CloudFront/S3 header contract.

Deployment sequence:

1. build and digest the SPA once;
2. render v3 from the exact reviewed Terraform output outside the repository;
3. validate the rendered bytes and record only their digest;
4. publish immutable build assets, then apply the exact reviewed edge plan that
   owns the separately controlled config object;
5. verify exact cache headers and synthetic startup; and
6. retain prior object/build versions for rollback.

Rollback restores the last reviewed compatible build and v3 config as a bound
pair through a new reviewed saved edge plan. The config resource is
`prevent_destroy`; normal rollback updates exact content and never deletes the
key. Do not edit config in place, rebuild with old values, perform an ad-hoc
CloudFront invalidation or fall back to a v1/ambiguous v2 document. If the
previous binding cannot be proven, stop and render a new v3 config through the
reviewed path.

## Focused repository checks

```bash
python -m pytest -q tests/test_gug101_frontend_config_v3.py
python tooling/validate_schema.py \
  --schemas-dir schemas --fixtures-dir fixtures --filter frontend-config-v3
make docs-check
```

These checks use synthetic data only and require no AWS profile, customer
account, real token or live Cognito provider.
