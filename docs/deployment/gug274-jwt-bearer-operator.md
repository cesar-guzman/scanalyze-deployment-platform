# GUG-274 JWT bearer operator integration

Status: **LOCAL IMPLEMENTATION; CONNECTED ACCEPTANCE PENDING**. 2026-09-14.

The owner selected the trusted-issuer alternative after the existing custom
Identity Center application rejected `authorization_code`. This implementation
adds an explicit v2 path. It does not enable the application or install a
trusted issuer, and it does not establish production readiness.

The owner has now confirmed AWS workforce sign-in through IAM Identity Center.
The [SSO reconciliation](gug274-workforce-identity-readback-20260914.md) verifies
the existing portal and distinguishes it from this custom JWT/TTI application.
Workforce sign-in is identified; this integration's external issuer and actual
owner mapping remain unconfigured. No new external identity provider is assumed.

## Current connected evidence

On 2026-09-14, after renewing the existing SSO session, read-only requests using
`042360977644_ScanalyzePlatformAuthorityBootstrap`, Region `us-east-1`, returned:

- `sts get-caller-identity`: account `042360977644`.
- `sso-admin list-trusted-token-issuers`, instance
  `arn:aws:sso:::instance/ssoins-72230e7bbcf51d3d`: empty list, no continuation.
- `sso-admin list-application-grants`, application
  `arn:aws:sso::042360977644:application/ssoins-72230e7bbcf51d3d/apl-722313749a62e03b`:
  empty list.

These reads made no cloud changes. The owner subsequently selected César Guzmán
as sole responsible operator. Use the explicit single-owner configuration below:
it requires one real owner reference and records no independent approval. The
legacy independent mode still requires two distinct people. No customer
authentication pool is adopted implicitly.

## Protocol and authority boundaries

1. The launcher authenticates a clean source commit and the private public-
   metadata binding file's independently reviewed SHA256. It imports its helper,
   JWT parser and OIDC client from captured Git object bytes. Dependencies absent
   from that closed snapshot cannot fall back to a later filesystem import.
2. The isolated CLI freezes and validates the Plan/Approval artifacts before
   emitting a v2 readiness record over an anonymous pipe. Its operation nonce
   is the domain-separated digest of operation, plan digest and approval digest.
   The broker independently recomputes the same value from validated artifacts.
3. The launcher opens the pinned issuer authorization endpoint with a fresh
   PKCE S256 challenge and state, `scope=openid`, `prompt=login`, `max_age=0` and
   that operation nonce. The callback remains exactly
   `http://127.0.0.1:38271/callback`. Its strict parser accepts code and state;
   an issuer requiring additional callback fields needs a separately reviewed
   extension rather than silently ignored parameters.
4. The public OIDC client exchanges the code once at the pinned HTTPS token
   endpoint. It uses no client secret, refresh flow, proxy, redirect, cookie jar
   or persistent credential store. The ID token travels to the CLI only through
   its anonymous grant pipe. Provider failures are sanitized and not retried.
5. Local JWT parsing enforces bounded canonical structure, RS256/kid, exact
   issuer and single-string audience, subject, JTI, recent authentication,
   expiration and operation nonce. This parsing does **not** verify a signature
   or authorize an operation. The exact Identity Center application's trusted
   issuer validates the signature and prevents reuse of an exchanged JTI.
6. `CreateTokenWithIAM` uses the JWT bearer grant and exact `sts:identity_context`
   scope. The existing response checks still require no refresh token, a
   `60..900` second lifetime and `awsAdditionalDetails.identityContext`.
   An `idToken` decoded locally is not a substitute for that provider field.
7. The operation-specific STS deny-all proof role establishes the expected
   Identity Store user. Independent mode excludes its peer; single-owner mode
   binds all three distinct proof roles to the one actual owner. The broker checks artifact
   expiration again using current time after authentication and storage reads.
   The record distinguishes independent approval from owner review. Apply constructs effect clients only
   after a successful terminal compare-and-swap transition.

No token, assertion, code, verifier, returned credential or raw provider response
belongs in a file, command argument, receipt, diagnostic capture or log. Python
reference clearing reduces retention; it is not a claim of guaranteed memory
zeroization. Raw SDK exceptions are never surfaced by this path.

## Immutable runtime selection

The authority CloudFormation template adds these public parameters. The common
environment block applies the same values to all three versioned functions.

| CloudFormation parameter | Runtime variable | v2 requirement |
| --- | --- | --- |
| `IdentityGrantVersion` | `GUG274_IDENTITY_GRANT_VERSION` | Literal `2` |
| `JwtTrustedTokenIssuerArn` | `GUG274_JWT_TRUSTED_TOKEN_ISSUER_ARN` | Actual issuer ARN in the authority account and instance |
| `JwtIssuerUrl` | `GUG274_JWT_ISSUER_URL` | Exact public HTTPS issuer identifier |
| `JwtAudience` | `GUG274_JWT_AUDIENCE` | Exact reviewed public-client audience |

The template defaults to v1 for historical compatibility. Its Rules reject
partial v2 metadata and nonempty JWT metadata in v1. Runtime parsing validates
the topology again. A request cannot select or downgrade the runtime's grant
version. A v2 runtime rejects v1 envelopes; v1 rejects v2. There is no fallback.

In independent mode, the identity binding uses a v2 domain and includes the issuer-binding digest.
Its STS proof receipt schema remains v1 because its proof semantics
are unchanged; its identity-binding digest differentiates configurations.
Existing receipts, signatures and source pins cannot be relabeled as JWT proof.

## Private operator binding

The following v2 example documents independent mode. For César's selected
single-owner mode, change `schema_version` to `3`, change `record_type` to
`platform_authority_bootstrap_single_owner_binding`, and add exactly two string
fields: `single_owner_authorized_at` and `single_owner_expires_at`. Both must be
actual reviewed UTC timestamps in `YYYY-MM-DDTHH:MM:SSZ` form; their interval must
be positive and at most 24 hours. This guide creates no implicit activation
date. All other fields and custody requirements below remain the same.

Create the binding outside the repository in an owner-only directory (`0700`),
with an owner-only regular file (`0600`, no symlink or multiple hard links).
All values below are strings. Replace placeholders with independently verified
public metadata; these placeholders are not installable configuration.

```json
{
  "schema_version": "2",
  "record_type": "platform_authority_bootstrap_jwt_binding",
  "authority_account_id": "042360977644",
  "region": "us-east-1",
  "application_arn": "<actual reviewed application ARN>",
  "instance_arn": "<actual reviewed instance ARN>",
  "redirect_uri": "http://127.0.0.1:38271/callback",
  "trusted_token_issuer_arn": "<actual reviewed trusted issuer ARN>",
  "issuer_url": "<exact issuer identifier>",
  "audience": "<public client ID and authorized audience>",
  "authorization_endpoint": "<pinned HTTPS authorization endpoint>",
  "token_endpoint": "<pinned HTTPS token endpoint>"
}
```

Review the SHA256 separately from the file it authenticates. The launcher
remains `scripts/deployment/platform-authority-bootstrap-identity-grant.py` with
`--source-commit`, `--binding`, `--expected-binding-sha256`, operation and existing
operation arguments. The binding selects v2 and the launcher adds the internal
`--identity-grant-version 2` flag. Do not pass a JWT or operation nonce in argv.
Use the canonical operation's explicitly verified short-lived SSO profile;
the foundation administrator is not the normal Apply identity.

## César's single-owner operation

The [owner decision](gug274-single-owner-decision-20260914.md) applies only to
authority `042360977644`, `us-east-1`, destination `905418363887`. Configure the
three immutable functions with `OperatorPolicyMode=single_owner_v1`, the same
reviewed start/end as the operator binding, and `IdentityGrantVersion=2`.
`PlanIdentityStoreUserId` is César's actual Identity Store reference;
`SecondPartyIdentityStoreUserId` is empty. `cesar-guzman` is the required public
operator label, not an authenticated user ID.

Use the existing Plan, review and Apply operations and their separate scoped
profiles. The launcher derives the mode and timestamps from the pinned schema3
binding; supplying those internal flags as caller arguments is rejected. Plan
expires at the earlier of one hour or policy expiry and rejects fewer than five
remaining minutes. Each operation obtains a fresh operation-bound grant.

Plan/Approval schema3 and proof/ledger/authority-receipt schema2 explicitly carry
`authorization_mode=single_owner_v1`, `independent_approval_present=false`, and
`operator_policy_digest`. The identity binding uses domain v3. The exact configured
policy is checked in the broker; rehashing a caller-edited record supplies no
authorization. Existing independent records cannot be relabeled or migrated.

The same Change Set keeps the same ledger key and trust-root generation across
modes. An existing incompatible or terminal record blocks another attempt;
never delete or reset it. Expiry is rechecked after provider/storage work,
after the terminal claim, and before each effect. Expiry after a terminal claim
leaves it consumed even if no effect ran; reconcile the actual outcome.

## Connected acceptance before activation

Verify these properties against the selected issuer and actual AWS responses:

- Public authorization-code client with PKCE, the exact loopback callback and
  no returned refresh token. The issuer must provide RS256 ID tokens containing
  `iss`, scalar `aud`, `sub`, `jti`, `nonce`, integer `iat`, `exp`, `auth_time`.
- Assertion lifetime at most 900 seconds, authentication age at most 300 seconds,
  no future dates, and exact operation nonce. Defaults from a familiar provider
  are not evidence of compatibility. Array audiences are deliberately rejected.
- Trusted issuer discovery/signature configuration and unique user mapping;
  exactly the reviewed issuer/audience in the application's JWT grant. Read back
  the actual ARN, assignment requirement, grant and actor policy. Do not derive
  an ARN or user identifier from an example.
- Fresh Plan, selected-mode review and Apply proofs with the expected STS user
  boundaries. Wrong user, changed operation, expired assertion, reused JTI and
  uncertain exchange must fail before any new ledger transition or effect.
- Actual exchanged scope, refresh absence, lifetime and provider context.
  The AWS token API has no lifetime request parameter; a 3,600-second response
  still fails the current implementation. A local timer or 900-second STS role
  does not shorten an upstream token. Different response/TTL handling requires
  an explicit reviewed contract change and corresponding tests.

Do not activate the application merely because local tests pass. Continue the
signed package, protected-main evidence and installation sequence in the
[production recreation playbook](../operations/production-recreation-playbook.md)
only with the actual connected acceptance evidence and exact reviewed changes.
Application runtime installation and the real document journey remain separate.

## Validation and rollback

Local tests exercise the real parser, launcher/CLI pipes, runtime configuration,
broker and proof verifier. Only external provider/storage/effect boundaries use
synthetic responses. They test failure ordering and custody, not AWS signature
acceptance, a real human sign-in or deployed production. The
[validation record](gug274-jwt-validation-20260914.md) records the final tested
files and results separately.

The Lambda source closure now includes the JWT module; the operator provenance
closure includes the OIDC client. SDK pins and the package-v2 format are
unchanged. A changed source commit requires fresh package/manifest digests,
signing and protected publication evidence. The unsigned `997354d` ZIP is
historical evidence and cannot deploy these changes.

No v2 resources have been installed, so rollback currently consists of reverting
only this reviewed local delta. For a future deployed v2 version, stop new
operations and reconcile outstanding/uncertain ledger claims before changing
configuration. Returning to v1 would restore the known rejected AWS grant; it
is not a proven operational recovery. Never reuse an old Apply or token, reset
a terminal claim, or relabel a v2 receipt to roll back.
