# Express production: human access implementation plan

## Confirmed scope and evidence

- Target: **new production environment** in AWS account `905418363887`, Region
  `us-east-1`; the owner confirmed this destination. Do not request account
  approval again or reinterpret the target as the existing DEV environment.
- Delivery objective: initial production use on Friday, September 11, 2026.
- This is a technical plan for reviewing identity changes, not deployment proof.
- Review used the current express-production worktree and official provider
  documentation. No AWS call, real login, customer data, or connected test was
  performed for this plan. No authentication or provider code was changed.
- Preserve the existing phishing-resistant MFA, freshness, membership, object
  authorization, tenant isolation, and durable-audit requirements.

## Current blockers

| Blocker | Current implementation | Required outcome |
| --- | --- | --- |
| No trusted authentication event | `backend/workers/scanalyze-ingest-api/app/auth.py`, `_resolve_human_authorization_snapshot`, sets all four assurance/provenance fields to `None`. | A reviewed provider adapter supplies event-bound evidence. |
| Sensitive reads deny | `app/enterprise_authorization.py`, `RESULTS_READ_FULL` and `_require_step_up`, require `read+admin`, the exact provenance tuple, and authentication age `0..300` seconds. | Preserve these checks; satisfy them with verified evidence. |
| PDP runtime is not installed | `app/main.py`, `create_app`, does not install `EnterpriseAuthorizationRuntime`; no production constructor was found in backend. | Compose current membership, audit references, and durable authorization audit at startup. |
| Lifecycle runtime is a different type | `app/user_lifecycle_adapters.py`, `compose_enterprise_lifecycle_runtime`, returns `EnterpriseLifecycleRuntime` only. | Reuse applicable storage patterns without treating lifecycle audit as a PDP audit receipt. |
| Hosted login trigger is rejected | `backend/lambdas/scanalyze-identity-control-plane/src/identity_control_plane/pre_token.py` permits only `TokenGeneration_Authentication` and `TokenGeneration_RefreshTokens`. SPA uses the OAuth authorization endpoint. | Review `TokenGeneration_HostedAuth` and initial `TokenGeneration_NewPasswordChallenge` with the same membership checks. |
| Renewal timing is incompatible | Backend rejects a membership snapshot older than 300 seconds; `modules/identity-control-plane/cognito.tf` sets access tokens to 15 minutes. `AuthProvider.tsx` has no explicit renewal before 300 seconds. | Refresh membership before its deadline; refresh must not renew step-up evidence. |
| Runtime promotion is undeclared | `modules/identity-control-plane/pre_token.tf` and `modules/services/locals.tf` hardcode human gates to false; `modules/services/variables.tf` requires the contract flag to remain false. | Introduce one reviewed rollout contract after dependencies are composed and validated. |
| Provider cannot express the proposed setting | Identity root locks AWS provider `5.100.0`; the module requires `~> 5.80`. That version's user-pool resource has no WebAuthn configuration. | Select and validate a compatible provider version before writing those arguments. |

## Proposed integration, in implementation order

1. **Resolve the provider and domain contract.** Review the exact RP ID, browser
   origin, Cognito domain, callback, logout URL, and new environment identifiers.
   Scope: `modules/identity-control-plane/cognito.tf`, `variables.tf`,
   `versions.tf`, relevant identity-root inputs/lockfile, and their tests.
   Native passkey MFA requires `UserVerification=required` and
   `FactorConfiguration=MULTI_FACTOR_WITH_USER_VERIFICATION`; retain MFA ON.
   Explicitly enable `WEB_AUTHN` in the pool sign-in policy and `ALLOW_USER_AUTH`
   for the exact app client; its current explicit flow is refresh only. Preserve
   the reviewed hosted-login path for initial enrollment and ordinary access.
   Verify the selected SDK/provider supports these exact settings. Inventory
   shared provider constraints before proposing any upgrade beyond this root.
2. **Complete ordinary human runtime and issuance.** Scope:
   `backend/workers/scanalyze-ingest-api/app/main.py`, `config.py`, a narrowly
   scoped authorization adapter, and identity `pre_token.py` with its tests.
   Install all three `EnterpriseAuthorizationRuntime` ports from trusted startup
   configuration. Read current membership consistently from its owner-bound key.
   Supply typed opaque audit references and the exact durable PDP audit receipt
   before allowing the handler's effect. Never install request callbacks as ports.
   Review hosted and initial-password triggers explicitly; retain rejection of
   foreign pools/clients, inactive membership, unknown roles, and stale policies.
   Bootstrap and invitation states must permit the intended first-login path;
   changing a password alone must never grant membership or assurance.
3. **Implement a bounded native passkey challenge adapter.** Proposed new scope:
   `app/authentication_assurance.py`, its Cognito adapter, and an authenticated
   step-up route registered by trusted startup code. Use `InitiateAuth(USER_AUTH)`
   followed exclusively by the expected `WEB_AUTHN` challenge and
   `RespondToAuthChallenge`. Browser code performs the WebAuthn ceremony; the
   server observes the provider's final response directly. A fallback password,
   OTP, remembered-device flow, or incomplete response cannot establish assurance.
   Use short-lived, one-use challenge state bound to the initiating session.
4. **Bind success to a new verified token.** Scope: the assurance adapter and
   `app/auth.py`. Verify the new Cognito access token returned by the completed
   challenge, including issuer, client, subject, customer/deployment, and times.
   Persist the event only after provider success and exact subject continuity.
   Resolve evidence for that exact token/session before building its snapshot.
   Do not alter an old token's `iat` or replace its authentication time with the
   local clock. Keep the existing operation policy and 300-second bounds intact.
5. **Complete scope issuance and passkey enrollment.** API-based Cognito sign-in
   normally returns `aws.cognito.signin.user.admin`, not the application's custom
   action scopes. Review pre-token V2 scope additions against current membership
   and the canonical scope catalog; do not copy scopes from client metadata.
   Enrollment APIs need `aws.cognito.signin.user.admin`; current SPA does not
   request it. Review client attribute write permissions before exposing that
   scope. Document initial enrollment, additional devices, loss, and recovery.
6. **Integrate session UX and renewal.** Scope:
   `frontend/scanalyze-frontend-ui/src/auth/AuthProvider.tsx`, auth helpers, and
   the result-access UI. Install the new verified session through the existing
   OIDC abstraction; do not create a second token-storage mechanism. Refresh
   membership before 300 seconds and require a new ceremony for expired step-up.
   Preserve failed/cancelled-step-up state and avoid recursive retry loops.
7. **Promote the explicit runtime contract.** Scope: identity/service contract
   projections, human runtime gates, workload IAM, startup checks, and tests.
   Gate enablement on exact configured adapters, tables, pool/client, ownership,
   and policy binding. The infrastructure execution plan owns provisioning order,
   reviewed commands, deployment authorization, and cloud readback.

## Trusted event requirements

- Exact normalized tuple: `phishing_resistant_mfa`,
  `authoritative_authentication_event_v1`, `phishing-resistant-mfa.v1`, and a
  valid opaque authentication-event reference.
- Provider success must come from the configured adapter's actual challenge
  completion response, never a browser-supplied success flag or token alone.
- Bind issuer/pool, client, immutable subject, customer, deployment, challenge,
  and the new token's identity. Prefer the exact token `jti` for initial scope;
  any refresh-lineage support needs explicit anti-replay and expiry semantics.
- Validate expected RP/origin and required user verification through the
  provider configuration and ceremony. Configuration alone does not prove use.
- Keep original authentication time and an expiry no later than 300 seconds.
  A token refresh, membership change, or reused opaque reference cannot extend it.
- Persist with conditional writes; confirm durable event and audit storage before
  returning elevated access. Deny on missing, conflicting, stale, or unavailable
  evidence. Never persist raw JWTs, challenge sessions, assertions, or credentials
  in the durable audit/evidence record or logs.
- Do not infer assurance from custom attributes, groups, `ClientMetadata`, MFA
  enrollment, `auth_time`, or a successful generic post-authentication trigger.
  `AdminListUserAuthEvents` is not an established method/session proof here.

## Required negative and connected tests

- Hosted login, first approved login, and refresh preserve membership validation;
  unknown trigger, foreign pool/client, disabled membership, or digest drift deny.
- Missing runtime, inconsistent current membership, wrong audit receipt, and
  audit/store timeouts deny before any protected effect.
- Password/TOTP/OTP success, absent user verification, wrong RP/origin, cancelled
  or expired challenges, replay, and substituted provider responses never elevate.
- Events from another token, user, client, customer, or deployment never elevate;
  a browser custom claim or event reference cannot choose trusted authority.
- Authentication and snapshot ages at 300 seconds pass only with all other
  checks; 301 seconds and future times deny. Refresh never renews assurance.
- Verify scope issuance for API sign-in and ordinary session continuity beyond
  five minutes. Enrollment must not permit changes to authorization attributes.
- Exercise real Cognito sign-in, enrollment, fresh step-up, full results, expiry,
  and two-deployment isolation with approved synthetic accounts/documents before
  release. Local fixtures and browser mocks cannot supply this evidence.

## Unresolved choices and rollback

The account/Region/new-environment decision is complete. Remaining choices are
the exact RP/domain/origins, compatible pinned SDK/provider versions and their
upgrade scope, enrollment/recovery policy, and review of this identity design.
These are prerequisites for a concrete high-risk patch, not new account approval.

Rollback disables both human runtime gates and verifies denial while preserving
membership/event/audit records, object authorization, and M2M boundaries. A code
revert must not remove the PEP or privacy protections. Resource deletion is not
the rollback procedure. Production readiness remains unproven until connected
tests and deployment evidence exist.

## Primary sources checked

- [AWS WebAuthn configuration and MFA factor semantics](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_WebAuthnConfigurationType.html).
- [AWS authentication flows, including native passkeys](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-authentication-flow-methods.html).
- [AWS RespondToAuthChallenge](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_RespondToAuthChallenge.html).
- [AWS pre-token triggers, inputs, and scope customization](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-pre-token-generation.html).
- [AWS access-token claims and API sign-in scopes](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-access-token.html).
- [AWS passkey enrollment authorization](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_StartWebAuthnRegistration.html).
- [AWS post-authentication inputs](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-post-authentication.html).
- [AWS auth-event challenge response schema](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ChallengeResponseType.html).
- [HashiCorp AWS provider 5.100.0 user-pool source](https://raw.githubusercontent.com/hashicorp/terraform-provider-aws/v5.100.0/internal/service/cognitoidp/user_pool.go).
