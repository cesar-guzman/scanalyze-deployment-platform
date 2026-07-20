# GUG-217 threat-model delta: identity-context-compatible retirement PEP

## Scope

This delta covers the split ordinary-invocation/identity-enhanced-proof design,
exact IAM-authenticated Lambda Function URLs, in-broker OAuth/STS proof,
zero-authority proof roles, durable proof-to-ledger binding and effect
attribution added to GUG-215 by GUG-217.

The repository implementation did not provision or invoke any live resource,
issue a token, create an identity-enhanced STS session or retire a Change Set.
Production is **NO-GO**.

## Assets

- immutable classifier and approver Identity Store UserIds;
- authorization code, PKCE verifier, access token and opaque identity context;
- exact Application, Instance, Identity Store and redirect binding;
- exact Function URL, alias and ordinary invoker-role authority;
- deny-all proof-role trust and policy;
- sanitized proof receipt and its canonical digest;
- GUG-215 ledger state, one-attempt claim and retained target;
- broker artifact, execution role and AWS effect attribution.

## Trust boundaries

### Human governance boundary

Two different actual humans and immutable UserIds are required. César is the
only current human and cannot provide live independent approval. Profiles,
roles, terminals and time separation are not people.

### Ordinary Function URL boundary

The human reaches one exact qualified Function URL through an ordinary
account-local invoker role. `AWS_IAM`, `BUFFERED`, exact principal,
`lambda:FunctionUrlAuthType` and `lambda:InvokedViaFunctionUrl` constrain the
reviewed principals to the URL path. They do not create a universal deny for a
different same-account identity policy that grants the Lambda API. The alias
supplies the duty, while live rollout also requires account-wide authority
inventory or an explicit organization/permissions-boundary guardrail. Strict
event validation and the exact STS proof prevent an unproved caller from
reaching ledger or target effects even if transport provenance is challenged.

### Secret transport boundary

The body contains bearer-like one-time authorization material. It has no
target selectors, but disclosure could permit token exchange before expiry.
No body, code, verifier, token or assertion may enter logs, traces, evidence or
durable state.

### Identity Center and STS proof boundary

Only the exact broker may call `CreateTokenWithIAM` for the exact application
and assume the exact proof role with one Identity Center `ProvidedContexts`
entry. STS evaluates the immutable UserId, Store, Instance and Application.
The resulting credentials have an explicit deny-all policy and are never used.

### Broker and ledger boundary

The broker is both proof verifier and sole mutation principal. It must bind a
sanitized proof digest into the service-owned CAS ledger before the protected
retirement effect. Broker code/policy compromise is therefore a high-value
trusted-computing-base risk.

### Attribution boundary

The human is evidenced by the STS proof receipt. CloudFormation sees the
broker execution role as the effect principal. These facts must remain
separate; native downstream `onBehalfOf` is not claimed.

## Threats and controls

| Threat | Control | Failure behavior |
|---|---|---|
| `v12` Lambda deny is relabeled compatible | Compatibility decision checks only exact `sts:SetContext` and fixes `live_effect_authorized` false | Drift or incompatible action blocks before OAuth |
| Broader IAM allow attempts to override `v12` | Identity-enhanced proof role is never the Lambda caller; its policy denies every action | No useful proof credential exists |
| Ordinary caller bypasses identity proof | Broker requires a valid proof-receipt digest for every operation and direct legacy entrypoint is disabled | Deny before ledger/target effect |
| Caller selects another user, alias, role, account or target | Request schema permits only code/verifier plus schema markers; alias and immutable config supply all authority | Additional or malformed fields deny |
| Foreign caller reaches Function URL | Exact ordinary invoker trust, qualified resource, `AWS_IAM`, principal policy and resource policy | AWS denies; any foreign authority blocks rollout |
| Caller invokes function directly or asynchronously | Reviewed principals have alias-qualified URL-only policies; strict event validation and exact STS proof still apply; rollout additionally proves no foreign identity grant or installs an account guardrail | Missing inventory/guardrail blocks live enablement; malformed or unproved call denies before ledger |
| Function URL points to `$LATEST` or another version | URL qualifier, alias version, code digest and signing config are read back by broker | Configuration drift denial |
| URL request body leaks through application logging | Handler emits sanitized response only, clears mutable body and uses no application payload logging | Security incident; stop and revoke |
| Platform access logs/proxies capture request bodies | Rollout requires account-wide observability review and body-capture prohibition | Live enablement blocked until proved |
| Authorization code or verifier is replayed | One-use envelope, OAuth authorization-code semantics, no retry and bounded lifetime | Replay/uncertainty denial; no automatic retry |
| Redirect URI is changed by caller | Exact loopback redirect is immutable configuration and absent from request authority | Binding denial before OIDC |
| OIDC response broadens grant/scope/lifetime | Exact authorization-code grant, Bearer type, exact scope, no refresh token, bounded lifetime | Stop before STS |
| Application decodes claims or trusts a caller UserId | Opaque AWS `identityContext` is passed unchanged to STS; proof-role trust evaluates UserId | No application-derived identity authority |
| Multiple or foreign context providers are supplied | Code constructs exactly one Identity Center `ProvidedContexts` entry | STS proof denied/test regression |
| Broker assumes foreign/useful or overlong role | Exact proof role ARN; fresh pre/post-`AssumeRole` expiry window; maximum 30-second clock skew; proof policy deny-all | Deny and clear response |
| Proof credentials are reused | Broker never instantiates a downstream client from them and clears credential map best-effort | Any use is a P0 regression |
| One person supplies both duties | Binding rejects equal UserIds and governance requires two different humans | `INDEPENDENT_OPERATOR_REQUIRED`; live blocked |
| Same code/session is treated as approval for multiple duties | Alias maps to one exact proof role/UserId; receipt binds role kind and alias | Digest mismatch/CAS denial |
| Proof exists only in transient response | Canonical proof digest enters `CLASSIFIED`, `APPROVED` or reconciliation CAS state | No protected effect without durable proof |
| Delete occurs before approval is durable | State machine requires approver proof in `APPROVED`, then one `ATTEMPTED` claim | CAS failure; no delete |
| Ambiguous delete is retried | SDK mutation retries disabled; `ATTEMPTED` is terminal for delete and allows reconciliation only | `RECONCILIATION_REQUIRED` |
| Human proof is misreported as CloudFormation caller | Ledger separates proof digests from broker effect principal and fixes `native_on_behalf_of=false` | Evidence rejected as overclaim |
| Function URL data event is assumed automatically audited | Runbook requires explicit audit design/readback and does not use default logging as proof | Missing evidence blocks live use |
| Broker role compromise forges proof or ledger | Exact code signing/version/policy digest, reserved concurrency, role readback, ledger resource policy and account-wide authority inventory | Any drift blocks; admin remains residual TCB |
| Synthetic test receipt is promoted to live evidence | Receipts label non-production and no live authorization; evidence classes remain separate | Live gate remains blocked |

## Attack-path result

The designed path is:

```text
ordinary exact human session
  -> exact alias Function URL
  -> broker-only OAuth exchange
  -> STS deny-all identity proof
  -> durable proof digest
  -> GUG-215 CAS state
  -> broker service-principal effect
```

The split prevents the identity-enhanced session from reaching Lambda and
therefore preserves the reviewed `v12` explicit deny. The proof role cannot
perform the effect. The ordinary invoker cannot manufacture proof. The broker
cannot perform the protected retirement effect until the independent approver
proof is durable and the one attempt has been claimed.

The current attack path stops at the human-governance boundary because only
one actual operator exists. That safe denial applies even if all repository
tests pass.

## Residual risks

- The broker holds OAuth, STS, ledger and CloudFormation authority in one
  process and is a sensitive trusted computing base.
- Python best-effort clearing cannot guarantee secret erasure from memory.
- Authorization-code one-time semantics depend partly on IAM Identity Center;
  no local distributed replay cache is claimed.
- Lambda Function URL request metadata and platform logging require live
  review; application no-log behavior alone cannot prove end-to-end secrecy.
- IAM/Identity Center/Lambda administrators can rewrite bindings and remain a
  governance trust boundary.
- Lambda resource policies are not a universal explicit deny for every
  same-account identity policy. Live rollout therefore depends on a complete
  authority inventory or a separately reviewed account-level guardrail.
- STS proof establishes immutable user identity, not employment separation or
  freedom from collusion.
- CloudTrail downstream attribution remains the broker service principal, so
  audit correlation depends on the durable proof digest and ledger chronology.
- Function URL and CloudFormation observations can be eventually consistent;
  uncertain outcomes remain reconciliation-only.
- A future AWS-managed policy version may change semantics and requires a new
  canonical review.

## Evidence handling

Sanitized evidence may include public managed-policy ARN/version/digest,
commit and PR identifiers, named test results, non-sensitive reason codes,
proof-receipt digests and ledger status counts.

Never publish request bodies, codes, PKCE values, tokens, assertions,
credentials, emails, raw UserIds, application/role/account identifiers,
Function URLs, CloudTrail, ledger documents, Change Set IDs or AWS responses.

## Evidence classes

| Class | Status |
|---|---|
| Implemented | Repository-only until the exact GUG-217 commit is reviewed and merged |
| Locally validated | Pending final exact-commit gates |
| CI validated | Not established |
| Live identity/runtime deployment | **Not performed** |
| Live OAuth / STS proof | **Not performed** |
| Live broker effect | **Blocked** |
| Two-person approval | **Blocked**; only one current human |
| Production | **NO-GO** |

## Authoritative references

- [AWS-managed identity-context allowlist](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSIAMIdentityCenterAllowListForIdentityContext.html)
- [CreateTokenWithIAM](https://docs.aws.amazon.com/singlesignon/latest/OIDCAPIReference/API_CreateTokenWithIAM.html)
- [STS AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)
- [Identity-enhanced IAM role sessions](https://docs.aws.amazon.com/singlesignon/latest/userguide/trustedidentitypropagation-identity-enhanced-iam-role-sessions.html)
- [Lambda Function URL authorization](https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html)
- [Lambda Function URL monitoring](https://docs.aws.amazon.com/lambda/latest/dg/urls-monitoring.html)
- [CloudTrail user identity](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html)
