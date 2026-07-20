# GUG-216 threat-model delta: identity-enhanced operator session compatibility

## Scope

This delta covers the offline compatibility guard, immutable operator binding,
one-shot `CreateTokenWithIAM` / STS `ProvidedContexts` adapter contract,
application actor policy, sanitized receipts and the human-separation boundary
for GUG-215.

The current repository command does not call AWS, open a browser, issue a
token, assume a role or invoke the broker. No Identity Center or Lambda resource
was created or changed. No Change Set was deleted or executed.

Production is **NO-GO**.

## Assets

- immutable classifier and approver Identity Store UserIds;
- exact Identity Center Application, Instance and Identity Store binding;
- authorization code, PKCE verifier, access token and opaque identity-context
  assertion;
- temporary STS credentials and exact assumed-role binding;
- reviewed AWS-managed policy version and canonical digest;
- GUG-215 alias capability and one-shot durable retirement state;
- sanitized compatibility and session receipts.

## Trust boundaries

### Human governance boundary

César is the sole current human operator. Repository work and read-only
inventory are allowed within their separate authorization, but one person
cannot provide both classifier and independent approver authority. Two
profiles, sessions or time windows do not create independent humans.

Live GUG-215 use requires two different people and two different immutable
Identity Store UserIds. No placeholder or duplicated assignment is accepted.

### Identity Center application boundary

The source permission-set role must be allowed to call
`CreateTokenWithIAM` for one exact application, and that application's actor
policy must independently name only the exact classifier and approver
provisioned role ARNs. Application, grant or assignment data supplied by the
request is not authority.

### OAuth and local callback boundary

Authorization code and PKCE material are process-local secrets. A future
browser flow is limited to authorization-code grant, PKCE, one exact loopback
callback and one-time consumption. The repository does not currently expose a
live callback server.

### STS context boundary

The only accepted identity assertion is the opaque
`awsAdditionalDetails.identityContext` returned by IAM Identity Center. STS
receives exactly one `ProvidedContexts` entry using the AWS Identity Center
context provider. Ordinary SSO sessions and caller-supplied context are not
accepted.

### AWS managed-policy compatibility boundary

AWS STS automatically attaches
`AWSIAMIdentityCenterAllowListForIdentityContext` to identity-enhanced sessions.
Its reviewed default `v12` policy explicitly denies every action not listed in
`NotAction`. `lambda:InvokeFunction` is absent, so the current GUG-215 broker
target is blocked before identity effects.

### Consumer and evidence boundary

Temporary credentials may be consumed only once in-process by the exact bound
capability and are then cleared. Receipts contain digests and status only.
Tokens, assertions, credentials, UserIds, emails and raw provider responses
must never reach output, logs or durable public evidence.

## Threats and controls

| Threat | Control | Failure behavior |
|---|---|---|
| Target-role allow is mistaken for sufficient authority | Compatibility guard models the STS-managed explicit `Deny` / `NotAction` before OAuth or STS | `BLOCKED_AWS_IDENTITY_CONTEXT_ACTION_UNSUPPORTED`; no token, session or consumer call |
| A broader permission set or Lambda resource policy is added to bypass the managed deny | Documentation and tests require exact source/actor policies and reject resource-policy/direct-invoke bypasses; explicit deny cannot be overridden | Live use remains blocked; policy broadening is a security regression |
| Bundled public policy snapshot is treated as live evidence | Snapshot is labeled offline-only; live enablement requires authorized default-version/document readback and exact digest review | Missing or stale live evidence is `UNKNOWN` and blocks |
| AWS changes the managed policy silently | Exact version plus canonical digest binding; any drift requires a new snapshot, tests, ADR/security review and authorization | `POLICY_DIGEST_UNREVIEWED` or version denial before effects |
| A malformed or ambiguous managed policy is evaluated permissively | Guard accepts one exact `Deny` / `NotAction` structure and rejects extra/missing statements, duplicates and altered resources/effects | Fail closed with sanitized policy error |
| Synthetic compatible fixture is presented as AWS support | Synthetic path is test-only; compatibility receipt for current snapshot forces all effect flags false | No live claim or execution |
| One person performs classifier and approver duties | Binding rejects equal UserIds; organizational roster requires two different people | `INDEPENDENT_OPERATOR_REQUIRED`; live GUG-215 blocked |
| Two profiles for César are treated as two operators | Human separation is person/UserId based, not profile/session based | Stop; no assignment or invocation |
| A placeholder user or invented UserId is configured | Live roster and assignment readback require real immutable Identity Store users; repository fixtures are synthetic only | Stop before provisioning or token exchange |
| Caller redirects authority to another account/application/role/alias | Immutable typed binding validates exact topology, source/target role names, duty and alias | Binding denial before OIDC |
| Foreign application actor obtains a token | Exact application actor policy principals plus exact source identity policy resource | AWS denies; any foreign actor blocks rollout |
| OAuth grant broadens to refresh, JWT bearer or token exchange | Adapter uses authorization-code grant only, explicit scope and rejects refresh tokens | Deny response and stop before STS |
| Authorization code is replayed | Mutable grant wrapper marks the code consumed before token exchange and rejects reuse | `AUTHORIZATION_CODE_REPLAY`; no second exchange |
| Authorization callback is redirected off-device | Only `http://127.0.0.1:<ephemeral-port>/callback`, no query, fragment, credentials or alternate host | `REDIRECT_URI_INVALID` before OIDC |
| Malicious callback changes state or PKCE verifier | Future live entrypoint must use high-entropy state/PKCE and exact constant-time state validation; current repo exposes no browser callback | Callback rejected; no token exchange |
| Token response omits or changes identity context | Exact Bearer/type/scope/lifetime and non-empty opaque `awsAdditionalDetails.identityContext` checks | Stop before STS |
| Application parses or trusts self-decoded JWT claims | Adapter consumes the AWS-provided opaque context assertion and never derives UserId from a decoded token | No caller-derived identity authority |
| Multiple or foreign context providers are sent to STS | AssumeRole request contains exactly one `ProvidedContexts` entry with the Identity Center provider | Tests reject any request-shape expansion |
| Caller adds session policy, tags, source identity or external ID | Adapter emits only RoleArn, random RoleSessionName, 900-second duration and one ProvidedContexts value | Additional session authority is absent by construction |
| Session name leaks PII | Random `gug216-<hex>` name independent of email or UserId | No user locator in session name or receipt |
| STS returns credentials for a foreign role/account | Exact assumed-role ARN shape, account and role validation | `STS_ASSUMED_ROLE_MISMATCH`; consumer not called |
| Token, context or credentials leak through `repr`, receipt or logs | Secret dataclass fields use non-revealing representations; schemas forbid raw secret/user fields; output is sanitized | Tests fail; no public evidence accepted |
| Session material becomes reusable authority | Adapter is capability-bound, returns no session material and clears mutable maps after consumer completion; injected clients and the consumer are explicitly part of the trusted computing base | Future live consumer must be fixed and reviewed; no shell process, temp file, serialization, logging or return value; clearing is defence in depth rather than proof of non-exportability |
| OIDC, STS or consumer error triggers retry | Errors are converted to sanitized uncertain codes; no retry loop | Stop and reconcile; never repeat automatically |
| Consumer claims broker invocation without performing it | Current receipt fixes `broker_invocation_performed` and `live_retirement_authorized` false | Schema rejects overclaim |
| Identity context is omitted to make Lambda work | ADR-042 explicitly rejects ordinary AssumeRole or ordinary SSO fallback | Live workflow remains blocked |
| Unrelated allowlisted AWS service is used as a proxy bypass | Any downstream redesign requires a separate ADR preserving immutable user attribution and the GUG-215 PEP | No implicit alternate service path |
| Read-only AWS inventory is partial or denied | Exact account/profile, pagination, policy version/document and assignment readback are mandatory under separate authorization | `UNKNOWN`; no mutation or token test |

## Current attack-path result

The intended path is:

```text
exact assigned human
  -> exact Identity Center application authorization code
  -> CreateTokenWithIAM
  -> opaque identityContext
  -> STS AssumeRole with ProvidedContexts
  -> exact GUG-215 invoker role
  -> lambda:InvokeFunction on one qualified alias
```

The reviewed AWS-managed policy stops the path at the final AWS action. This is
a safe denial, not an implementation failure to work around. The offline guard
stops earlier, before token issuance, so no sensitive session is created for a
capability AWS will deny.

Even if AWS later permits Lambda, the path remains blocked until classifier and
approver are two different actual users and every ADR-041 deployment/readback
gate passes.

## Sanitized AWS read-only evidence — 2026-07-20

Read-only STS verification succeeded for the expected management and authority
account classes without publishing complete identifiers. The live managed
policy reported default `v12` with canonical digest
`sha256:588e10587ff62c683615a9612b1f42ded9fccd03bd94810dc6760dad50665655`,
matching the reviewed snapshot. Its 119 `NotAction` entries excluded
`lambda:InvokeFunction`.

No Scanalyze Identity Center application, retirement source permission sets,
GUG-215 invoker roles, broker Lambda or retirement ledger was observed. The
authority stack was an empty `REVIEW_IN_PROGRESS` shell with one list-visible
retained Change Set in `AVAILABLE` state.

The session could not call `DescribeChangeSet`. Detailed target identity and
content are therefore **UNKNOWN**. This partial readback activates the existing
ambiguous-inventory stop control: it is not valid proof that the retained
object is the reviewed GUG-215 target. No token, identity-enhanced STS session,
broker invocation or mutation occurred.

## Residual risks

- AWS-managed policies can change independently of the repository. The
  snapshot detects reviewed behavior locally but cannot prove current live
  behavior.
- The adapter core models the exchange with injected clients; the repository
  does not yet contain a reviewed live browser callback or SDK client factory.
- A future application administrator can change grant, actor policy or
  assignments. Exact live readback and governance remain required.
- Identity context proves immutable user identity, not organizational
  independence. Human governance must confirm classifier and approver are
  actually different people.
- CloudTrail support for `onBehalfOf` varies by AWS service. Audit design cannot
  assume every downstream event exposes it.
- A control-plane administrator able to rewrite Identity Center, IAM or Lambda
  remains a trusted boundary outside application authorization.
- A future downstream redesign could accidentally create a confused-deputy
  path. It must retain exact application audience, actor, user, role, alias and
  target bindings and receive separate threat modeling.

## Evidence handling

Public/sanitized evidence may include the exact repository commit, named test
results, managed-policy public ARN/version/digest, compatibility status and
false effect flags.

Keep real UserIds, emails, assignments, application/role/account identifiers,
authorization codes, PKCE values, tokens, assertions, credentials, CloudTrail
and AWS responses outside Git, PRs, Linear and NotebookLM.

## Evidence classes

| Class | Status |
|---|---|
| Implemented | GUG-216 guard, adapter contract, exact policy/schema sources, fixtures, tests and documentation in the isolated worktree |
| Locally validated | GUG-215/GUG-216 focused: **92 passed**; platform-authority gate: **211 passed** plus schema, policy and offline CLI checks; `make preflight-m2`: **1319 passed** plus **114/114** contract-matrix scenarios on pinned Python 3.11.14 and Terraform 1.14.6; documentation and independent security review passed |
| CI validated | **Not established** until required checks pass |
| AWS live compatibility readback | **Read-only completed 2026-07-20**: expected reader account classes, live `v12` and snapshot digest match, 119 entries excluding Lambda. GUG-215 application/permission sets/runtime absent; detailed Change Set inventory **UNKNOWN** because `DescribeChangeSet` was **BLOCKED** |
| Live OAuth/token exchange | **Not performed** |
| Live STS identity context | **Not performed** |
| Live broker invocation | **Blocked** by managed-policy `v12` and missing second human |
| Live retirement | **Blocked** |
| Production | **NO-GO** |

## Authoritative references

- [AWS-managed identity-context allowlist](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSIAMIdentityCenterAllowListForIdentityContext.html)
- [CreateTokenWithIAM](https://docs.aws.amazon.com/singlesignon/latest/OIDCAPIReference/API_CreateTokenWithIAM.html)
- [AwsAdditionalDetails identityContext](https://docs.aws.amazon.com/singlesignon/latest/OIDCAPIReference/API_AwsAdditionalDetails.html)
- [STS AssumeRole ProvidedContexts](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)
- [Identity-enhanced IAM role sessions and logging](https://docs.aws.amazon.com/singlesignon/latest/userguide/trustedidentitypropagation-identity-enhanced-iam-role-sessions.html)
- [Identity Center application resource policies](https://docs.aws.amazon.com/singlesignon/latest/userguide/iam-auth-access-using-resource-based-policies.html)
