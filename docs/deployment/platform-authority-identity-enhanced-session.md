# Platform-Authority Identity-Enhanced Operator Session

## Scope

GUG-216 implements the repository-side contract for exchanging one IAM
Identity Center authorization code through `CreateTokenWithIAM`, attaching the
returned opaque identity context to one STS `AssumeRole` call through
`ProvidedContexts`, and consuming the resulting short-lived credentials inside
one exact capability.

The implementation is intentionally offline and fail-closed for the current
GUG-215 downstream target. It does not create or provision an Identity Center
application, grants, authentication methods, assignments, permission sets or
roles. It does not call AWS, open a browser, create a token, assume a live role,
invoke Lambda, mutate the GUG-215 ledger or retire a Change Set.

Production remains **NO-GO**.

## GUG-217 amendment

The compatibility result in this document remains valid for direct Lambda
invocation. ADR-043 / GUG-217 introduces a separate proof-only PEP: an ordinary
session invokes an exact `AWS_IAM` Function URL, and the broker then uses
`CreateTokenWithIAM` plus STS `ProvidedContexts` only to establish a deny-all
identity proof. The proof session never invokes Lambda or performs the effect.

The GUG-216 offline adapter remains non-live and is not a credential fallback.
See [the GUG-217 reference](platform-authority-identity-context-pep.md). That
architecture has not been provisioned or invoked and still requires two
independent humans.

## Current compatibility decision

AWS STS automatically attaches the AWS-managed policy
`AWSIAMIdentityCenterAllowListForIdentityContext` to identity-enhanced role
sessions. The reviewed default version `v12` is an explicit `Deny` whose
`NotAction` list defines the actions exempted from that deny.

The GUG-215 invoker roles require:

```text
lambda:InvokeFunction
```

That action is absent from the reviewed `v12` `NotAction` list. The resulting
decision is therefore:

```text
BLOCKED_AWS_IDENTITY_CONTEXT_ACTION_UNSUPPORTED
```

An allow in a permission set, target role or Lambda resource policy cannot
override this explicit deny. The correct behavior is to stop before OAuth,
STS or Lambda, not to broaden another policy or remove the identity context.

The checked-in managed-policy snapshot exists only for deterministic offline
tests. It is not live-policy evidence and cannot authorize a future exchange.

## Repository architecture

| Artifact | Responsibility |
|---|---|
| `tooling/platform_authority_identity_context_compatibility.py` | Canonicalize and validate the reviewed managed-policy snapshot; decide whether the exact required downstream action is compatible |
| `tooling/platform_authority_identity_enhanced_session.py` | Model immutable identity/application/role/alias bindings and a one-shot in-memory token-to-STS exchange |
| `scripts/deployment/platform-authority-identity-enhanced-session.py` | Expose only an offline `compatibility-check`; never call AWS or issue credentials |
| `policies/iam/aws-managed-identity-context-allowlist-v12.snapshot.json` | Reviewed public AWS-managed policy snapshot for reproducible tests, not live authority |
| `policies/iam/platform-authority-identity-enhanced-application-actor-policy.json` | Limit `CreateTokenWithIAM` application actors to the exact classifier and approver provisioned role ARNs |
| GUG-215 source permission-set policies | Permit `CreateTokenWithIAM` only for the exact application and assume/set-context only for the corresponding invoker role |
| GUG-216 schemas and fixtures | Reject ambiguous binding, effect overclaim and sensitive receipt fields |
| GUG-216 tests | Prove current-policy denial occurs before token/session/consumer effects and exercise a synthetic future-compatible path without AWS |

The adapter receives injected OIDC, STS and consumer interfaces. It does not
construct live clients. This keeps the current code testable without implying
that a live browser or SDK entrypoint exists. These injected implementations
are part of the trusted computing base: Python cannot make an in-process value
non-exportable, so a future production consumer must be fixed, reviewed and
forbidden from copying, retaining, serializing or logging session material.
Map clearing is defence in depth, not a substitute for that trust boundary.

## Binding contract

An `IdentityEnhancedBinding` is immutable and includes:

- exact non-production authority account and Region;
- exact Identity Center Application, Instance and Identity Store topology;
- duty: `classifier` or `approver`;
- expected immutable UserId and the peer UserId;
- exact provisioned source permission-set role;
- exact account-local invoker role;
- exact broker alias;
- exact required action `lambda:InvokeFunction`;
- role duration of 900 seconds;
- bounded token lifetime.

The contract rejects:

- equal expected and peer UserIds;
- source or target roles for the other duty;
- classifier aliases other than `classify`;
- approver aliases other than `retire` or `reconcile`;
- a customer-selected account, action, role or alias;
- malformed or cross-topology Application, Instance and Identity Store ARNs;
- production or an unreviewed environment.

The JSON binding contract records the current organizational fact explicitly:

```text
current_human_operator_count = 1
independent_approver_available = false
live_classification_authorized = false
live_retirement_authorized = false
```

Those fields are not feature flags. Changing them requires real people,
reviewed immutable UserIds, assignments, provisioning and a separate live
authorization. Do not place placeholder users in the contract.

## Operator duties

| Duty | Current/future owner | Exact authority |
|---|---|---|
| Repository implementer and read-only assessor | César, currently the only human operator | Code, documentation, synthetic local tests and separately authorized read-only AWS inventory only |
| Classifier | Future human A | Exact immutable UserId; source permission set `ScanalyzeAuthorityRetireClass`; alias `classify` only |
| Independent approver | Future human B, different from human A | Different immutable UserId; source permission set `ScanalyzeAuthorityRetireApprove`; aliases `retire` and `reconcile` only |
| Identity Center administrator | Future governed administrative duty | Exact application, actor policy, grant, assignment and provisioning changes; no direct retirement authority |
| Security/audit reviewer | Future read-only duty | Review policy versions/digests, bindings, CloudTrail and revocation evidence |
| GUG-215 broker execution role | Non-human service role | Sole ledger mutation and exact one-shot retirement authority under ADR-041 |

Two profiles or two time windows used by César are still one person. They do
not satisfy the classifier/approver separation. The founder bootstrap exception
does not apply to this operation.

## Compatibility guard

The guard accepts an exact policy ARN, version, document, required action and
reviewed canonical digest. It requires the reviewed policy structure to be one
unambiguous `Deny` / `NotAction` statement on all resources. Any extra or
missing statement, duplicated action, altered effect, unexpected version or
digest mismatch denies.

The offline command is:

```bash
python3 scripts/deployment/platform-authority-identity-enhanced-session.py \
  compatibility-check
```

Expected current output contains only sanitized facts:

```text
COMPATIBILITY_STATUS: BLOCKED_AWS_IDENTITY_CONTEXT_ACTION_UNSUPPORTED
MANAGED_POLICY_VERSION: v12
MANAGED_POLICY_DIGEST: sha256:<reviewed-canonical-digest>
TOKEN_ISSUED: false
STS_SESSION_ISSUED: false
BROKER_INVOCATION_PERFORMED: false
INDEPENDENT_APPROVER_AVAILABLE: false
PRODUCTION: NO-GO
```

This command is not an AWS preflight. It does not prove the live default policy
version or document.

## Future compatible session sequence

This sequence describes adapter invariants for tests and a future separately
reviewed implementation. It is not an executable live procedure today.

1. Obtain one short-lived authorization code through an exact Identity Center
   application authorization-code grant using PKCE S256 and a loopback
   `127.0.0.1` callback.
2. Validate the exact callback path, port, state, code lifetime and one-time
   consumption locally.
3. Call `CreateTokenWithIAM` for the exact application ARN with explicit scope
   `sts:identity_context`.
4. Require `Bearer`, the exact scope, a bounded expiration, no refresh token
   and one non-empty `awsAdditionalDetails.identityContext` assertion.
5. Treat access token, authorization code, PKCE verifier and context assertion
   as secrets. Do not parse, log, persist or include them in an error.
6. Call STS `AssumeRole` for the exact invoker role with duration 900 seconds,
   a random non-PII session name and exactly one `ProvidedContexts` entry:

   ```json
   {
     "ProviderArn": "arn:aws:iam::aws:contextProvider/IdentityCenter",
     "ContextAssertion": "<opaque-in-memory-assertion>"
   }
   ```

7. Do not send session policies, tags, transitive tags, `SourceIdentity`,
   `ExternalId` or caller-selected authority.
8. Consume the temporary credentials once in-process for the bound capability,
   then clear the credential map. Never print or return credentials to a shell.
9. Treat any ambiguous OIDC, STS or consumer result as uncertain and never
   retry automatically.

The current compatibility guard prevents step 1 from beginning for the
GUG-215 Lambda target.

## Identity Center policy boundary

The source permission-set role must have both sides of authorization:

- its identity policy allows `sso-oauth:CreateTokenWithIAM` only for the exact
  Identity Center application ARN;
- the exact application actor policy allows only the classifier and approver
  provisioned role ARNs to call `CreateTokenWithIAM`.

The source role may assume/set context only into its matching invoker role.
Direct CloudFormation retirement, DynamoDB writes and asynchronous Lambda
invocation remain denied.

GUG-216 does not authorize `CreateApplication`,
`PutApplicationAuthenticationMethod`, `PutApplicationGrant`,
`CreateApplicationAssignment`, permission-set provisioning or assignment
changes. These operations require a separate reviewed live package.

## Receipt and evidence boundary

The compatibility receipt records the exact policy ARN, version and digest,
required action, denied status, observation time and false effect flags. The
session receipt used by synthetic compatible tests records only:

- binding, UserId and role ARN digests;
- policy version and digest;
- duty and broker alias;
- bounded expiration;
- boolean session-consumption state;
- `broker_invocation_performed: false`;
- `live_retirement_authorized: false`.

Schemas use `additionalProperties: false`. Raw tokens, assertions, AWS
credentials, emails and UserIds are not valid receipt fields.

Keep live account identifiers, Identity Store users, application/grant data,
assignments, sessions, CloudTrail and AWS responses in the approved private
evidence system. Git, PRs, Linear and NotebookLM receive only sanitized status,
digests, counts and named gate results.

## Live-enablement gates

All of the following are required before any live token exchange, in addition
to all ADR-041 gates:

1. a new reviewed AWS-managed policy version and canonical digest whose
   semantics permit the exact downstream action;
2. authorized live readback proving that exact version/document with no drift;
3. a reviewed live browser/PKCE and SDK client entrypoint;
4. exact Identity Center application, authorization-code grant, IAM actor
   policy and assignment configuration;
5. two genuinely different people with different immutable UserIds;
6. exact source and target role provisioning and readback;
7. account-wide proof that no foreign principal can reach the broker aliases;
8. green local and CI gates for the exact commit;
9. an explicit non-production execution authorization and rollback plan.

If AWS still excludes `lambda:InvokeFunction`, a separate ADR must redesign
the downstream PEP without losing immutable user attribution. GUG-216 supplies
no fallback.

## Sanitized AWS read-only inventory — 2026-07-20

The separately authorized management and authority read-only sessions both
passed STS identity verification against their expected account classes.
Complete account and principal identifiers remain private.

| Read-only check | Result | Evidence limit |
|---|---|---|
| AWS-managed identity-context policy | Default `v12`; canonical digest `sha256:588e10587ff62c683615a9612b1f42ded9fccd03bd94810dc6760dad50665655` matched the reviewed snapshot | Public policy compatibility only; no token/session proof |
| Required downstream action | Absent from all 119 reviewed `NotAction` entries | `lambda:InvokeFunction` remains explicitly denied for the identity-enhanced session |
| Identity Center application | No Scanalyze application found | No grant, actor policy or assignment can be inferred |
| Source permission sets | `ScanalyzeAuthorityRetireClass` and `ScanalyzeAuthorityRetireApprove` not found | No source assignments or provisioned roles can be inferred |
| GUG-215 runtime | No invoker roles, broker Lambda or retirement ledger found | Broker path is not deployed |
| Authority shell | `REVIEW_IN_PROGRESS`, zero resources, one retained list-visible Change Set in `AVAILABLE` state | Shell/list evidence only |
| Detailed retained target | `DescribeChangeSet` denied | Exact ID, type, template, parameters, tags and change inventory are **UNKNOWN** |

No AWS mutation, OAuth exchange, `ProvidedContexts` session or Lambda
invocation occurred. The missing runtime resources and denied detailed target
read are stop conditions, not remediation authority.

## Evidence status

| Class | Status |
|---|---|
| Implemented | GUG-216 repository artifacts in the isolated branch/worktree; not yet merge evidence |
| Locally validated | GUG-215/GUG-216 focused: **92 passed**; platform-authority gate: **211 passed** plus schema, policy and offline CLI checks; `make preflight-m2`: **1319 passed** plus **114/114** contract-matrix scenarios on pinned Python 3.11.14 and Terraform 1.14.6; documentation and independent security review passed |
| CI validated | **Not established** until required PR checks pass |
| AWS inventory | **Read-only completed 2026-07-20** with expected STS account classes, exact `v12`/snapshot digest match and confirmed Lambda incompatibility; GUG-215 application, permission sets and runtime were absent; detailed retained Change Set inventory remains **UNKNOWN** because `DescribeChangeSet` was **BLOCKED** |
| Live token issuance | **Not performed** |
| Live STS identity-enhanced session | **Not performed** |
| Live broker invocation | **Blocked** by managed-policy `v12` and missing independent approver |
| Live Change Set retirement | **Blocked** |
| Production | **NO-GO** |

## AWS references

- [CreateTokenWithIAM](https://docs.aws.amazon.com/singlesignon/latest/OIDCAPIReference/API_CreateTokenWithIAM.html)
- [AwsAdditionalDetails](https://docs.aws.amazon.com/singlesignon/latest/OIDCAPIReference/API_AwsAdditionalDetails.html)
- [AssumeRole ProvidedContexts](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)
- [Identity-enhanced IAM role sessions](https://docs.aws.amazon.com/singlesignon/latest/userguide/trustedidentitypropagation-identity-enhanced-iam-role-sessions.html)
- [AWSIAMIdentityCenterAllowListForIdentityContext](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSIAMIdentityCenterAllowListForIdentityContext.html)
- [Application resource policies](https://docs.aws.amazon.com/singlesignon/latest/userguide/iam-auth-access-using-resource-based-policies.html)
