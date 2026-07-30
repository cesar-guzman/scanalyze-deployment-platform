# GUG-216 — Identity-enhanced operator session compatibility

## Purpose

GUG-216 models the missing repository-side exchange between a human IAM
Identity Center authorization and the immutable user context required by the
GUG-215 classifier and approver roles.

This source is sanitized. It contains no account/principal identifiers,
Identity Store UserIds, emails, assignments, application or role ARNs,
authorization codes, PKCE material, tokens, context assertions, temporary
credentials, CloudTrail, AWS responses or screenshots.

The implementation does not create Identity Center resources, issue a token,
assume a live role, invoke Lambda, mutate the GUG-215 ledger or retire a Change
Set. Production remains **NO-GO**.

## GUG-217 update

The GUG-216 compatibility result remains authoritative: an identity-enhanced
session cannot directly invoke Lambda under reviewed policy `v12`. GUG-217
does not broaden that policy. It uses `v12` only for the STS proof step inside
the broker, where the target proof role denies every action.

An ordinary exact `AWS_IAM` Function URL session reaches the broker first. The
broker exchanges one code, proves the immutable UserId, discards the proof
credentials and persists only a sanitized proof digest before the GUG-215
effect. No live use occurred, and a second actual human remains required.

## Why a normal SSO profile is insufficient

GUG-215 binds classifier and approver to different immutable Identity Store
UserIds. A normal SSO profile establishes an IAM role session but does not by
itself create the identity-enhanced `ProvidedContexts` assertion required by
the invoker-role trust policy.

AWS documents a two-step identity exchange:

1. `CreateTokenWithIAM` returns an opaque
   `awsAdditionalDetails.identityContext` assertion for an assigned user and
   exact application;
2. STS `AssumeRole` receives that assertion in exactly one `ProvidedContexts`
   entry using the Identity Center context provider.

The assertion should be treated as opaque. The application does not decode an
ID token to manufacture identity authority.

## The downstream compatibility blocker

AWS STS automatically attaches
`AWSIAMIdentityCenterAllowListForIdentityContext` to identity-enhanced role
sessions. The reviewed default version `v12` contains an explicit `Deny` with
a `NotAction` allowlist.

The GUG-215 invoker role needs `lambda:InvokeFunction`. That action is absent
from the reviewed allowlist, so the managed explicit deny applies. An allow on
the permission set, target role or Lambda resource cannot override it.

GUG-216 therefore reports:

```text
BLOCKED_AWS_IDENTITY_CONTEXT_ACTION_UNSUPPORTED
```

before it opens a browser, calls `CreateTokenWithIAM`, calls STS or invokes a
consumer. This is the intended fail-closed outcome.

The bundled `v12` policy snapshot supports deterministic local tests. It is not
evidence of the current live default policy version. A future rollout needs
authorized live readback plus a newly reviewed exact version and digest.

## Capability-bound adapter

The adapter models one authorization-code exchange and one short-lived STS
session for one exact capability. It never returns generic credentials.

Its immutable binding includes:

- exact non-production authority account and Region;
- exact Identity Center Application, Instance and Identity Store;
- operator duty and two different UserIds;
- exact source permission-set role and target invoker role;
- exact broker alias and required downstream action;
- 900-second role duration and bounded token lifetime.

Classifier maps only to `classify`. Approver maps only to `retire` or
`reconcile`. A caller cannot choose another role, alias, action, user or target.

The future-compatible synthetic path enforces authorization-code grant,
one-time PKCE material, exact loopback redirect, explicit
`sts:identity_context` scope, Bearer token, no refresh token, one opaque context
assertion, one `ProvidedContexts` value, no extra session policy/tags and
in-process credential consumption followed by clearing.

The injected clients and consumer are part of the trusted computing base.
Python cannot make an in-process object non-exportable; a future live consumer
must therefore be fixed and reviewed, must not retain or serialize session
material, and must treat map clearing only as defence in depth.

Uncertain OIDC, STS or consumer results are never retried automatically.

## Current and future people

César is currently the only human operator. He may implement, document, run
synthetic local tests and perform separately authorized read-only inventory.
He cannot provide both live classifier and independent approver authority.

A future live roster requires:

- one classifier human with one immutable UserId;
- a different approver human with a different immutable UserId;
- a governed Identity Center administrator for exact provisioning;
- a read-only security/audit reviewer;
- the non-human GUG-215 broker execution role as the only mutation principal.

Do not create placeholder users or assign César twice. Two profiles or
sessions for one person are not two-person approval. The founder bootstrap
exception does not apply to GUG-215.

## Exact policy boundaries

The classifier and approver source permission sets may call
`CreateTokenWithIAM` only for the exact reviewed application and may
assume/set context only into their corresponding exact invoker roles.

The application actor policy recognizes only the exact classifier and approver
provisioned role ARNs. GUG-216 does not provision that policy or any
application, grant, assignment or permission set live.

Direct CloudFormation retirement, DynamoDB writes, asynchronous Lambda invoke,
ordinary SSO fallback and caller-supplied context remain denied.

## Sanitized evidence

The compatibility receipt records only:

- public managed-policy ARN, reviewed version and canonical digest;
- exact required action and blocked status;
- observation time;
- `token_issued: false`;
- `sts_session_issued: false`;
- `broker_invocation_performed: false`;
- one current operator and no independent approver;
- `live_retirement_authorized: false`.

A synthetic session receipt may contain only digests of the binding, user and
role values plus bounded status and expiry. Raw secrets and identifiers are
invalid receipt fields.

## No bypass

GUG-216 rejects all of these alternatives:

- dropping `ProvidedContexts` to make Lambda work;
- treating a normal SSO profile as identity-enhanced;
- using an administrator or Lambda resource policy as a side door;
- broadening permissions to fight the managed explicit deny;
- repurposing an unrelated action from the allowlist;
- using one person for both GUG-215 duties;
- treating a local snapshot or synthetic fixture as live evidence.

A future live implementation requires AWS support for the exact downstream
action or a separate ADR for a PEP architecture that preserves immutable user
attribution and the one-shot GUG-215 ledger. There is no fallback in GUG-216.

## Sanitized read-only AWS inventory — 2026-07-20

The authorized management and authority readers passed STS identity
verification for their expected account classes. Full identifiers remain in
the private evidence system.

The live AWS-managed policy reported default version `v12`. Its canonical
digest was
`sha256:588e10587ff62c683615a9612b1f42ded9fccd03bd94810dc6760dad50665655`,
an exact match to the reviewed snapshot. The policy had 119 `NotAction` entries
and did not include `lambda:InvokeFunction`.

No Scanalyze Identity Center application, retirement classifier/approver
permission sets, GUG-215 invoker roles, broker Lambda or retirement ledger was
found. The platform-authority stack remained an empty `REVIEW_IN_PROGRESS`
shell with one retained Change Set listed as `AVAILABLE`.

`DescribeChangeSet` was blocked. The retained object's exact identity, type,
template, parameters, tags and change inventory are therefore **UNKNOWN**.
List-level availability is not proof that it matches the reviewed GUG-215
target.

The inventory was read-only. No token, STS identity-enhanced session, broker
invocation or AWS mutation occurred, and production remains **NO-GO**.

## Current evidence status

| Class | Status |
|---|---|
| Implemented | Repository guard, adapter contract, policy/schema sources, fixtures, tests and documentation in the isolated GUG-216 worktree |
| Locally validated | GUG-215/GUG-216 focused: **92 passed**; platform-authority gate: **211 passed** plus schema, policy and offline CLI checks; `make preflight-m2`: **1319 passed** plus **114/114** contract-matrix scenarios on pinned Python 3.11.14 and Terraform 1.14.6; documentation and independent security review passed |
| CI validated | **Not established** until required checks pass |
| AWS read-only inventory | **Completed 2026-07-20**: expected reader account classes, exact live `v12`/snapshot digest match, 119-entry exclusion of Lambda, and absence of GUG-215 identity/runtime resources. Detailed Change Set inventory is **UNKNOWN** because `DescribeChangeSet` was **BLOCKED** |
| Live `CreateTokenWithIAM` | **Not performed** |
| Live STS `ProvidedContexts` | **Not performed** |
| Live Lambda invocation | **Blocked** by reviewed managed-policy `v12` |
| Independent approver | **Blocked**; only one current human operator |
| Live GUG-215 retirement | **Blocked** |
| Production | **NO-GO** |

## Authoritative AWS references

- [CreateTokenWithIAM](https://docs.aws.amazon.com/singlesignon/latest/OIDCAPIReference/API_CreateTokenWithIAM.html)
- [AwsAdditionalDetails identityContext](https://docs.aws.amazon.com/singlesignon/latest/OIDCAPIReference/API_AwsAdditionalDetails.html)
- [STS AssumeRole ProvidedContexts](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)
- [Identity-enhanced IAM role sessions](https://docs.aws.amazon.com/singlesignon/latest/userguide/trustedidentitypropagation-identity-enhanced-iam-role-sessions.html)
- [AWS-managed identity-context allowlist](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSIAMIdentityCenterAllowListForIdentityContext.html)
- [Application resource policies](https://docs.aws.amazon.com/singlesignon/latest/userguide/iam-auth-access-using-resource-based-policies.html)

## Questions this source should answer

1. Why is a normal IAM Identity Center profile insufficient for GUG-215?
2. Which response field supplies the opaque trusted context assertion?
3. What must STS receive in `ProvidedContexts`?
4. Why does managed policy `v12` block `lambda:InvokeFunction`?
5. Why can a broader target-role allow not override that result?
6. What does the offline compatibility command prove and not prove?
7. Which secrets never appear in a receipt or log?
8. Why must the exchange be one-shot and capability-bound?
9. Why can César not act as both classifier and approver?
10. Which additional people and duties are required for a future live flow?
11. What review is required if AWS publishes a different managed-policy
    version?
12. Why does GUG-216 leave GUG-215 and production blocked?
