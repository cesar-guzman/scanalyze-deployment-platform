# Platform-Authority Identity-Context-Compatible Retirement PEP

## Scope

GUG-217 implements the repository contract that bridges ordinary IAM Identity
Center invocation and immutable UserId proof without asking an
identity-enhanced session to call Lambda.

It amends the GUG-215 retirement transport and the GUG-216 compatibility
decision. It does not deploy or invoke the path, mutate Identity Center,
retire a Change Set, run Terraform Apply, touch customer infrastructure or
authorize production. Production remains **NO-GO**.

## Architecture

| Layer | Exact responsibility | Explicit non-authority |
|---|---|---|
| Source permission-set session | Assume one exact classifier or approver invoker role | No Function URL, OAuth, context, ledger or retirement authority |
| Ordinary invoker role | Invoke only its exact `AWS_IAM` Function URL alias | No `CreateTokenWithIAM`, `sts:SetContext`, DynamoDB write or CloudFormation mutation |
| Exact alias Function URL | Synchronous `BUFFERED` transport for one operation | No caller-selected alias, action, user or target |
| Version-pinned broker role | Exchange the exact code, create proof session, validate runtime, write ledger and perform the exact broker operation | No customer account, stack execution/update/delete or repeated retirement attempt |
| Identity Center application | Allow `CreateTokenWithIAM` only for the exact broker execution role | No foreign application actor |
| Classifier/approver proof role | Let STS evaluate one exact immutable UserId and return a short-lived proof session | Explicit deny of every action; credentials are never used |
| GUG-215 ledger | Persist proof digests, approval and one-attempt CAS state | No caller or human writer |

The three public transport bindings are exact qualified aliases:

```text
classifier invoker -> Function URL :classify
approver invoker   -> Function URL :retire
approver invoker   -> Function URL :reconcile
```

Each URL is `AWS_IAM`, `BUFFERED`, and qualified to the reviewed published
version alias. IAM requires both Function URL authorization and
`lambda:InvokedViaFunctionUrl = true` for the reviewed invoker roles. Their
policies do not accept direct function invocation, `InvokeAsync`, unqualified
invocation or `$LATEST`. A separate same-account identity grant could still
authorize the Lambda API, so live enablement requires complete identity-policy
inventory or an account-level explicit guardrail; the Function URL resource
policy is not presented as a universal deny.

## Why managed policy `v12` is compatible only for proof

The reviewed default `AWSIAMIdentityCenterAllowListForIdentityContext` policy
still excludes `lambda:InvokeFunction`. GUG-217 does not reinterpret or bypass
that explicit deny.

Instead, the ordinary invoker reaches the Function URL without an
identity-enhanced session. Inside the broker, `v12` is evaluated only for
`sts:SetContext`. The broker then creates an identity-enhanced session in a
proof role whose effective policy denies every action. The session proves that
STS accepted the exact user/application/store binding; it is never used as an
effect credential.

The compatibility receipt is therefore proof-only and always states that no
live retirement effect is authorized.

## Immutable binding

The deployed broker configuration must bind all of these values before a
request is evaluated:

- authority account and Region;
- exact Identity Center Application, Instance and Identity Store;
- exact loopback redirect URI;
- two distinct immutable Identity Store UserIds;
- exact classifier and approver source permission-set role ARNs;
- exact ordinary invoker role names and policy digests;
- exact classifier and approver proof role names and deny-all policy digests;
- exact Identity Center application actor-policy digest;
- exact broker execution role, code, code-signing configuration and policy;
- exact qualified aliases and Function URL configurations;
- the complete existing GUG-215 stack, Change Set and ledger binding.

Missing, malformed, conflicting or drifted bindings fail closed. A request can
never supply or override them.

## Request contract and secret containment

The Function URL accepts only an HTTP API v2 event matching:

```json
{
  "schema_version": "1",
  "record_type": "platform_authority_identity_context_pep_request",
  "authorization_code": "<one-time-secret>",
  "code_verifier": "<pkce-secret>"
}
```

The request must be `POST /`, use `application/json`, have no query string and
not be base64 encoded. Additional keys are rejected. The example placeholders
are not usable credentials and must never be replaced in committed files.

The authorization code, PKCE verifier, access token, opaque context assertion
and temporary STS credentials are sensitive. The implementation:

- never writes them to logs, receipts, the ledger, Git, Linear or NotebookLM;
- clears the Function URL body and mutable response maps best-effort;
- consumes the code envelope once;
- uses no automatic retry after ambiguous OIDC or STS outcomes;
- returns `Cache-Control: no-store` and sanitized reason codes only.

Best-effort clearing is defence in depth, not proof that Python memory is
non-recoverable. The version-pinned broker and SDK clients remain part of the
trusted computing base.

## Identity proof

For `classify`, the broker targets `ScanalyzeGug217ClassifierProof`. For
`retire` and `reconcile`, it targets `ScanalyzeGug217ApproverProof`.

`CreateTokenWithIAM` must return a Bearer token with exact
`sts:identity_context` scope, bounded lifetime, no refresh token and one opaque
`awsAdditionalDetails.identityContext`. The assertion is never decoded.

STS receives exactly:

- the exact proof role;
- a random non-PII `gug217-<hex>` session name;
- 900-second duration;
- one `ProvidedContexts` entry with the Identity Center context provider.

The proof role trust requires the exact broker role, UserId, Identity Store,
Instance and Application. Its inline policy explicitly denies `*` on `*`.
The broker validates the returned assumed-role ARN and expiry against a fresh
request/response clock window, allows no more than 30 seconds of explicit
clock skew, clears the credentials and never calls another API with them.

## Ledger-before-effect ordering

The proof receipt contains digests and bounded metadata only. Its canonical
digest is mandatory broker input.

```text
classifier proof -> CLASSIFIED create-only item
approver proof   -> APPROVED CAS
approval         -> ATTEMPTED CAS (attempts = 1)
ATTEMPTED        -> one exact DeleteChangeSet request
reconcile proof  -> RETIRED_RECONCILED CAS after exact absence
```

The independent approver proof is durable before the protected retirement
effect. A missing, wrong-duty, conflicting or replayed digest cannot advance
the state machine. An uncertain delete leaves `ATTEMPTED` and cannot be
retried.

## Attribution model

Identity context proves the human at the STS trust boundary. The broker
execution role remains the AWS principal that writes DynamoDB and calls
CloudFormation.

Evidence must report both facts:

- human authorization: proof-receipt digests bound to distinct UserIds;
- AWS effect: `ScanalyzeGug215BrokerExecution` service principal.

The current design explicitly records `native_on_behalf_of = false`. Do not
claim CloudTrail native `onBehalfOf` attribution for the CloudFormation effect.

## Required people

Live use requires two different real people:

1. classifier with one immutable Identity Store UserId;
2. independent approver with a different immutable Identity Store UserId.

César is currently the sole operator. He may implement and run synthetic local
tests, but he cannot perform both live duties. Two profiles, roles, browsers,
sessions or time windows for César do not meet this control. Do not provision
placeholder users and do not reuse the founder-bootstrap exception.

## Live-enablement gates

Before any token exchange or Function URL invocation, all of the following
must be separately authorized and evidenced:

1. exact commit reviewed, required CI green and main verification complete;
2. two independent humans and distinct UserIds approved;
3. exact Identity Center application, grant, actor policy, permission sets,
   assignments and provisioned roles read back;
4. live `v12` version/document digest or a newly reviewed successor proved;
5. code-signed published broker version and all exact Function URL/resource
   policies read back with no foreign authority;
6. proof-role trust and deny-all effective policies read back;
7. GUG-215 ledger, resource policy, stack and exact retained target proved;
8. non-production execution authorization, monitoring, no-retry response and
   revocation plan approved;
9. account-wide inventory proves no alternate invoker, writer or deleter;
10. fresh recovery preflight remains fail-closed.

The current one-person roster fails gate 2. Stop before live provisioning or
invocation.

## Evidence classification

| Class | Status |
|---|---|
| Implemented | Repository artifacts only on the exact reviewed GUG-217 commit |
| Locally validated | Named tests and gates only for that commit |
| CI validated | Pending exact PR checks |
| Live Identity Center / IAM provisioning | **Not performed** |
| Live Function URL / broker deployment | **Not performed** |
| Live token or STS proof | **Not performed** |
| Live broker invocation / retirement | **Blocked** |
| Independent approver | **Blocked**; only one current human |
| Production | **NO-GO** |

## Related documents

- [ADR-043](../../ADR/ADR-043-identity-context-compatible-retirement-pep.md)
- [GUG-217 operations runbook](../operations/platform-authority-identity-context-pep.md)
- [GUG-217 threat-model delta](../security/gug-217-identity-context-pep-threat-model-delta.md)
- [GUG-215 retirement contract](platform-authority-change-set-retirement.md)
- [GUG-216 compatibility contract](platform-authority-identity-enhanced-session.md)
