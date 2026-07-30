# ADR-043: Identity-Context-Compatible Retirement PEP

- **Status:** Accepted for repository implementation; live activation blocked
- **Date:** 2026-07-20
- **Work package:** GUG-217
- **Amends:** ADR-041 and ADR-042
- **Production:** **NO-GO**

## Context

ADR-041 requires two different immutable IAM Identity Center users to classify
and approve retirement of one exact retained CloudFormation Change Set. Its
original design attempted to let an identity-enhanced session invoke the
version-pinned Lambda broker directly.

ADR-042 established that this direct path is incompatible with the reviewed
default `AWSIAMIdentityCenterAllowListForIdentityContext` policy `v12`.
Identity-enhanced sessions receive an explicit `Deny` for actions outside the
policy's `NotAction` list, and that list does not contain
`lambda:InvokeFunction`. Adding an allow to the permission set, target role or
Lambda resource policy cannot override that managed explicit deny.

The same reviewed policy does permit the STS context-establishment action
needed to create a short-lived identity-enhanced session. That capability can
prove an immutable Identity Store user without granting the resulting session
authority over Lambda, CloudFormation or DynamoDB.

The current organization has only one human operator. Repository
implementation and synthetic tests may model both duties, but one person,
multiple profiles or separate time windows do not provide independent
approval.

## Decision

### 1. Managed policy `v12` is a proof-only compatibility boundary

GUG-217 reviews `v12` only for exact action `sts:SetContext`. A compatible
result is named `COMPATIBLE_PROOF_ONLY_TRANSPORT` and always carries
`live_effect_authorized: false`.

This decision does **not** claim that `v12` authorizes Lambda, CloudFormation,
DynamoDB or any retirement effect. The resulting identity-enhanced role is a
zero-authority proof object. Any managed-policy version or canonical digest
drift requires new readback, tests, security review and an explicit decision.

### 2. Ordinary invocation and identity proof are separate phases

The amended path is:

```text
exact classifier or approver permission-set session
  -> exact ordinary account-local invoker role
  -> exact alias Lambda Function URL (AWS_IAM, BUFFERED)
  -> version-pinned broker execution role
  -> CreateTokenWithIAM for the exact application
  -> opaque identityContext assertion
  -> STS AssumeRole + one ProvidedContexts entry
  -> exact deny-all classifier or approver proof role
  -> sanitized proof-receipt digest
  -> service-owned ledger CAS
  -> exact broker operation
```

There are three Function URLs, each bound to one published alias:

- classifier role: `classify` only;
- approver role: `retire` and `reconcile` only.

Every URL uses `AWS_IAM` and synchronous `BUFFERED` invocation. The invoker
policies require both `lambda:InvokeFunctionUrl` with
`lambda:FunctionUrlAuthType = AWS_IAM` and `lambda:InvokeFunction` with
`lambda:InvokedViaFunctionUrl = true` on the exact qualified alias. Those
policies deny direct, unqualified, `$LATEST` and asynchronous invocation for
the reviewed principals. Because another same-account identity policy could
independently grant `lambda:InvokeFunction`, live rollout additionally requires
an account-wide authority inventory or an explicit organization/permissions
boundary guardrail. The strict URL event shape and exact STS human proof remain
mandatory defense in depth; this repository does not claim that a Lambda
resource policy alone can deny every same-account identity grant.

The ordinary invoker roles never receive `CreateTokenWithIAM`, `sts:SetContext`,
CloudFormation retirement or DynamoDB write authority. The broker execution
role is the sole application actor allowed by the exact Identity Center
application policy and the sole principal that may create the proof session,
write the ledger or request the one reviewed retirement effect.

### 3. The request carries secrets but no authority selector

The Function URL accepts exactly one HTTP API v2 request:

- method `POST`;
- path `/`;
- no query string;
- `Content-Type: application/json`;
- non-base64 body;
- bounded body size;
- exact keys `schema_version`, `record_type`, `authorization_code` and
  `code_verifier`.

Account, Region, duty, alias, action, application, redirect URI, role, user,
stack, Change Set and ledger identifiers are forbidden request authority. The
invoked alias and immutable function configuration supply those bindings. The
redirect URI is exact configuration and cannot be overridden by the payload.

The authorization code and PKCE verifier are confidential one-time material.
They are consumed once, cleared best-effort from mutable in-process objects and
never logged, persisted or returned. Token responses, opaque context assertions
and STS credentials receive the same treatment. OIDC and STS calls do not
retry after uncertain outcomes.

### 4. STS proves the exact user in a zero-authority role

The broker passes the opaque `awsAdditionalDetails.identityContext` value to
STS as exactly one `ProvidedContexts` entry using
`arn:aws:iam::aws:contextProvider/IdentityCenter`. It never decodes a token or
accepts a caller-supplied UserId.

Two proof roles are immutable deployment bindings:

- `ScanalyzeGug217ClassifierProof` accepts only the exact broker principal and
  classifier UserId;
- `ScanalyzeGug217ApproverProof` accepts only the exact broker principal and
  approver UserId.

Their trust policies also bind the exact Identity Store, Identity Center
Instance and Application. Their only inline policy is an explicit deny of
every action on every resource; they have no attached policies or permissions
boundary. Requested proof duration is exactly 900 seconds. The broker validates
the returned assumed-role ARN and expiration against timestamps captured
immediately before and after `AssumeRole`, with at most 30 seconds of explicit
clock skew. It rejects expired or overlong sessions, clears returned
credentials and never uses those credentials for a downstream call.

The proof receipt contains only bounded status and digests. It cannot contain
authorization codes, PKCE values, tokens, assertions, credentials, emails, raw
UserIds, request bodies or provider responses.

### 5. Human proof is durable before a protected retirement effect

The proof-receipt digest is a required argument to the existing GUG-215 broker.
The broker rejects a missing or malformed digest and revalidates the exact
Function URL, invoker roles, proof roles, policies, aliases, artifact and
service-owned ledger before continuing.

The ledger records:

- classifier proof in the create-only `CLASSIFIED` item;
- approver proof in the `APPROVED` compare-and-swap transition;
- the same approved state before the `ATTEMPTED` one-shot claim and before
  `DeleteChangeSet`;
- reconciliation proof before the terminal CAS.

The protected CloudFormation effect can occur only after the independent
approver proof is durable and the one attempt has been consumed. Missing,
foreign, conflicting or replayed proof state fails closed. An uncertain delete
remains `ATTEMPTED` and permits reconciliation only, never a second delete.

### 6. Human proof and AWS effect attribution remain distinct

The STS proof demonstrates which immutable Identity Store user satisfied the
classifier or approver trust boundary. It does not turn that proof session into
the AWS effect principal.

CloudTrail for the retirement effect is expected to attribute the API call to
`ScanalyzeGug215BrokerExecution`. The ledger therefore records the human proof
digests separately from:

```text
aws_effect_principal = BROKER_EXECUTION_ROLE
native_on_behalf_of = false
effect_attribution = BROKER_SERVICE_PRINCIPAL_AFTER_STS_PROOF
```

Documentation and evidence must never claim native downstream `onBehalfOf`
attribution when the service event does not provide it.

### 7. Independent approval remains a real-person control

Live classification requires one actual classifier human and one immutable
UserId. Live approval, retirement and reconciliation require a different
actual human and a different immutable UserId. Equality is rejected in the
typed binding and deployment rules.

César is currently the only human operator. He may implement, review synthetic
fixtures, run local tests and perform separately authorized read-only inventory.
He cannot satisfy both live duties. A second profile, role, terminal, browser
session or delayed self-approval is not a second person. The founder-bootstrap
exception is out of scope and cannot authorize this retirement.

### 8. Repository implementation is not live authorization

GUG-217 does not authorize Identity Center provisioning, application changes,
Lambda or ledger deployment, token exchange, STS proof sessions, Function URL
invocation, Change Set deletion, Terraform Apply, customer deployment or
production.

Live use remains blocked until two independent humans exist and all GUG-215,
GUG-216 and GUG-217 provisioning, account-wide authority inventory, exact
readback, CI, non-production execution authorization, revocation and recovery
gates pass.

ADR-044/GUG-218 defines that inventory as a separate read-only capture and
pure analyzer. Only collector-sealed authenticated evidence can produce
`REVIEW_SAFE_REPORT_ONLY`; offline caller-authored evidence always blocks. A
clean result is still an observation, not a live invocation authorization or
preventive guardrail.

## Consequences

- The reviewed `v12` policy no longer needs to authorize Lambda; it is used
  only to prove a deny-all STS session.
- Ordinary sessions can reach only exact IAM-authenticated Function URLs and
  cannot manufacture identity proof.
- The broker remains the only mutation principal and becomes part of the
  OAuth/STS trusted computing base.
- Proof-role credentials are intentionally useless and never consumed.
- Human proof is durable before the one protected retirement effect.
- AWS effect attribution remains honest: service principal plus separately
  bound human proof, not native delegation.
- The sole-operator organization remains blocked from live use.

## Alternatives rejected

- **Drop `ProvidedContexts` and use ordinary SSO as identity:** loses immutable
  UserId proof.
- **Fight `v12` with broader Lambda allows:** an allow cannot override the
  managed explicit deny.
- **Use an unrelated allowlisted AWS service as a proxy:** expands the trusted
  computing base and creates a confused-deputy path.
- **Give the proof role useful authority:** converts an identity proof into a
  reusable effect credential.
- **Let request fields choose identity, alias, role or target:** creates IDOR
  and confused-deputy authority.
- **Use Lambda credentials returned by STS proof:** bypasses the broker-only
  mutation and attribution boundary.
- **Treat one person in two sessions as independent approval:** violates the
  governance and immutable-user model.
- **Log or persist request bodies for troubleshooting:** exposes bearer-like
  one-time secrets.

## Rollback and recovery

Before any live attempt, repository rollback removes the GUG-217 code and IaC
from the reviewed deployment package; it does not delete cloud resources.

After a separately authorized deployment, rollback means disabling/revoking
the exact human assignments and Function URL invoke authority, then performing
read-only reconciliation. Never delete or reset the GUG-215 ledger to recreate
an attempt. If the ledger is `ATTEMPTED`, only the original version-pinned
`reconcile` path may determine terminal state. Destructive cloud cleanup
requires a separate approved package.

## Evidence classification

| Class | Status |
|---|---|
| Implemented | Only on the exact reviewed GUG-217 commit containing the proof PEP, exact Function URL/IAM topology, ledger binding, schemas, tests and documentation |
| Locally validated | Only named local gates for that exact commit |
| CI validated | Not established until required PR checks pass |
| Live policy inventory | Historical read-only `v12` evidence only; it does not prove a deployed GUG-217 path |
| Live Function URL / broker deployment | **Not performed** |
| Live `CreateTokenWithIAM` | **Not performed** |
| Live STS `ProvidedContexts` proof | **Not performed** |
| Independent approver | **Blocked**; only one current human |
| Live retirement | **Blocked** |
| Production | **NO-GO** |

## Authoritative references

- [AWSIAMIdentityCenterAllowListForIdentityContext](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSIAMIdentityCenterAllowListForIdentityContext.html)
- [CreateTokenWithIAM](https://docs.aws.amazon.com/singlesignon/latest/OIDCAPIReference/API_CreateTokenWithIAM.html)
- [STS AssumeRole and ProvidedContexts](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)
- [Identity-enhanced IAM role sessions](https://docs.aws.amazon.com/singlesignon/latest/userguide/trustedidentitypropagation-identity-enhanced-iam-role-sessions.html)
- [Lambda Function URLs](https://docs.aws.amazon.com/lambda/latest/dg/urls-invocation.html)
- [Lambda Function URL authorization](https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html)
- [CloudTrail user identity](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html)
- [ADR-044 account-wide Lambda authority inventory](ADR-044-account-wide-lambda-invocation-authority.md)
