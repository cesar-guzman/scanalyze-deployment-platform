# GUG-217 — Identity-context-compatible retirement PEP

## Purpose

GUG-217 preserves immutable human identity proof for the GUG-215 retirement
broker without requiring an identity-enhanced session to invoke Lambda.

This source is sanitized. It contains no account or role identifiers, UserIds,
emails, Function URLs, authorization codes, PKCE values, tokens, assertions,
credentials, Change Set locators, ledger documents, CloudTrail or AWS
responses.

The repository implementation did not deploy or invoke the PEP. It did not
issue a live token or STS session and did not retire a Change Set. Production
is **NO-GO**.

## The `v12` decision is proof-only

The reviewed AWS-managed identity-context policy `v12` does not permit
`lambda:InvokeFunction` in an identity-enhanced session. GUG-217 does not
bypass or weaken that explicit deny.

The policy does support the STS context-establishment step used to prove a
human identity in a short-lived role. GUG-217 calls that
`COMPATIBLE_PROOF_ONLY_TRANSPORT`. It never means Lambda, CloudFormation,
DynamoDB or retirement is authorized.

## Split-phase authorization

```text
ordinary duty-scoped human session
  -> exact AWS_IAM Function URL alias
  -> version-pinned broker
  -> exact CreateTokenWithIAM exchange
  -> opaque identityContext
  -> STS AssumeRole with ProvidedContexts
  -> exact deny-all proof role
  -> sanitized proof digest
  -> durable GUG-215 ledger state
  -> broker service-principal operation
```

There are three synchronous, `BUFFERED` Function URLs: `classify`, `retire`
and `reconcile`. IAM binds each URL to its exact qualified alias and ordinary
invoker role. Direct, asynchronous, unqualified and `$LATEST` invocation are
not accepted.

The ordinary invoker cannot call OAuth, set context, write the ledger or retire
the Change Set. The proof role cannot call any AWS action. The broker is the
only application actor, ledger writer and possible Change Set deleter.

## Request and secret boundary

The request contains only schema markers, one authorization code and one PKCE
verifier. It cannot choose an account, Region, user, role, duty, alias, action,
stack, Change Set or ledger key. Those values come from the alias and immutable
configuration.

Codes, verifiers, tokens, context assertions and STS credentials are
process-local secrets. They are never logged, persisted or returned. Mutable
objects are cleared best-effort and uncertain OIDC/STS results are never
retried automatically.

## Zero-authority identity proof

The broker sends the opaque AWS identity context to STS in exactly one
`ProvidedContexts` entry. STS evaluates the exact immutable UserId, Identity
Store, Instance, Application and proof role.

Classifier and approver use different proof roles and different UserIds. Both
proof-role policies explicitly deny every action. The broker validates the
assumed-role ARN and 900-second expiry against a fresh request/response clock
window with at most 30 seconds of skew, discards the credentials and retains
only a sanitized receipt digest.

## Durable proof before effect

The classifier proof enters the create-only `CLASSIFIED` item. The independent
approver proof enters the `APPROVED` compare-and-swap transition. The ledger
then consumes the single `ATTEMPTED` transition before the broker can call the
one exact delete. Reconciliation proof is required before terminal state.

An uncertain effect remains `ATTEMPTED`. It permits reconciliation, not a
second delete.

## Honest attribution

The proof receipt identifies the authorized human through digests. The AWS
effect is still performed by the broker execution role. GUG-217 records these
as separate facts and sets `native_on_behalf_of` false. It does not claim that
CloudFormation natively attributes the effect to the human.

## Human separation

Live use requires two different real people and two different immutable
Identity Store UserIds. César is currently the only human operator. Two
profiles, sessions, roles or time windows for César do not satisfy independent
approval.

César may implement, document and run synthetic local tests. Live
classification, approval, retirement and reconciliation remain blocked until
a second actual operator exists and every provisioning/readback gate passes.

## Evidence status

| Class | Status |
|---|---|
| Implemented | Repository-only on the exact reviewed GUG-217 commit |
| Locally validated | Named exact-commit gates only |
| CI validated | Not established until required PR checks pass |
| Live Function URL / broker deployment | **Not performed** |
| Live token / STS proof | **Not performed** |
| Independent approver | **Blocked** |
| Live retirement | **Blocked** |
| Production | **NO-GO** |

## Questions this source should answer

1. Why does `v12` remain incompatible with direct Lambda invocation?
2. What does proof-only compatibility authorize and not authorize?
3. Why does the ordinary invoker use an exact Function URL alias?
4. Which request fields are allowed, and why are none authority selectors?
5. How are authorization code, PKCE, token, assertion and credentials handled?
6. How does STS prove the immutable UserId?
7. Why can the proof-role credentials perform no action?
8. When does each human proof digest enter the durable ledger?
9. Which principal appears as the AWS retirement effect actor?
10. Why is `native_on_behalf_of` false?
11. Why can one person with two profiles not complete the live workflow?
12. Why do repository and CI success leave production NO-GO?

## Authoritative references

- [AWS-managed identity-context allowlist](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSIAMIdentityCenterAllowListForIdentityContext.html)
- [CreateTokenWithIAM](https://docs.aws.amazon.com/singlesignon/latest/OIDCAPIReference/API_CreateTokenWithIAM.html)
- [STS AssumeRole and ProvidedContexts](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)
- [Identity-enhanced IAM role sessions](https://docs.aws.amazon.com/singlesignon/latest/userguide/trustedidentitypropagation-identity-enhanced-iam-role-sessions.html)
- [Lambda Function URL authorization](https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html)
