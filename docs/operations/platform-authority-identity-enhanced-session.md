# Runbook: Platform-Authority Identity-Enhanced Operator Session

## Purpose and hard boundary

This runbook validates the repository-side GUG-216 identity-enhanced session
contract and records why the current GUG-215 Lambda invocation remains blocked.
It provides stop conditions for a future authorized rollout.

The current procedure is offline only. It does not authorize or perform:

- Identity Center application, grant, authentication-method, assignment or
  permission-set mutation;
- browser authorization or token creation;
- STS role assumption with `ProvidedContexts`;
- Lambda deployment or invocation;
- GUG-215 ledger writes or `DeleteChangeSet`;
- `ExecuteChangeSet`, `DeleteStack`, Terraform Apply, seed, customer
  deployment, production, migration, destruction or redrive.

Production is **NO-GO**.

## GUG-217 disposition

This runbook remains authoritative for proving that an identity-enhanced
session cannot directly invoke the GUG-215 Lambda under reviewed policy `v12`.
Do not execute its historical direct path.

ADR-043 / GUG-217 defines a different proof-only transport: an ordinary exact
Function URL invocation reaches the broker, which then establishes a deny-all
STS proof and binds its digest to the ledger. See the
[GUG-217 runbook](platform-authority-identity-context-pep.md). The new path has
not been deployed or invoked and remains blocked while only one human operator
exists.

## Required people and duties

### Current state

César is the only current human operator. He may implement, review local
synthetic behavior and perform only separately authorized read-only AWS
inventory. This is not independent approval and cannot authorize a live
classifier or approver action.

### Future live roster

Before a live GUG-215 flow, create an approved private roster with real users,
not placeholders:

1. **Classifier:** one human with one immutable Identity Store UserId and only
   the classifier assignment;
2. **Independent approver:** a different human with a different immutable
   UserId and only the approver assignment;
3. **Identity Center administrator:** a governed administrative duty that
   provisions the reviewed application and assignments without receiving
   direct Change Set retirement authority;
4. **Security/audit reviewer:** a read-only reviewer of bindings, managed-policy
   compatibility, CloudTrail and revocation evidence;
5. **Broker execution role:** a non-human service principal and the only
   GUG-215 ledger writer/deleter.

Do not assign César to both live duties. Two profiles, terminals, sessions or
time windows for the same person do not produce two independent people. The
founder bootstrap exception does not extend to GUG-215.

## Phase 0 — Repository and authorization preflight

Before running even the offline check:

1. identify the exact GUG-216 branch/commit under review;
2. confirm the worktree contains no unrelated or sensitive files;
3. confirm the schemas, policies, fixtures, tests, ADR and threat-model delta
   belong to the same review;
4. confirm no AWS mutation or live identity exchange has been authorized;
5. confirm no live UserId, email, account identifier, application ARN, token,
   assertion, credential or AWS response will be copied to terminal evidence,
   Git, a PR, Linear or NotebookLM.

Stop if any request attempts to supply its own action, role, alias, UserId,
application or context assertion as authority.

## Phase 1 — Offline managed-policy compatibility

Run only the repository command:

```bash
python3 scripts/deployment/platform-authority-identity-enhanced-session.py \
  compatibility-check
```

For the reviewed AWS-managed policy snapshot `v12`, require all of these
sanitized outcomes:

```text
COMPATIBILITY_STATUS: BLOCKED_AWS_IDENTITY_CONTEXT_ACTION_UNSUPPORTED
TOKEN_ISSUED: false
STS_SESSION_ISSUED: false
BROKER_INVOCATION_PERFORMED: false
INDEPENDENT_APPROVER_AVAILABLE: false
PRODUCTION: NO-GO
```

The command also prints the reviewed policy version and canonical digest. Do
not interpret them as live readback. The bundled snapshot proves only that the
repository deterministically models the reviewed public policy document.

Any `COMPATIBLE_REVIEWED_ACTION` result against the bundled `v12` snapshot is a
test or source-integrity failure. Stop; do not continue to OAuth or STS.

## Phase 2 — Local contract validation

Run the named GUG-216 tests through the repository's existing validation
entrypoint. Record the exact command, commit and counts without including
synthetic secret values.

Validation must prove at minimum:

- managed-policy `Deny` / `NotAction` semantics;
- absence of `lambda:InvokeFunction` from reviewed `v12`;
- guard execution before OIDC, STS and consumer calls;
- policy ARN/version/digest drift denial;
- equal classifier/approver UserId denial;
- exact duty, source role, target role and alias binding;
- one-use authorization code and loopback callback validation;
- exact OIDC scope/type/lifetime and no refresh token;
- exactly one Identity Center `ProvidedContexts` entry and 900-second STS
  duration in the synthetic future-compatible test;
- no token, assertion, credential, email or raw UserId in receipts, errors,
  output or `repr`;
- no automatic retry after uncertain OIDC, STS or consumer outcomes;
- GUG-215 still rejects direct ordinary-profile invocation.

The synthetic injected clients and consumer are test seams and part of the
trusted computing base. A future live entrypoint must replace them with one
fixed, reviewed capability consumer and prove it does not copy, retain,
serialize, log or return session material. In-memory clearing alone is not
accepted as proof of non-exportability.

A synthetic compatible fixture is a unit-test seam only. It is never evidence
that AWS currently supports the target action.

## Phase 3 — CI and review

Before merge, require:

1. local focused GUG-216 tests pass;
2. the applicable platform-authority and repository gates pass;
3. `git diff --check` is clean;
4. an independent security review confirms the guard precedes all sensitive
   effects and no credential material can escape;
5. required PR checks are green for the exact commit;
6. documentation classifies local, CI and live evidence separately.

CI does not make the adapter live-ready. It neither proves the current AWS
managed-policy version nor creates a second independent human.

## Phase 4 — Separately authorized AWS read-only compatibility inventory

This phase is not performed by the offline CLI. Run it only under a later
authorization that names the account, Region and read-only profile.

Read-only evidence must prove:

- STS caller identity matches the authorized read-only role;
- the exact AWS-managed policy ARN;
- its current default version ID;
- the complete default-version policy document;
- the canonical document digest;
- whether the exact downstream action appears in the effective `NotAction`
  allowlist;
- the exact Identity Center application, grant, authentication method,
  assignment requirement and actor policy, if those resources exist;
- the exact two assignments and two distinct immutable UserIds, if they exist;
- no foreign application actor or alias-invoke principal.

Missing permission, pagination, version, statement, assignment or policy data
is `UNKNOWN` and blocks. Do not substitute the repository snapshot for a
denied live read.

Current expected decision remains blocked while
`lambda:InvokeFunction` is absent. Do not call `CreateTokenWithIAM` merely to
test the boundary.

### Recorded read-only result — 2026-07-20

The authorized inventory completed with no AWS mutation:

- STS verified the expected management and dedicated authority reader account
  classes; full account/principal identifiers remain private;
- the live managed policy default was `v12` and its canonical digest
  `sha256:588e10587ff62c683615a9612b1f42ded9fccd03bd94810dc6760dad50665655`
  matched the reviewed snapshot exactly;
- `lambda:InvokeFunction` was absent from the 119 `NotAction` entries;
- no Scanalyze Identity Center application and neither retirement permission
  set existed;
- no GUG-215 invoker role, broker Lambda or retirement ledger existed;
- the authority shell was `REVIEW_IN_PROGRESS`, had zero resources and exposed
  one retained `AVAILABLE` Change Set through list-level metadata;
- `DescribeChangeSet` was denied, so the detailed target inventory is
  **UNKNOWN**.

The correct operational state is still **STOP**. Do not infer the Change Set's
type, template, parameters, tags or reviewed four-change inventory from its
list status. Do not add read or mutation permissions under this runbook.

## Phase 5 — Future live-enablement review

Do not enter this phase under GUG-216's current authorization. A new package
and explicit authorization must prove all of the following:

1. AWS supports the exact downstream action in the identity-context session;
2. a new reviewed managed-policy version and digest are committed and tested;
3. two real, different humans and immutable UserIds are approved;
4. the exact application uses authorization-code grant, PKCE and the reviewed
   loopback redirect;
5. the IAM actor policy and source permission sets are exact and provisioned;
6. the account-local invoker-role trusts still enforce exact identity context;
7. the GUG-215 broker/ledger deployment and all ADR-041 controls are read back;
8. no foreign principal can invoke any broker alias;
9. revocation, uncertainty reconciliation and rollback owners are present;
10. the operation is explicitly non-production.

If AWS has not added the required action, stop. A new architecture ADR may
select another downstream PEP only if it preserves immutable user attribution,
empty request authority, qualified capability selection and the one-shot
durable GUG-215 ledger. Do not repurpose an unrelated allowlisted service.

## Future exchange invariants

For reference, a compatible, separately authorized implementation must:

1. create a fresh PKCE verifier and state in memory;
2. use only `http://127.0.0.1:<ephemeral-port>/callback`;
3. accept one authorization response and consume it once;
4. call `CreateTokenWithIAM` for the exact application with explicit
   `sts:identity_context` scope;
5. reject refresh tokens, unexpected scopes/types and unbounded lifetime;
6. use only the opaque `awsAdditionalDetails.identityContext` assertion;
7. call STS for the exact invoker role, 900 seconds, with exactly one Identity
   Center `ProvidedContexts` entry and no additional session authority;
8. consume credentials in-process for one exact alias capability;
9. clear the credential map and emit only a sanitized receipt;
10. never retry an uncertain exchange or consumer result automatically.

This is a contract description, not authorization to implement or run a live
browser/SDK client.

## Stop conditions

Stop immediately if any of the following is true:

- `lambda:InvokeFunction` is absent from the reviewed effective allowlist;
- the managed-policy version or digest is unknown or differs from review;
- only one human is available for classifier and approver duties;
- a placeholder, alias, email or profile is proposed instead of immutable
  distinct UserIds;
- a normal SSO profile is treated as an identity-enhanced session;
- a token, assertion or credential would cross process, shell, log or evidence
  boundaries;
- the caller supplies action, role, alias, UserId, application or target;
- an application actor, grant, assignment or invoker path is foreign or
  ambiguous;
- a Lambda resource policy or administrator role is proposed as a bypass;
- the workflow would omit `ProvidedContexts`, retry or invoke asynchronously;
- a requested action includes AWS mutation not separately authorized.

## Rollback and uncertain outcomes

The current offline command has no AWS rollback because it performs no AWS
effect. Repository rollback removes the GUG-216 artifacts.

For any future live exchange, an ambiguous OIDC or STS response means no
retry. Revoke/expire the session, retain sanitized evidence and reconcile the
downstream durable state. If the consumer may have reached GUG-215, follow the
ADR-041 non-delete reconciliation path; never manufacture a second attempt.

## Evidence handling

Allowed public evidence:

- exact source commit and PR URL;
- named test/check results and counts;
- managed-policy public ARN, reviewed version and canonical digest;
- sanitized compatibility status;
- false/true effect flags that do not overclaim;
- whether AWS inventory, token issuance, STS session and broker invocation
  occurred.

Private evidence only:

- real UserIds, emails and assignments;
- application, role and account identifiers;
- authorization codes, PKCE material, tokens and context assertions;
- temporary credentials;
- CloudTrail and raw AWS responses;
- GUG-215 target and ledger data.

## Current evidence classification

| Class | Status |
|---|---|
| Implemented | Repository work in the isolated GUG-216 branch/worktree |
| Locally validated | GUG-215/GUG-216 focused: **92 passed**; platform-authority gate: **211 passed** plus schema, policy and offline CLI checks; `make preflight-m2`: **1319 passed** plus **114/114** contract-matrix scenarios on pinned Python 3.11.14 and Terraform 1.14.6; documentation and independent security review passed |
| CI validated | **Not established** |
| AWS read-only inventory | **Completed 2026-07-20**: reader identities verified, live `v12` digest matched snapshot, 119-action allowlist excluded Lambda, and GUG-215 identity/runtime resources were absent. `DescribeChangeSet` was **BLOCKED**; detailed target inventory remains **UNKNOWN** |
| Live `CreateTokenWithIAM` | **Not performed** |
| Live STS `ProvidedContexts` | **Not performed** |
| Live Lambda invocation | **Blocked** by managed-policy `v12` |
| Independent human approval | **Blocked**; César is currently the sole operator |
| Live retirement | **Blocked** |
| Production | **NO-GO** |

## AWS references

- [CreateTokenWithIAM API](https://docs.aws.amazon.com/singlesignon/latest/OIDCAPIReference/API_CreateTokenWithIAM.html)
- [Opaque identityContext response field](https://docs.aws.amazon.com/singlesignon/latest/OIDCAPIReference/API_AwsAdditionalDetails.html)
- [STS AssumeRole and ProvidedContexts](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)
- [Identity-enhanced IAM role sessions](https://docs.aws.amazon.com/singlesignon/latest/userguide/trustedidentitypropagation-identity-enhanced-iam-role-sessions.html)
- [Identity-context AWS-managed policy](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSIAMIdentityCenterAllowListForIdentityContext.html)
- [Application resource-policy authorization](https://docs.aws.amazon.com/singlesignon/latest/userguide/iam-auth-access-using-resource-based-policies.html)
