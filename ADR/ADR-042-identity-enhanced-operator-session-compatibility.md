# ADR-042: Identity-Enhanced Operator Session and Downstream Compatibility

- **Status:** Accepted for repository implementation; live invocation blocked
- **Date:** 2026-07-19
- **Work package:** GUG-216
- **Amends:** ADR-041
- **Production:** **NO-GO**

## Context

ADR-041 requires the GUG-215 classifier and approver to reach their exact
account-local invoker roles through IAM Identity Center identity-enhanced role
sessions. A normal IAM Identity Center profile proves an IAM role session, but
does not by itself provide the immutable Identity Store `UserId` context used
by the invoker-role trust conditions.

AWS documents the required exchange as:

1. an application obtains an authorization code for an assigned Identity
   Center user;
2. the application calls `CreateTokenWithIAM` for the exact Identity Center
   application;
3. the response supplies the opaque `awsAdditionalDetails.identityContext`
   assertion without requiring JWT parsing;
4. the application passes that assertion to STS `AssumeRole` as exactly one
   `ProvidedContexts` entry whose provider is
   `arn:aws:iam::aws:contextProvider/IdentityCenter`.

The resulting session is also constrained by an AWS-managed policy. AWS STS
automatically attaches
`AWSIAMIdentityCenterAllowListForIdentityContext` to identity-enhanced role
sessions. The reviewed default version, `v12`, contains an explicit `Deny`
with a `NotAction` allowlist. `lambda:InvokeFunction` is not in that list.
Consequently, a target-role allow for `lambda:InvokeFunction` cannot make an
identity-enhanced session invoke the current GUG-215 Lambda broker.

This is an AWS service-compatibility boundary, not a missing local IAM allow.
Adding broader permission-set, target-role or Lambda resource policies cannot
override the managed explicit deny.

There is also only one current human operator, César. The repository may model
and test both duties with synthetic identities, but César cannot be configured
as both live classifier and live approver. ADR-041 continues to require two
different people represented by two different immutable Identity Store
`UserId` values.

## Decision

### 1. The adapter is capability-bound and offline by default

GUG-216 adds a typed adapter that models one authorization-code exchange and
one STS identity-enhanced role session. It does not expose a generic credential
process, print credentials, persist tokens or return reusable authority.

The adapter accepts an immutable binding for one duty and one exact broker
alias. The binding contains the reviewed account, Region, Identity Center
Application, Instance and Identity Store, expected and peer UserIds, source
and target roles, required AWS action, alias and short lifetime limits.

The classifier binding permits only alias `classify`. The approver binding
permits only `retire` or `reconcile`. Equal expected and peer UserIds are
rejected even when they differ only in letter case.

The public session receipt contains only digests and bounded status metadata.
It cannot contain an authorization code, PKCE verifier, access token, refresh
token, ID token, context assertion, temporary AWS credential, email address or
raw Identity Store UserId.

The repository command is intentionally offline. It evaluates the reviewed
managed-policy snapshot and reports a sanitized compatibility result. It does
not open a browser, call AWS, create a token, assume a role or invoke Lambda.

### 2. Compatibility is checked before identity or broker effects

The required downstream action for GUG-215 remains exactly
`lambda:InvokeFunction`. The compatibility guard validates:

- the exact AWS-managed policy ARN;
- an explicit reviewed version and canonical document digest;
- one unambiguous `Deny` / `NotAction` statement on `Resource: "*"`;
- the membership of the exact required action in that `NotAction` list.

Missing, malformed, drifted, differently versioned or ambiguous policy input
fails closed. A future policy document that adds the required action is not
accepted under the old digest. It requires a new reviewed snapshot, tests,
security review and explicit live authorization.

For the reviewed `v12` document, the deterministic result is:

```text
BLOCKED_AWS_IDENTITY_CONTEXT_ACTION_UNSUPPORTED
```

That result must be produced before `CreateTokenWithIAM`, STS `AssumeRole` or a
broker consumer can run. A receipt for this result records all effect flags as
false.

The bundled snapshot is an offline reproducibility source. It is not proof of
the current live default policy version. Any future live workflow must obtain
authorized read-only live policy metadata and document, compare their exact
version and canonical digest to a newly reviewed contract, and stop on any
drift or incomplete readback.

### 3. A future compatible exchange is one-shot and secret-contained

If a future, separately reviewed compatibility decision permits the required
action, the adapter enforces all of these invariants:

- authorization-code grant only;
- PKCE verifier with the reviewed syntax and one-time consumption;
- loopback redirect only on `http://127.0.0.1:<ephemeral-port>/callback`;
- exact application ARN and explicit scope `sts:identity_context`;
- `Bearer` token type, exact scope set and bounded lifetime;
- no refresh token;
- opaque `awsAdditionalDetails.identityContext`, never JWT parsing;
- STS duration exactly 900 seconds;
- exactly one `ProvidedContexts` entry with the Identity Center provider;
- no session policy, managed session policy, tags, transitive tags,
  `SourceIdentity` or caller-selected authority;
- a random non-PII session name;
- in-memory credential consumption followed by clearing the credential map;
- no automatic retry after an ambiguous OIDC, STS or consumer result.

The injected OIDC, STS and consumer implementations are part of the trusted
computing base. Python cannot enforce non-exportability against an in-process
consumer that deliberately copies a value. A future live implementation must
therefore use one fixed, reviewed capability consumer that never retains,
serializes, logs or returns session material; best-effort map clearing is only
defence in depth.

The adapter returns a sanitized receipt only after the in-process consumer has
consumed the session. It still records `broker_invocation_performed: false`
and `live_retirement_authorized: false`; the offline adapter test does not
claim a live broker effect.

### 4. Identity Center application authority remains exact

The source permission-set policies may call
`sso-oauth:CreateTokenWithIAM` only for the exact reviewed Identity Center
application ARN and may assume/set context only for their corresponding exact
invoker role.

The application actor policy recognizes only the exact provisioned classifier
and approver permission-set role ARNs. `Resource: "*"` in an Identity Center
application resource policy does not broaden its actor principals: the policy
is attached to one application and its principal list remains exact.

GUG-216 does not create or provision the application, grant, authentication
method, assignments or permission sets. Those are live Identity Center
mutations and remain separately authorized changes. No placeholder user,
invented UserId or duplicated assignment is permitted.

### 5. One current operator does not satisfy independent approval

The current roster is documented honestly:

| Actor | Current state | Permitted GUG-216 activity |
|---|---|---|
| César | Sole current human operator | Repository implementation, local synthetic validation and separately authorized read-only inventory |
| Classifier | Future distinct human required | Bind one immutable UserId and invoke only `classify` after all live gates pass |
| Independent approver | Future second distinct human required | Bind a different immutable UserId and invoke only `retire`/`reconcile` after independent review |
| Identity Center administrator | Future governed administrative duty | Provision exact application, policies and assignments; not target authority |
| Security/audit reviewer | Future read-only duty | Review bindings, compatibility, CloudTrail and revocation evidence |
| Broker execution role | Non-human service principal | Sole ledger writer and exact Change Set retirement principal under ADR-041 |

César may not be assigned to both live duties, use two profiles as a substitute
for two people, or self-assert a second UserId. The earlier founder bootstrap
exception does not apply to GUG-215 approval and is not extended by this ADR.

### 6. There is no approved live bypass for the Lambda incompatibility

The implementation must not:

- omit `ProvidedContexts` to make Lambda invocation work;
- use ordinary SSO credentials as if they contained immutable user context;
- invoke the broker through a broader administrator role;
- add a Lambda resource policy or alternate direct invoke principal;
- replace the required action with an unrelated allowlisted AWS action;
- accept caller-supplied UserId, target role, alias or context assertion;
- treat an offline snapshot or synthetic compatible fixture as live evidence.

A future live path requires either AWS support for the exact downstream action
or a separately reviewed architecture that preserves immutable end-user
attribution and the ADR-041 one-shot PEP without weakening any deny. That work
is outside GUG-216.

## Consequences

- The missing identity-enhanced exchange is represented as a typed, testable
  repository boundary.
- Sensitive OAuth and STS material remains process-local and cannot appear in
  receipts, logs, Git, PRs, Linear or NotebookLM.
- The exact current AWS managed-policy incompatibility is detected before any
  token, session or broker effect.
- GUG-215 remains live-blocked even after GUG-216 is implemented.
- A second independent human remains mandatory; the sole current operator is
  not silently accepted as both duties.
- Future AWS policy changes require new evidence and review, not an automatic
  compatibility upgrade.

## Alternatives rejected

- **Use an ordinary IAM Identity Center profile:** it does not establish the
  required `ProvidedContexts` identity boundary.
- **Decode the ID token in application code:** AWS exposes the opaque trusted
  identity-context assertion specifically without requiring JWT parsing.
- **Persist a refresh token or temporary credentials:** standing or reusable
  authority is outside the one-shot design.
- **Broaden the target IAM policy:** an allow cannot override the STS-managed
  explicit deny.
- **Drop the identity context:** that removes immutable user attribution and
  defeats ADR-041.
- **Let César perform both duties:** profile or terminal separation is not
  independent human approval.
- **Auto-accept a future managed-policy version:** managed AWS policy drift is
  a new authorization fact and requires explicit review.

## Rollback and recovery

Before any live deployment, repository rollback removes the GUG-216 adapter,
policy sources, contracts, fixtures, tests and documentation without AWS
effect. No token, STS session or Lambda invocation must have occurred through
the offline command.

If a future exchange becomes compatible and an outcome is uncertain, do not
repeat it automatically. Expire or revoke the session, retain only sanitized
evidence, reconcile the downstream GUG-215 ledger and target through the
reviewed non-delete path, and require a new authorization for any fresh token.

## Sanitized AWS read-only inventory — 2026-07-20

A separately authorized read-only inventory verified the expected STS context
for both the management-account reader and the dedicated authority-account
reader without publishing complete account or principal identifiers.

The inventory established these bounded facts:

- the live AWS-managed identity-context policy reported default version `v12`;
- its canonical document digest was
  `sha256:588e10587ff62c683615a9612b1f42ded9fccd03bd94810dc6760dad50665655`,
  exactly matching the reviewed repository snapshot;
- the single reviewed `NotAction` list contained 119 actions and did not
  contain `lambda:InvokeFunction`;
- no Scanalyze Identity Center application was found;
- neither `ScanalyzeAuthorityRetireClass` nor
  `ScanalyzeAuthorityRetireApprove` permission set was found;
- no GUG-215 invoker roles, broker Lambda or retirement ledger was found;
- the canonical authority stack remained a `REVIEW_IN_PROGRESS` shell with
  zero resources and one retained Change Set reported as `AVAILABLE` by the
  list-level inventory.

`DescribeChangeSet` was denied under the authorized read-only session. The
Change Set's detailed identity, type, content, template, parameters, tags and
resource-change inventory therefore remain **UNKNOWN**. The list-level
observation must not be promoted into proof that the retained object matches
the GUG-215 target contract.

This inventory performed no token exchange, STS `ProvidedContexts` role
assumption, broker invocation, deployment or mutation. It strengthens the
current blocked decision; it does not authorize live use.

## Evidence classification

| Class | Status |
|---|---|
| Implemented | Present only in the GUG-216 branch/worktree until reviewed commit, PR and merge evidence exist |
| Locally validated | GUG-215/GUG-216 focused: **92 passed**; platform-authority gate: **211 passed** plus schema, policy and offline CLI checks; `make preflight-m2`: **1319 passed** plus **114/114** contract-matrix scenarios on pinned Python 3.11.14 and Terraform 1.14.6; documentation and independent security review passed |
| CI validated | **Not yet established**; requires successful checks for the exact PR commit |
| AWS read-only inventory | **Completed 2026-07-20**: both reader identities verified; live managed policy default `v12` and canonical digest matched the snapshot; 119 `NotAction` entries excluded `lambda:InvokeFunction`; GUG-215 identity/runtime resources were absent; shell was empty with one list-visible retained `AVAILABLE` Change Set. `DescribeChangeSet` was **BLOCKED**, so detailed target inventory is **UNKNOWN** |
| Live `CreateTokenWithIAM` | **Not performed** |
| Live STS `ProvidedContexts` session | **Not performed** |
| Live broker invocation | **Blocked** by the reviewed managed-policy `v12` action boundary and missing second human |
| Live GUG-215 retirement | **Blocked** |
| Production | **NO-GO** |

## Authoritative AWS references

- [CreateTokenWithIAM API](https://docs.aws.amazon.com/singlesignon/latest/OIDCAPIReference/API_CreateTokenWithIAM.html)
- [AwsAdditionalDetails identityContext](https://docs.aws.amazon.com/singlesignon/latest/OIDCAPIReference/API_AwsAdditionalDetails.html)
- [STS AssumeRole ProvidedContexts](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)
- [Identity-enhanced IAM role sessions](https://docs.aws.amazon.com/singlesignon/latest/userguide/trustedidentitypropagation-identity-enhanced-iam-role-sessions.html)
- [AWSIAMIdentityCenterAllowListForIdentityContext](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSIAMIdentityCenterAllowListForIdentityContext.html)
- [IAM Identity Center application resource policies](https://docs.aws.amazon.com/singlesignon/latest/userguide/iam-auth-access-using-resource-based-policies.html)
