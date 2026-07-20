# ADR-041: Version-pinned Broker for Retained Change Set Retirement

- **Status:** Accepted for repository implementation; live retirement remains blocked
- **Date:** 2026-07-19
- **Work package:** GUG-215
- **Amends:** ADR-034 and ADR-040
- **Production:** **NO-GO**

## Context

The dedicated platform-authority account contains one retained, unexecuted
CloudFormation Change Set on the canonical empty bootstrap shell. Sanitized
read-only inspection observed `REVIEW_IN_PROGRESS`, zero stack resources and
one `CREATE_COMPLETE` / `AVAILABLE` Change Set with four expected resource
creations. The original private bootstrap Plan receipt cannot be proved.

The historical `cancel` command correctly refuses to act without that Plan.
Reconstructing it from live metadata would fabricate provenance, while leaving
the Change Set active prevents GUG-214 from proving a recoverable shell.

An earlier GUG-215 design still placed CloudFormation and DynamoDB mutations in
human sessions and lacked an AWS-enforced immutable-user boundary. Those
controls were insufficient: a human role with `DeleteChangeSet` can bypass a
process-local PEP, and local files are not durable authority.

## Decision

### 1. One version-pinned Lambda is the only mutation authority

GUG-215 uses the stack defined by
`bootstrap/cfn-platform-authority-change-set-retirement-ledger.yaml`. It creates
one dedicated DynamoDB ledger, one Lambda function, one immutable published
version, three aliases and three IAM roles:

- `classify` invokes the classification operation;
- `retire` performs independent approval, claims the one attempt and may issue
  the one exact `DeleteChangeSet` request;
- `reconcile` performs target reconciliation and may write only the terminal
  ledger transition after exact absence;
- `ScanalyzeGug215ClassifierInvoker` is a human-facing invoke-only role;
- `ScanalyzeGug215ApproverInvoker` is a distinct human-facing invoke-only role;
- `ScanalyzeGug215BrokerExecution` is the sole CloudFormation and DynamoDB
  mutation principal.

The Lambda alias, not a request field, chooses the operation. The invocation
payload must be exactly `{}`. Customer IDs, deployment IDs, Change Set names,
ARNs, ledger keys, identities and requested actions are rejected as payload
authority.

Human permission sets and invoker roles never receive `DeleteChangeSet` or
DynamoDB write authority. The human CLI has no direct delete or ledger-write
adapter; it validates the exact invoker role and synchronously invokes one
pinned alias.

### 2. Identity separation uses immutable Identity Store users

The broker deployment binds two explicit, distinct IAM Identity Center
`IdentityStore UserId` values:

- one classifier user;
- one independent approver user.

The CloudFormation rule and runtime configuration reject equality. Trust and
invoke policies require identity-enhanced sessions created with
`sts:SetContext`, the Identity Center context provider, exact Identity Store,
exact Instance, exact Application and the corresponding immutable UserId.
There is no `IfExists` or session-name fallback.

The two source permission sets are named exactly
`ScanalyzeAuthorityRetireClass` and `ScanalyzeAuthorityRetireApprove`; both fit
the portable 32-character contract. Their provisioned roles may only
assume/set context into their respective invoker roles. The classifier invoker
can invoke only `classify`. The approver invoker can invoke only `retire` and
`reconcile`. Both explicitly deny direct CloudFormation retirement effects and
DynamoDB writes.

Repository code does not prove that two live users or assignments exist. Live
retirement remains blocked until two genuinely independent operators, their
immutable UserIds, permission-set assignments, provisioning and
identity-enhanced sessions are reviewed and read back.

An ordinary IAM Identity Center `AWS_PROFILE` does not create the required
identity context. The repository does not yet implement the safe
`CreateTokenWithIAM` plus STS `ProvidedContexts` credential adapter. The
documented broker commands remain non-live interfaces until that separate
prerequisite is implemented, reviewed and validated.

### 3. Broker code and effective authority are deployment-bound

The Lambda uses a versioned S3 object, a required code-signing configuration,
an expected code SHA-256 and one published version. All three aliases point to
that version; `$LATEST` is never accepted. Reserved concurrency is exactly one
to reduce concurrent mutation races, and SDK mutation retries are disabled.

Before every operation, the broker reads back and validates:

- its execution-role trust policy, sole inline-policy inventory and absence of
  attached policies or a permissions boundary;
- the canonical digest of the effective broker inline policy;
- alias-to-version binding, function version, code digest, execution role,
  code-signing configuration and reserved concurrency;
- absence of function-, invoked-alias- and resolved-version resource policies
  and absence of weighted alias routing;
- the exact identity-store/instance/application binding carried in immutable
  function configuration.

Lambda does not expose the direct invoker identity to this handler. IAM trust
and invoke authorization enforce the exact UserId boundary before execution.
Live use therefore also requires an account-wide permission inventory proving
that no foreign identity can invoke the aliases. Administrators able to rewrite
IAM or Lambda remain an explicitly reviewed control-plane trust boundary.

The expected broker policy digest is a deployment parameter and is compared to
the live IAM policy. A local rendered JSON policy is not authority and is not a
runtime input. Assignment and invoker-policy digests are also immutable
deployment bindings and are included in the ledger identity binding; their
actual Identity Center provisioning must be verified externally before
invocation because the broker does not query Identity Center administration
APIs.

### 4. The dedicated ledger is service-owned and compare-and-swap protected

The ledger table is named
`scanalyze-platform-authority-change-set-retirements` and is keyed by:

```text
retirement_id = gug215#sha256:<64-hex-sha256-of-full-change-set-id>
```

It is deletion-protected, KMS encrypted, point-in-time recoverable for 35 days,
PAY_PER_REQUEST, unstreamed, non-replicated and tagged as non-production
control metadata. Its DynamoDB resource policy denies every supported write
operation unless `aws:PrincipalArn` is the exact broker execution role. IAM on
human roles cannot override that resource-policy deny.

Broker item permissions require the exact `dynamodb:LeadingKeys` value and
`Null=false`, preventing absent multivalued context from satisfying the allow.

The state machine is monotonic:

```text
CLASSIFIED v1, attempts=0
  -> APPROVED v2, attempts=0
  -> ATTEMPTED v3, attempts=1
  -> RETIRED_RECONCILED v4, attempts=1
```

- `classify` derives the key from the full live Change Set ID and creates
  `CLASSIFIED` with `attribute_not_exists(retirement_id)`.
- `retire`, invoked by the independent approver identity, transitions
  `CLASSIFIED -> APPROVED -> ATTEMPTED` through digest/version/state CAS before
  the protected effect.
- An interrupted `retire` resumes safely from exact `APPROVED` state and claims
  `ATTEMPTED` without recreating approval or deleting first.
- `reconcile` transitions `ATTEMPTED -> RETIRED_RECONCILED` only after exact
  absence and preserved-shell proof.
- An ambiguous delete leaves the ledger `ATTEMPTED`; no path resets it or
  permits a second delete.

The ledger binds target digests, both Identity Store user digests, assignment
and invoker-policy digests, broker code and policy digests, state, version and
attempt count. Sanitized CLI output or copied local data cannot create or
advance authority.

### 5. Every protected operation revalidates the live boundary

The broker fails closed unless fresh AWS reads prove:

- the canonical stack is an empty `REVIEW_IN_PROGRESS` shell;
- no service role, notifications, parent or root metadata exists;
- every `ListChangeSets` page contains exactly the expected inventory;
- the retained object is the exact `CREATE`, `CREATE_COMPLETE`, `AVAILABLE`
  Change Set bound in configuration;
- its full ARN/UUID, original template digest, parameters, tags and four-change
  resource inventory match the reviewed baseline;
- the ledger controls and resource policy remain exact.

Immediately before deletion, `retire` re-reads the target after the durable
`ATTEMPTED` claim and compares the retirement key plus every target digest to
the claimed ledger record. Only the broker execution role has stack-plus-name
`DeleteChangeSet` authority. It has no `ExecuteChangeSet`, `DeleteStack`,
`CreateChangeSet`, stack-update, IAM, Organizations, StackSets, Terraform or
customer-account authority.

Describe, original-template read and delete use the final full Change Set ID
rather than only its reusable name. That raw identifier stays process-local;
the ledger stores only its digest and IAM retains the exact name condition.

### 6. Uncertain outcomes permit reconciliation only

The broker issues at most one `DeleteChangeSet` request with SDK retries
disabled. A timeout, transport loss, ambiguous AWS response or process failure
after `ATTEMPTED` returns `RECONCILIATION_REQUIRED` and does not retry.
Re-invoking `retire` while the ledger is `ATTEMPTED` also returns reconciliation
required without another delete.

The reviewed CLI invokes synchronously. Asynchronous direct invocation is an
unsupported foreign-authority path that blocks live execution; the durable
attempt claim still prevents a redelivery from obtaining a second delete.

The `reconcile` alias can never call delete. It checks the original full
`StackId` digest against the exact durable item and uses that full ID for every
resource and Change Set page. Exact target absence, zero active Change Sets
and the unchanged empty shell are checked again immediately before the
terminal CAS.
Target presence, a foreign object or ambiguity leaves the ledger at
`ATTEMPTED`.

### 7. Retirement never declares platform recovery ready

Terminal reconciliation records effect attribution as `UNPROVEN`; it does not
claim which response path removed the metadata. Recovery readiness is never
`READY`. The broker returns only:

- `RETIREMENT_ROLE_REVOCATION_REQUIRED` when account-level S3 Public Access
  Block is already all true;
- `PAB_AND_REVOCATION_REQUIRED` when PAB is missing or partial;
- a blocking/reconciliation state for every uncertain result.

Both temporary human assignments and active sessions must be revoked and read
back. All-true PAB must be independently proved before a fresh GUG-214
preflight can decide recovery readiness.

### 8. Evidence is sanitized and durable state remains authoritative

The human CLI prints only sanitized status, ledger digest and next-required
control. The Lambda emits no logs from application code, has no CloudWatch Logs
permissions and converts failures to non-sensitive denial codes. Raw Identity Store values, account/principal
identifiers, ARNs, Change Set names/UUIDs, templates, AWS responses and ledger
documents must remain outside Git, PRs, Linear and NotebookLM.

No local classification, approval, policy, attempt or verification file is
accepted by the broker. The version-pinned function configuration, live AWS
readback and durable ledger are the authority boundary.

## Consequences

- No human principal can directly delete the retained object or mutate the
  GUG-215 ledger.
- Independent approval is bound to two different immutable Identity Store
  users through identity-enhanced context.
- A resource-policy deny protects the ledger even if a human identity later
  acquires an accidental IAM allow.
- One immutable code version owns classification, approval, attempt,
  deletion and reconciliation semantics.
- A lost response cannot trigger a second delete request.
- Deployment and Identity Center provisioning become explicit prerequisites;
  repository implementation alone cannot authorize live invocation.
- Account-level PAB and role/session revocation remain separate recovery gates.

## Alternatives rejected

- **Human Plan/Retire roles with direct writes:** IAM authority would bypass a
  process-local PEP.
- **Caller-selected identity evidence:** only the identity-enhanced immutable
  UserId context is accepted.
- **A locally rendered effective policy:** a file does not prove live IAM
  authority or prevent later drift.
- **Caller-supplied target or action:** request data cannot establish
  authorization.
- **Invoke `$LATEST` or an unqualified function:** mutable code cannot anchor a
  one-shot control.
- **Use IAM alone for the ledger:** a resource-policy deny is required to
  constrain all non-broker writers.
- **Retry after an ambiguous delete:** durable attempt consumption makes
  reconciliation the only safe continuation.
- **Delete the review shell:** shell deletion is outside GUG-215 and would
  destroy recovery evidence.

## Rollback and recovery

Before any separately authorized live deployment, repository rollback removes
the broker, template, policies, schemas, tests and documentation without AWS
effect. A deployed ledger is retained; repository rollback does not delete or
reset it.

After a one-shot attempt, rollback is not object recreation. Revoke the human
assignments/sessions and perform only broker `reconcile` invocations against
the original deployment binding. A replacement Change Set requires a new
reviewed bootstrap Plan.

## Evidence classification

| Class | Status |
|---|---|
| Implemented | Only after the reviewed commit contains the version-pinned broker, three aliases, identity-enhanced invoker roles, resource-policy-protected ledger, exact PEP, CLI, tests and documentation |
| Locally validated | Only after named local gates pass for that exact commit |
| CI validated | Pending required checks for the exact PR commit |
| Live inventory | Sanitized read-only observation only |
| Live broker deployment | **Not performed** |
| Live broker invocation | **Not performed** |
| Live retirement | **Blocked** pending reviewed deployment, two independent immutable Identity Store users, assignments, provisioning, account-wide invoke inventory and exact readback |
| Identity-enhanced credential adapter | **Blocked**; normal SSO profiles are not sufficient |
| Production | **NO-GO** |
