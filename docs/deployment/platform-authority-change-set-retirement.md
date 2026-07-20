# Platform-Authority Retained Change Set Retirement

## Scope

GUG-215 implements a fail-closed control plane for retiring one exact,
unexecuted CloudFormation Change Set retained on the canonical empty
platform-authority review shell when the original bootstrap Plan cannot be
proved.

The implementation does not authorize or perform deployment. It does not
permit `ExecuteChangeSet`, `DeleteStack`, `CreateChangeSet`, Terraform Apply,
seed, customer deployment, migration, destruction or production.

## Authoritative architecture

`bootstrap/cfn-platform-authority-change-set-retirement-ledger.yaml` defines
the complete GUG-215 PEP boundary:

| Component | Authority |
|---|---|
| Classifier permission set | Assume/set Identity Center context into the exact classifier invoker role only |
| `ScanalyzeGug215ClassifierInvoker` | `lambda:InvokeFunction` on alias `classify` only; the reviewed CLI uses `RequestResponse` |
| Approver permission set | Assume/set Identity Center context into the exact approver invoker role only |
| `ScanalyzeGug215ApproverInvoker` | `lambda:InvokeFunction` on aliases `retire` and `reconcile` only; the reviewed CLI uses `RequestResponse` |
| Version-pinned Lambda broker | Sole CloudFormation target reader/deleter and sole DynamoDB ledger writer |
| DynamoDB resource policy | Deny all supported writes from every principal except the exact broker execution role |

The human CLI accepts only account and Region plus the explicit safety flag for
the applicable operation. It checks the exact invoker role and sends an empty
payload to one qualified alias. It cannot call `DeleteChangeSet` or write the
ledger directly.

## Immutable broker boundary

The template creates one function named
`scanalyze-platform-authority-gug215-retirement`, one published version and
three aliases:

```text
classify  -> reviewed immutable version
retire    -> same reviewed immutable version
reconcile -> same reviewed immutable version
```

The deployment is bound to:

- an exact versioned S3 artifact and base64 code SHA-256;
- an exact Lambda code-signing configuration;
- an expected canonical broker execution-policy SHA-256;
- exact authority account, Region, stack and retained Change Set name;
- reviewed original-template and resource-inventory digests;
- exact Identity Store, Identity Center Instance and Application;
- two distinct immutable Identity Store UserIds;
- exact assignment and invoker-policy digests for both operators;
- the exact `retirement_id`.

The broker rejects `$LATEST`, alias drift, code drift, execution-role drift,
attached policies, altered trust, broker-policy digest mismatch, missing code
signing, weighted alias routing, any function/alias/version resource policy or
reserved concurrency other than one. SDK retries are disabled.

`ExpectedBrokerPolicySha256` is checked against the live inline policy on the
broker execution role. It is not a locally rendered human authorization file.
Assignment and invoker-policy digests are immutable deployment bindings and
must be established by the separately reviewed Identity Center provisioning
change.

## Identity-enhanced operator separation

Two different actual IAM Identity Center users are mandatory:

1. the classifier is bound to `ClassifierIdentityStoreUserId`;
2. the independent approver is bound to `ApproverIdentityStoreUserId`.

CloudFormation and broker configuration reject equal UserIds. The invoker-role
trust and invoke policies require `sts:SetContext` with the Identity Center
context provider and exact `identitystore:UserId`, `IdentityStoreArn`,
InstanceArn and ApplicationArn. Conditions have no `IfExists` fallback.

The source permission sets are named exactly
`ScanalyzeAuthorityRetireClass` and `ScanalyzeAuthorityRetireApprove`. Their
repository policy sources are:

- `policies/iam/platform-authority-change-set-retirement-classifier-role.json`;
- `policies/iam/platform-authority-change-set-retirement-role.json`.

They allow only `sts:AssumeRole` and `sts:SetContext` into the corresponding
invoker role and explicitly deny direct CloudFormation retirement effects,
DynamoDB writes and direct Lambda invocation. The account-local invoker roles
add only `lambda:InvokeFunction` on their exact aliases. That IAM action cannot
differentiate `RequestResponse` from `Event`; the reviewed CLI forces
`RequestResponse`, and any separately authorized asynchronous path is a live
inventory blocker.

Repository parameters do not prove the users, assignments or sessions exist.
Provisioning and readback are separate live changes. Until both genuinely
independent users and their identity-enhanced sessions are verified, live
retirement remains blocked.

An ordinary IAM Identity Center `AWS_PROFILE` does not create the required
identity context. The repository does not yet implement the safe
`CreateTokenWithIAM` plus STS `ProvidedContexts` credential adapter. The
documented broker commands therefore remain non-live interfaces until that
separate prerequisite is implemented, reviewed and validated.

Lambda does not expose the direct invoker identity to this handler. The IAM
trust and invoke policies enforce the human UserId boundary before invocation;
the broker revalidates those roles and rejects any Lambda resource-based
policy. Live use additionally requires an account-wide permission inventory
proving that no foreign identity can invoke the broker aliases. Control-plane
administrators who can rewrite IAM or Lambda remain a reviewed trusted
boundary, not an application-level approval path.

## Request-authority boundary

Each Lambda invocation must carry exactly this payload:

```json
{}
```

The invoked alias determines the operation. Function configuration and fresh
AWS metadata determine every target and identity binding. Any payload field,
including an operation, account, stack, Change Set, `retirement_id`, UserId or
resource locator, produces a sanitized denial before a ledger or target write.

## Durable service-owned ledger

The dedicated table is named
`scanalyze-platform-authority-change-set-retirements`. Its exact key is:

```text
retirement_id = gug215#sha256:<64-hex-sha256-of-full-change-set-id>
```

Controls validated before every operation include:

- `ACTIVE` status and exact key schema;
- deletion protection;
- KMS encryption;
- 35-day point-in-time recovery;
- PAY_PER_REQUEST billing;
- no stream and no replicas;
- exact non-production control-metadata tags;
- exact resource policy denying writes outside the broker execution role.

The broker IAM allow for item operations requires both the exact
`dynamodb:LeadingKeys` value and its explicit presence; a vacuous
`ForAllValues` match cannot authorize a missing key context.

The durable state machine is:

```text
CLASSIFIED v1, attempts=0
  -> APPROVED v2, attempts=0
  -> ATTEMPTED v3, attempts=1
  -> RETIRED_RECONCILED v4, attempts=1
```

`classify` creates the item once with `attribute_not_exists`. `retire` is the
independent approver operation: it validates the current live target, creates
the durable approval digest, advances to `APPROVED`, then claims `ATTEMPTED`
before the one possible delete request. `reconcile` can write the terminal
state only after exact absence. Every transition uses state, version, attempt
count and ledger-digest compare-and-swap.

If execution stops after `APPROVED`, the same approver operation resumes from
that exact durable state and claims `ATTEMPTED`; it does not recreate approval
or issue a delete before the one-shot claim.

No human-facing artifact can create, approve, reset or advance this state.

## Exact target PEP

Before classification and again immediately before deletion, the broker proves
from fresh AWS calls:

- canonical empty `REVIEW_IN_PROGRESS` stack shell;
- zero stack resources;
- no service role, notifications, parent or root stack metadata;
- complete paginated Change Set inventory;
- exactly the configured `CREATE`, `CREATE_COMPLETE`, `AVAILABLE` object;
- full Change Set ARN/UUID and canonical stack identity;
- exact original template digest, parameters and tags;
- exactly four reviewed resource additions and no other change;
- exact broker runtime and ledger controls.

The broker execution role permits `DeleteChangeSet` only on the canonical stack
with exact `cloudformation:ChangeSetName`. It has no permission to execute the
Change Set, delete/update the stack, create another Change Set, mutate IAM or
touch a customer account.

Runtime calls `DescribeChangeSet`, `GetTemplate` and `DeleteChangeSet` with the
full Change Set ID returned by the final paginated inventory, never with only
the reusable name. The raw ID remains process-local and is never written to the
ledger or returned to the CLI; IAM still requires the canonical Change Set name.

## Documented invocation sequence

These commands describe the repository interface. They were not run live by
GUG-215 implementation. Use only separately authorized, short-lived profiles
whose STS identity is the exact account-local invoker role.

### 1. Classifier invokes the pinned `classify` alias

```bash
python3 scripts/deployment/platform-authority-change-set-retirement.py \
  broker-classify \
  --authority-account-id '<12-digit-authority-account-id>' \
  --region '<authority-region>' \
  --allow-broker-classification
```

Expected sanitized status is `CLASSIFIED` with
`INDEPENDENT_APPROVAL_REQUIRED`. The broker, not the human session, performs
target inspection and the create-only ledger write.

### 2. Independent approver invokes the pinned `retire` alias

After an independently reviewed change package and exact provisioning
readback, a different immutable Identity Store user assumes the approver
invoker role:

```bash
python3 scripts/deployment/platform-authority-change-set-retirement.py \
  broker-retire \
  --authority-account-id '<12-digit-authority-account-id>' \
  --region '<authority-region>' \
  --allow-retire-exact-change-set
```

The broker performs `CLASSIFIED -> APPROVED -> ATTEMPTED`, revalidates every
target digest against the attempt claim and may issue exactly one delete
request by the full Change Set ID and full Stack ID. A
successful request returns `RETIREMENT_ATTEMPTED`; an ambiguous response
returns `RECONCILIATION_REQUIRED`. Neither result authorizes another retire
invocation to issue a second delete.

### 3. Approver invokes the pinned `reconcile` alias

```bash
python3 scripts/deployment/platform-authority-change-set-retirement.py \
  broker-reconcile \
  --authority-account-id '<12-digit-authority-account-id>' \
  --region '<authority-region>' \
  --allow-broker-reconciliation
```

The alias cannot call delete. It proves the current full Stack ID still
matches the classified stack digest and uses that ID for all inventories. If
the target remains present it returns
`RECONCILIATION_REQUIRED` without a ledger transition. Exact target absence,
zero active Change Sets and the preserved empty shell, re-read immediately
before the terminal CAS, allow `RETIRED_RECONCILED`. The terminal response
still requires PAB and/or revocation work; it is never recovery `READY`.

## No-retry behavior

Once the durable item is `ATTEMPTED`, any later `retire` invocation returns
reconciliation required before inspecting for a new delete. Transport loss,
timeout or an exception around `DeleteChangeSet` is deliberately ambiguous.
Operators must not wrap the command in shell, CI, SDK, Step Functions or manual
retry logic.

Direct asynchronous invocation is unsupported and forbidden operationally.
The reviewed CLI always requests `RequestResponse`; if a separately privileged
principal nevertheless requests asynchronous delivery, the durable
`ATTEMPTED` claim still prevents a repeated delete effect, but that access is a
live IAM inventory failure and blocks execution.

The `reconcile` alias may be invoked again for read-only target observation
while the target is still present. It never issues another delete and writes
only the one terminal CAS after exact absence.

## Recovery-readiness boundary

Retirement and recovery readiness are separate:

```text
RETIRED_RECONCILED
  != temporary assignments revoked
  != active sessions revoked
  != account PAB all true
  != platform authority recovered
  != deployment authorized
```

The broker returns `RETIREMENT_ROLE_REVOCATION_REQUIRED` when PAB is already all
true and `PAB_AND_REVOCATION_REQUIRED` otherwise. GUG-215 does not repair PAB,
remove Identity Center assignments, revoke sessions or run GUG-214.

## Evidence and logging boundary

The CLI prints only sanitized status, ledger digest and next required control.
The broker accepts no local evidence files, emits no application logs and its
execution role intentionally has no CloudWatch Logs permissions. It returns
only sanitized denial reason codes synchronously; the durable ledger and
CloudTrail are the authoritative service-side evidence boundaries. Raw AWS
responses remain governed private evidence.

Never commit or publish account/principal identifiers, Identity Store UserIds,
assignments, role ARNs, Lambda artifact locators, code-signing configuration,
Change Set names/ARNs/UUIDs, templates, ledger documents or AWS responses.

## Current evidence status

| Class | Status |
|---|---|
| Implemented | Repository design only, on the exact reviewed commit |
| Locally validated | Only after named local gates pass for that commit |
| CI validated | Pending required checks for the exact PR commit |
| Live inventory | Sanitized read-only observation only |
| Broker/ledger stack deployed | **No** |
| Identity-enhanced assignments validated | **No** |
| Identity-enhanced credential adapter | **Not implemented; live blocker** |
| Account-wide foreign alias-invoke inventory | **Not performed; live blocker** |
| Broker aliases invoked | **No** |
| Live retirement | **Blocked** |
| Production | **NO-GO** |
