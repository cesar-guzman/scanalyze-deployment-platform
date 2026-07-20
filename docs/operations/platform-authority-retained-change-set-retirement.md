# Runbook: Retire One Retained Platform-Authority Change Set

## Purpose and hard boundary

This runbook covers the separately authorized retirement of one exact,
unexecuted Change Set from the canonical empty platform-authority review shell
through the GUG-215 version-pinned Lambda PEP.

It never authorizes `ExecuteChangeSet`, `DeleteStack`, `CreateChangeSet`,
Terraform Apply, seed, customer deployment, production, migration, destruction
or redrive. The repository implementation did not deploy or invoke this path.

## Roles and separation

The workflow requires two genuinely independent IAM Identity Center users:

1. **Classifier user** — exact immutable `ClassifierIdentityStoreUserId`;
   assumes `ScanalyzeGug215ClassifierInvoker` with identity-enhanced context and
   may invoke alias `classify` only.
2. **Approver user** — a different immutable
   `ApproverIdentityStoreUserId`; assumes
   `ScanalyzeGug215ApproverInvoker` with identity-enhanced context and may
   invoke aliases `retire` and `reconcile` only.

The source permission sets are exactly `ScanalyzeAuthorityRetireClass` and
`ScanalyzeAuthorityRetireApprove`. Their provisioned roles may only call
`sts:AssumeRole` and `sts:SetContext` for the exact invoker role. The invoker
roles may call `lambda:InvokeFunction` only on their qualified aliases, and the
reviewed CLI forces `RequestResponse`. IAM does not distinguish synchronous
from asynchronous invocation for that action, so any alternate async invoke
path is a live inventory blocker. Humans receive no direct Change Set deletion
or retirement-ledger write permission.

Profiles, terminals or timestamps do not establish independent operators. Stop
unless two distinct live Identity Store UserIds, their assignments,
provisioning and identity-enhanced contexts are read back.

An ordinary SSO profile is insufficient. Stop before deployment or invocation
until a separately reviewed adapter produces identity-enhanced role
credentials through `CreateTokenWithIAM` and STS `ProvidedContexts`, and live
readback proves the resulting immutable UserId context.

## Phase 0 — Authorization and immutable deployment review

Before any AWS mutation, require a separately approved non-production change
that identifies:

- exact authority account and Region;
- exact GUG-215 implementation commit and required green CI checks;
- exact reviewed Change Set name and original-template/resource digests;
- exact versioned broker artifact, code digest and code-signing configuration;
- canonical effective broker execution-policy digest;
- exact Identity Store, Identity Center Instance and Application;
- two distinct immutable Identity Store UserIds;
- exact source permission-set role ARNs;
- exact assignment and invoker-policy digests;
- rollback, revocation and evidence owners.

The CloudFormation stack
`bootstrap/cfn-platform-authority-change-set-retirement-ledger.yaml` must be
planned, independently reviewed, executed and read back through a separately
authorized deployment process. This runbook contains no implicit authorization
to deploy it.

Stop if any parameter comes from a request, naming inference, chat history or
unreviewed live value.

## Phase 1 — Read back the deployed PEP boundary

Before invocation, independently prove:

1. one dedicated table named
   `scanalyze-platform-authority-change-set-retirements` is `ACTIVE`;
2. the table has exact `retirement_id` hash key, deletion protection, KMS
   encryption, PAY_PER_REQUEST billing, no stream/replica and 35-day PITR;
3. its resource policy denies all writes outside the exact broker execution
   role;
4. the broker execution role has exactly one inline policy, no attached policy,
   no permissions boundary and Lambda-service-only trust;
5. the live canonical broker policy digest matches the deployment binding;
6. the function uses the reviewed versioned artifact, code SHA, execution role
   and code-signing configuration;
7. reserved concurrency equals one;
8. aliases `classify`, `retire` and `reconcile` all point to the same reviewed
   published version, never `$LATEST`, with no weighted routing;
9. the classifier and approver permission-set assignments are each bound to
   the reviewed distinct UserId and provisioned to the authority account;
10. the invoker trusts and policies contain exact identity-enhanced conditions,
    no `IfExists`, and only the expected alias invocation;
11. the Lambda function, invoked alias and resolved version have no
    resource-based policy;
12. an account-wide IAM inventory proves no foreign principal can invoke the
    function or its aliases;
13. no human role has an allow for `DeleteChangeSet` or DynamoDB writes.

Any missing, denied, partial or ambiguous readback blocks the workflow. Do not
add a broad managed policy as a shortcut.

## Phase 2 — Classifier invokes `classify`

Use a fresh session whose STS identity is exactly the account-local
`ScanalyzeGug215ClassifierInvoker` role. The human CLI sends an empty payload to
the qualified alias:

```bash
python3 scripts/deployment/platform-authority-change-set-retirement.py \
  broker-classify \
  --authority-account-id '<12-digit-authority-account-id>' \
  --region '<authority-region>' \
  --allow-broker-classification
```

The broker fails closed unless it proves:

- exact empty `REVIEW_IN_PROGRESS` shell;
- no service role, notifications, parent or root metadata;
- zero stack resources;
- exactly one active Change Set across all pages;
- exact full ID, `CREATE`, `CREATE_COMPLETE`, `AVAILABLE` state;
- exact original template digest, parameters, tags and four reviewed resource
  additions;
- exact runtime, identity and ledger controls.

Only the Lambda then creates
`retirement_id = gug215#sha256:<64-hex-change-set-id-digest>` in state
`CLASSIFIED`, version 1, attempt count zero with `attribute_not_exists`.
Expected sanitized output is:

```text
BROKER_STATUS: CLASSIFIED
NEXT_REQUIRED_CONTROL: INDEPENDENT_APPROVAL_REQUIRED
AWS_CHANGE: exact GUG-215 broker invocation only
```

The printed ledger digest is evidence for review, not authority outside the
durable item.

## Phase 3 — Independent review

The second operator must review the approved private change package and live
readback without receiving direct target mutation authority. At minimum,
confirm:

- classifier and approver are the two reviewed different Identity Store users;
- the ledger is exactly `CLASSIFIED` version 1 with zero attempts;
- target, template and inventory digests match the reviewed baseline;
- broker code, effective broker policy, assignments and invoker policies match
  their deployment-bound digests;
- no original bootstrap Plan is being asserted or reconstructed;
- the approver invoker can call only `retire` and `reconcile`.

The approver's identity-enhanced invocation of `retire` is the only accepted
approval action; caller-supplied identity or approval data is rejected.

## Phase 4 — Approver invokes the one-shot `retire` alias

Use a fresh session whose STS identity is exactly
`ScanalyzeGug215ApproverInvoker` and whose identity-enhanced context is bound to
the reviewed approver UserId:

```bash
python3 scripts/deployment/platform-authority-change-set-retirement.py \
  broker-retire \
  --authority-account-id '<12-digit-authority-account-id>' \
  --region '<authority-region>' \
  --allow-retire-exact-change-set
```

The broker:

1. verifies runtime, identity and ledger controls;
2. requires `CLASSIFIED` version 1 or the exact resumable `APPROVED` version 2;
3. revalidates the exact target;
4. when starting from `CLASSIFIED`, writes `APPROVED` version 2 through CAS;
5. writes `ATTEMPTED` version 3, attempt count one through CAS;
6. revalidates the target again after the durable attempt claim;
7. compares the retirement key and every target digest to the claimed ledger;
8. may issue one `DeleteChangeSet` request by the final full Change Set ID and
   full Stack ID, with SDK retries disabled.

Expected status is `RETIREMENT_ATTEMPTED` or
`RECONCILIATION_REQUIRED`. Both require reconciliation. Never wrap this command
in a shell retry, CI retry, workflow retry, SDK retry or manual second-attempt
procedure.

If the process stops after the `APPROVED` CAS, the same reviewed approver may
resume `broker-retire`. The broker accepts that exact state and proceeds only
to the one `ATTEMPTED` claim; it does not recreate approval or delete before
the claim.

Re-invoking `broker-retire` while the ledger is `ATTEMPTED` cannot issue another
delete; it returns reconciliation required. Treat every lost or malformed
response as uncertain regardless of what the terminal displayed.

## Phase 5 — Reconcile through the non-delete alias

Use the same reviewed approver invoker class and invoke only `reconcile`:

```bash
python3 scripts/deployment/platform-authority-change-set-retirement.py \
  broker-reconcile \
  --authority-account-id '<12-digit-authority-account-id>' \
  --region '<authority-region>' \
  --allow-broker-reconciliation
```

This alias has no delete branch. It compares the current full Stack ID digest
to the claimed ledger and uses that full ID for the complete resource and
Change Set inventories. If the target remains present, it returns
`RECONCILIATION_REQUIRED` without changing the ledger. A foreign or ambiguous
inventory denies. Immediately before CAS it repeats the exact Stack ID,
zero-resource and zero-Change-Set proofs. Only exact target absence and the
preserved empty `REVIEW_IN_PROGRESS` shell permit CAS to
`RETIRED_RECONCILED`, version 4, attempt count one.

The terminal ledger records effect attribution as `UNPROVEN`. Do not claim the
client response proved which path removed the metadata.

## Phase 6 — Revoke and re-run recovery preflight

After terminal reconciliation, or immediately while containing an uncertain
attempt:

1. remove both temporary Identity Center assignments;
2. provision the removals to the exact authority account;
3. read back zero matching assignments;
4. revoke/invalidate active classifier and approver sessions;
5. read back the absence of usable temporary authority;
6. verify account-level S3 Public Access Block is present and all true;
7. run a fresh, separately authorized GUG-214 recovery preflight.

GUG-215 never returns `READY`. It returns
`RETIREMENT_ROLE_REVOCATION_REQUIRED`, `PAB_AND_REVOCATION_REQUIRED`, or a
blocking/reconciliation state. Missing PAB does not authorize this runbook to
repair it.

## Stop conditions

Stop before any broker invocation, or continue only with `broker-reconcile`
after an attempt, when any of these is true:

- wrong account, Region, invoker role, UserId, Identity Store, Instance or
  Application;
- fewer than two genuinely independent operators;
- assignment, invoker policy, broker policy, code, alias, signing or concurrency
  digest/readback mismatch;
- ledger missing, malformed, unprotected, not KMS encrypted, without PITR, or
  writable by a non-broker principal;
- request payload or local artifact is proposed as target/identity authority;
- shell or Change Set metadata differs from the reviewed contract;
- target inventory is empty/multiple/foreign before classification;
- target, template, tag, parameter or four-change inventory drift;
- durable state/version/attempt count is unexpected;
- delete response is ambiguous or any attempt already exists;
- assignment/session revocation cannot be proved.
- the identity-enhanced credential adapter is absent or its context cannot be
  read back;
- any foreign identity or resource-based policy can invoke the broker;
- invocation is asynchronous or wrapped in an automatic retry mechanism.

## Evidence handling

Publish only sanitized status classes, digests, counts, exact commit/PR checks
and whether deployment/invocation occurred. Keep Identity Store UserIds,
assignment records, role/function/table ARNs, Lambda artifact locators, code
signing configuration, Change Set names/UUIDs, templates, ledger documents,
CloudTrail and AWS responses in the approved private evidence system.

No live stack deployment, broker invocation or Change Set deletion occurred
during GUG-215 repository implementation. Live retirement remains blocked and
production is **NO-GO**.
