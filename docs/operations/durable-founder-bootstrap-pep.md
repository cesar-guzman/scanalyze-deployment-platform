# Runbook: durable founder bootstrap PEP

This runbook is executable only after GUG-211 review, green CI, merge, exact
main verification, and a separate live change authorization. It does not grant
that authorization itself.

## Phase 0 — private evidence and read-only preflight

Use only SSO profiles. Unset static credential variables. Store raw subject
IDs, principal ARNs, policies, intents, plans, exceptions, ledgers, backend
configuration and AWS responses under a private mode-0700 directory with
mode-0600 files outside the repository.

From the management account, run the seed `preflight` command. Confirm:

- exact management account and all-features organization;
- authority account has exactly one OU parent;
- S3 policy type and StackSets trusted-access current state;
- no foreign S3 policy target or StackSet instance;
- zero standing broad administrator assignments usable by the founder during
  the Plan/Apply windows; the exact temporary permission set is the only live
  execution authority;
- reviewed template digest.

The seed profile must resolve to the exact management-account SSO permission
set `ScanalyzeFounderPepSeed`. The later Identity Center lifecycle profile must
resolve to `ScanalyzeFounderPepIdentityAdmin`. Attach only the two reviewed IAM
policy templates. Creating/assigning these permission sets is a separate
management-account change: review it, read back the inline policies and remove
the generic administrator assignment before opening the founder windows.

From the authority Plan profile, run the GUG-214 canonical
`preflight-recovery` and confirm the backend stack is an empty
`REVIEW_IN_PROGRESS` shell, every active Change Set page is empty, and account
S3 PAB is present/all true. The shell must have no CloudFormation service role,
notification destination or parent/root nesting metadata. A resource, unknown status, active/ambiguous Change
Set, missing PAB or existing backend stops the process. A general ReadOnly
profile is independent evidence only and cannot replace this exact Plan role.
Do not infer KMS/S3/DynamoDB resource names from the empty shell.

## Phase 1 — seed root of trust

After exact authorization, run the seed with `--allow-management-seed`. The
expected changes are limited to:

1. enable the Organizations S3 policy type if disabled;
2. attach one `all` Block Public Access policy only to the authority account;
3. activate service-managed StackSets trusted access if disabled;
4. create one non-automatic StackSet and one account/Region intersection
   instance containing the protected ledger table.

AWS requires both `organizations:CreatePolicy` and
`organizations:TagResource` for a tagged policy creation request. The Seed
permission set must contain the reviewed create-bound statement for both
actions. If policy-type enablement succeeds but policy creation is denied,
stop, preserve the enabled type, reconcile read-only and repair the reviewed
permission set through CI and merge. Do not retry with a generic administrator
or create an untagged policy.

`ListTagsForResource` must not share `aws:ResourceTag/*` conditions with the
post-trust policy reads: those tags do not establish IAM authority until the
read succeeds. Its reviewed grant is read-only and limited to the exact
management organization and S3-policy ARN family. If the policy was created
but tag readback is denied, do not retry the seed. Verify zero targets,
disabled/unchanged StackSets state, and absence of the ledger; repair the
permission set through a reviewed PR and merged-main verification first.

Verify from the authority account that the effective S3 BPA is all true and
the table is ACTIVE, exact-ARN, single-key, deletion-protected, encrypted and
PITR-enabled. Seed success does not permit founder Plan.

## Phase 2 — temporary Identity Center authority

Use the separately verified `ScanalyzeFounderPepIdentityAdmin` management-account
profile only with `--identity-admin-profile`. `prepare-authority-shells` creates
both tagged permission sets as deny-only, provisions them only to account
`042360977644`, verifies zero assignments, and writes the two derived STS
principal ARNs privately. It never assigns access. The administrator policy is
rendered from the reviewed
`platform-authority-founder-pep-identity-admin-role.json` template and permits
no Identity Store group or membership mutation.

Create the reviewed intent after the shells exist. `activate-authority --mode
plan` then replaces the exact shell policy, provisions it, and creates exactly
one direct `USER` assignment for the subject digest in the intent. It fails if
normal GUG-206 Plan has any assignment, either founder permission set has a
foreign assignment, the opposite founder mode is assigned, the tags/policy
differ, or the time window is not open. `activate-authority --mode apply` uses
the same controls in the later non-overlapping window.

Do not edit rendered timestamps, subject, exception ID, Change Set name, table,
account, Region, stack, tags or resource inventory in the console. Read back
the provisioned inline policy and compare its canonical digest before the
window. Retain the expired AWS-side deny for twelve hours.

## Phase 3 — initialize and Plan

Create the zero-attempt item once with `initialize-ledger`. Duplicate creation
must fail. Use `verify-ledger` before Plan.

The integrated `plan` command:

1. validates STS founder Plan role and intent digest;
2. verifies S3 BPA, exact table controls through `DescribeTable` plus
   `DescribeContinuousBackups`, the exact empty review stack with no inherited
   service role/notifications/nesting, and every active Change Set page;
3. commits `PREPARED -> PLAN_ATTEMPTED` by CAS;
4. repeats the exact shell-authority and paginated zero-active-Change-Set
   inventories immediately before create;
5. creates one exact CREATE Change Set;
6. waits and re-reads ARN, name, status, tags and four resources;
7. builds GUG-206 Plan and GUG-209 exception receipts privately;
8. commits `PLAN_ATTEMPTED -> PLAN_REVIEWED` by CAS.

If steps 4–8 are ambiguous, the ledger becomes `UNCERTAIN`. Never invoke Plan
again and never create a replacement Change Set under the same exception.

The second inventory narrows but cannot eliminate CloudFormation TOCTOU: there
is no atomic zero-inventory-and-create operation. An unexpected concurrent
writer is a P0 stop. After the CAS, any non-empty or ambiguous inventory
consumes the one attempt and permits only read-only reconciliation.

## Phase 4 — quarantine gap and Apply

After Plan expiry and before Apply begins, run `revoke-authority --mode plan`.
It removes the exact direct-user assignment, reads back zero assignments,
reprovisions the expired AWS-side time-deny policy, and rejects early/late
revocation. Wait the recorded gap. Activate Apply only for its exact later
window.

The integrated `apply` command:

1. validates STS founder Apply role and private receipt digests;
2. verifies S3 BPA, the exact table and PITR through `DescribeTable` plus
   `DescribeContinuousBackups`, empty stack without inherited authority and
   the exact executable Change Set again;
3. commits `PLAN_REVIEWED -> APPLY_ATTEMPTED` by CAS;
4. rechecks the shell metadata immediately before and executes the exact Change
   Set once;
5. waits for `CREATE_COMPLETE` and re-reads exactly four resources;
6. commits terminal success, or `UNCERTAIN` on any ambiguous response.

Never call `execute-change-set` directly. Never retry Apply.

## Phase 5 — revoke and close

After Apply reaches `SUCCEEDED`, but before the Apply window expires:

1. run `revoke-authority --mode apply` with the management administrator
   profile; the command permits only the direct-user assignment and retains the
   time-deny policy;
2. while the already-issued Apply session is still within its AWS window, run
   `close-revocation` with both the founder Apply profile and the separate
   management administrator profile;
3. read back zero normal Plan, founder Plan and founder Apply assignments,
   exact `USER` principal type, no group membership, both tagged permission
   sets, exact inline-policy digests, and exact authority-account provisioning;
4. commit `SUCCEEDED -> REVOKED` by DynamoDB CAS and write the private typed
   revocation receipt;
5. retain both expired-deny policies through `deny_retain_until` and publish
   only sanitized digests, state classes and named gate results;
6. after retention, run `retire-authority`; it requires the exact receipt,
   verifies no assignment, removes inline policies and deletes only the two
   tagged temporary permission sets;
7. keep the durable ledger and organization controls retained.

Only `REVOKED` closes the exception. A missing readback remains
`REVOCATION_REQUIRED` and blocks GUG-206/GUG-125 continuation.

The expected command order is therefore:

```text
seed preflight -> seed apply -> prepare-authority-shells -> prepare-intent
-> initialize-ledger -> activate plan -> plan -> revoke plan
-> activate apply -> apply -> revoke apply -> close-revocation
-> retain deny 12h -> retire-authority
```

Every mutating command has a separate explicit `--allow-*` flag. Reusing a
receipt, overwriting an output, substituting a group, mixing profiles, missing
an exact readback, or invoking a phase outside its window fails closed.

## Uncertain-result reconciliation

Use read-only STS, `DescribeChangeSet`, `DescribeStacks`,
`ListStackResources`, S3/KMS control reads, and a consistent DynamoDB GetItem.
Do not update or delete the ledger. Do not cancel a Change Set after an
ambiguous execution. Classify:

- no protected effect and Plan claim consumed: terminal failed/uncertain;
- stack `CREATE_COMPLETE` with exact controls: record read-only evidence and
  follow reviewed terminal reconciliation without a second effect;
- partial/rollback/unknown: retain all resources and denials, escalate;
- any foreign resource or mismatch: P0 stop.

## Rollback

Before a CAS claim, revoke temporary access and stop. After a claim, rollback
is reconciliation, not reset. Never delete the retained table, detach the S3
policy, disable StackSets trusted access, delete retained state resources, or
reuse the exception as an ordinary rollback step.

Do not describe the DynamoDB condition as non-bypassable by an account
administrator. IAM restricts the table and partition key but cannot require a
specific `ConditionExpression`; deliberate protocol bypass is a residual risk
and blocks production use of the founder exception.
