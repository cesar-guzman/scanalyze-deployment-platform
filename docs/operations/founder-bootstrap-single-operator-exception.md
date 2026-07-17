# Founder Bootstrap Single-Operator Exception

## Purpose and hard boundary

This runbook describes the **exceptional** GUG-209 process for a temporarily
single-operator founder bootstrap. It is not the normal GUG-206 process and
does not authorize a self-approved deployment.

The exception is valid only for the dedicated platform-authority account
`042360977644`, AWS Region `us-east-1`, and the literal
`non-production` environment. It describes the required binding for one fresh
CloudFormation Change Set and one intended future durable-PEP attempt; it does
not currently permit either AWS operation. It does not authorize a
customer destination, production, Terraform apply, Scanalyze workload
deployment, S3/KMS deletion, BreakGlass use, or a retry.

The normal `ScanalyzeAuthorityBootstrapPlan` /
`ScanalyzeAuthorityBootstrapApply` approval flow remains mandatory whenever an
independent reviewer exists. This exception has the following explicit offline
record format:

```text
approval_mode: SINGLE_OPERATOR_FOUNDER_EXCEPTION
independent_approval_present: false
approver_id: null
single_execution: true
```

This offline model represents a risk-acceptance receipt; it is not an
independent approval or durable authorization.

## Execution status: OFFLINE-ONLY — LIVE EXECUTION BLOCKED

GUG-209 currently creates only local private JSON records, digests, and policy
renderings. None is durable authorization, a live policy enforcement point
(PEP), trusted identity/event evidence, or a compare-and-swap (CAS) execution
ledger. They cannot establish freshness or exactly-once execution and must not
be used to call `ExecuteChangeSet`.

This runbook specifies requirements for a future separately reviewed live PEP.
It neither attaches an IAM Identity Center policy, changes an assignment, calls
CloudFormation, nor authorizes Terraform apply. Until that PEP exists and has
separate live authorization, the sole correct live state is **BLOCKED**.

Both rendered templates deliberately contain
`DenyOfflineOnlyFounderPlanMutations` and
`DenyOfflineOnlyFounderApplyMutations`. Their explicit IAM denies override
mutation allows, so accidental attachment remains mutation-blocked while the
durable PEP is absent. These statements are a safety interlock, not a way to
enable a live window; no GUG-209 command attaches, alters, or removes them.

## Preconditions

Do not start a founder window unless every condition below is established in
private, controlled evidence:

1. STS proves the exact authority account and Region. A profile name, account
   alias, local username, email, or last-four-digit check is not authority.
2. The account is explicitly classified `non-production`; no customer
   destination is within the exception scope.
3. The normal Plan assignment has been revoked and the revocation is
   timestamped. A twelve-hour session quarantine from that revocation must
   finish before the founder Plan window begins.
4. The account-level S3 public-access block is already all true. Founder Apply
   never receives a direct API permission to change it.
5. The reviewed template has only the allowed initial state-backend resources,
   uses `CREATE`, and has no replacement or update action.
6. A bounded risk-acceptance reference exists and the raw Identity Center user
   ID hashes to the controlled exception record. Never store or publish the raw
   user ID, principal ARN, group membership, permission-set assignment,
   Change Set ID, plan, rendered policy, backend file, or AWS response in this
   repository, Linear, NotebookLM, terminal history, or general CI artifacts.
7. A future live PEP design has an approved controlled durable CAS ledger with
   zero prior attempts and no predecessor/reuse relationship. A local JSON
   ledger is not sufficient evidence of this precondition.

If a precondition is missing, malformed, stale, conflicting, or cannot be
verified, stop. The correct state is **Blocked** or
`REVOCATION_REQUIRED`, not an inferred approval.

## Timed authorization model

The controlled exception record declares two temporary windows:

| Window | Maximum role | Authority | Required separation |
|---|---|---|---|
| Founder Plan | `ScanalyzeFounderBootstrapPlan` | Future PEP only: create/review/cancel one exact unexecuted Change Set | Starts after the twelve-hour normal-Plan session quarantine; cannot execute |
| Founder Apply | `ScanalyzeFounderBootstrapApply` | Future PEP only: execute one reviewed Change Set once | Starts after Founder Plan expires and after a recorded minimum gap; cannot create/cancel a Change Set |

Each temporary policy is rendered privately and binds the same authenticated
Identity Center subject. It contains explicit `Deny` conditions based on AWS
`aws:CurrentTime` before and after the authorized window. A local timer,
operator assertion, or removed assignment is not a revocation signal.

The policy is retained with the time-bound deny for at least twelve hours after
the latest founder window. This retention is mandatory even after membership
and assignment cleanup, because active AWS sessions are not proven revoked by
identity-store cleanup alone.

No temporary policy is attached and no window is live in GUG-209. The table is
the required design for a separately approved future PEP, not a grant of
present authority.

## Controlled sequence

### 1. Prepare, but do not execute

Create the private exception record format and private draft execution model
from the exact reviewed bootstrap plan. The record must bind the authority
account, Region, non-production environment, template digest, complete allowed
resource inventory, one Change Set, window bounds, risk acceptance, and hashed
operator subject.

No CLI option may convert the normal approval command into a self-approval
command. Do not run `apply`, `execute-change-set`, or Terraform apply as part
of preparing this exception.

### 2. Future PEP: give founder Plan authority only for its window

Render and independently policy-review the temporary founder Plan policy. It
must bind the exact Change Set name, authenticated Identity Center subject,
account, Region, and AWS-side date window. Its explicit deny must block
execution, direct S3/KMS writes, resource deletion, IAM/Organizations actions,
customer access, BreakGlass, and every request outside the Plan window.

Provisioning an Identity Center permission set or assignment is a separately
authorized live operation; this runbook does not make it implicit. Record only
sanitized policy digest and timing evidence.

For a future live PEP, the exact CloudFormation binding must authorize the
stack resource only with `cloudformation:ChangeSetName` equal to the exact
reviewed founder Change Set name. A stack ARN alone, a wildcard Change Set ARN,
or the local exception JSON is insufficient.

If the future PEP reuses the existing `create-change-set --tags` command, it
must allow `cloudformation:TagResource` only for the exact review stack and
exact Change Set, with `cloudformation:CreateAction=CreateChangeSet`, exact
`aws:RequestTag` values `managed_by=cloudformation`,
`service=scanalyze-platform-authority`, and `work_package=GUG-206`, plus the
exact `aws:TagKeys` set containing only those three keys. It must never inherit
tag authority from a wildcard or strip the offline deny in place.

Bounded KMS alias creation is `kms:CreateAlias` only. KMS alias-resource
statements cannot use conditions, so the exact alias resource statement has no
condition; a companion tagged-key statement permits only `kms:CreateAlias`
with `aws:CalledVia=cloudformation.amazonaws.com`. `DeleteAlias` and
`UpdateAlias` are outside the founder boundary.

### 3. Future PEP: create and review the single Change Set

The current GUG-209 tool does not create a Change Set. A future PEP may create
exactly one fresh Change Set during the Founder Plan window only after its
durable CAS and trusted identity/event boundary are live. Review the template
digest, all resource actions, account public-access-block precondition, and
the Change Set binding. Do not reuse an expired or cancelled Change Set. Do not
create a second Change Set to “repair” a plan or extend timestamps.

At Plan expiry, the AWS policy denies further Plan actions automatically. The
identity administrator then starts structural removal of temporary Plan
assignment and membership, but must retain the AWS-side deny policy for the
required twelve-hour retention period.

### 4. Future PEP: establish the bounded Apply authority

Only after the Plan window is closed, the minimum recorded Plan/Apply gap has
elapsed, and the exact Change Set review is complete may a separately rendered
Founder Apply policy be considered. It may name only the reviewed Change Set
and must retain all direct-write and destructive denials. It cannot change S3
account public access block, create/cancel Change Sets, or use a broad resource
prefix.

The exception receipt must continue to show that independent approval is absent;
no new `approver_id` may be filled in to make the record look normal.

### 5. Future PEP: consume the sole attempt only with durable proof

GUG-209 does not provide a live PEP, durable CAS transition, or authority to
execute AWS. Its local offline transition output is a review artifact only and
must never be treated as a consumed live attempt.

Before a future PEP calls `ExecuteChangeSet`, it must use a controlled durable
CAS ledger and trusted identity/event evidence; immediately read back the exact
Change Set, template, complete stack/resource inventory, account, Region,
Change Set name, and current execution state; then atomically consume the
zero-attempt ledger for the exact exception and Apply-principal digests. A lost
response, timeout, or ambiguous CloudFormation state is `UNCERTAIN`. It must
not be retried. Use read-only reconciliation only.

### 6. Revoke, retain deny, and prove cleanup

At the end of the Apply window, the AWS-side date denial takes effect without
an operator deciding that a local clock has expired. The required cleanup is:

1. remove temporary Plan and Apply account assignments;
2. remove temporary founder group memberships;
3. read back both assignments and memberships from the governed identity
   system;
4. retain the explicit AWS-side date-deny policy for at least twelve hours
   after the latest window; and
5. write a sanitized revocation receipt that classifies each cleanup proof.

Only a receipt with all cleanup readbacks and the full deny-retention schedule
is `REVOKED`. Any failure, absent readback, provider delay, conflicting
identity state, or response loss is `REVOCATION_REQUIRED`; retain the denial
and escalate. Do not delete or weaken the deny policy early to make a cleanup
screen look green.

## Evidence publication

Publish only the GUG-209 branch/commit/PR, sanitized policy and record digests,
resource-type counts, result class, named gate outcomes, and the fact that the
operation lacked independent approval. Do not publish user identifiers, ARNs,
Change Set identifiers, account assignments, backend values, plans, receipts,
AWS responses, logs, or screenshots.

Use these status classes exactly:

| Class | Meaning for this exception |
|---|---|
| Implemented | Repository contract exists in the reviewed commit |
| Locally validated | Named offline tests/gates passed |
| CI validated | Exact-commit checks passed |
| Live validated | No; live execution is blocked until a separately reviewed PEP, durable CAS, trusted evidence, exact readback, and authorization exist |
| Blocked | A required precondition, durable live PEP, live authorization, or revocation proof is absent |
| Production | **NO-GO** in all cases |

## Recovery

For any uncertain execution, expired record, invalid policy rendering, or
failed cleanup, follow
[the platform-authority recovery runbook](platform-authority-bootstrap-recovery.md).
Never recreate the exception from a copy, alter an expiry in place, or use the
normal apply flow to bypass a future durable ledger. The local JSON record is
not a recovery ledger and cannot be used to infer a live execution state.
