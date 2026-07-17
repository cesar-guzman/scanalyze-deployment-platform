# ADR-037: Bounded Single-Operator Founder Bootstrap Exception

- **Status:** Proposed; accepted only after reviewed merge and main verification
- **Date:** 2026-07-17
- **Work package:** GUG-209
- **Parent:** GUG-206 / GUG-125 / GUG-117
- **Baseline:** `dc94eb51258a15e4960a0d154a42d6d5410528b0`
- **AWS live validation:** None; no Change Set execution or Terraform apply is authorized by this decision
- **Execution status:** **OFFLINE-ONLY — LIVE EXECUTION BLOCKED**
- **Production:** **NO-GO**

## Context

GUG-206 deliberately requires independently attributable IAM Identity Center
Plan and Apply principals. That is the normal bootstrap control and remains the
only acceptable steady-state process. A newly created platform-authority
account can temporarily lack a second independently attributable operator,
which would otherwise leave the initial state-backend bootstrap blocked.

The user authorized a narrow founder exception for one operator, but a local
profile, a self-approval field, a standing administrator role, or a generic
break-glass path would weaken the durable design. The exception must therefore
be an explicit, one-use risk acceptance with a smaller authority envelope than
the normal Apply path, not a relaxation of GUG-206 approval validation.

## Decision

### 1. The normal two-person flow is unchanged

`ScanalyzeAuthorityBootstrapPlan` and
`ScanalyzeAuthorityBootstrapApply` retain their normal requirement for
non-overlapping, independently attributable initiator and approver/executor
identities. The normal approval code must continue to reject an equal operator
ID or equal authenticated principal digest.

GUG-209 introduces a separate record type and separate, temporary permission
sets. It must not add `--allow-self-approval`, alter the normal approval
predicate, alias the normal roles, or reuse the BreakGlass policy. The
BreakGlass role remains forbidden from Plan/Apply promotion.

### 2. The exception is bound to one authority boundary

Every founder-exception record is fail-closed unless all of the following are
exactly true:

- `authority_account_id` is `042360977644`;
- `region` is `us-east-1`;
- `environment` is `non-production`;
- the stack uses `CREATE` semantics and the reviewed bootstrap resource
  inventory only;
- it references one newly created, exact CloudFormation Change Set and its
  reviewed template digest;
- it describes one intended execution attempt for a future live policy
  enforcement point (PEP); it does not itself authorize or consume an AWS
  execution attempt.

There is no customer selector, destination-account selector, production
variant, wildcard account/region, existing-stack update, replacement Change
Set, or retry path. Expired, cancelled, uncertain, malformed, foreign, or
previously consumed records are terminally unusable.

Local JSON records, digests, and offline policy renderings are inputs to review
only. They are not durable authorization, cannot prove freshness, and cannot
enforce exactly-once execution across workstations, sessions, or failures.

The rendered Plan and Apply templates include explicit
`DenyOfflineOnlyFounderPlanMutations` and
`DenyOfflineOnlyFounderApplyMutations` statements. IAM explicit deny overrides
their accompanying allow statements, so even an accidental attachment remains
mutation-blocked while no durable PEP exists. Those denies are not a live
enablement switch and no GUG-209 command attaches a template.

### 3. The offline waiver model is explicit and cannot impersonate independent approval

The offline exception record format models the following required semantics.
A future durable PEP record must preserve them rather than converting the
offline artifact into authorization:

```text
approval_mode: SINGLE_OPERATOR_FOUNDER_EXCEPTION
independent_approval_present: false
approver_id: null
single_execution: true
```

It also records a bounded risk-acceptance reference and a digest of the
operator's authenticated Identity Center subject. The raw user ID, principal
ARN, permission-set assignment, Change Set ID, plan, policy rendering, and
AWS response remain controlled private evidence. They must never enter Git,
Linear, NotebookLM, logs, or general CI artifacts.

This record is evidence that independent approval did **not** exist. It is not
an approval substitute, and cannot be used by later normal or customer
deployment workflows.

### 4. Plan and Apply remain temporally separated

Before the founder Plan window can open, the normal bootstrap Plan assignment
must be revoked and quarantined for the maximum possible existing Identity
Center session lifetime. The minimum quarantine is twelve hours from the
documented revocation time; profile names and assignment intent are not proof.

The founder Plan and founder Apply windows are disjoint, have a recorded
minimum gap, and each accepts only the same hashed Identity Center subject.
The temporary Plan policy cannot execute a Change Set. The temporary Apply
template describes a future PEP that could execute only the one reviewed Change
Set and cannot create or cancel a Change Set, create customer resources, delete
a stack, use BreakGlass, or directly change account S3 public-access block
settings. It is not attached or executable authority in GUG-209.

The state bucket's account public-access block is a precondition for this
exception. The founder path must not add a direct account-level S3 mutation as
a convenience fallback.

### 5. A future PEP binds CloudFormation and KMS exactly

A future reviewed live PEP must allow `cloudformation:ExecuteChangeSet` on the
exact review-stack resource only when the request condition
`cloudformation:ChangeSetName` equals the exact founder Change Set name. It
must not rely on a local record, a wildcard Change Set ARN, a stack name alone,
or a request-supplied identifier.

If that future PEP reuses the existing `create-change-set --tags` command, it
must also authorize `cloudformation:TagResource` only on the exact stack and
Change Set resources with `cloudformation:CreateAction=CreateChangeSet`, exact
`aws:RequestTag` values for `managed_by=cloudformation`,
`service=scanalyze-platform-authority`, and `work_package=GUG-206`, and the
exact `aws:TagKeys` set. The future policy is separately reviewed; it must not
remove the offline deny from an attached policy in place.

The bounded KMS alias creation path permits `kms:CreateAlias` only. It excludes
`kms:DeleteAlias` and `kms:UpdateAlias`. Because KMS does not support conditions
on an alias resource statement, the policy uses the exact alias resource without
conditions plus a companion tagged-key statement for `kms:CreateAlias` that
requires `aws:CalledVia=cloudformation.amazonaws.com`. Both grants are required;
neither may be broadened or treated as direct API authority.

### 6. AWS enforces expiry; local time is not an authority signal

Both temporary permission-set policies contain explicit `Deny` statements
based on the AWS request-context key `aws:CurrentTime`, before and after their
respective window. CloudFormation invocation is also bound to the authenticated
Identity Center `identitystore:UserId`; the raw value is inserted only into a
private rendered policy after matching its digest to the exception record.

The time-bound deny remains attached for at least twelve hours after the
latest founder window expires. This is mandatory because removal of Identity
Center assignments alone does not prove that an already issued AWS session has
lost access. Structural cleanup separately removes temporary assignments and
memberships, and requires readback evidence. A missing, conflicting, or
unverifiable readback produces `REVOCATION_REQUIRED`, never success. In this
package these are offline policy templates and contract requirements, not
attached live permission sets.

### 7. A future live PEP must make exactly-once and revocation durable

A future live PEP must use a controlled durable compare-and-swap (CAS) ledger,
not the local JSON ledger produced by this package. It must bind the exact
exception and Apply-principal digests to trusted identity and event evidence.
Immediately before `ExecuteChangeSet`, it must read back the exact Change Set,
template, stack/resource inventory, state, account, Region, and Change Set
name; only then may it atomically consume the zero-attempt durable ledger.

A lost response, timeout, or ambiguous CloudFormation result is `UNCERTAIN`;
it cannot be retried. Only read-only reconciliation is allowed after
uncertainty. The offline records cannot report a live final result.

A future PEP final result cannot be `SUCCEEDED` until the founder Apply window
has expired, the AWS-side deny retention is scheduled, and a revocation receipt
records successful structural cleanup and readback. Automatic authorization
expiry is provided by the AWS-side time condition. Cleanup automation is a
separate accountable action and must not be claimed from a local timer alone.

## Consequences

- The current package can prepare auditable offline exception and policy
  artifacts only; it cannot bootstrap an authority backend.
- Normal independent approval is preserved for every later bootstrap, saved
  Terraform plan, customer deployment, and production action.
- A prior or future session cannot obtain authority merely because a local
  process considers its window closed.
- The exception carries a deliberate residual risk: there is no independent
  human approval for its single attempt.
- No AWS Change Set execution, Terraform apply, Scanalyze deployment, customer
  workload, or production operation is authorized by this repository change.

## Alternatives rejected

- **Allow self-approval in GUG-206:** turns an exceptional risk acceptance
  into an invisible normal-flow bypass.
- **Use BreakGlass:** its purpose and ownership are different; it must not
  promote a bootstrap plan to apply authority.
- **Trust profile names or an operator email:** neither proves the authenticated
  Identity Center subject or temporal policy conditions.
- **Remove assignments and assume instant revocation:** existing AWS sessions
  require a durable AWS-side deny window plus independent readback.
- **Retry an uncertain execution:** permits duplicate resource creation or a
  second unreviewed state transition.
- **Broaden to customer accounts or production:** violates the dedicated
  platform-authority and non-production boundaries.

## Rollback and recovery

Before the founder Apply attempt, allow the exact unexecuted Change Set to
expire or be cancelled through the normal reviewed cancellation boundary.
Never edit its identifiers in place or create a replacement under the same
exception. After an uncertain result, run read-only reconciliation only. Do
not execute again, delete retained S3/KMS resources, remove the AWS-side deny
early, or infer cleanup from local state.

If structural cleanup cannot be verified, retain the deny policy through its
full twelve-hour retention and escalate with a sanitized
`REVOCATION_REQUIRED` receipt. A future exception requires a new risk
acceptance, new windows, a new Change Set, and a new durable zero-attempt
ledger.

## Evidence classification

| Class | Status |
|---|---|
| Implemented | Offline contracts, policy templates, schemas, tests, and documentation only, after reviewed commit |
| Locally validated | Pending named offline gates on the GUG-209 branch |
| CI validated | Pending required checks for the exact commit |
| Live validated | No; this ADR does not authorize any AWS execution |
| Blocked | A separate reviewed live PEP with durable CAS, trusted identity/event evidence, immediate AWS readback, controlled temporary policy provisioning, explicit execution authorization, read-only reconciliation, and verified revocation |
| Production | **NO-GO** |
