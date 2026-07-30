# Platform-Authority Lambda Audit Permission Set

## Purpose

GUG-220 materializes and verifies the exact Identity Center permission set
required by the GUG-219 account-wide Lambda-authority collector. It is a
bounded non-production bootstrap change for one dedicated platform-authority
account and one current operator.

It grants no Lambda invocation, IAM/Lambda mutation, role relay, deployment or
production authority. `sts:AssumeRole` is explicitly denied so an
account-local resource policy cannot supply the missing relay authority.
Production remains **NO-GO**.

## Portable public contract

| Field | Required value |
|---|---|
| Permission-set name | `ScanalyzeAuthorityLambdaAudit` |
| Session duration | `PT1H` |
| Inline policy source | `policies/iam/platform-authority-lambda-invocation-inventory-role.json` |
| AWS-managed policies | none |
| Customer-managed policy references | none |
| Permissions boundary | none |
| Relay or secondary role | explicit `Deny` on `sts:AssumeRole` |
| Assignment type | exactly one direct `USER` during bounded bootstrap |
| Provisioned targets | exactly one approved platform-authority account |
| Region | `us-east-1` |
| Production effect | none |

The mechanism is reusable, while this release intentionally pins the reviewed
management and platform-authority account IDs in versioned deployment code.
Generated evidence does not repeat those raw IDs. Identity Store `UserId`,
assignment ID, permission-set ARN, generated role ARN and suffix, STS ARN and
provider payloads belong only in private operational evidence. Replication for
another organization requires a separately reviewed account-binding release;
runtime inference is forbidden.

## Authority model

The desired inline policy is rendered from the GUG-219 policy template for the
exact private target binding. The implementation computes and records both:

- the reviewed template-byte digest; and
- the canonical rendered-policy digest.

The intent also records the exact reviewed `source_commit`. It must be an
existing ancestor whose GUG-219 template, policies and runtime plus the
GUG-220 core and CLI bytes equal the executing checkout. Dirty, missing or
rebound critical source blocks plan/apply/reconcile. The policy is rendered
once, digest-checked and then passed unchanged through partial-state checks,
`PutInlinePolicy`, permission-set readback and IAM-role readback; those paths
do not reopen the worktree.

The rendered policy contains only the complete read surfaces needed by the
GUG-218 inventory. `DenyUnreviewedActions` denies every action except that exact
closed read set, even when an account-local resource policy would otherwise
grant it. `DenyGetPolicyOutsideExactBroker` limits resource-policy inspection
to the exact broker and qualifiers, and
`DenyFunctionReadsOutsideAuthorityAccount` closes cross-account expansion for
the resource-scoped Lambda list actions. Those list allows use the
authority-account function ARN; only Lambda discovery actions without
resource-level support use `Resource: "*"`. The policy also contains the exact
`DenyRoleChaining` statement; an
implicit deny alone would not stop a same-account role trust from authorizing a
role session. No request parameter can add an action, resource or target.

The private intent binds canonical digests of the exact live Identity Center
`InstanceArn`, `IdentityStoreId` and the unique authority-account AWS SSO SAML
provider ARN discovered during planning. Its validity is
at most 15 minutes from `created_at` to `expires_at`, and the implementation
checks both digests and expiry again immediately before every protected
mutation and again before final evidence. Any intent v1 generated before these
source and live-binding fields became mandatory is
obsolete and must be replaced by a new read-only plan and a new create-only
private evidence file; it is never amended or reused.

The intent additionally contains the digest of the selected private
execution-ledger directory. The CLI requires
`--execution-ledger-directory` for both `plan` and `apply`; using another
directory at apply time is a binding failure. The only accepted location is
`~/.scanalyze-private-evidence/gug-220-live-v2`; it must be outside the
repository, owned by the current effective user, non-symlink and mode exactly
`0700`. A stable work-package ledger filename—not the intent digest—blocks a
second intent or alternate principal/policy from reopening the mutation
window on the same operator host and home.

This local marker is not a cross-host durable lock and cannot resist deletion
by the same operating-system user. That limitation is acceptable only for the
authorized single-operator non-production bootstrap. Multi-operator or live
operation requires a separately reviewed immutable external ledger. It is not
production evidence.

The current direct `USER` assignment is a temporary bootstrap mechanism for
the only present operator. It does not represent independent review. A future
multi-operator model must introduce separately reviewed group or user bindings
without reusing this exception as precedent.

## State machine

```text
PLAN_ONLY
  -> MUTATION_IN_PROGRESS
  -> READBACK_VERIFIED

MUTATION_IN_PROGRESS
  -> UNCERTAIN_RECONCILE_ONLY
  -> read-only reconciliation
  -> READBACK_VERIFIED, BLOCKED_DRIFT or READBACK_INCOMPLETE
```

Before entering `MUTATION_IN_PROGRESS`, `apply` creates one immutable ledger
at the stable GUG-220 work-package filename using `O_EXCL` and reserves the
receipt output before the first AWS write. The ledger consumes the one allowed
mutation window across every intent on that host/home. Reuse fails with
`EXECUTION_LEDGER_ALREADY_CONSUMED`.

`READBACK_VERIFIED` is available only after the permission set, inline policy,
attachments, boundary, assignment, provisioned target and account-local IAM
role all match exactly. A create, assignment or provisioning API success is
not sufficient.

If the canonical inline policy is installed or changed, the target must be
explicitly reprovisioned even when it already appears in the provisioned-
account list. Policy mutation without a corresponding successful
`ProvisionPermissionSet` and target IAM readback cannot reach
`READBACK_VERIFIED`.

## Readback requirements

The post-mutation verifier must use complete pagination and prove:

1. exactly one organization Identity Center instance with status `ACTIVE`;
2. one exact permission set with the canonical name;
3. exact description and `PT1H` duration;
4. canonical inline-policy digest equality;
5. zero AWS-managed or customer-managed attachments;
6. absent permissions boundary;
7. exactly one direct `USER` assignment in the exact target account;
8. no assignment or provisioning in a foreign account;
9. successful target-account provisioning;
10. exactly one account-local `AWSReservedSSO_` role for the permission set;
11. trust naming exactly the SAML provider bound into the intent, with no relay;
12. exact role policy, zero attached role policies and no role boundary.

The final receipt additionally requires non-null
`permission_set_arn_digest` and `collector_role_iam_arn_digest`, plus
`account_assignment_verified`, `permission_set_provisioning_verified` and
`collector_role_verified` all set to `true`.

Missing pages, access denial, duplicates, foreign state or unexpected fields
block. Absence is never inferred from a partial response.

Complete pagination also applies to every IAM inventory surface. Replayed
tokens, truncated pages or an extra policy, role, attachment or boundary on a
later page block verification.

## Private evidence boundary

The live intent, provider responses and collector binding are stored outside
the repository using directories with mode `0700` and files with exact mode
`0600`. Inputs are opened with `O_NOFOLLOW`, verified from the open descriptor
with `fstat` as regular files owned by the current effective user, and outputs
use exclusive creation. Logs and public receipts contain only status, counts
and canonical digests.

The execution ledger and reserved receipt follow the same private-custody
rules. After a write may have begun, a timeout, `OSError` or any post-write
readback failure writes `UNCERTAIN_RECONCILE_ONLY` to the reserved receipt and
never authorizes a retry. If that reserved sink itself cannot be persisted, the
CLI emits sanitized public `UNCERTAIN_RECONCILE_ONLY` status with a null
receipt digest; the consumed ledger remains the authoritative no-retry marker.
A later read-only reconcile that cannot complete its evidence emits
`READBACK_INCOMPLETE` with `aws_mutation_attempted = false` rather than
misclassifying an unknown observation as deterministic drift.

## Typed artifacts

| Artifact | Contract |
|---|---|
| Provisioning intent | `schemas/platform-authority-lambda-audit-provisioning-intent.v1.schema.json` |
| One-shot execution ledger | `schemas/platform-authority-lambda-audit-execution-ledger.v1.schema.json` |
| Provisioning receipt | `schemas/platform-authority-lambda-audit-provisioning-receipt.v1.schema.json` |

The stable ledger contains the exact `intent_digest`, records
`MUTATION_WINDOW_CONSUMED`, permits one attempt and never authorizes retry.
It is authoritative only for the same operator host/home; it is not a
cross-host immutable ledger and cannot establish production readiness.

Never commit or publish:

- account or principal identifiers;
- permission-set, assignment or IAM role ARNs;
- the generated Identity Center suffix;
- STS session identities;
- live inline policies or provider responses;
- local profile names; or
- Candidate A/B raw snapshots and releases.

## Live outcome and GUG-221 recovery boundary

The authorized GUG-220 mutation window is consumed. Its result was
`UNCERTAIN_RECONCILE_ONLY`; no write retry is authorized. Sanitized read-only
reconciliation proved that the exact collector permission set exists while
the inline policy, direct assignment, authority-account provisioning and
account-local collector role remain absent or unverified.

Do not delete or reset the GUG-220 ledger and do not run GUG-220 `apply` again.
GUG-221 owns the only reviewed repair path. It limits the human
`ScanalyzeLambdaAuditRepair` permission set to exact private Lambda aliases,
requires the exact partial state and a separate provider-backed DynamoDB CAS
ledger, and exposes exactly three server-side effects: policy installation,
direct `USER` assignment and target provisioning. Its final readback must
satisfy every GUG-220 verification gate before this contract can hand off to
GUG-219.

## GUG-219 handoff

Only after exact readback and a fresh dedicated SSO session may the private
collector binding be created with the three GUG-219 fields:

```text
identity_center_region
collector_iam_role_arn
collector_sts_session_arn
```

GUG-219 then owns Candidate A, deterministic materialization and Candidate B.
Those steps remain read-only and private. If the reviewed GUG-217 broker is not
present, collection stops as blocked; GUG-220 does not deploy it.

## Evidence classification

| Evidence | Classification |
|---|---|
| Schemas, policies, CLI, tests and docs | Repository implemented on exact reviewed commit only |
| Named local gates | Locally validated only |
| Required PR checks | CI validated only for exact commit |
| GUG-220 live execution | Ledger consumed; `UNCERTAIN_RECONCILE_ONLY` |
| Permission-set readback | Partial live state only; collector not verified |
| GUG-221 repair | **Blocked** until separately reviewed broker stacks, invoke-only human boundary, authorization and exact readback |
| Candidate A/B | Read-only report material only |
| Current direct user assignment | Bootstrap operation; **not independent approval** |
| GUG-215 retirement | **Blocked** pending two different humans |
| Deployment and production | **Not authorized / NO-GO** |

## Related records

- [ADR-046](../../ADR/ADR-046-lambda-audit-permission-set-provisioning.md)
- [Operations runbook](../operations/platform-authority-lambda-audit-permission-set.md)
- [Threat-model delta](../security/gug-220-lambda-audit-permission-set-threat-model-delta.md)
- [GUG-219 materialization contract](platform-authority-lambda-invocation-materialization.md)
- [GUG-221 repair contract](platform-authority-lambda-audit-provisioning-repair.md)
