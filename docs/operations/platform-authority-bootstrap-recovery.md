# Platform-Authority Bootstrap Recovery

## Safety rules

- Stop dispatch before diagnosis.
- Verify the exact authority account and region through STS.
- Never re-run `apply` after a lost response.
- Never create a replacement bucket/key or infer ownership from names.
- Never empty, delete, migrate, restore, or copy state automatically.
- Keep customer destinations, Audit, Log Archive, and corporate shared-services
  accounts outside this procedure.

## State classification

| State | Allowed action | Forbidden shortcut |
|---|---|---|
| Preflight failed | Correct identity/binding/tooling and repeat read-only preflight | Bypass account or region check |
| Existing review shell | Run canonical `preflight-recovery` under exact Plan identity; require `REVIEW_IN_PROGRESS`, canonical StackId, zero resources, zero active Change Sets on all pages, no service role/notifications/nesting and all-true account PAB | Treat zero resources or a general ReadOnly session as sufficient authority |
| Shell carries `RoleARN`, notification ARNs or nested-stack metadata | Quarantine and reconcile read-only; obtain a separate reviewed disposition | Adopt the shell, trust the role name, or execute a Change Set through inherited authority |
| Account Public Access Block missing/partial | Stop and obtain separate reviewed remediation authorization | Repair PAB from the read-only recovery command |
| Active or ambiguous Change Set inventory | Preserve the shell and reconcile read-only | Delete the stack/Change Sets automatically or ignore pagination |
| One exact unexecuted Change Set retained and original Plan receipt absent/ambiguous | Use the separately authorized GUG-215 version-pinned broker with two identity-enhanced independent users and qualified aliases | Reconstruct a Plan, grant a human direct delete/ledger write, weaken historical `cancel`, or execute the Change Set |
| Change Set creation failed | Inspect sanitized status; delete only the failed unexecuted Change Set after review | Execute template directly |
| Change Set IAM binding failure | Stop; verify the canonical stack ARN, exact `cloudformation:ChangeSetName`, request tags, and Plan/Apply separation offline | Add a Change Set ARN resource, broaden the name, or bypass the renderer |
| Change Set available, unapproved | Let it expire or obtain independent approval | Self-approve or edit receipt |
| Approval expired | Cancel only the exact Change Set, retain the zero-resource review shell, then create a new plan | Extend timestamps or delete the stack |
| Founder exception Plan or Apply window expired | Retain AWS-side time denial, remove temporary identity assignment/membership, and record readback | Extend the window, edit timestamps, reuse the exception, or use normal apply as a bypass |
| Future founder-PEP execution response lost | Mark the durable CAS attempt `UNCERTAIN` and reconcile read-only against the original Change Set | Execute again, create a replacement Change Set, or reset the ledger |
| Founder exception cleanup incomplete | Keep the date-deny policy through its required twelve-hour retention and escalate as `REVOCATION_REQUIRED` | Claim revocation from local time or remove the deny early |
| Apply response lost | Run read-only `verify` against the original plan | Execute again |
| Stack rollback in progress | Wait and inspect CloudFormation events under controlled evidence handling | Start a competing stack |
| Stack rollback failed | Escalate; inventory retained S3/KMS resources read-only | Delete retained resources |
| Alias authorization failure | Stop; inspect the exact stack events and rendered policy read-only, then repair through GUG-207 and a new reviewed plan | Create, update, or delete the alias directly |
| Stack complete, verification failed | Stop platform-authority Terraform; remediate through a new reviewed change | Render/use backend config |
| Verification complete | Preserve receipt privately and proceed to a separate Terraform plan | Claim Scanalyze live validation |

## Read-only reconciliation

For an existing zero-resource review shell without an original plan receipt,
run the canonical recovery preflight first:

```bash
python3 scripts/deployment/platform-authority-bootstrap.py preflight-recovery \
  --authority-account-id '<authority-account-id>' \
  --region '<authority-region>' \
  --destination-account-id '<customer-a-account-id>' \
  --destination-account-id '<customer-b-account-id>'
```

Only the exact normal Plan SSO role is authoritative. The command consumes all
`ListChangeSets` pages and reports sanitized counts/state only. A general
ReadOnly profile may independently corroborate AWS inventory but cannot replace
the Plan role or be attached to a Scanalyze permission set. Because an empty
shell exposes no trusted physical IDs, do not derive S3, KMS or DynamoDB names
from templates or conventions.

The stack metadata must not contain `RoleARN`, non-empty `NotificationARNs`,
`ParentId` or `RootId`. CloudFormation retains and reuses a stack service role;
therefore even an otherwise empty shell with that metadata is foreign
authority, not a recoverable shell. Plan and Apply repeat this check immediately
before Create/Execute to minimize stale preflight evidence.

After an uncertain client result, use the original plan and new exclusive
output paths:

```bash
python3 scripts/deployment/platform-authority-bootstrap.py verify \
  --authority-account-id '<authority-account-id>' \
  --region '<authority-region>' \
  --destination-account-id '<customer-a-account-id>' \
  --destination-account-id '<customer-b-account-id>' \
  --plan '<private-evidence-dir>/bootstrap-plan.json' \
  --verification-out '<private-evidence-dir>/reconciled-verification.json' \
  --backend-config-out '<private-evidence-dir>/reconciled-backend.hcl'
```

`verify` performs no writes. If any control is missing or ambiguous, it emits
no usable backend configuration.

## Retained Change Set without a provable original Plan (GUG-215)

The historical `cancel` command below remains valid only when the original
private bootstrap Plan receipt exists and binds the exact live Change Set. If
that receipt is absent or ambiguous, do not reconstruct it from live metadata,
the repository template, a name, prior chat, or expected values.

Use the separate
[GUG-215 deployment contract](../deployment/platform-authority-change-set-retirement.md)
and [retirement runbook](platform-authority-retained-change-set-retirement.md).
That path has one version-pinned Lambda PEP, a dedicated durable ledger and two
identity-enhanced human invocation boundaries:

- two genuinely independent operators are bound by different immutable
  Identity Store UserIds, exact Identity Center context and exact assignments;
- the classifier human can invoke only the qualified `classify` alias;
- the approver human can invoke only the qualified `retire` and `reconcile`
  aliases;
- human roles explicitly lack Change Set delete and DynamoDB write authority;
- the Lambda broker is the sole ledger writer and sole exact Change Set
  deleter;
- the table resource policy denies writes outside the exact broker execution
  role;
- `classify` creates only the exact `CLASSIFIED` ledger item;
- `retire` performs `CLASSIFIED -> APPROVED -> ATTEMPTED` before at most one
  `DeleteChangeSet` request;
- `reconcile` has no delete path and writes `RETIRED_RECONCILED` only after
  exact absence. Ambiguity leaves `ATTEMPTED` and permits no second delete.

The broker accepts an empty payload only and binds the target, immutable code,
live effective broker-policy digest, assignments and invoker policies through
deployment configuration and fresh AWS readback. Caller artifacts and terminal
output are not authority.

Missing or partial Public Access Block does not authorize repair and does not
change the metadata-only nature of Change Set retirement. It does keep this
GUG-214 recovery procedure blocked after retirement until a separately
authorized path establishes and proves all-true PAB and the temporary
retirement assignment/session are revoked and read back. GUG-215 never returns
recovery readiness `READY`.

Sanitized current inspection found zero shell resources and one active exact
`CREATE_COMPLETE` / `AVAILABLE` Change Set with expected tags and four creation
changes. The version-pinned broker/ledger stack and the two independent
identity-enhanced operator bindings have not been deployed or invoked.
Therefore canonical live classification and retirement remain blocked. No live
delete was executed by GUG-215 implementation.

## Cancel an unexecuted plan

Cancellation is allowed only while the exact Change Set is `AVAILABLE`, the
stack is `REVIEW_IN_PROGRESS`, and `ListStackResources` proves the stack has
zero resources. It removes only the exact Change Set. The empty CloudFormation
review stack remains because neither bootstrap permission set grants
`DeleteStack`.

```bash
python3 scripts/deployment/platform-authority-bootstrap.py cancel \
  --authority-account-id '<authority-account-id>' \
  --region '<authority-region>' \
  --destination-account-id '<customer-a-account-id>' \
  --destination-account-id '<customer-b-account-id>' \
  --plan '<private-evidence-dir>/bootstrap-plan.json' \
  --allow-cancel-unexecuted
```

If any resource exists or the Change Set has started execution, cancellation
fails closed and this command never calls a bucket/KMS delete operation.

After a successful cancellation, `plan` accepts the same stack name only when
the live status is still `REVIEW_IN_PROGRESS` and a fresh
`ListStackResources` result is exactly empty and every `ListChangeSets` page is
empty, and the stack carries no service role, notifications or nesting. It
repeats the stack-authority and Change Set inventories immediately before
creating a new
`CREATE` Change Set from the current reviewed template. Any other stack status,
resource or active/ambiguous Change Set forces escalation; the workflow never
deletes the review stack as a recovery shortcut.

Every replacement plan invalidates the prior rendered Apply policy. Remove the
old Apply assignment and render a new exact policy from the replacement plan;
never edit the `cloudformation:ChangeSetName` condition in place or reuse an
expired policy artifact. The replacement Plan policy must also be rendered for
the new canonical name before `CreateChangeSet`. The full ARN/UUID is retained
as PEP evidence and must be re-read before any future execution.

## Founder-exception recovery boundary

The GUG-209 founder exception is not a fallback for normal independent
approval. It is limited to the separately approved authority account and Region,
`non-production`, one fresh `CREATE` Change Set, and one intended future
durable-PEP attempt. Its offline record format explicitly models that no
independent approval existed. The normal approval record must never be edited
to imitate that state.

GUG-209 is **OFFLINE-ONLY — LIVE EXECUTION BLOCKED**. Its local JSON/digests
cannot be treated as the ledger in the state table. Any future PEP must use a
controlled durable CAS ledger, trusted identity/event evidence, and immediate
readback of the exact Change Set, template, and resource inventory before it
can call `ExecuteChangeSet`.

Its temporary Plan and Apply policies are bounded by AWS-side date conditions,
not a local operator clock. Keep their explicit deny statements for at least
twelve hours after the latest founder window. Structural cleanup requires
governed identity-system readback proving temporary assignment and membership
removal. A lost response, failed cleanup, missing readback, or policy timing
ambiguity is `REVOCATION_REQUIRED`; retain denial and perform only read-only
reconciliation. Do not use BreakGlass, run a second apply, or create an
exception replacement from copied evidence.

## Retained resource boundary

The state bucket and KMS key use retain semantics. Stack deletion is therefore
not a decommission workflow. A future decommission must prove that no Terraform
state, lock, plan, release, registry, ledger, or evidence depends on the key;
export only sanitized inventory evidence; define a KMS waiting period; and
receive explicit destructive authorization. No automated decommission is part
of GUG-206.

## Rollback

Before execution, remove the unexecuted Change Set only and retain the empty
review stack shell. After the account S3
public-access block is enabled, retain it even if the stack fails. After stack
completion, do not roll back storage automatically; treat the verified backend
as durable control-plane infrastructure and use a reviewed forward fix.

Production remains **NO-GO**.
