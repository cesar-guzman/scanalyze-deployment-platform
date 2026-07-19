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
approval. It is limited to authority account `042360977644`, `us-east-1`,
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
