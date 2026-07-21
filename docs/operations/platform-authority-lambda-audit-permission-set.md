# GUG-220 Lambda Audit Permission-Set Runbook

## Safety boundary

This runbook covers one exact Identity Center permission-set creation or
reconciliation, one direct `USER` assignment, provisioning to one approved
platform-authority account, exact readback and report-only GUG-219 handoff.

It does not authorize group creation, managed-policy attachment, permissions
boundaries, role relay, foreign-account provisioning, Lambda invocation,
IAM/Lambda mutation, broker deployment, token exchange, STS provided contexts,
Change Set operations, Terraform Apply, customer deployment, migration,
destruction, redrive or production.

The reviewed inline policy must include `DenyUnreviewedActions`, whose
`NotAction` exception list exactly equals the reviewed read surface, and the
exact `DenyRoleChaining` statement for `sts:AssumeRole` on `*`. Absence of an
identity-policy allow is
not accepted as proof of no relay because same-account role trust can otherwise
grant the role session directly.

Production remains **NO-GO**.

## Current governance state

One human currently performs the planner, authorized mutation and evidence-
custody duties. The records must state
`independent_review_present = false`. Different profiles or sessions for the
same person do not satisfy human separation.

The direct user assignment is limited to this bootstrap. GUG-215 classification
and retirement remain blocked until two different humans can hold the required
classifier and approver duties.

## Phase 0 — Repository and authorization preflight

1. Verify the exact GUG-219 merged baseline is an ancestor of the GUG-220
   branch.
2. Record the issue, branch, worktree, candidate commit and exact authorized
   mutation boundary.
3. Verify the public contract names
   `ScanalyzeAuthorityLambdaAudit`, `PT1H` and the exact GUG-219 policy source.
4. Define a private evidence root outside the repository with mode `0700` and
   a `umask` of `077`.
5. Create exactly `~/.scanalyze-private-evidence/gug-220-live-v2`, owned by the
   current effective user, non-symlink and mode exactly `0700`. No other ledger
   path is accepted. Pass this path through `--execution-ledger-directory` to
   both `plan` and `apply`.
6. Confirm the approved management profile and `us-east-1`; never use the
   default AWS profile.
7. Call STS and verify the management account before Identity Center access.
8. Stop if the target binding, current operator or authorization is missing,
   ambiguous or outside the approved non-production scope.
9. Reject AWS endpoint/CA environment overrides and force the AWS CLI to ignore
   endpoints configured in local profiles; authenticated canonical AWS
   endpoints are part of the evidence boundary.

Do not place the live account ID, user identifier, ARNs, suffixes or provider
responses in command history, Git, Linear, NotebookLM, chat or public logs.

## Phase 1 — Read-only plan

Use complete pagination to discover:

- exactly one Identity Center instance owned by the approved organization and
  require its status to be `ACTIVE`;
- the exact permission set, or prove it is absent;
- every existing attachment, boundary, assignment and provisioned target when
  the permission set already exists; and
- exactly one Identity Store user matching the separately approved current
  operator binding; and
- exactly one authority-account AWS SSO SAML provider returned by
  `iam:ListSAMLProviders` and matching the canonical provider shape.

Reject multiple users, multiple active instances, a name collision with drift,
foreign provisioning, group assignment, duplicate assignment, incomplete
pagination or access denial.

All IAM inventory calls are paginated to exhaustion with token-replay
detection. Do not accept a first-page-only result for roles, inline policies,
managed attachments or boundaries.

Render the inline policy using the exact private target and canonical broker
function contract. Verify the reviewed template-byte digest and canonical
rendered digest before producing an owner-only, create-only private intent.

Resolve repository `HEAD` and require an existing 40-hex ancestor commit.
Verify that the current GUG-219 template, policies and materializer runtime
plus the GUG-220 core and CLI bytes equal that commit. Apply, reconcile and
binding handoff repeat the check. Render the policy once, compare its template
and canonical digests to the intent, and pass that same sealed object to every
provider-effect and readback path without reopening the worktree. Dirty,
missing or rebound source requires a new reviewed commit and plan.

The intent must bind the source commit, exact target, Region, instance, identity store, SAML provider,
principal, permission-set contract, policy digests, expected assignment,
expected target and expiration. Store only canonical digests of the live
`InstanceArn` and `IdentityStoreId` in the portable intent and require
`expires_at - created_at` to be no more than 15 minutes. Publish only sanitized
digests and status. Store the raw provider ARN only in owner-only private
evidence; publish only its canonical digest.

Bind the canonical digest of the exact
`~/.scanalyze-private-evidence/gug-220-live-v2` execution-ledger directory into
the intent. No alternate directory is accepted. The intent remains
digest-sealed, but the ledger filename is stable across all intents,
principals and policy versions for this work package and target.

Any intent v1 produced before the source commit, live Instance/Identity Store digests and
15-minute expiry became mandatory is obsolete. Do not patch, overwrite or
reuse it. Run a new read-only plan and write the replacement into a new
create-only private evidence location.

## Phase 2 — Exact mutation

Revalidate STS, source-commit byte equality, the intent digest, its unexpired
maximum 15-minute window and the exact live `InstanceArn`/`IdentityStoreId`
digests immediately before every mutation. Refresh complete state and
recompute the still-authorized action set each time. Then perform only the missing operations from this closed
sequence:

Before any AWS write:

1. use the fixed
   `gug220-lambda-audit-provisioning.execution-ledger.v1.json` filename;
2. create the ledger with `O_EXCL` and exact mode `0600` in the intent-bound
   directory;
3. verify its digest-sealed `MUTATION_WINDOW_CONSUMED` record, attempt limit
   one and `mutation_retry_authorized = false`;
4. reserve the receipt file with `O_EXCL` and exact mode `0600`; and
5. revalidate intent freshness and live authority bindings once more.

If the ledger already exists, stop with
`EXECUTION_LEDGER_ALREADY_CONSUMED`. Do not inspect its presence as approval,
delete it, overwrite it or retry under any intent. This same-host owner-local
marker is not a cross-host durable lock and is not production evidence. A
future multi-operator/live design requires an immutable external ledger.

The closed AWS mutation sequence is:

1. create the exact permission set if absent;
2. install the exact canonical inline policy;
3. create the exact direct `USER` assignment for the approved target; and
4. provision that permission set only to the approved target account.

Step 4 is mandatory whenever step 2 installs or changes the inline policy,
even if the target is already listed as provisioned. Never treat historical
provisioning as proof that the account-local role contains the new policy.

Do not create a group. Do not attach AWS-managed or customer-managed policies.
Do not install a boundary. Do not update a different permission set or target.

For each asynchronous assignment or provisioning request, poll only the exact
request token using bounded `Describe` calls. Never start another mutation
because a waiter timed out or a response was lost.

## Phase 3 — Ambiguous-result handling

Any timeout, transport loss, unknown request status or incomplete post-write
readback sets the write operation to:

```text
UNCERTAIN_RECONCILE_ONLY
```

From that point, prohibit mutation retries. Reconcile with only paginated
`List`, `Get` and `Describe` calls against the frozen intent. Classify the
result as:

- `READBACK_VERIFIED` when the complete exact state exists;
- `BLOCKED_DRIFT` when state is missing, extra or conflicting; or
- `READBACK_INCOMPLETE` when the read-only evidence cannot be completed.

Repair requires a new issue or explicit reviewed authorization. Do not infer
success from eventual consistency or partial absence.

After the first AWS write may have started, `OSError`, timeout, provider error
or any post-write readback failure must consume the existing ledger and write
an `UNCERTAIN_RECONCILE_ONLY` result to the pre-reserved receipt. It never
returns the intent to a retryable state.

If the reserved receipt cannot be persisted, the CLI emits only sanitized
public `UNCERTAIN_RECONCILE_ONLY` status with `receipt_digest = null`; the
already consumed ledger still prohibits retry. A failed read-only reconcile
uses `READBACK_INCOMPLETE`, `aws_mutation_attempted = false` and
`ambiguous_response = true`; it never claims deterministic drift.

## Phase 4 — Exact Identity Center and IAM readback

Require all checks from the deployment contract:

- exact name, description and `PT1H`;
- exact canonical inline-policy digest;
- no managed/customer-managed policies or boundary;
- exactly one direct `USER` assignment in the approved target;
- no foreign assignment or provisioned target;
- target provisioning completed;
- one account-local role with the exact permission-set prefix and opaque
  suffix;
- trust naming the exact SAML provider bound into the intent, with no relay;
- exact inline-policy `DenyUnreviewedActions` closed read set;
- exact inline-policy `DenyRoleChaining` for `sts:AssumeRole`;
- exact role inline-policy equality; and
- zero role attachments and no role boundary.

Before issuing `READBACK_VERIFIED`, require non-null canonical digests for the
exact permission-set ARN and collector IAM role ARN and require all three
semantic gates to be true:

```text
account_assignment_verified
permission_set_provisioning_verified
collector_role_verified
```

Missing role discovery or a null ARN digest is never a verified result.

The role suffix is observed, never guessed. Retain its exact value and ARNs in
private evidence only.

## Phase 5 — Dedicated session and GUG-219 handoff

Create or select a local SSO profile for the exact provisioned permission set.
Authenticate interactively without exposing credentials. Immediately call STS
and compare its normalized principal with the read-back IAM role.

Write the GUG-219 collector binding outside the repository with exactly:

```text
identity_center_region
collector_iam_role_arn
collector_sts_session_arn
```

The containing directory must have mode `0700` and the file mode must be
exactly `0600`. Open every private input with `O_NOFOLLOW`, then use `fstat` on
the open descriptor to require a regular file owned by the current effective
user and mode `0600`; do not rely on a path-only symlink check. Create outputs
exclusively without following symlinks. A profile name is never serialized as
authority.

## Phase 6 — Candidate A and B

Only under the approved read-only window:

1. collect Candidate A using the exact dedicated session;
2. materialize the deterministic allowlist and separate release anchor in
   private storage;
3. revalidate a fresh dedicated session;
4. collect Candidate B; and
5. run the GUG-218 exact report-only comparison.

Follow the five-minute chronology and private-custody rules in the GUG-219
runbook. Candidate A cannot approve itself and B cannot reuse A's nonce,
snapshot or pages.

If the target broker, aliases, roles or policies are not deployed, record a
sanitized blocked result and stop. This runbook does not deploy or invoke them.

## Stop conditions

Stop immediately for:

- wrong account, Region, instance or operator;
- zero, multiple or non-`ACTIVE` Identity Center instances;
- missing or expired authorization;
- an intent older than 15 minutes, an obsolete pre-hardening intent or a live
  Instance/Identity Store digest mismatch;
- default, root, IAM-user, administrator or generic read-only substitution;
- multiple Identity Store matches or inferred principal;
- a foreign assignment, account target or permission set;
- any managed/customer-managed policy, boundary or relay;
- policy template or rendered digest mismatch;
- incomplete pagination or access denial;
- a ledger-directory mismatch, foreign owner, symlink or mode other than
  `0700`;
- an existing stable GUG-220 ledger from any intent;
- failure to reserve the receipt before the first AWS write;
- ambiguous mutation response;
- an inline-policy change without explicit target reprovisioning;
- `READBACK_VERIFIED` without both ARN digests and all assignment,
  provisioning and role verification gates;
- a private input that is a symlink, is not regular, has a foreign owner or
  does not have exact mode `0600`;
- more than one write attempt after uncertainty;
- raw evidence entering a public channel;
- Candidate A/B requiring Lambda invocation or deployment;
- one human represented as independent approval; or
- any production-readiness claim.

## Contract inventory

```text
schemas/platform-authority-lambda-audit-provisioning-intent.v1.schema.json
schemas/platform-authority-lambda-audit-execution-ledger.v1.schema.json
schemas/platform-authority-lambda-audit-provisioning-receipt.v1.schema.json
```

Validate all three. The ledger is durable replay prevention, not a success
receipt, and remains consumed for both verified and uncertain outcomes.

## Rollback and containment

Repository rollback uses a reviewed revert. Cloud rollback is a separate
Identity Center change and is not automatically authorized by this runbook.

If exact readback discovers over-privilege, stop collection, invalidate the
private binding, preserve sanitized evidence and request an independently
reviewed containment authorization. Do not delete or mutate unrelated
assignments, permission sets or roles.

## Sanitized closeout template

```text
Implemented: <exact commit and PR>
Locally validated: <named gates>
CI validated: <required checks for exact commit or not established>
Permission-set contract: <READBACK_VERIFIED / BLOCKED_DRIFT / READBACK_INCOMPLETE / UNCERTAIN_RECONCILE_ONLY>
Target count: <sanitized count>
Direct assignment count: <sanitized count>
Managed/customer policies: 0
Permissions boundary: absent
Relay authority: absent
Candidate A: <not run or sanitized result>
Candidate B: <not run or sanitized report-only result>
Independent review present: false while one human is on roster
GUG-215 retirement authorized: no
Production: NO-GO
```

## References

- [ADR-046](../../ADR/ADR-046-lambda-audit-permission-set-provisioning.md)
- [Deployment contract](../deployment/platform-authority-lambda-audit-permission-set.md)
- [GUG-219 operations runbook](platform-authority-lambda-invocation-materialization.md)
- [Threat-model delta](../security/gug-220-lambda-audit-permission-set-threat-model-delta.md)
