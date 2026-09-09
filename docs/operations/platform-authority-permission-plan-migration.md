# Offline permission and Plan migration review

## Scope and current status

This procedure prepares one private, deterministic migration draft. It does not
connect to AWS, verify a user, change a permission set, provision an account, or
create or delete an assignment. The implementation has no SDK, provider or
apply path. Its result is `DRAFT_REVIEW_ONLY`, not an approval, admission grant,
live snapshot or deployment receipt. Production remains **NO-GO**.

The draft separates two changes that must not be conflated:

1. Add the closed management-account Plan seed inventory supplement to the
   existing reader inline policy, preserving every existing statement.
2. Review the canonical Plan predecessor policy, ownership tags and an exact
   future `GROUP`-to-`USER` assignment transition in the authority account.

Only local implementation and synthetic validation are authorized for this
iteration. No real private request was executed. No AWS read, mutation,
publication, commit, push or Linear update is authorized by this runbook.

## Required private input

The input must explicitly bind the Identity Center instance and Identity Store,
the distinct existing reader and Plan permission-set ARNs, the exact target
user, the previous Plan group assignment, the account scope, ownership tags and
the proposed UTC validity window. The request carries ARNs, not permission-set
name fields; confirming the exact name-to-ARN association is a future provider
review requirement. The tool must not infer these coordinates from a profile
alias, a generated role suffix, a repository example, or a matching name alone.

Include the supplied existing reader inline policy, Plan permission-set inline
policy and generated-role inline policy, the provisioned-account lists, existing
Plan tags and group assignment. The draft accepts incomplete supplied evidence;
it never validates a complete live baseline. `reader_assignments_coverage` is
`COMPLETE` or `NOT_COMPLETE`. Both `reader_boundary_observation` and
`plan_boundary_observation` accept only `ABSENT`, `PRESENT` or `NOT_OBSERVED`.
`NOT_OBSERVED` remains a review blocker, and even a supplied `ABSENT` value is not
provider proof. A generic `ResourceNotFoundException` without exact causal
attribution remains inconclusive. A missing role policy is represented by
`plan_role_inline_policy: null` and cannot establish SSO/IAM policy equality.

Each supplied inline policy may contain one `Statement` object or a nonempty
list of statements, as permitted by the [IAM Statement contract](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_statement.html).
Only a separate working copy converts the singleton object to a list for
merging, statement deltas, Deny detection and structural SSO/IAM comparison.
The request, `supplied_input`, `input_digest` and rollback before-image retain
the original representation. Equivalent singleton/list inputs therefore retain
distinct input digests. A structural match still does not prove live parity.
Malformed statements and duplicate statement IDs remain rejected.

The JSON object has an exact field set. The following is a **SYNTHETIC SHAPE
EXAMPLE ONLY**, not a real baseline, approved target, valid cloud authorization,
or a request to execute. All resource/principal coordinates are synthetic; the
two account constants and Region are fixed by the source contract. The example
account list is not the observed nineteen-account inventory. Never substitute
this example for missing evidence or copy its dates into a live request.

```json
{
  "schema_version": 1,
  "management_account_id": "839393571433",
  "authority_account_id": "042360977644",
  "region": "us-east-1",
  "identity_center_instance_arn": "arn:aws:sso:::instance/ssoins-SYNTHETICaaaaaaa",
  "identity_store_id": "d-synthetic00",
  "reader_permission_set_arn": "arn:aws:sso:::permissionSet/ssoins-SYNTHETICaaaaaaa/ps-SYNTHETICreader0",
  "plan_permission_set_arn": "arn:aws:sso:::permissionSet/ssoins-SYNTHETICaaaaaaa/ps-SYNTHETICplan000",
  "target_user_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  "change_set_name": "scanalyze-platform-authority-bootstrap-21000101000000",
  "not_before": "2100-01-01T00:00:00Z",
  "not_after": "2100-01-01T00:30:00Z",
  "target_plan_tags": {"example_only": "SYNTHETIC_TARGET"},
  "baseline": {
    "reader_inline_policy": null,
    "reader_provisioned_accounts": ["839393571433", "042360977644"],
    "reader_assignments_coverage": "NOT_COMPLETE",
    "reader_boundary_observation": "NOT_OBSERVED",
    "plan_inline_policy": {
      "Version": "2012-10-17",
      "Statement": [{
        "Sid": "SyntheticPlanBaseline",
        "Effect": "Allow",
        "Action": "sts:GetCallerIdentity",
        "Resource": "*"
      }]
    },
    "plan_role_inline_policy": null,
    "plan_tags": {"example_only": "SYNTHETIC_BEFORE"},
    "plan_assignment": {
      "account_id": "042360977644",
      "principal_type": "GROUP",
      "principal_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    },
    "plan_provisioned_accounts": ["042360977644"],
    "plan_boundary_observation": "NOT_OBSERVED"
  }
}
```

The interval must be positive and no longer than one hour. Validating its shape
does not approve, activate or prove freshness of the supplied window. The reader
account list must include management; the Plan list must contain authority only.
The old assignment must be `GROUP` in authority, with a principal distinct from
the target `USER`. These structural restrictions are not assignment verification.

Keep the source input and draft in an owner-only private directory outside Git,
worktrees and synced storage. Both paths must be absolute `.json` paths without
symlinks or parent traversal. Use directory mode `0700`, input-file mode `0600`
and a new output path; output is create-only and written as `0600`. The input
must be a regular, single-link file. Input and output are each limited to one
MiB. Recognized CloudStorage/File Provider locations are rejected; do not use an
unrecognized synced path to bypass custody. Do not paste ARNs, user or group
identifiers, policy documents, or raw input/output into a PR, issue, terminal
transcript or this repository.
Review public status and digests instead. The supplied baseline remains
unverified operator-provided data until a separately authorized provider read verifies
its exact identities, contents, completeness and freshness.

## Reader supplement: preserve the shared baseline

The supplement template is
[`platform-authority-plan-seed-management-read-supplement.json`](../../policies/iam/platform-authority-plan-seed-management-read-supplement.json).
It covers the management inventory used by the existing Plan seed snapshot:
seventeen Identity Center read actions and `identitystore:DescribeUser`.
It does not grant Identity Center writes, IAM mutation, KMS decryption, or the
full collision inventory. A future connected run still needs its separate
identity-first authorization and evidence checks.

The merger preserves the reader inline policy's existing statements and rejects
statement-ID collisions instead of replacing a statement. It does not detach
existing managed policies, rewrite the reader's permission-set metadata, or
change assignments. Every new Allow is bounded to management principal account,
`us-east-1`, the reviewed resource envelope and the explicit start/expiry
window. Expiry disables that new Allow; it does not delete policy documents or
revoke existing sessions.

Do not copy the collision catalog's global Deny statements into this supplement.
The original collision policy is a closed authority contract; its global
before-start, expiry and unreviewed-action Denies can restrict unrelated
permissions when added to a shared reader. An additive supplement is not proof
that the resulting role meets that separate closed-authority contract.

The observed reader permission set is shared across nineteen accounts. Its full
assignment inventory is not established by a provisioned-account list. An
account condition restricts the new Allow only; it does not constrain existing
Allows, establish a human identity, or override another Deny. Review the shared
permission-set change as such, even if a future provisioning operation targets
management alone. Do not use `ALL_PROVISIONED_ACCOUNTS` for that operation.

## Plan predecessor: not a read-only role

The proposed Plan document is rendered through the existing canonical bootstrap
and repair functions. It is not copied from an example or independently
reimplemented. It remains the predecessor of the later, narrowly authorized
`ListOnlyExactBootstrapChangeSets` repair; this draft does not add that statement
or bypass the [protected repair procedure](platform-authority-bootstrap-plan-permission-repair.md).

**The predecessor name does not mean read-only.** The canonical document retains
bounded `cloudformation:CreateChangeSet`, `cloudformation:TagResource` and an
exact version-qualified `lambda:InvokeFunction` grant. Its permissions must be
reviewed against the real baseline and effective authority. A changed document
or a narrower-looking name is not proof of privilege reduction.

Ownership tags are a separate owner decision. Preserve the observed tags as
before-state and review the exact proposed additions, replacements and removals.
Tags supplied to this planner neither prove live ownership nor permit adopting
an existing resource. Do not rename or recreate either permission set, or edit
its generated `AWSReservedSSO` role directly.

Proposed and supplied existing tags use the [Identity Center Tag contract](https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_Tag.html):
keys contain 1–128 characters; values contain 0–256 characters, including an
empty string. Both admit Unicode letters, separators and numbers plus
`_.:/=+-@`. Other characters, including asterisks, quotes, backslashes, control
characters and combining marks, are rejected. Text is preserved without
trimming or Unicode normalization. The existing limit of 50 entries,
case-insensitive rejection of reserved `aws:` keys and requirement for a
nonempty target tag map remain unchanged; an empty baseline tag map is valid.

The snapshot implementation fixes its reader profile and `AWSReadOnlyAccess`
SSO role bindings. Another permission set is not an alias-only substitute; using
a different role requires a separate reviewed source-contract change.

## Proposed assignment sequence: review only

The draft records the intended sequence below; it cannot execute it or certify
that its preconditions hold:

1. Separately authorize exact-user verification in the named Identity Store.
   Verify the requested user and account, the existing group assignment, every
   relevant assignment, policy, boundary, tag and pending provisioning or
   assignment operation. Missing pages, access denial or drift block changes.
2. Review the merged reader document and its shared-account effects. A separately
   authorized reader update provisions management only, preserving attachments
   and assignments. Retain the complete baseline for bounded cleanup.
3. Before creating the intended `USER` assignment, prove equality of the current
   Plan permission-set policy and provisioned IAM role policy, verify the exact
   user, and explicitly authorize temporary `GROUP`/`USER` access overlap.
   `CreateAccountAssignment` also provisions the policy: it is not a harmless
   metadata-only prerequisite. With those gates and a separate exact assignment
   authorization, establish the `USER` assignment in authority while preserving
   the `GROUP`. Verify terminal asynchronous success, both assignments, and the
   unchanged role ARN, trust and policy before considering group removal.
4. Remove only the reviewed old group assignment after proving the intended
   replacement exists and all required access remains available. Never remove
   the sole assignment to an account. Preserve the generated role's identity
   throughout; do not assume that a recreated assignment preserves its suffix
   or the trust bindings that depend on that role ARN.
5. Prove closure or containment of sessions obtained through the former group
   under a separately reviewed procedure **before migrating Plan permissions**.
   Removing an assignment, a `PT1H` setting, or expiry of the reader supplement
   window does not revoke existing sessions. Do not infer session closure from
   the disappearance of an assignment.
6. Only after all preceding gates, separately authorize the complete Plan
   policy replacement and ownership-tag change, including tag-based
   administrator impact. Preserve unrelated metadata and attachments, provision
   authority only, and require terminal success and complete SSO/IAM readback.
   Do not use `ALL_PROVISIONED_ACCOUNTS` or treat a policy write as completed
   provisioning.
7. Use fresh conclusive evidence for the unchanged connected Plan seed snapshot
   and subsequent protected additive repair. A draft or a successful individual
   API response is not accepted snapshot evidence.

The operator must decide how to handle any coexistence of old and new access
before authorizing this transition. Unexpected users, groups, accounts, policies,
boundaries or pending operations require a new decision; the planner does not
choose whom to remove or expand the approved target set.

## Local draft generation and validation

The CLI is `scripts/deployment/platform-authority-permission-plan-migration.py`.
It accepts `--input` for one private JSON request and `--output` for one new
private JSON draft. There is no `--apply` command or AWS profile argument.
Run it only after the input's exact coordinates and review decisions are
available; synthetic fixtures are not operational defaults.

```console
python3 scripts/deployment/platform-authority-permission-plan-migration.py --help
```

For an explicitly prepared private request, the local-only command shape is:

```console
python3 scripts/deployment/platform-authority-permission-plan-migration.py \
  --input "$MIGRATION_PRIVATE_INPUT" \
  --output "$MIGRATION_PRIVATE_DRAFT"
```

These variables denote reviewed private paths, not repository fixtures. Do not
run this example with guessed inputs. A valid draft must remain
`DRAFT_REVIEW_ONLY`; passing synthetic tests does not verify the shared
permission set, target user, live boundaries or deployment. Preserve a failed
attempt's files for diagnosis rather than editing evidence to make it pass.

The private output includes `supplied_input`, both proposed reader documents,
`plan_proposed_predecessor_policy`, proposed assignment/tags, structural
statement-digest differences, required reviews and the non-executable outline.
It always sets `baseline_verified=false`. Matching supplied SSO/IAM policy
digests may avoid a structural mismatch warning, but cannot establish live
policy parity without fresh provider evidence.

`source_material_digests` records the bytes of the two templates read from the
local working copy. The declared source status is
`LOCAL_WORKING_COPY_NOT_ATTESTED`: these hashes are not a Git commit/tree
attestation, approved-source proof, or executable source-closed package.

Standard output contains only `status`, `draft_digest`,
`reader_provisioned_account_count`, `required_reviews`, `aws_calls`,
`aws_mutations`, `execution_authorized`, `deployment_authorized` and
`production_status`. Expected values include `DRAFT_REVIEW_ONLY`, zero calls and
mutations, both authorization flags false and production `NO-GO`. A draft can
be generated while reviews remain required; exit `0` means private draft
creation, not approval or readiness. Exit `2` reports a stable error code.
The output is never overwritten; preserve any partial failed output privately.

Focused synthetic validation is:

```console
python3 -m pytest -q \
  tests/test_deployment/test_permission_plan_migration.py \
  tests/test_deployment/test_plan_seed_management_read_supplement.py
```

## Three decisions before any live action

1. **Reader scope:** approve the exact additive document and time window for the
   management account, with complete before-state and shared-account impact.
2. **Plan scope:** approve the complete canonical predecessor diff and ownership
   tags, acknowledging its bounded write/invocation capabilities and the later
   independent `ListChangeSets` repair.
3. **Assignment transition:** confirm the exact user, account and old group;
   approve SSO/IAM equality before automatic provisioning, replacement-first
   ordering, temporary coexistence, evidence before removing an assignment and
   old-session closure before changing Plan permissions.

Those decisions support review, not execution by this offline tool. Any future
cloud mutation additionally needs an exact authorized profile, command,
resource/account scope and recovery boundary. This iteration does not request
or imply that authorization.

## Rollback and custody

Before any separately authorized future write, retain a timestamped, digest-bound
private baseline containing the complete affected inline policies, managed and
customer-managed policy attachments, boundary observations, metadata, tags,
assignments, provisioned accounts and pending-operation state. Record the exact
source and planned diff. Missing or inconclusive before-state cannot support an
automatic rollback claim.

There is no automatic rollback. A proposed restoration must preserve unrelated
baseline statements and attachments and affect only the exact authorized
accounts. Never delete an entire inline policy merely because the supplement
was additive if the baseline already contained statements. Never remove a sole
assignment or recreate a permission set to restore access. Identity Center
provisioning and assignment restoration require terminal readback, just as the
forward change does. After uncertain delivery, stop new writes and preserve
evidence for separately authorized reconciliation; do not replay the operation.

Repository-only rollback is a reviewed revert of this local implementation.
No AWS rollback is required for the synthetic validation performed here because
no live action was executed.

## Local implementation evidence — 2026-09-08

Base commit: `0f32549e07fbe74f1c03e49fb2807ed8d9b1e7b2`.
Local branch: `codex/gug-376-permission-plan-migration`.
The implementation is uncommitted and unpublished; this is not exact-head CI
or merged-source evidence.

| Validation | Observed result |
| --- | --- |
| New draft and read-supplement tests | 103 passed |
| New tests plus existing snapshot and repair tests | 257 passed |
| Bootstrap Plan repair gate, including new tests | 1,634 passed; schema, fixture, policy and compilation checks passed |
| Full Python suite excluding the separately run sentinel tests | 7,504 passed, 1 skipped; 2 dependency deprecation warnings |
| Sentinel gate and its tests | Exit 0; 8 passed; 7 STATE_PLAN warnings, unchanged in the clean base comparison |
| Lint, documentation, IAM policy structure, diff whitespace | Passed |
| Documented synthetic example and CLI help | Passed; no provider calls |
| Independent code review | Two path/privacy findings corrected; no confirmed P0/P1/P2 remaining in the local-draft scope |

The initial documentation check lacked the historical Phase 0 baseline Git
object. Importing that exact object from the existing local repository restored
the check; neither the gate nor its expected baseline was changed. No remote
fetch was necessary. `pip check` could not run because the reused Python
environment has no `pip` module. No dependency was added, installed or changed.
The security scanner and its allowlist were not modified.

No fresh GitHub CI, AWS identity/inventory, permission update, assignment
transition, artifact upload or deployment was performed for this implementation.
The user authorized local preparation only. Real input materialization and cloud
effects still require the decisions and evidence above. Linear was not accessed.
The production goal remains incomplete: **NOT_DEPLOYED / PRODUCTION_NO_GO**.

## PR #104 review follow-up — local correction

The two P2 review findings were reproduced before correction: valid empty tag
values were rejected while unsupported tag characters were accepted, and valid
singleton policy statements were rejected. Regression tests now cover both tag
maps, character categories and length limits, all three supplied policy slots,
preserved Deny/Condition/Id content, input immutability and original digests,
statement-ID collisions, malformed containers and the real private CLI.

Local validation of the correction: 243 focused tests passed; the full Python
suite passed 7,646 tests with one skip and two dependency deprecation warnings;
the separately run Sentinel gate passed with eight tests. The bootstrap repair
gate passed 1,774 tests plus schema, fixture, policy and compilation checks;
the governance gate passed 387 tests. Lint and documentation checks passed,
and independent local review found no outstanding confirmed P0/P1/P2 findings.

These fixes do not alter IAM policy templates, the connected snapshot contract,
cloud permissions or execution gates. Local validation does not resolve GitHub
review conversations or constitute final-head CI or reviewer approval. Publish
the reviewed correction, verify CI, and address both review threads before
merge. Repository rollback is a reviewed revert of the correction; no cloud
rollback is required because the correction performs no AWS action.
