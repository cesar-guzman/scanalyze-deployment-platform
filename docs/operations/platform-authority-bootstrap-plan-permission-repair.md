# Bootstrap Plan permission repair runbook

## Scope and current status

This runbook operates the dedicated server-side PEP that can add the one
missing `ListOnlyExactBootstrapChangeSets` statement to the normal
`ScanalyzeAuthorityBootstrapPlan` policy and reprovision it to the authority
account.

This checked-in procedure is not deployment or mutation authorization. The
repository implementation has made no AWS call. Production remains **NO-GO**.

The reviewed AWS wrapper now binds the concrete zero-retry Identity Center,
effective-IAM and durable-ledger adapters in a deterministic source-closed
package. The local CLI remains intentionally non-executable. Do not stage or
deploy either stack from a working tree: package only the exact merged commit,
authenticate its required review/checks, sign the immutable S3 source version
and use the read-back CloudFormation tuple.

## Non-negotiable stops

Stop with `HUMAN_DECISION_REQUIRED` if any of the following is true:

- the exact bootstrap route, accounts, Region, templates, Change Sets, creator
  or executor are not explicitly authorized;
- the caller profile or expected account/role is not exact and non-default;
- the reviewed source, artifact, parameter or live-state digest differs;
- the Plan policy differs from the target by anything other than the one
  allowed statement;
- pagination, provider state, CloudTrail attribution or collision evidence is
  incomplete;
- any retained resource, role, alias, assignment or stack name already exists
  without exact ownership evidence;
- either SSO effect may already have been dispatched; or
- the ledger is missing, changed, uncertain or not strongly read back; or
- Plan/reconcile has 60,000 milliseconds or less remaining at entry, repair has
  480,000 milliseconds or less, either write has 75,000 milliseconds or less
  before dispatch, or a provider read/poll has 60,000 milliseconds or less.

Never repair with `AWSAdministratorAccess`, a console edit, an `aws sso-admin`
command, the normal Plan role or the GUG-221 collector PEP.

## Phase 0 — Repository gate

Use a clean isolated worktree at the exact reviewed commit:

```bash
git status --short --branch
git diff --check
make platform-authority-bootstrap-plan-repair-check
make platform-authority-bootstrap-check
make docs-check
```

Record these as repository evidence only. Do not claim AWS, deployment or live
repair from local or CI success.

## Phase 1 — Approve the bootstrap route

The control plane requires two separately scoped deployment paths:

1. management account ending `1433` for the delegation stack; and
2. authority account ending `7644` for the PEP stack.

The approved route must be either exact temporary Change Set executors or a
reviewed service-managed StackSet restricted to the two templates, target
accounts and `us-east-1`. Read back the effective policy before use. If no such
route exists, stop; do not substitute a broad profile.

## Phase 2 — Read-only preflight

Using only explicitly approved read-only profiles and `AWS_REGION=us-east-1`:

1. make `sts:GetCallerIdentity` the first signed call for each session;
2. verify exact account, role and session type;
3. inspect the active Identity Center instance and Identity Store;
4. enumerate the exact normal Plan permission set, metadata, tags, inline
   policy, attachments, boundary, assignments and provisioned accounts with
   complete pagination;
5. enumerate pending provisioning and assignment operations;
6. inspect the generated authority-account IAM role, trust, policies and
   boundary;
7. prove the live policy is the exact canonical predecessor; and
8. collision-probe both stacks and every retained name.

Persist the existing Plan tags as the private
`ExpectedPlanPermissionSetTagsJson` value. Do not reuse them for the temporary
invoker: its six-tag contract is derived independently from the exact merged
`SourceCommit` and fixed delegation-template values.

An `AccessDenied`, generic S3 response, repeated token or partial list is
uncertainty, not absence. No read-only preflight may repair or adopt a resource.

## Phase 3 — Build and authenticate the artifact

Build only from the exact clean merged commit into a new mode-`0700` directory
outside Git and synced storage. The deterministic package must include the
reviewed runtime, renderer and lock file. Upload and AWS Signer actions require
their own exact authorization. Never deploy an unsigned object or an object
without an exact version and SHA-256 readback.

Build the unsigned artifact offline:

```bash
python3 scripts/deployment/platform-authority-plan-permission-repair-package.py \
  --source-commit "$SOURCE_COMMIT" \
  --expected-boto3-version "$EXPECTED_BOTO3_VERSION" \
  --expected-botocore-version "$EXPECTED_BOTOCORE_VERSION" \
  --output-directory "$PRIVATE_OUTPUT_DIRECTORY"
```

After a separately authorized immutable S3 upload and Signer job, use the exact
read-only verifier profile and write the private receipt outside the repository:

```bash
AWS_PROFILE=042360977644_AWSReadOnlyAccess AWS_REGION=us-east-1 \
python3 scripts/deployment/platform-authority-plan-permission-repair-signed-artifact.py \
  --profile 042360977644_AWSReadOnlyAccess \
  --region us-east-1 \
  --source-commit "$SOURCE_COMMIT" \
  --expected-boto3-version "$EXPECTED_BOTO3_VERSION" \
  --expected-botocore-version "$EXPECTED_BOTOCORE_VERSION" \
  --job-id "$SIGNING_JOB_ID" \
  --expected-profile-version-arn "$SIGNING_PROFILE_VERSION_ARN" \
  --output-receipt "$PRIVATE_SIGNED_RECEIPT"
```

The verifier makes STS caller identity its first signed call. A profile,
account, role, protected-main commit, review, required check, Signer coordinate,
S3 version or checksum mismatch stops before producing parameters.

The closed read-only verifier session must permit exactly the provider reads
used by this command: `sts:GetCallerIdentity`, `signer:DescribeSigningJob`,
`s3:GetBucketVersioning`, `s3:ListBucketVersions`, `s3:GetObject` and the
corresponding exact-version metadata read, `acm:GetCertificate`, and
`signer:GetRevocationStatus`. The SDK service name for the last call is
`signer-data`; its IAM action remains `signer:GetRevocationStatus`. Missing
`revokedEntities` in a successful response represents the API's valid empty
result; any non-empty value, malformed response or `AccessDenied` stops the
handoff. No alternate profile or broader mutation role may be substituted.

Only the AWS/Git-backed constructor is an operational entrypoint. It derives
the certificate hash, revocation evidence and both CloudFormation template
digests from exact readbacks and Git-object bytes. The private lower-level
constructor exists solely for hermetic contract tests; operator-supplied
digests or revocation assertions are not deployable evidence.

Before creating the PEP Change Set, assemble one owner-only JSON object whose
keys are exactly the operator-controlled CloudFormation inputs used by the
Lambda environment, from `SourceCommit` through `SigningProfileVersionArn` as
defined by the offline materializer. Values from the signed receipt must match
byte-for-byte; private Identity Center values remain outside Git. Derive, never
type, the version-replacement digest:

```bash
python3 scripts/deployment/platform-authority-plan-permission-repair.py \
  materialize-configuration-digest \
  --parameters "$PRIVATE_CONFIGURATION_PARAMETERS" \
  >"$PRIVATE_CONFIGURATION_DIGEST_RECEIPT"
```

Use only the returned `ImmutableConfigurationDigest` parameter in the Change
Set. Recompute it immediately before review. A missing, stale or manually
substituted digest is `HUMAN_DECISION_REQUIRED`. The materializer and Lambda
both calculate the exact UTF-8 `key + value` environment budget; no function
may exceed 4,096 bytes. Description and tag JSON must use the template's
printable-ASCII/canonical-JSON form, with tag JSON at most 1,024 bytes.

Independently verify:

- source commit and tree;
- package byte digest and contents;
- successful Signer job and profile version;
- source and signed S3 version IDs/checksums;
- Code Signing Config; and
- the exact numeric Lambda versions and aliases that will be created.

Keep all IDs, ARNs and receipts in owner-only private evidence, not this
repository, shell history or PR comments.

## Phase 4 — Deploy management delegation

Create an exact Change Set for
`scanalyze-platform-authority-bootstrap-plan-repair-delegation`. Before
execution, verify template hash, parameters, four-resource inventory, tags,
capabilities, creator/executor identity and absence of imports, nested stacks,
notifications, masked parameters or alternate `RoleARN`.

`RepairInvokerAssignmentEnabled` has no default. For this initial deployment it
must be explicitly set to `true`; any omitted or different value is a stop. The
verified Change Set must create the single `RepairInvokerAssignment` together
with the two service roles and invoke-only permission set.

Execute only the UUID-bearing verified Change Set. Read back:

- exact mutation and readback roles plus trust/policies;
- invoke-only human permission-set policy;
- `RepairInvokerAssignmentMode=true`;
- the single temporary `USER` assignment; and
- absence of every unsupported SSO/IAM authority.

Any mismatch stops before the authority stack.

## Phase 5 — Deploy authority PEP

The authority template exceeds the direct CloudFormation `TemplateBody` byte
limit. Under a separate exact S3 authorization, place the reviewed template in
the approved versioned artifact bucket, require SHA-256 and version-ID readback,
and bind its exact `TemplateURL` into the Change Set evidence. Do not use an
unversioned latest-object URL, overwrite a key or accept an ETag as the content
digest.

Create, verify and execute the exact Change Set for
`scanalyze-platform-authority-bootstrap-plan-repair-pep`. Read back the full
resource inventory, retention/deletion protection, table resource policy,
KMS policy, role separation, signed code, versions, aliases, reserved
concurrency, `RuntimeManagementConfig=FunctionUpdate`, qualified runtime
version readback and zero-retry event configuration. Each Version must depend
on its runtime-management resource and its description must end with the exact
materialized `ImmutableConfigurationDigest`.

Inventory Lambda and IAM account-wide to prove there is no alternate invoker,
public permission, function URL, event source, alias routing or role reuse.

## Phase 6 — Plan

Start a fresh invoke-only SSO session. Invoke only the qualified `plan-v1`
alias with the literal JSON object `{}`. The function must:

- verify its version, alias mode and execution role;
- read the exact provider and invocation graph state;
- prove the sole eligible predecessor;
- reserve the immutable intent; and
- create `PLAN_VERIFIED` with conditional `PutItem`.

The invocation must enter with more than 60,000 milliseconds remaining. The
bound adapter re-checks that same read reserve before every provider call
rather than relying only on the entry check.

Independently read the ledger and public receipt. A blocked or uncertain Plan
does not authorize repair.

## Phase 7 — One-shot repair

Require an explicit, time-bounded authorization for the two exact effects and
the exact `PLAN_VERIFIED` digest. Use a fresh invoke-only session and invoke only
`repair-v1` with `{}`.

The function claims the ledger before any write. It must record the attempting
state before each one-attempt provider call, require exact readback, and always
run `ProvisionPermissionSet` after a confirmed policy update. The operator does
not retry a timeout, disconnect, provider error or non-terminal response.

Repair must enter with more than 480,000 milliseconds remaining. The bound
adapter requires more than 75,000 milliseconds immediately before each write
and more than 60,000 milliseconds before each read or provisioning poll.
Crossing a threshold stops before the next provider call; it never authorizes
a retry.

Independently, the immutable intent must retain at least 660 seconds before the
Plan claim and more than 75 seconds immediately before each write. These
wall-clock guards do not substitute for the Lambda millisecond reserves.

## Phase 8 — Reconcile and functional proof

Invoke `reconcile-v1` with `{}` even after apparent success. It performs no
mutation and must enter with more than 60,000 milliseconds remaining. Require
convergence of:

- desired inline policy digest;
- unchanged metadata, tags, attachments, boundary and assignment;
- only the authority account provisioned;
- zero relevant pending operation;
- exact generated role trust and `AwsSSOInlinePolicy`; and
- CloudTrail attribution of both effects to the mutation service role and
  repair source identity.

Then start a completely new normal Plan SSO session and run the bounded GUG-214
read-only recovery preflight. Successful `ListChangeSets` pagination is the
functional proof. It is not production certification.

## Phase 9 — Revoke temporary access

Create a separately reviewed update Change Set against the same management
stack using the exact same merged delegation-template bytes and every prior
parameter value, changing only `RepairInvokerAssignmentEnabled` from `true` to
`false`. Its resource change set must contain exactly one change:

```text
Action=Remove
LogicalResourceId=RepairInvokerAssignment
ResourceType=AWS::SSO::Assignment
```

Execute only that UUID-bearing Change Set. Read back
`RepairInvokerAssignmentMode=false`, zero assignments for the temporary
`ScanalyzeBootstrapPlanRepair` permission set, and a terminal assignment
deletion state with no relevant pending operation. After Identity Center
converges, prove the corresponding
`AWSReservedSSO_ScanalyzeBootstrapPlanRepair_*` role is absent. The two service
roles and the invoke-only permission-set configuration must remain unchanged;
do not delete them or any authority-stack evidence resource.

Do not set the parameter back to `true` for the same repair. Any later temporary
assignment requires a new repair ID, window, artifact binding, reviewed Change
Set and explicit authorization. Preserve the ledger, KMS key, function
versions, logs, signed artifact and sanitized receipts according to the
evidence-retention policy.

## Uncertainty and recovery

After any possible dispatch:

1. do not invoke repair again;
2. do not edit the permission set from a console or CLI;
3. do not delete or rewrite the ledger;
4. invoke only the read-only reconcile alias;
5. preserve exact CloudTrail and provider readback; and
6. request a new reviewed recovery decision.

Equivalent final provider state is insufficient if the ledger cannot attribute
both effects. A new attempt requires a new repair ID, window, artifact binding
and explicit authorization.

If the attempt to seal an uncertain state is itself unproven, the function
emits no public receipt and returns `UNCERTAINTY_LEDGER_UNPROVEN`. The existing
attempting state still blocks repair replay; preserve it and stop for a new
reviewed recovery decision.

## Rollback boundary

Stack rollback may remove only resources whose retention policy and evidence
contract permit it. KMS, ledger and logs remain retained. The repaired desired
Plan policy is not reverted automatically to the known-bad predecessor.

```text
REPOSITORY_VALIDATED=NOT_LIVE_EVIDENCE
RUNTIME_PORTS=BOUND_IN_SOURCE_CLOSED_PACKAGE
SIGNED_ARTIFACT=NOT_BUILT
AWS_CALLS=0
AWS_MUTATIONS=0
DEPLOYMENT=NOT_EXECUTED
REPAIR=NOT_EXECUTED
PRODUCTION=NO-GO
```

## References

- [ADR-057](../../ADR/ADR-057-bootstrap-plan-permission-repair-pep.md)
- [Deployment contract](../deployment/platform-authority-bootstrap-plan-permission-repair.md)
- [Bootstrap recovery](platform-authority-bootstrap-recovery.md)
- [Retained Change Set retirement](platform-authority-retained-change-set-retirement.md)
