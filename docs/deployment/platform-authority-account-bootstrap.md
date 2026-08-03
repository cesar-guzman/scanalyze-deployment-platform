# Dedicated Platform-Authority Account Bootstrap

## Scope

This runbook creates only the remote Terraform state boundary required by
`roots/platform-authority`. It does not deploy Scanalyze, customer workloads,
GitHub OIDC, terminal roles, registries, ledgers, releases, Cognito, or any
destination-account resource.

The authority account must be newly approved or formally dedicated, different
from every destination account, and governed through IAM Identity Center.
Examples below use placeholders only. Never commit operational receipts,
backend files, account inventories, credentials, or real bindings.

> **GUG-274 authority boundary:** Any older instruction that grants the human
> Apply session direct CloudFormation, account-PAB, KMS, S3, IAM, or DynamoDB
> mutation is superseded. The human Apply role is read-only plus exact
> invocation; only `scanalyze-platform-authority-bootstrap-apply-executor:1`
> owns the post-CAS effects. This target is not live-authorized.

## Artifact package and activation boundary

Build the common unsigned Lambda service package only after the exact reviewed
source is committed and the worktree is clean. The builder compares `HEAD` and
every closed source path with Git object bytes, fixes ZIP ordering, timestamps,
permissions and metadata, and emits per-file/archive digests plus
`unsigned_archive_code_sha256`. Its Git subprocess uses a closed
environment/config/locale and `--no-replace-objects`, rejects any
`refs/replace`, ignores caller `PATH`, and accepts neither caller Git
configuration nor any tracked or untracked working-tree change. It rejects an
existing output path and any output inside the repository.

```bash
env -u PYTHONPATH -u PYTHONHOME python3 -I -S \
  scripts/deployment/platform-authority-bootstrap-artifact-package.py \
  --source-commit '<exact-reviewed-40-character-commit>' \
  --expected-boto3-version '1.42.57' \
  --expected-botocore-version '1.42.97' \
  --output-directory '<new-private-directory-outside-repository>'
```

The output is intentionally unsigned, marked non-deployable, and is not
publication evidence. A separately authorized signing lane must sign those exact bytes with
the fixed AWS Signer profile
`scanalyze_gug274_bootstrap_artifact_authority` and one immutable profile
version and upload the AWS Signer destination object. This runbook neither
starts that job nor uploads bytes.

The second GUG-274 CLI is a read-only collector/verifier. It rebuilds the exact
package, proves that the source commit is merged to protected `main` with all
exact required checks green, reads the verifier STS identity, completed Signer
job, versioned unsigned source, and single versioned signed S3 destination, and
validates the signed ZIP. Every invocation must also use isolated Python:

```bash
export SCANALYZE_GUG274_SDK_RUNTIME_ROOT='<absolute-reviewed-sdk-runtime-root>'

env -u PYTHONPATH -u PYTHONHOME python3 -I -S \
  scripts/deployment/platform-authority-bootstrap-signed-artifact.py \
  --profile '<exact-authority-read-only-verifier-profile>' \
  --region '<authority-region>' \
  --source-commit '<exact-reviewed-40-character-commit>' \
  --expected-boto3-version '1.42.57' \
  --expected-botocore-version '1.42.97' \
  --job-id '<exact-signer-job-uuid>' \
  --output-receipt '<new-private-directory-outside-repository>/signed-receipt.json'
```

The receipt is private, write-once, and valid for no more than 15 minutes. It
contains the exact S3 tuple, `SignedAuthorityArtifactCodeSha256`,
`AuthoritySigningReceiptDigest`, and
`AuthoritySigningTrustRootContractDigest`. Its unkeyed domain digest is an
integrity value, not authority. Immediately before any CloudFormation parameter
is consumed, the same flow must refresh GitHub, Signer, and S3 and require the
complete immutable receipt projection to match. A command-line parameter,
locally redigested receipt, unsigned manifest, source ZIP digest, or template
declaration is not proof.

The verifier loads only
`bootstrap/platform-authority-bootstrap-artifact-signing-trust-root.json`.
That fixed contract is deliberately `NOT_CONFIGURED`, with no profile version
and no activation authorization, so the command currently fails closed with
`SIGNING_TRUST_ROOT_NOT_CONFIGURED` before provider verification. The template
also permits only `AuthoritySigningTrustRootConfigured=false` while its Rule
requires `true`, so it cannot create a Change Set. A separate reviewed commit
must pin the exact signer version ID/ARN and contract digest in both the Git
contract and closed template allowlists before unlocking. The runtime rejects
`AWS_DATA_PATH` and other provider configuration/endpoint overrides. Packaging,
signing, real provider receipt/refresh, deployment, and readback remain
**NOT_OBSERVED**.

### Repository and host runtime boundary

All three GUG-274 entry points -- the normal bootstrap CLI, package builder,
and signed-artifact verifier -- fail before repository imports unless invoked
with isolated Python and both Python path overrides absent:
`env -u PYTHONPATH -u PYTHONHOME python3 -I -S ...`. Each entry point opens
`tooling/platform_authority_source_only_import.py` as UTF-8 source and compiles
those bytes before making repository modules importable. The installed finder
compiles exact repository `.py` bytes for `tooling` modules directly and neither
consumes nor emits repository `.pyc`; repository bytecode writes remain
disabled.

The two entry points that
import the operational AWS SDK require
`SCANALYZE_GUG274_SDK_RUNTIME_ROOT` to name an absolute root outside the
repository and any repository-local `.venv`. Its direct `site-packages/` child
is dedicated to, and may contain only, the fixed closure. The root and every
directory in its POSIX ancestor chain must be owned by root or the effective
user and group/world non-writable; only a root-owned sticky directory in that
chain may be writable. Every `site-packages/` entry must also have a trusted
owner and safe mode and be a regular file or directory, with no symlink and no
sticky-root exception. `-S` prevents
automatic `site`, `.pth`, and `sitecustomize` execution; the loader then admits
the dedicated path explicitly and authenticates the entire closure before
importing any SDK code. The environment path selects candidate bytes but grants
no authority: source-reviewed official wheel identities, canonical
installed-manifest hashes, and every authoritative file remain binding. The
closure fixes
`boto3==1.42.57`, `botocore==1.42.97`,
`s3transfer==0.16.1`, `jmespath==1.1.0`,
`python-dateutil==2.9.0.post0`, `urllib3==2.7.0`, and `six==1.17.0`, plus every
distribution's canonical installed-manifest SHA-256. It rejects external
`pycache_prefix`, preloaded closure modules,
missing/ambiguous distributions, symlinks, unsafe or mismatched files, and
unrecorded extras -- including `.pyc` -- in importable package trees, while
disabling bytecode writes. Raw installation-specific `RECORD` bytes are not
pinned or trusted; the wheel-owned package/stable-metadata projection must
match the source-reviewed manifest digest before every authoritative file,
size/digest, and import origin is verified. Caller version flags are equality
assertions for the two public pins, not runtime selectors.

Git, AWS CLI, and GitHub CLI selection never trusts caller `PATH`. Resolution
uses only the source-reviewed absolute candidates, rejects an executable inside
the repository, and requires the resolved file and every ancestor to be owned
by root or the effective user. The file must be regular/executable and
group/world non-writable; every ancestor must be a group/world non-writable
directory except for a root-owned sticky ancestor. The complete path check is
repeated after hashing, and stable executable metadata must not change across
the digest read. A non-root binary additionally requires an exact digest
allowlist entry; that digest cannot override an unsafe path. The current sole
entry is GitHub CLI v2.89.0 for arm64 macOS with
`sha256:abc4a820c3f423c17902feba71f8af9ae73c2b20559d117bac628d4cb53f3416`;
Git and AWS CLI have no non-root digest exception. Subprocesses use the resolved
absolute path and a derived constrained `PATH`. The currently inspected
Homebrew `gh` fails closed because its resolved path crosses group-writable
`/opt/homebrew/Cellar` at mode `0775`, even though its file digest is reviewed.

The repository reviews and authenticates this runtime contract; it does not
install, upgrade, or roll back the host interpreter, wheels, or executables. A
missing or mismatched host dependency is a fail-closed tooling stop. Remediation
is a separately reviewed host/toolchain change or a reviewed repository commit
that changes the public pins/bindings and rebuilds, re-signs, and revalidates
the artifact. Never work around the stop with `PATH`, `PYTHONPATH`, a local
shadow module, placeholder version, or in-place receipt/package edit.

The service ZIP deliberately excludes the SDK wheels. CloudFormation fixes all
three functions to Lambda `python3.12` and passes the same expected versions;
each function matches them to the embedded runtime lock and checks the
AWS-managed `boto3`/`botocore` `__version__` values before constructing clients.
The operator-host closure authenticator does not extend into Lambda. This
AWS-managed boundary is not active because the signing trust root/CFN lock still
makes Change Set creation impossible. After future activation, managed SDK
drift is a fail-closed runtime stop, and neither repository nor host-toolchain
rollback can downgrade that AWS-owned runtime.

## Identity Center permission sets

Create three dedicated permission sets:

- `ScanalyzeAuthorityBootstrapPlan`, rendered from
  `policies/iam/platform-authority-bootstrap-plan-role.json`, for real Identity
  Store user A;
- `ScanalyzeAuthorityBootApprove`, rendered from
  `policies/iam/platform-authority-bootstrap-approval-role.json`, for real
  Identity Store user B's independent Approval invocation;
- `ScanalyzeAuthorityBootstrapApply`, rendered from
  `policies/iam/platform-authority-bootstrap-apply-role.json`, for the
  same real user B's separate read-only/invoke-only Apply role after the exact
  Change Set exists.

These names are canonical. Each satisfies the IAM Identity Center 1-to-32
character service contract and the portable ASCII character allowlist. Do not
prepend `Platform`, append an environment/customer label, abbreviate the
Plan/Approval/Apply suffix, or reuse the rejected overlength GUG-206 names. The
CLI validates the name contract and the exact account-local
`AWSReservedSSO_*` role before every protected operation.

All three permission sets require:

- a short session duration;
- no managed `AdministratorAccess` policy;
- assignment only to the dedicated platform-authority account;
- user A receives only Plan; different user B receives the distinct Approval
  and Apply roles. User B holding both does not merge their policies, grants,
  proof roles, or invocations;
- organization audit retention and the standard emergency revocation path.

For each operation, the real user supplies a new Identity Center authorization
code and PKCE verifier through a non-persistent pipe or socket file descriptor.
The CLI rejects regular files and terminals. Never place the code/verifier in a
command argument, environment variable, Plan, Approval, receipt, log, Git,
Linear, NotebookLM, or CI artifact. Candidate `initiator_id`, `approver_id`, and
principal-digest fields are attribution assertions only; fixed UserIds and
identity-proof receipt digests are the live authority. Those attribution fields
are not cryptographically correlated with the live UserIds; strengthening that
correlation is a P2 follow-up, not current authority.

The exact service execution roles are
`ScanalyzeGug274BootstrapPlanAuthority`,
`ScanalyzeGug274BootstrapApprovalAuthority`, and
`ScanalyzeGug274BootstrapApplyExecutor`. Their distinct deny-all proof roles are
`ScanalyzeGug274BootstrapPlanIdentityProof`,
`ScanalyzeGug274BootstrapApprovalIdentityProof`, and
`ScanalyzeGug274BootstrapApplyIdentityProof`. Similar names or shared roles are
invalid.

The DynamoDB table resource policy is deny-only and grants no positive access.
Every positive DynamoDB Allow lives solely in the relevant execution-role
identity policy, is limited to that service's exact action/table/key boundary,
and requires its exact unqualified source-function ARN through
`lambda:SourceFunctionArn`. AWS supplies that condition key without a version
suffix, so qualified `:1` invocation, Lambda permission, deployment/readback,
and runtime checks enforce the published version separately. Never add a
positive table-policy Allow or direct human ledger grant.

### Bounded founder exception (GUG-209)

The durable enforcement implementation for this exception is ADR-039 / GUG-211
and its dedicated deployment and operations runbooks. The original GUG-209
JSON/policy artifacts stay offline-only and are never upgraded in place.

The normal two-person rule above is not changed by GUG-209. If a newly created
dedicated authority account temporarily has one founder operator and no
independent reviewer, the only permitted alternative is the separate
[founder bootstrap exception][founder-exception] contract. It is exactly
bound to authority account `042360977644`, Region `us-east-1`, literal
`non-production`, one fresh `CREATE` Change Set, and one intended future
durable-PEP attempt. GUG-209 is **OFFLINE-ONLY — LIVE EXECUTION BLOCKED**: its
local records/digests do not authorize AWS or provide durable exactly-once
control.

Its offline record format explicitly models
`approval_mode: SINGLE_OPERATOR_FOUNDER_EXCEPTION`,
`independent_approval_present: false`, and `approver_id: null`. It is not
normal approval, cannot use BreakGlass, and must not add a self-approval switch
to this CLI or the normal approval core. The exception's offline Plan and Apply
policy templates define AWS request-time `Deny` conditions, bind one
authenticated Identity Center subject privately, remain disjoint, and require
deny retention for at least twelve hours after expiry. Assignment/membership
removal and identity-system readback are also mandatory; an absent readback is
`REVOCATION_REQUIRED`, not success. The local record is only an offline model,
never durable authorization. No founder policy is attached by this package.

This repository change neither creates the temporary permission sets nor
executes a Change Set. Those are separately authorized live operations. The
account-level S3 public-access block is a founder-exception precondition; the
founder Apply policy has no direct authority to change it. See the separate
runbook for the complete no-retry and cleanup boundary.

If a future live founder PEP is separately reviewed, it must use a controlled
durable CAS ledger with trusted identity/event evidence and immediate readback
of the exact Change Set, template, and resources before `ExecuteChangeSet`.
It binds execution on the exact stack resource through
`cloudformation:ChangeSetName`. Its stricter KMS alias path permits
`kms:CreateAlias` only: the exact alias statement has no condition because KMS
does not support conditions there, while the companion tagged-key statement
requires `aws:CalledVia=cloudformation.amazonaws.com`.

### KMS alias authorization boundary

KMS authorizes alias management against the alias and every affected key. The
service-owned Apply-executor role, not the human Apply policy, therefore
contains two complementary forward-access grants:

- one for the exact `alias/scanalyze-platform-authority-state` ARN;
- one for keys in the exact authority account and region with the canonical
  state ownership tags.

Both sides include `kms:CreateAlias`, `kms:UpdateAlias`, and
`kms:DeleteAlias`. The exact alias statement contains no conditions because
KMS does not support condition keys on an alias resource. The key-side
statement requires the ownership tags and `aws:CalledVia` to contain
`cloudformation.amazonaws.com`. Because KMS requires both permissions, a
direct API request still fails on the key side. Do not add `kms:RequestAlias`
to these actions or put any condition on the alias-resource statement. Do not
replace the split model with an alias wildcard, a key wildcard outside the
bound account/region, or a direct API fallback.

### GUG-210 supported Change Set IAM binding

The Plan policy cannot execute a Change Set or create backend resources. The
human Apply policy cannot create, execute, or retire a Change Set, mutate PAB,
or delete the stack. Only the exact service-owned Apply executor has the
`cloudformation:ChangeSetName`-conditioned Execute permission and effect
permissions after CAS. The normal Create and service Execute statements
authorize against the exact stack ARN and require the exact Change Set name.
One pure helper derives that
name only from a fully validated ARN bound to the expected partition, Region,
account and UUID-shaped ID, returning one immutable typed identity rather than
an independently supplied mutation field. The full Change Set ARN and UUID
remain persisted PEP evidence and are used for exact readback; they are not
sent as the final Execute mutation argument. Backend-mutating S3 and
key-side KMS actions additionally require the multivalued `aws:CalledVia`
context to contain `cloudformation.amazonaws.com`; a direct S3/KMS API call
therefore does not receive all required permissions. The executor is also the
sole account-level PAB writer; the human role explicitly denies every such
mutation.

Both pre-PAB and final readback require the same full ARN/UUID, `Original`
template, tags/status/resources, exact parameters `AuthorityAccountId`,
`StateKey`, and `NoncurrentVersionRetentionDays=365`, and canonical request
metadata: `OnStackFailure=ROLLBACK`, `IncludeNestedStacks=false`, empty
capabilities/notifications, `ImportExistingResources=false`, absent
`RoleARN`/`DeploymentMode`/parent/root IDs, and
absent-or-empty default rollback configuration. Freshness is checked at both
points; only the final request uses the derived bare name. Remove or disable
all human assignments after the bootstrap window.

Render the initial Plan policy offline into the controlled evidence directory;
do not substitute policy placeholders by hand:

```bash
umask 077
mkdir -p '<private-evidence-dir>'
export SCANALYZE_GUG274_SDK_RUNTIME_ROOT='<absolute-reviewed-sdk-runtime-root>'

env -u PYTHONPATH -u PYTHONHOME python3 -I -S \
  scripts/deployment/platform-authority-bootstrap.py render-plan-policy \
  --authority-account-id '<authority-account-id>' \
  --region '<authority-region>' \
  --destination-account-id '<customer-a-account-id>' \
  --destination-account-id '<customer-b-account-id>' \
  --change-set-name '<scanalyze-platform-authority-bootstrap-YYYYMMDDHHMMSS>' \
  --policy-out '<private-evidence-dir>/bootstrap-plan-policy.json'

env -u PYTHONPATH -u PYTHONHOME python3 -I -S \
  scripts/deployment/platform-authority-bootstrap.py render-approval-policy \
  --authority-account-id '<authority-account-id>' \
  --region '<authority-region>' \
  --destination-account-id '<customer-a-account-id>' \
  --destination-account-id '<customer-b-account-id>' \
  --policy-out '<private-evidence-dir>/bootstrap-approval-policy.json'
```

The identity administrator validates both files with IAM Access Analyzer and
uses the governed IAM Identity Center process to create or update only the
canonical Plan and Approval permission sets. The commands perform no AWS call.

Identity Center creates the account-local `AWSReservedSSO_*` role. Do not
create a manual IAM role or IAM user for this workflow. The policy template is
rendered from the exact account, region, and bucket binding under change
control; placeholders must never be submitted to AWS. The CLI checks the live
STS principal: `plan` requires the canonical
`ScanalyzeAuthorityBootstrapPlan` permission set, `approve` requires
`ScanalyzeAuthorityBootApprove`, and `apply`/`verify` require
`ScanalyzeAuthorityBootstrapApply`. `AWS_PROFILE` text is not trusted as proof
of any role, and STS role text is not the live UserId proof produced inside the
services. The retained `cancel` compatibility command requires
no AWS identity because it fails locally before an AWS client can be created;
GUG-215 is the sole retirement path.

## Preflight: read-only

Use an SSO profile for the authority account. Do not export access keys or
session tokens.

```bash
export AWS_PROFILE='<authority-bootstrap-plan-sso-profile>'
export AWS_REGION='<authority-region>'
export AWS_DEFAULT_REGION="$AWS_REGION"
export SCANALYZE_GUG274_SDK_RUNTIME_ROOT='<absolute-reviewed-sdk-runtime-root>'

env -u PYTHONPATH -u PYTHONHOME python3 -I -S \
  scripts/deployment/platform-authority-bootstrap.py preflight \
  --authority-account-id '<authority-account-id>' \
  --region "$AWS_REGION" \
  --destination-account-id '<customer-a-account-id>' \
  --destination-account-id '<customer-b-account-id>'
```

The command fails if STS, region, destination separation, stack absence,
template validation, or the current S3 account setting is ambiguous. It prints
no ARN or AWS response and performs no writes.

### Recovery of an existing review shell (GUG-214)

If the canonical stack already exists, do not infer that an empty resource list
means the account is safe to re-plan. Use the exact normal Plan profile and the
dedicated recovery command:

```bash
export SCANALYZE_GUG274_SDK_RUNTIME_ROOT='<absolute-reviewed-sdk-runtime-root>'

env -u PYTHONPATH -u PYTHONHOME python3 -I -S \
  scripts/deployment/platform-authority-bootstrap.py preflight-recovery \
  --authority-account-id '<authority-account-id>' \
  --region "$AWS_REGION" \
  --destination-account-id '<customer-a-account-id>' \
  --destination-account-id '<customer-b-account-id>'
```

It succeeds only for the exact `REVIEW_IN_PROGRESS` stack with a canonical
StackId, zero resources, zero active Change Sets across every page, no service
role, notifications or nested-stack metadata, and present all-true account S3
Block Public Access. Missing PAB, inherited stack authority, denied inventory,
malformed pagination or any active Change Set blocks recovery. The Plan policy grants
`cloudformation:ListChangeSets` separately on the exact stack ARN; do not add a
general ReadOnly managed policy to the permission set.

The empty shell has no authoritative physical resource locators. Do not inspect
KMS, S3 or DynamoDB by deriving expected names. A separately assigned ReadOnly
profile may provide independently classified corroborating evidence, but it is
not Plan authority and cannot make this command pass.

CloudFormation can reuse a stack service role without a later caller presenting
`iam:PassRole`. Normal and founder Plan/Apply therefore share one fail-closed
shell contract and repeat it immediately before their protected Create/Execute
effect.

## Plan: metadata write only

Choose a private directory outside every repository with permissions 0700. The
CLI creates the receipt with mode 0600 and refuses existing paths or symlinks.

```bash
umask 077
mkdir -p '<private-evidence-dir>'
export SCANALYZE_GUG274_SDK_RUNTIME_ROOT='<absolute-reviewed-sdk-runtime-root>'

env -u PYTHONPATH -u PYTHONHOME python3 -I -S \
  scripts/deployment/platform-authority-bootstrap.py plan \
  --authority-account-id '<authority-account-id>' \
  --region "$AWS_REGION" \
  --destination-account-id '<customer-a-account-id>' \
  --destination-account-id '<customer-b-account-id>' \
  --initiator-id '<approved-operator-id>' \
  --change-set-name '<same-exact-name-used-to-render-plan-policy>' \
  --plan-out '<private-evidence-dir>/bootstrap-plan.json' \
  --identity-grant-fd '<non-persistent-pipe-or-socket-fd>' \
  --allow-change-set-write
```

This creates one CloudFormation Change Set and an empty
`REVIEW_IN_PROGRESS` stack record; it creates no template resources and does not
execute the Change Set. Review the sanitized resource-type/action inventory,
template digest, expiry, account public-access transition, and plan digest. Plan
obtains the Change Set's `Original` template by full ARN with its existing
exact-stack `GetTemplate` grant and requires byte-for-byte UTF-8 equality with
the local bootstrap template before persisting the digest. The raw receipt
remains controlled operational evidence.

Creation fixes `AuthorityAccountId`, `StateKey`, and
`NoncurrentVersionRetentionDays=365`; `OnStackFailure=ROLLBACK` and
`IncludeNestedStacks=false` are explicit. The readback must also show
`ImportExistingResources=false`, empty capabilities and notifications, absent
`RoleARN`/`DeploymentMode`/parent/root metadata, and
absent-or-empty default rollback configuration. Plan then passes the fresh
non-persistent grant to Plan service `:1`, which proves user A and creates the
exact durable anchor. An ambiguous anchor is terminal and does not authorize a
retry or success claim.

For a retained shell, `plan` repeats the complete active Change Set inventory
immediately before creation. `ListChangeSets` is an active inventory, not a
historical audit. Any returned or ambiguous summary stops; no stack or Change
Set is auto-deleted.

At this point, the identity administrator renders the human Apply inline policy
from the still-valid controlled Plan:

```bash
export SCANALYZE_GUG274_SDK_RUNTIME_ROOT='<absolute-reviewed-sdk-runtime-root>'

env -u PYTHONPATH -u PYTHONHOME python3 -I -S \
  scripts/deployment/platform-authority-bootstrap.py render-apply-policy \
  --authority-account-id '<authority-account-id>' \
  --region "$AWS_REGION" \
  --destination-account-id '<customer-a-account-id>' \
  --destination-account-id '<customer-b-account-id>' \
  --plan '<private-evidence-dir>/bootstrap-plan.json' \
  --policy-out '<private-evidence-dir>/bootstrap-apply-policy.json'
```

The renderer validates the exact unexpired Plan plus account, Region, and both
destination bindings and writes mode 0600. The result fixes only the qualified
`scanalyze-platform-authority-bootstrap-apply-executor:1` ARN, bounded
verification reads, explicit direct-effect denies, and a final deny for every
other non-read/non-broker action. It contains no direct effect authority. The
executor's immutable runtime configuration, not the human policy, owns the
exact Change Set name and effect permissions. The identity
administrator validates the output with IAM Access Analyzer, provisions the
canonical Apply permission set, and assigns it only to user B for the approved
window. Do not publish either ARN component in Git, Linear, NotebookLM, or
general CI artifacts.

## Approval: a different SSO principal

Real user B signs in through the distinct Approval permission set in the same
account. Merely changing a profile or STS role name is insufficient; Approval
service `:1` exchanges a fresh code-plus-PKCE grant and proves the fixed user-B
Identity Store binding through its operation-specific deny-all proof role.

```bash
export AWS_PROFILE='<independent-authority-approval-sso-profile>'
aws sso login --profile "$AWS_PROFILE"
export SCANALYZE_GUG274_SDK_RUNTIME_ROOT='<absolute-reviewed-sdk-runtime-root>'

env -u PYTHONPATH -u PYTHONHOME python3 -I -S \
  scripts/deployment/platform-authority-bootstrap.py approve \
  --authority-account-id '<authority-account-id>' \
  --region "$AWS_REGION" \
  --destination-account-id '<customer-a-account-id>' \
  --destination-account-id '<customer-b-account-id>' \
  --plan '<private-evidence-dir>/bootstrap-plan.json' \
  --approver-id '<approved-reviewer-id>' \
  --approval-out '<private-evidence-dir>/bootstrap-approval.json' \
  --identity-grant-fd '<non-persistent-pipe-or-socket-fd>'
```

Approval expires no later than the plan. If the plan, template, account,
principal, or time binding changes, create a new plan and obtain new approval.
The candidate approver label/principal digest is anchored attribution, not
UserId authority; the ledger proof receipt carries that authority. An ambiguous
approval transition is terminal and never retried.

## Apply and verify

Apply is authorized separately. The exact command must be reviewed with its
account, region, plan digest, approval digest, cost boundary, and change window.
Real user B switches to the separate Apply permission set. User A is
technically unable to approve or invoke Apply, and the human Apply role is
technically unable to execute the Change Set or set account PAB directly.

Apply first performs strict local Plan/Approval validation and consumes a fresh
Apply-specific code-plus-PKCE grant from a pipe/socket. The exact Apply executor
`:1` proves user B, reads the complete authenticated ledger item, revalidates
freshness, and conditionally writes `CLAIMED` version 3/attempt 1. It constructs
no CloudFormation or S3 Control client until that CAS succeeds unambiguously.

After CAS, the executor validates the exact empty shell, full ARN/UUID,
parameters, request metadata, tags/status/resources, and `Original` template,
then revalidates freshness. It sets all-true account PAB, repeats that complete
readback and freshness check, and issues one `ExecuteChangeSet` using only the
helper-derived bare name plus exact stack. Any identity, CAS, PAB, or execution
ambiguity is terminal: no retry and no success claim. The current package has
no independent strongly consistent read-only ledger reconciliation endpoint;
live activation remains blocked, and operators must not add ad hoc IAM to
invent one.

`OnStackFailure=ROLLBACK` and `DisableRollback=false` govern the CloudFormation
stack only. The executor writes account-level S3 Public Access Block before
`ExecuteChangeSet`; CloudFormation rollback cannot undo that account control.
Retain PAB on failure and follow the recovery runbook. Do not weaken it as a
rollback shortcut.

```bash
export SCANALYZE_GUG274_SDK_RUNTIME_ROOT='<absolute-reviewed-sdk-runtime-root>'

env -u PYTHONPATH -u PYTHONHOME python3 -I -S \
  scripts/deployment/platform-authority-bootstrap.py apply \
  --authority-account-id '<authority-account-id>' \
  --region "$AWS_REGION" \
  --destination-account-id '<customer-a-account-id>' \
  --destination-account-id '<customer-b-account-id>' \
  --plan '<private-evidence-dir>/bootstrap-plan.json' \
  --approval '<private-evidence-dir>/bootstrap-approval.json' \
  --verification-out '<private-evidence-dir>/bootstrap-verification.json' \
  --backend-config-out '<private-evidence-dir>/platform-authority.backend.hcl' \
  --identity-grant-fd '<non-persistent-pipe-or-socket-fd>' \
  --allow-bootstrap-apply
```

Only after the service returns may the human role use its read-only permissions
to wait for stack completion and verify the backend controls below.

Success requires all of the following:

- account-level and bucket-level S3 public access blocked;
- bucket owner enforced;
- versioning enabled;
- default SSE-KMS with the exact key and S3 Bucket Key enabled;
- KMS rotation enabled;
- every mandatory bucket-policy deny present;
- exact stack/account/region/bucket/state-key outputs;
- native Terraform lockfile enabled and no DynamoDB lock table.

After success, initialize only `roots/platform-authority` with the generated
backend file. A separate saved Terraform plan, independent approval, and exact
GUG-125 apply are still required to create the platform-authority resources.

## Evidence and status

Publish only sanitized digests, resource-type counts, gate results, commit/PR,
and evidence classification to Linear/GitHub. Do not publish principal IDs,
Change Set ARNs, bucket/KMS identifiers, backend config, AWS responses, stack
events, plans, approvals, or receipts.

Repository and CI evidence are not live evidence. Backend live verification is
not a Scanalyze deployment and does not establish two-customer isolation.
The read-only verifier/receipt/refresh implementation is repository evidence.
The deterministic package, Signer result, real provider receipt/refresh,
operational CloudFormation handoff, signed S3 object version, deployed
functions/roles, real user-A/user-B proof, DynamoDB transitions, PAB write, and
CloudFormation execution are **NOT_OBSERVED**. The fixed signer contract is
**SIGNING_TRUST_ROOT_NOT_CONFIGURED**, and Change Set creation is impossible.
The independent strongly
consistent exact-item ledger reconciliation capability is **NOT_IMPLEMENTED**
and tracked as a P2 recovery follow-up, so activation is blocked. Production
remains **NO-GO**.

[founder-exception]: ../operations/founder-bootstrap-single-operator-exception.md
