# ADR-034: Dedicated Platform-Authority Account Bootstrap

- **Status:** Proposed; accepted only after reviewed merge and main verification
- **Date:** 2026-07-16
- **Work package:** GUG-206
- **Parent / phase gate:** GUG-125 / GUG-117
- **Baseline:** `daf010d3c6cc17d1885b6c0627b9c06bc73d849d`
- **AWS live validation:** Read-only account inventory only; bootstrap not applied
- **Production:** **NO-GO**

> **GUG-207 amendment:** The PR #21 policy used `kms:RequestAlias` on
> alias-management actions. ADR-035 supersedes that condition with exact
> alias-side and tagged-key-side permissions. The alias side has no conditions,
> as required by KMS; the key side enforces `aws:CalledVia`. GUG-206 remains
> incomplete until the amendment is merged and verified on main.
>
> **GUG-208 amendment:** The original Identity Center permission-set names
> exceeded the AWS 32-character service limit. ADR-036 replaces them with the
> exact portable names `ScanalyzeAuthorityBootstrapPlan` and
> `ScanalyzeAuthorityBootstrapApply`. The rejected names never established
> live authority and must not be inferred or aliased.
>
> **GUG-210 amendment:** AWS authorizes CloudFormation `CreateChangeSet`,
> `DeleteChangeSet`, and `ExecuteChangeSet` against the stack resource, not a
> Change Set ARN. ADR-038 replaces the unsupported resource shape with the
> exact canonical stack ARN plus an exact `cloudformation:ChangeSetName`
> condition. The full Change Set ARN/UUID remains mandatory PEP evidence.
>
> **GUG-214 amendment:** ADR-040 adds the canonical `preflight-recovery`
> command for a retained review shell. Normal Plan receives a separate
> exact-stack `ListChangeSets` grant and may adopt the shell only after proving
> `REVIEW_IN_PROGRESS`, zero resources, zero active Change Sets across every
> page, and present all-true account S3 Block Public Access. General ReadOnly
> evidence never substitutes for the exact Plan identity.
>
> **GUG-274 amendment:** ADR-048 supersedes every direct-human-Apply effect
> statement in this ADR. The normal path now uses Plan v2/Approval v2, a fixed
> DynamoDB CAS trust root, real Identity Store user A for Plan and different
> user B for separate Approval and Apply roles, and exact service versions. The
> human Apply role is read-only plus invocation of
> `scanalyze-platform-authority-bootstrap-apply-executor:1`; only that service
> may claim, construct CloudFormation/S3 Control clients, set account PAB, and
> execute after the CAS. GUG-215 remains the sole retirement authority. The
> deterministic package is unsigned and non-deployable. Its read-only
> Signer/S3 verifier and short-lived receipt are implemented, but the fixed Git
> signer contract and CloudFormation activation lock are deliberately
> **SIGNING_TRUST_ROOT_NOT_CONFIGURED**. All three GUG-274 CLIs require isolated
> Python without `PYTHONPATH`/`PYTHONHOME`; exact SDK pins and absolute
> Git/AWS/GitHub executable bindings are source-reviewed and caller `PATH` is
> not authority. Signing, deployment, identity
> proof, ledger activity, and AWS effects are **NOT_OBSERVED** live; production
> remains **NO-GO**.

## Context

GUG-125 introduced a portable Terraform root for the Scanalyze machine control
plane, but correctly required its state and human recovery plane to pre-exist.
The original repository bootstrap template was designed for customer
deployments. It permitted production, created a legacy DynamoDB lock table,
derived resources from a deployment ID, and did not prove that the current AWS
account was the dedicated platform authority. Reusing it would collapse the
control-plane/customer boundary and conflict with the native S3 lockfile
contract established by GUG-122.

A newly vended authority account was inventoried read-only. It contained only
the organization baseline and no Scanalyze storage, workloads, IAM identities,
OIDC provider, or state. Organization security services remain owned by their
delegated administrators; this package must not create competing member-level
administration.

## Decision

### 1. The authority account is a distinct ownership boundary

The platform authority must be different from every customer destination
account. It stores deployment control metadata, releases, approvals, and
execution state only. It never stores customer documents, PII, extracted
payloads, customer Terraform state, processing queues, or runtime workloads.

Human bootstrap and recovery use short-lived IAM Identity Center sessions.
Normal machine execution later uses the exact GitHub OIDC roles declared by
`roots/platform-authority`. IAM users, access keys, copied SSO credentials, and
a customer or corporate audit account acting as the authority are forbidden.

### 2. A dedicated bootstrap owns only the Terraform state boundary

`cfn-platform-authority-state-backend.yaml` creates one retained, rotating KMS
key, one alias, one versioned S3 bucket, and one restrictive bucket policy. The
template rejects a supplied account or bucket that does not equal the current
account and region. The fixed state key is:

```text
platform-authority/terraform.tfstate
```

Terraform uses `use_lockfile = true`. No DynamoDB lock table, workspace prefix,
customer/deployment prefix, production selector, or request-supplied key is
accepted.

The bucket is bucket-owner-enforced, KMS-encrypted with a bucket key, versioned,
private, retained on stack deletion/replacement, and limited to the state and
lockfile keys. Bucket policy denies insecure transport, cross-account access,
wrong/missing encryption, unexpected object keys, and direct state deletion.

### 3. Account-level S3 public access is one explicit planned step

CloudFormation does not expose a native resource that changes the S3 account
public-access-block setting. The bootstrap Plan therefore binds the current
setting and the all-true desired setting. Under ADR-048, the exact Apply
executor first proves user B and consumes the approved ledger state by CAS.
Only after that terminal claim may it construct S3 Control/CloudFormation
clients, write the all-true account control, repeat the exact readback, and
execute. A later stack failure does not roll back that safe account-wide
setting.

Bucket-level public access remains independently enforced by CloudFormation.
Organization SCPs and Control Tower controls remain additional layers, not
substitutes for either control.

### 4. Planning, approval, execution, and verification are separate

`plan` validates STS identity and template, creates a CloudFormation Change Set
plus its empty `REVIEW_IN_PROGRESS` stack record, and records the exact resource
changes and template digest. It cannot execute the change set or create template
resources. The plan expires within one hour and is written mode 0600 outside
the repository.

When the exact shell already exists, `preflight-recovery` is required before a
new Plan attempt. The Plan path repeats the complete active Change Set inventory
immediately before create. An empty shell provides no trusted KMS, S3 or
DynamoDB physical locator, so resource names are never inferred from the
template, request or naming convention.

`approve` requires real Identity Store user B, distinct from Plan user A, and
anchors Approval v2 plus an operation-specific identity-proof receipt. User B
also holds the separate Apply role, but Approval and Apply retain distinct
permission sets, proof roles, fresh code-plus-PKCE grants, and invocations.
Candidate initiator/approver IDs and principal digests remain attribution
assertions, not live UserId authority, and are not cryptographically correlated
with the fixed UserIds. Stronger correlation is a P2 follow-up.

`apply` performs local validation and asks the exact service-owned executor to
prove user B, authenticate the complete Plan/Approval/identity ledger state,
and claim it once. Only the executor then validates the full ARN/UUID,
`Original` template, exact parameters and request metadata, and freshness;
sets account PAB; repeats the complete validation; and executes one derived
bare-name request. The human session performs no direct effect and later uses
read-only verification to emit the backend configuration.

Request fields, profile names, aliases, last-four digits, local usernames, and
plain approval labels never establish authority. Operational plans, approvals,
backend files, AWS responses, and verification receipts stay outside Git,
Linear, NotebookLM, and general CI artifacts.

### 5. Human roles and service effects are separated

The normal path uses three time-bound IAM Identity Center permission sets:

- `ScanalyzeAuthorityBootstrapPlan`, rendered from
  `platform-authority-bootstrap-plan-role.json`, belongs only to real user A.
  It can create/read the metadata-only Change Set and invoke the exact Plan
  service `:1`; it cannot approve, execute, retire, write PAB, or write the
  ledger directly.
- `ScanalyzeAuthorityBootApprove`, rendered from
  `platform-authority-bootstrap-approval-role.json`, belongs only to real user
  B. It invokes only the exact Approval service `:1` and has no CloudFormation
  or ledger authority.
- `ScanalyzeAuthorityBootstrapApply`, rendered from
  `platform-authority-bootstrap-apply-role.json`, also belongs to user B but is
  a separate role. It is read-only plus exact Apply-executor `:1` invocation
  and explicitly denies direct CloudFormation, account-PAB, S3, KMS, IAM, and
  DynamoDB mutation.

The Apply renderer accepts only the exact unexpired Plan with matching account,
Region, and destinations. It fixes the qualified executor `:1`, bounded
verification reads, explicit direct-effect denies, and a deny for every other
non-read/non-broker action; no caller-selected function or effect authority is
rendered.

Each invocation receives a fresh authorization code and PKCE verifier only
through a non-persistent pipe/socket. The exact service exchanges it through
the fixed Identity Center application and assumes an operation-specific
deny-all proof role. The proof receipt, not a profile name or candidate label,
binds the fixed UserId and service role. Tokens, assertions, credentials, raw
UserIds, and provider responses are not persisted.

The service execution roles
`ScanalyzeGug274BootstrapPlanAuthority`,
`ScanalyzeGug274BootstrapApprovalAuthority`, and
`ScanalyzeGug274BootstrapApplyExecutor` own the three CAS transitions. Only the
last role owns the backend effects, and only after `APPROVED -> CLAIMED`.
The DynamoDB table resource policy is deny-only and grants no positive access.
Each service's positive DynamoDB Allow lives solely in that execution-role
identity policy, is constrained to its exact action/table/key boundary, and
requires the exact unqualified source-function ARN through
`lambda:SourceFunctionArn`. Because AWS supplies that key without a version
suffix, qualified `:1` invocation, Lambda permission, deployment/readback, and
runtime checks enforce the exact published version separately.
GUG-210 remains exact: both pre-PAB and final readback use the full ARN/UUID,
`Original` template, exact `AuthorityAccountId`/`StateKey`/retention-365
parameters, canonical `ROLLBACK`/no-nesting/
`ImportExistingResources=false`/no-`DeploymentMode`/empty
capability-notification metadata, and freshness; only the final Execute uses
the derived bare name.

The builder emits one deterministic clean-commit but unsigned and non-deployable
package plus `unsigned_archive_code_sha256`. It closes Git config/environment,
uses `--no-replace-objects`, resolves a reviewed absolute Git executable rather
than caller `PATH`, rejects `refs/replace` and all tracked/untracked working-tree
changes, and embeds the source/SDK runtime lock at exact pins
`boto3==1.42.57` and `botocore==1.42.97`; caller flags must equal those pins.
All three GUG-274 CLIs require
`env -u PYTHONPATH -u PYTHONHOME python3 -I -S ...`, so automatic `site`, `.pth`,
and `sitecustomize` execution cannot precede the gate. Each entry point first
reads `tooling/platform_authority_source_only_import.py` as UTF-8 source and
compiles those bytes before making repository modules importable. Its finder
compiles exact repository `.py` bytes for `tooling` modules directly and neither
consumes nor emits repository `.pyc`; repository bytecode writes remain
disabled.

For normal bootstrap/verifier, `SCANALYZE_GUG274_SDK_RUNTIME_ROOT` names an
absolute root outside the repo/local `.venv` whose direct `site-packages/`
contains only the fixed operational closure. The runtime root and every directory in its POSIX
ancestor chain must be owned by root or the effective user and group/world
non-writable; only a root-owned sticky directory in that chain may be writable.
The complete site tree must likewise have trusted ownership and safe modes, with
no symlink or non-regular/non-directory entry and no sticky-root exception. That
environment path selects candidate bytes and grants no authority: before
import, the loader admits the path explicitly and
authenticates it against source-reviewed official wheel identities and
canonical installed-manifest hashes. The complete closure is
`boto3==1.42.57`, `botocore==1.42.97`,
`s3transfer==0.16.1`, `jmespath==1.1.0`,
`python-dateutil==2.9.0.post0`, `urllib3==2.7.0`, and `six==1.17.0`.
Each installed-manifest digest covers the wheel-owned package and stable
metadata rows before full authoritative-file/origin validation; external
`pycache_prefix`, preloads, symlinks, `.pyc`, unsafe/mismatched or extra
import-tree files fail closed. Raw
installation-specific `RECORD` bytes are neither pinned nor authority. Git,
AWS CLI, and GitHub CLI
resolution ignores caller `PATH`, uses reviewed absolute candidates, and
requires the resolved executable and every ancestor to be owned by root or the
effective user. The executable must be regular/executable and group/world
non-writable; ancestor directories must be group/world non-writable except for
a root-owned sticky ancestor. That complete check is repeated after the digest,
and stable executable metadata must not change. A non-root executable also
requires an exact reviewed digest, but the digest cannot excuse an unsafe path;
only the pinned GitHub CLI digest is currently allowed. The inspected Homebrew
`gh` fails closed because `/opt/homebrew/Cellar` is mode `0775` and therefore a
group-writable ancestor. Services reject `AWS_DATA_PATH` and
other provider overrides. The ZIP excludes SDK wheels: Lambda `python3.12`
supplies the AWS-managed SDK, and each service matches environment pins to the
embedded lock then checks managed-module `__version__` before clients. The host
closure authenticator does not extend into Lambda; that managed boundary is not
active while CFN activation remains impossible. After future activation,
managed-runtime drift fails closed and cannot be reversed by
repository/workstation rollback.
The implemented read-only verifier proves merged
protected `main` plus exact required checks, reads the completed Signer job and
exact versioned S3 bytes, validates the signed ZIP, and emits the closed
CloudFormation projection in a receipt valid for at most 15 minutes. The
receipt digest is not authority by itself; GitHub, Signer, and S3 must be
refreshed immediately before consumption.

The verifier loads only the fixed contract
`bootstrap/platform-authority-bootstrap-artifact-signing-trust-root.json`,
which deliberately has no profile version and is `NOT_CONFIGURED`.
CloudFormation separately allows only activation lock `false` while its Rule
requires `true`; therefore no Change Set can be created. A separate reviewed
commit must pin the exact version ID/ARN and contract digest in both contract
and template allowlists. Until then,
**SIGNING_TRUST_ROOT_NOT_CONFIGURED** blocks activation and the declared
`UntrustedArtifactOnDeployment=Enforce` is not live evidence. The current
package also lacks an independent
strongly consistent read-only ledger reconciliation endpoint; both are
live-activation blockers. Reconciliation is tracked as a P2 recovery follow-up;
neither gap permits ad hoc IAM.

## Consequences

- A customer account can never silently become the deployment authority.
- Backend creation is recoverable without static credentials or local state.
- State and lock ownership agree with the GUG-122/GUG-125 contracts.
- Initial bootstrap needs two independently attributable SSO principals.
- The account-wide S3 control is explicit because it is outside the
  CloudFormation resource graph and belongs only to the post-CAS Apply
  executor.
- Security Hub, GuardDuty, organization trails, and delegated Config controls
  remain organization responsibilities and are verified separately.

## Alternatives rejected

- **Reuse the customer backend template:** wrong ownership, production option,
  deployment-derived naming, and legacy DynamoDB locking.
- **Bootstrap with local Terraform state:** the recovery boundary would reside
  on an operator workstation and could be lost or altered.
- **Use an audit or customer account:** combines evidence/customer authority
  with deployment authority and breaks independent isolation proof.
- **Execute a template directly:** skips exact change review and independent
  approval.
- **Treat a profile name as identity:** profile configuration is local and
  request-controlled; STS account/principal evidence is authoritative.

## Rollback and recovery

Before execution, retire an unexecuted Change Set only through GUG-215 after
recording sanitized evidence; the normal path has no delete. After an ambiguous
identity/CAS result or uncertain execution, do not retry, claim success, or
create/execute a new plan. Existing read-only `verify` and CloudFormation events
may inspect only the original target; the required independent ledger
reconciliation capability is not implemented and must not be approximated with
ad hoc IAM. Retained state storage is never automatically emptied or deleted.
Decommission requires a separately approved change, an empty-state/evidence
inventory, KMS retention decision, and explicit rollback procedure.

The repository defines but does not provision or roll back host Python, SDK
wheels, Git, AWS CLI, or GitHub CLI. Before live activation, repository rollback
is an atomic reviewed revert of source, pins, executable policy, and docs. After
signing or deployment, host-tool changes or rebuilding are not rollback: revoke
the affected generation/version, preserve evidence, and use a separately
reviewed known-good immutable signed artifact or forward fix.

CloudFormation `ROLLBACK`/`DisableRollback=false` governs stack resources only.
The executor sets account-level S3 Public Access Block before Execute; retain
that control because stack rollback cannot undo it.

## Evidence classification

| Class | Status |
|---|---|
| Implemented | Repository declarations for Plan/Approval v2, identity proof, CAS authority, service-owned Apply effects, deterministic package/runtime lock, minimum policies, tests and documentation |
| Locally validated | Pending named offline gates on this branch |
| CI validated | Pending PR checks for the exact commit |
| Live validated | **NOT_OBSERVED**; signing, deployment, user-A/user-B proof, ledger transitions, PAB and execution were not performed |
| Blocked | `SIGNING_TRUST_ROOT_NOT_CONFIGURED`; separately reviewed exact signer version/contract digest and operational refreshed receipt handoff; exact signed/deployed `:1` services; real user A/B assignments and proof; independent ledger reconciliation capability; authorized Change Set/apply; live verification; platform-authority root plan/apply |
| Production | **NO-GO** |
