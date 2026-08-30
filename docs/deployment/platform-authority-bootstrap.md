# Platform-Authority Bootstrap and Customer Onboarding

## Purpose

The Scanalyze platform authority is a dedicated control-plane AWS account. It
is neither a customer account nor a generic corporate shared-services account.
It stores only deployment control metadata and immutable release material:

- one GitHub OIDC provider;
- one exact `ScanalyzeOrchestrator-<deployment_id>` role per deployment;
- the deployment registry and live execution ledger;
- a versioned, KMS-encrypted release bucket.

It must never store customer documents, PII, Terraform state for a customer
deployment, processing queues, ECS workloads, Cognito tenants, or extracted
payloads.

## Identity planes

IAM Identity Center is the human bootstrap and recovery plane. A short-lived,
audited permission-set session establishes the authority backend and reviews the
first plan. GitHub OIDC is the machine runtime plane after bootstrap. Static
access keys, copied SSO credentials, long-lived IAM users, and a customer
account acting as the authority are forbidden.

The authority does not create or manage the organization's Identity Center
instance. The organization's identity team assigns three distinct, time-bound
Plan, Approval, and Apply permission sets in the authority account. The Plan
initiator assignment must not overlap either second-party assignment. The
normal two-person path may bind the same independently attributable second
operator to the separate Approval and Apply permission sets, but it never
collapses their policies or grants that operator Plan authority. None is trusted
by customer terminal roles during normal deployment execution.

The immutable identity topology names these people as real Identity Store user
A for Plan and a different real user B for both Approval and Apply. Each
operation still has a distinct permission set, service execution role, deny-all
proof role, and fresh authorization-code-plus-PKCE grant. The grant may enter
the CLI only through a non-persistent pipe/socket descriptor and is never
written to a file, receipt, log, or command output.

Candidate initiator/approver labels and principal digests are attribution
assertions only and are not cryptographically correlated with the live fixed
UserIds. The immutable user-A/user-B bindings and operation-specific proof
receipt digests, not those labels, authorize the service transitions. Stronger
correlation remains a P2 follow-up.

## Authenticated bootstrap artifacts (GUG-274 target state)

The normal bootstrap no longer treats local Plan and Approval hashes as
authority. Plan v1 and Approval v1 use unkeyed SHA-256 digests that detect
partial changes but cannot authenticate their author: an attacker can replace
both records, change the UUID-bearing Change Set ARN, and recompute both hashes.
The active target path therefore requires Plan v2 and Approval v2 plus one exact
matching service-owned DynamoDB CAS record. Active Apply rejects v1 and mixed
versions without fallback.

The trust root uses the fixed table
`scanalyze-platform-authority-bootstrap-artifacts`. Its item coordinate,
generation, and qualified service versions come from the immutable bootstrap
binding and reviewed deployment configuration. They are never accepted from a
Plan, Approval, CLI flag, environment variable, profile, or caller. Three
separate service authorities own exactly one transition each:

The key schema is exactly partition key `trust_root_id` plus sort key
`authority_record_id`; generation 1 fixes the partition value to the canonical
table ARN plus `#generation/1`.

| Service authority | Exact transition | Human boundary |
|---|---|---|
| Plan anchor writer | absent -> `PLAN_ANCHORED`, ledger `version` 1, attempt 0 | For ledger effects, the Plan human is invoke-only and cannot approve, claim, execute, retire, or write DynamoDB directly |
| Approval writer | `PLAN_ANCHORED` -> `APPROVED`, ledger `version` 2, attempt 0 | Distinct approver is invoke-only and cannot replace the Plan or write DynamoDB directly |
| Apply executor | `APPROVED` -> `CLAIMED`, ledger `version` 3, attempt 1, then exact PAB/readback/execute effects | The Apply human is read-only plus exact invocation; only the executor owns CloudFormation/S3 Control mutation |

Every writer is an exact published service version with its own execution role.
The only accepted function versions are
`scanalyze-platform-authority-bootstrap-plan-authority:1`,
`scanalyze-platform-authority-bootstrap-approval-authority:1`, and
`scanalyze-platform-authority-bootstrap-apply-executor:1`. The DynamoDB table
resource policy is deny-only and grants no positive access. Each positive
DynamoDB Allow exists only in the corresponding service execution-role identity
policy, is limited to that role's exact action/table/key boundary, and requires
`lambda:SourceFunctionArn` to equal the exact unqualified source-function ARN.
AWS supplies that key without a version suffix; qualified invocation, Lambda
permission, deployment/readback, and runtime controls separately enforce the
generation-1 `:1` binding. The deny-only table policy blocks foreign principals,
foreign trust-root keys, insecure transport, and unsupported operations. The
exact execution roles are `ScanalyzeGug274BootstrapPlanAuthority`,
`ScanalyzeGug274BootstrapApprovalAuthority`, and
`ScanalyzeGug274BootstrapApplyExecutor`; identity proof uses the separate
deny-all roles `ScanalyzeGug274BootstrapPlanIdentityProof`,
`ScanalyzeGug274BootstrapApprovalIdentityProof`, and
`ScanalyzeGug274BootstrapApplyIdentityProof`.
User A and user B must be distinct; user B's Approval and Apply roles remain
separate even though they bind the same second person. Direct human DynamoDB,
CloudFormation-execution, account-PAB, KMS, or IAM writes; unqualified
functions; aliases; `$LATEST`; shared service roles; and caller-selected ledger
coordinates are forbidden.

The external record binds the complete authority projection: contract/domain,
authority account, partition, Region, canonical stack, full Change Set ARN,
name, UUID and type, original template digest, planned resource inventory,
the exact parameters `AuthorityAccountId`, `StateKey`, and
`NoncurrentVersionRetentionDays=365`, plus `OnStackFailure=ROLLBACK`,
`IncludeNestedStacks=false`, `ImportExistingResources=false`, empty
capabilities/notifications, absent
`RoleARN`/`DeploymentMode`/parent/root IDs, and absent-or-empty default rollback
configuration,
state bucket/key, initiator and approver identities/principal digests, validity
windows, immutable Identity Center topology and proof-receipt digests, both
artifact digests, trust-root generation, ledger state/`version`, and attempt
count. Approval authenticates the existing Plan anchor rather than merely
accepting a caller-provided Plan digest.

All provider-independent JSON, schema, digest, binding, identity, time, and
trust-root checks precede provider authority. The exact service proves the live
operation-specific user and reads the exact item. Only unambiguous
`APPROVED -> CLAIMED` CAS success permits the Apply executor to construct
CloudFormation and S3 Control clients. It then validates the empty shell, full
ARN/UUID, exact parameters/metadata and `Original` template, rechecks freshness,
applies all-true account PAB, repeats the complete readback/freshness sequence,
and issues one bare-name `ExecuteChangeSet`. An unavailable, stale, foreign,
malformed, already claimed, or ambiguous record stops before effect-client
construction.

The service ZIP is a closed deterministic but unsigned and non-deployable
artifact built only from an exact clean commit. Its closed Git subprocess
resolves a reviewed absolute Git executable rather than caller `PATH`, rejects
`refs/replace`, caller Git config/environment, and any tracked or untracked
working-tree change. The manifest records `unsigned_archive_code_sha256`,
never a deployable signed digest, and embeds a source-commit plus exact runtime
pins `boto3==1.42.57` and `botocore==1.42.97`. Caller version flags must equal
those source-reviewed constants. `AWS_DATA_PATH` and other provider overrides
are rejected.

The normal bootstrap, package-builder, and signed-artifact-verifier CLIs all
require `env -u PYTHONPATH -u PYTHONHOME python3 -I -S ...`. In the normal
bootstrap, package builder, and verifier, each entry point first reads
`tooling/platform_authority_source_only_import.py` as UTF-8 source and compiles
those bytes before making repository modules importable. The installed finder
compiles exact repository `.py` bytes for `tooling` modules and neither consumes
nor writes repository `.pyc`; repository bytecode writes stay disabled.

In the normal bootstrap and verifier,
`SCANALYZE_GUG274_SDK_RUNTIME_ROOT` must identify an
absolute runtime outside the repository and any repository-local `.venv`, with
a direct `site-packages/` dedicated to and containing only the fixed closure.
The runtime root and every directory in its POSIX ancestor chain must be owned
by root or the effective user and group/world non-writable; only a root-owned
sticky directory in that chain may be writable. Every entry in the
`site-packages/` tree must also be owned by root or the effective user and
group/world non-writable, and symlinks or non-regular/non-directory entries are
rejected without a sticky-directory exception.
`-S` prevents automatic `site`, `.pth`, and `sitecustomize` execution before the
gate. The loader then admits the path explicitly and authenticates it before
importing SDK code. The environment path selects candidate bytes but supplies
no authority; source-reviewed official wheel identities and canonical
installed-manifest hashes authenticate the closure
`boto3==1.42.57`, `botocore==1.42.97`, `s3transfer==0.16.1`,
`jmespath==1.1.0`, `python-dateutil==2.9.0.post0`, `urllib3==2.7.0`, and
`six==1.17.0`. Each source-pinned installed-manifest digest covers the
wheel-owned package and stable metadata rows before every authoritative
file/size/digest and import origin is verified. External `pycache_prefix`,
preloaded modules, symlinks, unsafe/mismatched files, and unrecorded extras such as `.pyc` are denied;
bytecode writes remain disabled. Raw installation-specific `RECORD` bytes are
neither pinned nor authority.
Git, AWS CLI, and GitHub CLI resolution ignores caller `PATH` and invokes only
reviewed absolute candidates. The resolved file and every ancestor must be
owned by root or the effective user. The file must be regular/executable and
group/world non-writable; every ancestor must be a group/world non-writable
directory except for a root-owned sticky ancestor. This complete path check is
repeated after hashing, and stable executable metadata must remain unchanged.
A non-root binary also requires an exact reviewed digest, which cannot override
an unsafe path. The only digest exception is the source-pinned GitHub CLI
digest; Git and AWS CLI have no non-root digest exception. The currently
inspected Homebrew `gh` fails closed because `/opt/homebrew/Cellar` is mode
`0775` and group-writable.

These controls authenticate a repository-to-host runtime boundary; they do not
provision the host interpreter, wheels, or executables. An unavailable or
mismatched host tool is a fail-closed stop. Changing host tooling is a separate
controlled action; changing a source pin/binding requires a reviewed commit and
new package/signature/readback evidence.

The service ZIP does not vendor SDK wheels. The template fixes Lambda
`python3.12` and supplies the same expected versions to every function. Each
function first matches them to the embedded lock and then checks the
AWS-managed SDK `__version__` values before provider construction. The
operator-host closure authentication does not apply inside Lambda. That
AWS-managed boundary is not active while the signer trust root/CFN lock makes
Change Set creation impossible. After future activation, managed-runtime drift
fails closed and cannot be rolled back by reverting the repository or changing
the operator host.

A separate authorized lane must use the fixed signer profile and immutable
profile version. The implemented read-only verifier rebuilds the exact package,
proves the source commit is merged to protected `main` with all exact required
checks green, and reads the exact STS, Signer-job, and versioned S3 source and
destination evidence. It emits a closed receipt with a maximum 15-minute TTL
and derives `SignedAuthorityArtifactCodeSha256`,
`AuthoritySigningReceiptDigest`,
`AuthoritySigningTrustRootContractDigest`, and the exact S3 tuple.

The receipt digest is integrity only, not authentication by itself. The same
flow must refresh GitHub, Signer, and S3 and match the full immutable receipt
immediately before any CloudFormation parameter is used. Raw parameters, a
locally redigested receipt, the unsigned manifest, or the template are not
evidence.

The fixed contract
`bootstrap/platform-authority-bootstrap-artifact-signing-trust-root.json` is
deliberately `NOT_CONFIGURED`, so the verifier returns
`SIGNING_TRUST_ROOT_NOT_CONFIGURED`. CloudFormation also accepts only lock value
`false` while a Rule requires `true`, making Change Set creation impossible. A
separate reviewed commit must pin the exact signer profile version ID/ARN and
contract digest in the Git contract and closed template allowlists before
unlocking. `UntrustedArtifactOnDeployment=Enforce` is declared but not live
evidence; publication readiness and actual `:1` versions are not established.

This is currently a repository target, not a deployed capability. Live use
requires separate deployment and readback of the exact table, deny-only resource
policy, execution-role identity policies, published service versions, roles,
runtime lock, signed object/signer policy,
logging/retention controls, and exact user-A/user-B assignments and proof,
plus a separately reviewed configured signing trust root and fresh operational
receipt handoff, followed by independent P0 review. Strongly consistent read-only reconciliation for
ambiguous CAS results is also required, tracked as a P2 recovery follow-up, and
not implemented by the current three-service package. GUG-119 remains a
governance dependency and production remains **NO-GO**. See
[ADR-048](../../ADR/ADR-048-platform-authority-bootstrap-artifact-authentication.md)
and the [GUG-274 threat-model delta](../security/gug-274-platform-authority-artifact-authentication-threat-model-delta.md).

The only documented temporary departure for an initial single-founder condition
is GUG-209's bounded founder exception. It does not change normal independent
approval, and is hard-bound to authority account `042360977644`, `us-east-1`,
`non-production`, one `CREATE` Change Set, and one intended future durable-PEP
attempt. Its receipt explicitly declares that independent approval is absent;
it is neither self-approval nor BreakGlass. GUG-209 is **OFFLINE-ONLY — LIVE
EXECUTION BLOCKED**: AWS-side `aws:CurrentTime` deny conditions and cleanup
readback are policy-design requirements, not attached founder authority. No
live Apply, Terraform apply, Scanalyze deployment, or production action is
authorized by GUG-209.

## Required onboarding record

Each new client supplies an independently approved record containing:

| Field | Authority |
|---|---|
| `customer_id` | Scanalyze customer registry; canonical `cust_` ULID |
| `deployment_id` | Scanalyze deployment registry; canonical `dep_` ULID |
| destination account and region | verified STS and account-vending evidence |
| environment | `sandbox`, `dev`, or `staging` for GUG-125 |
| repository owner/repository numeric IDs | fresh GitHub API evidence; enforced as immutable OIDC trust claims |
| GitHub OIDC subject | exact customized immutable-ID subject derived from fresh GitHub evidence; bound to the deployment Environment, `nonprod-release.yml` on protected `main`, and `workflow_dispatch`; never legacy or wildcard |
| release bucket | globally unique authority-owned name |
| backend binding | independently bootstrapped authority state bucket/key/KMS |

Request payloads, profile names, account aliases, repository names, environment
names, customer slugs, and the last digits of an account never establish
authority.

## Bootstrap sequence

1. Allocate or formally designate a third AWS account for Scanalyze platform
   authority. Verify that it is different from every destination account.
2. Follow the dedicated GUG-206
   [`platform-authority-account-bootstrap.md`](platform-authority-account-bootstrap.md)
   procedure. Through IAM Identity Center, obtain a short-lived plan session
   whose scope is limited to Change Set creation/readback and exact Plan-service
   invocation. Normal cancellation is retired; GUG-215 is the only retirement
   path.
3. Create and review the exact CloudFormation Change Set and Plan v2. Through
   the exact version-pinned Plan service, create the fixed `PLAN_ANCHORED`
   record. A different attributable SSO principal invokes the separate Approval
   service, which may transition only that unchanged anchor to `APPROVED`.
   Apply must authenticate Plan v2 and Approval v2 against the same record and
   claim it once as `CLAIMED`; the service-owned Apply executor, not the human
   session, then owns the exact PAB/readback/execute effects. Each of Plan,
   Approval, and Apply supplies a fresh code-plus-PKCE grant through a
   non-persistent descriptor. This step
   remains blocked until the GUG-274 trust root is deployed and read back under
   separate authorization. Record only sanitized statuses/digests; never store
   backend files, plans, approvals, ledger records, credentials, state, or AWS
   responses in Git, Linear, or NotebookLM.
4. Render the root inputs from the approved onboarding records. The root and
   module reject missing, malformed, production, duplicated, wildcard, or
   authority-equals-destination bindings.
5. Produce and review a saved Terraform plan. Confirm the exact account guard,
   resources, KMS key, two protected DynamoDB tables, release bucket, OIDC
   provider, permissions boundary, one role per deployment, and runtime decrypt
   access limited to the exact authority KMS key.
6. Only after explicit non-production authorization, execute that exact saved
   plan with the short-lived Identity Center session. Capture sanitized digests
   and resource counts, not identifiers or payloads.
7. Run the customer account-vending flow separately in each destination. It
   creates customer-owned terminal roles, state/evidence backends, and
   `ACCOUNT_READY`; the platform-authority root does not.
8. Configure one protected GitHub Environment per deployment with independent
   review, the exact OIDC subject recorded in the authority contract, immutable
   `repository_owner_id` and `repository_id` trust conditions, and an explicit
   3,600-second role-duration request. Only the customized immutable-ID subject
   derived from the reviewed GitHub Environment evidence is accepted; legacy
   subjects are rejected. IAM role configuration has a
   one-hour minimum ceiling; relying on its default would issue a one-hour
   session and is not the accepted GUG-123 contract.
9. Exercise GUG-125 sequentially: deployment A plan/apply/health, idempotent
   no-change rerun, deployment B plan/apply/health, then negative cross-customer
   and cross-deployment attempts.
10. Reconcile and clean synthetic customer resources under their separately
    authorized destroy roles. The platform authority is retained unless a
    separately reviewed decommission is approved.

## Minimum human permission boundary

The state bootstrap uses three distinct permission sets rendered from
`policies/iam/platform-authority-bootstrap-plan-role.json`,
`policies/iam/platform-authority-bootstrap-approval-role.json`, and
`policies/iam/platform-authority-bootstrap-apply-role.json`. They are assigned
only to the dedicated authority account. The Plan initiator does not overlap
the independent approver/apply operator; Approval and Apply remain separate
permission boundaries even when the same second operator holds both. The Plan
role cannot execute. The Approval role can invoke only the exact approval
authority and cannot call CloudFormation. The Apply role is read-only plus
invocation of `scanalyze-platform-authority-bootstrap-apply-executor:1`; it
cannot create, execute, or retire a Change Set, mutate account PAB, or delete
the stack. Its renderer first validates the exact unexpired Plan/account/Region/
destination binding, fixes that qualified `:1` ARN, emits bounded verification
reads and explicit direct-effect denies, and denies every other non-read/
non-broker action. The executor's immutable runtime binding fixes the exact
Change Set name and service-side effect authority. The later Terraform apply permission is derived
separately from the reviewed saved plan and must be limited to:

- the exact platform-authority state bucket, state key, and KMS key;
- `ScanalyzePlatformAuthority*` policies and
  `ScanalyzeOrchestrator-<deployment_id>` roles;
- the single GitHub OIDC provider;
- the two canonical DynamoDB tables;
- the exact configured release bucket and authority KMS alias;
- read-only identity and tagging APIs required by Terraform.

Creation APIs that cannot be resource-scoped remain constrained by the exact
authority account, region, permission boundary, required request tags, and an
explicit deny for IAM users/access keys, `iam:PassRole`, Organizations, customer
workloads, and production. The final permission set must be generated from and
reviewed against the provider plan; a generic administrator policy is not an
acceptable bootstrap shortcut.

GUG-274 adds three service-side authorities without granting any human
permission set a DynamoDB write. Plan, Approval, and Apply humans may invoke
only the exact qualified service version for their role. The Plan writer can
create only the fixed anchor; the Approval writer can perform only the exact
approval transition; the Apply executor consumes one exact approval and then
owns the exact PAB/readback/execute effects. It cannot create Plan/Approval
authority or retire a Change Set. GUG-215 remains the sole `DeleteChangeSet`
path.

## Fail-closed stops

Stop before any AWS mutation when the authority profile/account is absent,
identity differs from the approved account, the backend is not independently
bound, any destination equals the authority, a customer/deployment binding is
ambiguous, a GitHub subject contains a wildcard, repository numeric claims do
not match, the plan is not an exact saved binary, or independent approval is
missing.

For the normal GUG-274 path, also stop when either artifact is v1 or unknown;
when schemas, canonical digests, domain separators, full ARN/name/UUID,
parameters/request metadata, template/resource inventory, identity proof, time,
state, trust-root generation or ledger coordinate do not match; when user A and
user B are not distinct; when a grant did not arrive through a pipe/socket; or
when the external item is missing, stale, superseded, malformed, unavailable,
already claimed or ambiguous. A fully rewritten and redigested pair is
untrusted unless it matches the exact external anchor and approval transition.
A conditional-write ambiguity permits no effect client, retry, or success
claim. Because the independent strongly consistent reconciliation endpoint is
not implemented, activation remains blocked; do not add ad hoc IAM reads.

Also stop when the source tree is dirty, commit bytes drift, the deterministic
package/manifest/runtime lock differs, untracked content exists, Python is not
isolated, repository `tooling` was not loaded through the source-only importer,
the operational SDK is inside the repository/`.venv`, the runtime root or an
ancestor/site entry has an untrusted owner or unsafe group/world-write mode,
any closure module was preloaded, a source-pinned installed manifest or
authoritative file differs, an external `pycache_prefix` is set, an import tree
contains a symlink, SDK `.pyc`, or other extra, caller SDK flags differ from
`1.42.57`/`1.42.97`, a reviewed
Git/AWS/GitHub executable cannot be resolved independently of caller `PATH`, its
file/ancestor ownership or mode is unsafe, or its metadata changes while being
digested, a provider override is unexpected, the signer profile version or
signed S3 object version is not exact, code-signing enforcement is absent, or any
published function is not the actual version `:1`.

For the sole GUG-209 founder exception, stop unless its separate offline
exception record format models the exact authority account, Region,
non-production environment, risk acceptance, hashed authenticated subject,
prior normal-Plan session quarantine, exact fresh Change Set, temporal
Plan/Apply separation, and a future controlled durable CAS ledger. Local
JSON/digest records are not durable authorization and cannot establish
exactly-once. Any expired/foreign/malformed record, missing AWS-side deny
retention, absent cleanup readback, absent trusted identity/event evidence, or
absent immediate Change Set/template/resource readback is a fail-closed stop;
it does not become a normal approval.

Before live activation, rollback is a reviewed repository revert that keeps
GUG-206 blocked; it does not downgrade or install host tooling. After signing
or deployment, an out-of-band host change or rebuild is not rollback. Revoke
the affected generation/version, preserve receipts and ledger evidence, and
select a separately reviewed known-good immutable signed artifact or forward
fix through the same controls.

CloudFormation `ROLLBACK`/`DisableRollback=false` applies only to stack
resources. Account-level S3 Public Access Block is written before Execute and
is not undone by stack rollback; retain it during containment and recovery.

## Evidence classification

Repository declarations and synthetic tests are **Implemented** and **Locally
validated** only after their named gates pass. CI, reviewed merge, main
verification, authority bootstrap, two-client isolation, cleanup, and live AWS
validation remain separate evidence classes. The GUG-274 table, services,
signed package, verified Signer receipt handoff, assignments, Identity Center proof, anchors, approval
transitions, claims, PAB write, and execution are **NOT_OBSERVED** live. The
read-only verifier is implemented, but the signer trust root is
**SIGNING_TRUST_ROOT_NOT_CONFIGURED**, making Change Set creation impossible. The
required independent strongly consistent reconciliation path is
**NOT_IMPLEMENTED**. Independent P0 review and GUG-119 remain blocking.
Production remains **NO-GO**.
