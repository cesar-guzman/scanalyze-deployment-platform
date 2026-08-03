# Platform-Authority Bootstrap Recovery

## Safety rules

- Stop dispatch before diagnosis.
- Verify the exact authority account and region through STS.
- Never re-run `apply` after a lost response.
- Never retry an ambiguous Plan anchor, Approval transition, or Apply claim.
- Never treat an ambiguous service response as success; the current package has
  no independent read-only ledger reconciliation endpoint.
- Never grant ad hoc DynamoDB/IAM access to manufacture that missing recovery
  path. Live activation stays blocked until it is separately implemented and
  reviewed, or the affected generation is retired under controlled authority.
- Never persist an Identity Center authorization code, PKCE verifier, token,
  context assertion, proof credentials, raw UserId, or provider response.
- Never create a replacement bucket/key or infer ownership from names.
- Never infer a trust-root table, item, generation, or state from an artifact,
  resource name, profile, or local digest.
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
| One exact unexecuted Change Set retained | Use the separately authorized GUG-215 version-pinned broker with two identity-enhanced independent users and qualified aliases; the normal `cancel` compatibility command is locally retired even when the original Plan exists | Reconstruct a Plan, grant a human direct delete/ledger write, re-enable normal `cancel`, or execute the Change Set |
| Change Set creation failed | Inspect sanitized status and obtain a separately reviewed GUG-215 retirement disposition | Invoke normal `cancel`, delete directly, or execute the template |
| Change Set IAM binding failure | Stop; verify the canonical stack ARN, exact `cloudformation:ChangeSetName`, request tags, and Plan/Apply separation offline | Add a Change Set ARN resource, broaden the name, or bypass the renderer |
| Change Set parameter/request metadata differs | Stop before PAB/Execute; require exact AuthorityAccountId, StateKey, retention 365, ROLLBACK, no nesting, `ImportExistingResources=false`, no `DeploymentMode`, empty capabilities/notifications, no RoleARN/parent/root and absent-or-empty rollback config | Trust template defaults, ignore a service role, or compare only ARN/template/resources |
| Plan v1, Approval v1, or mixed versions presented to active Apply | Quarantine as historical-only evidence and create no CloudFormation/S3 Control effect client | Enable a compatibility fallback, upgrade fields in place, or treat a digest as authentication |
| Plan v2 has no exact external anchor | Terminal stop. The independent exact-item read-only reconciliation capability is `NOT_IMPLEMENTED`; preserve evidence and use only separately authorized controlled generation retirement | Recreate the anchor from the local Plan, invoke a current mutating service to inspect, add ad hoc IAM/DynamoDB reads, or continue to approval/apply |
| Exact `PLAN_ANCHORED` version 1/attempt 0 observed | Verify the complete canonical Plan projection and wait for a separate independently attributable Approval transition | Approve directly, edit the item, or let Apply infer approval |
| Exact `APPROVED` version 2/attempt 0 observed through separately authorized evidence | Revalidate Plan/Approval, fixed user-A/user-B proof, freshness, assignments and generation; only exact Apply executor `:1` may attempt one CAS claim | Execute from the human role, reset version/attempt, or grant a human DynamoDB write |
| Plan/Approval/claim response is ambiguous | Terminal stop with no retry and no success claim; live activation requires a separately reviewed strongly consistent read-only reconciliation path, currently `NOT_IMPLEMENTED`, or controlled generation retirement | Invoke a mutating service to inspect, add ad hoc IAM/DynamoDB reads, assume failure/success, or create/execute a replacement |
| Exact `CLAIMED` version 3/attempt 1 observed through separately authorized evidence | Treat claim as consumed and inspect only the original Change Set through existing read-only CloudFormation verification | Reset to `APPROVED`, decrement attempt count, reuse Approval, or execute a second time |
| Identity grant is stale/replayed or came from a file/terminal | Stop, clear the material, and obtain a fresh operation-specific code+PKCE grant through a new pipe/socket after authorization | Reuse, persist, log, copy into a receipt, or pass Approval grant to Apply |
| Identity proof UserId/role/topology differs | Stop; fixed real user A owns Plan and distinct real user B owns separate Approval and Apply roles | Trust candidate `initiator_id`/principal-digest labels as live identity or remap users ad hoc |
| Package/source/SDK evidence differs | Stop activation; rebuild only from exact clean Git object bytes with closed env/config, no `refs/replace`, exact runtime lock, and no `AWS_DATA_PATH`/provider override | Build dirty/replaced bytes, trust caller Git config, change SDK/provider configuration, or use the unsigned digest as deployable proof |
| Signing trust root is not configured | Stop with `SIGNING_TRUST_ROOT_NOT_CONFIGURED`; the fixed Git contract pins no signer version, the CFN lock permits only `false`, and its Rule requires `true`, so Change Set creation is impossible | Supply parameters manually, edit the contract/template in place, or treat `Enforce` as activation evidence |
| Signed receipt is stale, locally redigested, or not provider-refreshed | Rebuild through the read-only verifier; require protected-main/required-check source review, exact Signer/S3 evidence, TTL no greater than 15 minutes, then refresh GitHub+Signer+S3 in the consumption flow | Trust the receipt digest alone, reuse parameters, extend expiry, or skip fresh provider comparison |
| Trust-root generation revoked, superseded, or rotated | Keep old records read/reconcile-only and require a new reviewed generation plus a new Plan v2 | Rebind an old item to the new generation or copy approval state |
| Change Set available, unapproved | Let it expire or obtain independent approval | Self-approve or edit receipt |
| Approval expired | Preserve the exact Change Set and use the separately authorized GUG-215 retirement process before creating a new plan | Extend timestamps, invoke normal `cancel`, or delete the stack |
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
export SCANALYZE_GUG274_SDK_RUNTIME_ROOT='<absolute-reviewed-sdk-runtime-root>'

env -u PYTHONPATH -u PYTHONHOME python3 -I -S \
  scripts/deployment/platform-authority-bootstrap.py preflight-recovery \
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
export SCANALYZE_GUG274_SDK_RUNTIME_ROOT='<absolute-reviewed-sdk-runtime-root>'

env -u PYTHONPATH -u PYTHONHOME python3 -I -S \
  scripts/deployment/platform-authority-bootstrap.py verify \
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

## GUG-274 trust-root reconciliation

GUG-274 changes the normal Plan/Approval recovery boundary. Local v2 artifacts
are candidates, not authority. The table is
`scanalyze-platform-authority-bootstrap-artifacts` with partition key
`trust_root_id` and sort key `authority_record_id`; both coordinates and
generation derive from immutable runtime binding and are never operator input.
The exact active transition/effect endpoints are
`scanalyze-platform-authority-bootstrap-plan-authority:1`,
`scanalyze-platform-authority-bootstrap-approval-authority:1`, and
`scanalyze-platform-authority-bootstrap-apply-executor:1`. Aliases,
unqualified functions, `$LATEST`, and any other version are invalid.

The corresponding execution roles are
`ScanalyzeGug274BootstrapPlanAuthority`,
`ScanalyzeGug274BootstrapApprovalAuthority`, and
`ScanalyzeGug274BootstrapApplyExecutor`; the proof roles are
`ScanalyzeGug274BootstrapPlanIdentityProof`,
`ScanalyzeGug274BootstrapApprovalIdentityProof`, and
`ScanalyzeGug274BootstrapApplyIdentityProof`. Do not substitute a role with a
similar name during recovery.

Do not interpret the DynamoDB table resource policy as a grant. It is deny-only:
all positive DynamoDB permissions live solely in the three service execution-role
identity policies, each constrained to its exact action/table/key boundary and
to the exact unqualified source-function ARN through
`lambda:SourceFunctionArn`. AWS supplies that condition key without the version
suffix; qualified `:1` invocation, Lambda permission, deployment/readback, and
runtime checks enforce the version separately. Recovery must preserve both
layers and must not add a positive table-policy Allow or a compensating human
grant.

The three services prove real Identity Store user A for Plan and different real
user B for both Approval and Apply. Approval and Apply still use distinct
permission sets, execution roles, deny-all proof roles, code-plus-PKCE grants,
and invocations. The grant must arrive through a non-persistent pipe/socket and
must never be recovered from a file. Candidate `initiator_id`, `approver_id`,
and principal-digest fields are anchored attribution assertions, not live
identity authority; interpret the ledger through the fixed UserId bindings and
identity-proof receipt digests.

Compare the entire external item, not only its ledger digest:

- trust-root contract and generation;
- authority account, partition, Region and canonical stack;
- full Change Set ARN, name, UUID and type;
- exact `AuthorityAccountId`, `StateKey`, and
  `NoncurrentVersionRetentionDays=365` parameters;
- `OnStackFailure=ROLLBACK`, `IncludeNestedStacks=false`,
  `ImportExistingResources=false`, empty capabilities/notifications, absent
  `RoleARN`/`DeploymentMode`/parent/root IDs, and
  absent-or-empty default rollback configuration;
- original template and resource-inventory digests;
- state bucket/key contract;
- Plan and Approval artifact digests and canonical projections;
- fixed identity topology, user-A/user-B proof receipt digests and time windows;
- attribution labels/principal digests, without treating them as UserId proof;
  and
- ledger state, version, attempt count and prior-transition digest.

The normal sequence is exact and monotonic:

```text
PLAN_ANCHORED version 1 / attempt 0
  -> APPROVED version 2 / attempt 0
  -> CLAIMED version 3 / attempt 1
```

No recovery command repairs, imports, edits, resets, or advances this record.
The current three-service package intentionally has no independent read-only
ledger reconciliation endpoint or human reconciliation role. Therefore an
ambiguous Plan anchor, Approval transition, or Apply claim is a terminal stop:
no retry, no success claim, no replacement execution, and no invocation of a
mutating endpoint for diagnosis. Do not add a temporary DynamoDB grant or alter
IAM ad hoc.

An independently reviewed, strongly consistent, exact-item read-only
reconciliation capability is a prerequisite for any future live activation and
is currently **NOT_IMPLEMENTED** and tracked as a P2 recovery follow-up. Until
it exists, the only safe disposition for an ambiguous live generation would be
separately authorized controlled
revocation/retirement while preserving all records. Even if later evidence
shows `APPROVED`, no automatic claim retry follows; if it shows `CLAIMED`, the
approval remains consumed and only the original Change Set may be inspected
through existing separately authorized read-only CloudFormation verification.

The Apply executor must complete user-B proof and the terminal CAS before it
constructs CloudFormation or S3 Control clients. After CAS it performs the
empty-shell/full-ARN/parameters/metadata/`Original`/freshness checks, PAB, the
same final checks again, and one bare-name Execute. Any post-claim uncertainty
also remains terminal and never resets `CLAIMED`.

Package recovery is likewise fail-closed. Rebuild only from the exact clean
reviewed commit into a new outside-repository owner-only directory. The builder
must use the closed Git environment/config, resolve Git by a reviewed absolute
binding rather than caller `PATH`, reject `refs/replace` and every tracked or
untracked working-tree change, and emit only the non-deployable
`unsigned_archive_code_sha256`. Require the embedded source/SDK runtime lock at
exact pins `boto3==1.42.57` and `botocore==1.42.97`, and reject `AWS_DATA_PATH`
or other provider overrides. Caller version flags must equal those pins. Do not
treat the unsigned manifest as a signed artifact.

Every normal-bootstrap, package-builder, or signed-artifact-verifier recovery
command uses `env -u PYTHONPATH -u PYTHONHOME python3 -I -S ...`. In normal
bootstrap, package-builder, and verifier recovery paths, each entry point opens
`tooling/platform_authority_source_only_import.py` as UTF-8 source and compiles
those bytes before repository modules become importable. Its finder compiles the
exact `.py` bytes for repository `tooling` modules directly and neither consumes
nor emits repository `.pyc`; repository bytecode writes remain disabled.

In normal bootstrap and verifier recovery paths,
`SCANALYZE_GUG274_SDK_RUNTIME_ROOT` must identify an absolute root outside the
repository and any local `.venv`; its direct `site-packages/` child is dedicated
to and contains only the fixed closure. The runtime root and every directory in
its POSIX ancestor chain must be owned by root or the effective user and must not
be group/world-writable; only a root-owned sticky directory in that chain may be
writable. Every site-tree entry must also have one of those owners and a safe
mode, with no symlinks or non-regular/non-directory entries and no sticky-root
exception. `-S` prevents automatic `site`, `.pth`,
and `sitecustomize` execution. The loader explicitly admits that candidate path
and authenticates the complete source-reviewed closure before import; the
environment path grants no authority, because source-pinned official wheel
identities and canonical installed-manifest hashes remain binding:
`boto3==1.42.57`, `botocore==1.42.97`, `s3transfer==0.16.1`,
`jmespath==1.1.0`, `python-dateutil==2.9.0.post0`, `urllib3==2.7.0`, and
`six==1.17.0`. Each wheel-owned package/stable-metadata projection must match
its source-pinned installed-manifest SHA-256 before every authoritative
file/size/digest and import origin is checked. Reject external `pycache_prefix`,
any preloaded closure module, symlink, unsafe/mismatched file, `.pyc`, or other
unrecorded import-tree extra; bytecode writes stay disabled. Raw
installation-specific `RECORD` bytes are neither pinned nor trusted. Git, AWS
CLI, and GitHub CLI resolution ignores caller `PATH` and uses only reviewed
absolute candidates. The resolved executable and every ancestor must be owned
by root or the effective user. The file must be regular/executable and
group/world non-writable; each ancestor must be a group/world non-writable
directory except for a root-owned sticky ancestor. Repeat that complete check
after reading the digest and require stable executable metadata. Non-root `gh`
also requires the reviewed SHA-256, but a matching digest never repairs an
unsafe path; Git and AWS CLI have no non-root digest exception. The currently
inspected Homebrew `gh` fails closed because `/opt/homebrew/Cellar` is mode
`0775` and group-writable. A missing or mismatched interpreter, wheel, or
executable is a host tooling stop, not permission to repair the repository,
package, or receipt in place.

The deployed ZIP excludes SDK wheels. Lambda `python3.12` supplies the
AWS-managed SDK; each function requires the template environment versions to
match the embedded lock and then checks the managed modules' `__version__`
values before provider construction. Operator-host closure authentication does
not apply inside Lambda. This AWS-managed boundary is not active
because current CFN activation is impossible. After future activation,
managed-runtime drift is a separate fail-closed stop that repository or
workstation rollback cannot reverse.

The implemented read-only verifier rebuilds the exact package, proves the
source commit is merged to protected `main` with all exact required checks
green, and reads the verifier identity, completed Signer job, exact versioned
unsigned source, and exact versioned signed destination from STS/Signer/S3. It
validates the signed ZIP and emits a closed receipt whose TTL is at most 15
minutes. The receipt digest is unkeyed integrity, not authority: the consuming
flow must refresh GitHub, Signer, and S3 and match every immutable receipt field
before using its CloudFormation parameter projection.

The fixed Git contract
`bootstrap/platform-authority-bootstrap-artifact-signing-trust-root.json` is
deliberately `NOT_CONFIGURED`, with no signer version and no activation
authorization. The verifier therefore stops with
`SIGNING_TRUST_ROOT_NOT_CONFIGURED`. The template independently permits only
`AuthoritySigningTrustRootConfigured=false` while its Rule requires `true`, so
no Change Set can be created. A separate reviewed commit must pin the exact
signer version ID/ARN and contract digest in both the contract and template
allowlists before unlocking. Never repair package bytes, runtime versions,
signer metadata, receipt fields, or provider configuration in place.

Rotation creates a new exact trust-root generation, clean-commit package,
immutable signer profile version, runtime lock, identity topology, and qualified
service set.
Revoke old invoke assignments and writer authority, verify that revocation
readback, and retain old items as immutable read/reconcile-only evidence. Never
copy `APPROVED` or `CLAIMED` into the new generation. A replacement attempt
starts with a new Plan v2 and absent item after separate review.

The read-only verifier/receipt/refresh implementation is repository evidence.
The repository currently contains no configured signer trust root, live
provider receipt, operational CloudFormation handoff, trust-root deployment,
Identity Center proof, transition, PAB write, or execution.
Consequently these steps describe the target failure and reconciliation model,
not authorization to query or mutate AWS. Live recovery requires separately
approved profiles/regions, exact resource/policy/signer/package/version and
user-A/user-B readback, the missing independent reconciliation capability, and
independent P0 review. Live evidence is **NOT_OBSERVED**, GUG-119 remains
blocking, and production remains **NO-GO**.

## Retained Change Set retirement (GUG-215)

The historical normal-bootstrap `cancel` mutation path is retired. Its
compatibility command always returns the stable sanitized
`NORMAL_CANCEL_RETIRED` diagnostic before constructing an AWS client, reading
the supplied Plan, making an AWS call or writing any ledger. No flag or
environment setting re-enables direct deletion. If the original private Plan
receipt is absent or ambiguous, do not reconstruct it from live metadata, the
repository template, a name, prior chat, or expected values.

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

## Normal cancel compatibility boundary

Do not use the normal bootstrap CLI to retire an unexecuted Change Set. The
retained `cancel` subcommand exists only so older operator automation fails
closed with a stable migration diagnostic. It performs zero AWS calls, zero
`DeleteChangeSet` calls and zero ledger writes regardless of whether the Plan
is present, valid or expired. GUG-215 is the sole retirement authority.

After GUG-215 has separately proved exact retirement and canonical recovery
preflight proves the live status is still `REVIEW_IN_PROGRESS`, a fresh
`ListStackResources` result is exactly empty, every `ListChangeSets` page is
empty, and the stack carries no service role, notifications or nesting, `plan`
may create a new `CREATE` Change Set from the current reviewed template. Any
other stack status, resource or active/ambiguous Change Set forces escalation;
the workflow never deletes the review stack as a recovery shortcut.

Every replacement Plan invalidates the prior authority record and the Apply
executor's immutable Change Set binding. The former direct-Apply policy model is
superseded: never add `cloudformation:ExecuteChangeSet` or account-PAB mutation
to the human Apply role, and never edit a deployed function environment or
policy in place to target a replacement. Retire/revoke the old generation under
separate authorization, then use a new reviewed generation, exact Plan policy,
exact freshly rendered Apply policy, clean-commit unsigned source package,
configured fixed signing contract, newly provider-refreshed signed-artifact
receipt, runtime binding, and absent ledger item. The full
ARN/UUID, parameters, request metadata, and `Original` template remain PEP
evidence and must be read twice before any future execution.

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

Before execution, retire an unexecuted Change Set only through the separately
reviewed GUG-215 broker, and retain the empty review stack shell. After the account S3
public-access block is enabled, retain it even if the stack fails. After stack
completion, do not roll back storage automatically; treat the verified backend
as durable control-plane infrastructure and use a reviewed forward fix. A
GUG-274 rollback revokes the affected trust-root generation and assignments
and retains the ledger for a future separately reviewed read-only
reconciliation capability, which is currently not implemented. It never
deletes or rewrites history, resets `CLAIMED`, grants direct human DynamoDB/IAM
reads or writes ad hoc, or re-enables Plan/Approval v1.

Before live activation, repository rollback is one reviewed atomic revert of
the GUG-274 source, SDK pins, executable policy, and documentation; it does not
install or downgrade host Python, wheels, Git, AWS CLI, or GitHub CLI. Host
toolchain rollback is a separate controlled workstation action. After an
artifact has been signed or a service deployed, do not rebuild under changed
host tooling and call it rollback: revoke the affected generation/version,
preserve evidence, and use a separately reviewed known-good immutable artifact
or forward fix under the normal signing and deployment controls.

Production remains **NO-GO**.
