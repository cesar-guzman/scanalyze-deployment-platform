# GUG-274 Threat-Model Delta: Platform-Authority Artifact Authentication

## Document control

| Field | Value |
|---|---|
| Owner | Platform Engineering / Security |
| Audience | Security reviewers, platform engineers, identity administrators, and bootstrap operators |
| Status | TARGET STATE pending reviewed repository implementation and live activation |
| Scope | Normal GUG-206 Plan v2 / Approval v2 authentication, live Identity Center proof, one-shot CAS, and service-owned Apply effects |
| Exclusions | GUG-209 founder exception, GUG-215 retirement, GUG-273 topology binding, AWS deployment, and production |
| Baseline | `2bc194c49a3cba35dd8a05b415af785e76704184` |
| Last verified | 2026-08-02, repository inspection only |
| Review path | Independent P0 security/architecture review; GUG-119 remains blocking |
| Production | **NO-GO** |

## Security objective

The normal bootstrap must reject a fully rewritten, internally consistent and
redigested Plan/Approval pair before any Apply effect. Local SHA-256 digests
remain integrity checks; a fixed service-owned DynamoDB CAS record is the
external authority for artifact origin, independently proven Identity Center
users, and one-shot consumption. Only the exact Apply executor may construct
CloudFormation/S3 Control clients and perform the approved effects after the
terminal CAS succeeds.

## Assets and trust boundaries

Protected assets are:

- the exact Plan v2 and Approval v2 canonical projections;
- the full Change Set ARN, name, UUID, type, original template digest, and
  planned resource inventory;
- the exact parameters `AuthorityAccountId`, `StateKey`, and
  `NoncurrentVersionRetentionDays=365`;
- the exact `OnStackFailure=ROLLBACK`, `IncludeNestedStacks=false`, empty
  capabilities/notifications, `ImportExistingResources=false`, absent
  `RoleARN`/`DeploymentMode`/parent/root metadata, and
  absent-or-empty default rollback configuration;
- the authority account, partition, Region, canonical stack, state bucket/key,
  and trust-root generation;
- the candidate initiator/approver attribution labels and principal digests,
  which are anchored assertions but not live identity authority;
- the fixed Identity Center application/instance/store/redirect topology, real
  user A for Plan, different real user B for Approval and Apply, and the three
  operation-specific proof receipts;
- the DynamoDB ledger item, state, `version`, attempt count, and digest; and
- the deterministic unsigned service package, source commit, SDK runtime lock,
  source-pinned official-wheel and canonical installed-manifest closure for
  `boto3`/`botocore`/`s3transfer`/`jmespath`/`python-dateutil`/`urllib3`/`six`,
  fixed Git signing-trust-root contract, reviewed absolute Git/AWS/GitHub CLI bindings,
  merged-main/required-check source review, verified Signer/S3 receipt, exact
  signer profile version, signed object version, signed Lambda code digest,
  15-minute TTL, and refresh boundary; and
- the exclusive right of the Apply executor to create effect clients after one
  unambiguous claim.

Trust boundaries are:

1. Untrusted local JSON enters strict parsing and closed-schema validation.
2. A one-shot authorization code and PKCE verifier enter only through a
   non-persistent pipe/socket and are cleared after exchange.
3. Pure policy code derives canonical projections and the fixed ledger
   coordinate from the immutable bootstrap binding.
4. Version-pinned Plan and Approval services prove their exact users and write
   separate CAS transitions. Positive DynamoDB access exists only in each
   service execution-role identity policy and is conditioned on the exact
   unqualified source-function ARN through `lambda:SourceFunctionArn`; the table
   resource policy is deny-only. The qualified `:1` binding is enforced by the
   separate invocation, Lambda-permission, deployment/readback, and runtime
   boundaries because AWS supplies that condition key without a version suffix.
5. The Apply executor proves user B, authenticates the complete record, and
   performs the terminal CAS.
6. CloudFormation and S3 Control effect clients remain unavailable until that
   CAS is unambiguous.
7. A deterministic clean-commit package remains unsigned and non-deployable.
   All three GUG-274 CLIs require `python3 -I -S` without `PYTHONPATH` or
   `PYTHONHOME`, preventing automatic `site`, `.pth`, or `sitecustomize`
   execution. Each entry point loads
   `tooling/platform_authority_source_only_import.py` from UTF-8 source before
   repository import; its finder compiles exact repository `.py` bytes for
   `tooling` modules without consuming or emitting repository `.pyc`.
   Before host SDK import, normal/verifier take
   `SCANALYZE_GUG274_SDK_RUNTIME_ROOT`; it must be an absolute external root
   whose direct `site-packages/` contains only the fixed closure. The path is a
   candidate locator, not authority: source-pinned wheel identities and
   canonical installed-manifest hashes authenticate it before import; preloads,
   symlinks, SDK `.pyc`, mismatched or extra import-tree files are rejected. The
   runtime root and its POSIX ancestor chain must be owned by root/effective user
   and group/world non-writable, except for a root-owned sticky directory in the
   ancestor chain. Every `site-packages/` entry must have a trusted owner and
   safe mode; symlinks and non-regular/non-directory entries are rejected with
   no sticky-directory exception.
   Git/AWS/GitHub CLI resolution ignores caller `PATH` and uses reviewed
   absolute bindings. The executable and every ancestor require ownership by
   root or the effective user and group/world-safe modes, with a root-owned sticky exception
   only for ancestors; the full path check repeats after the digest and stable
   executable metadata must match. A reviewed digest cannot rescue an unsafe
   path. The currently inspected Homebrew `gh` therefore fails closed because
   `/opt/homebrew/Cellar` is mode `0775`.
   The ZIP excludes SDK wheels; Lambda `python3.12` supplies AWS-managed
   modules that are checked only through the embedded lock and exact
   `__version__` values before provider construction. This Lambda boundary is
   separate and currently inactive.
   The implemented read-only verifier binds merged protected `main`, required
   checks, the exact Signer job, and exact versioned S3 source/destination bytes
   into a short-lived receipt, then requires a same-flow provider refresh before
   any CloudFormation parameter is consumed.
8. The fixed Git signing contract and CloudFormation Rule remain an independent
   activation boundary. Both deliberately prevent Change Set creation while the
   signer version trust root is not configured.

The local filesystem, caller `PATH`, CLI arguments, environment variables,
profile names, host-installed modules/executables, Git, Linear, NotebookLM, CI
logs, synthetic fixtures, a package manifest, and an unsigned ZIP are not live
trust roots. The repository reviews exact runtime bindings but does not install
or mutate host tooling. The reviewed immutable deployment binding resolves only
the table
`scanalyze-platform-authority-bootstrap-artifacts` and the published service
versions `scanalyze-platform-authority-bootstrap-plan-authority:1`,
`scanalyze-platform-authority-bootstrap-approval-authority:1`, and
`scanalyze-platform-authority-bootstrap-apply-executor:1`. No request can replace
those coordinates or select an alias, an unqualified function, or `$LATEST`.
The table key is exactly partition key `trust_root_id` and sort key
`authority_record_id`.

## Actors and authority separation

| Actor | Allowed GUG-274 authority | Explicitly forbidden |
|---|---|---|
| Real user A / Plan human | Use the Plan permission set, create/review the metadata-only Change Set, and invoke exact Plan service `:1` with a fresh Plan grant | Hold either user-B role, approve, claim, direct-write the ledger, execute, or retire |
| Plan anchor service | Prove user A and create exact `PLAN_ANCHORED` version 1/attempt 0 | Update an item, approve, claim, or perform Apply effects |
| Real user B / approver | Use the distinct Approval permission set and invoke exact Approval service `:1` with a fresh Approval grant | Replace Plan, impersonate user A, claim through the Approval role, direct-write, execute, or retire |
| Approval service | Prove user B and CAS `PLAN_ANCHORED -> APPROVED`, preserving the Plan anchor | Create an item, alter Plan authority, claim, or perform Apply effects |
| Real user B / Apply verifier | Use the separate read-only/invoke-only Apply permission set and fresh Apply grant | Direct CloudFormation/S3/KMS/IAM/ledger mutation, mint Plan/Approval authority, or retire |
| Apply executor | Prove user B, CAS `APPROVED -> CLAIMED`, then construct effect clients and perform the exact PAB/readback/execute sequence | Reset/reuse a claim, create/approve evidence, create/delete a Change Set, delete a stack, or retire |
| GUG-215 broker | Separately authorized retained Change Set retirement only | Act as normal Apply or authenticate GUG-274 artifacts |

User A and user B must be different immutable Identity Store users. Approval
and Apply are separate roles and grants held by the same user B; this preserves
the normal two-person workflow without collapsing authority boundaries. Any
user-A overlap, cross-role proof, direct human effect, or non-`:1` invocation is
a failed control, not an exception.

The exact execution roles are `ScanalyzeGug274BootstrapPlanAuthority`,
`ScanalyzeGug274BootstrapApprovalAuthority`, and
`ScanalyzeGug274BootstrapApplyExecutor`; their deny-all proof roles are
`ScanalyzeGug274BootstrapPlanIdentityProof`,
`ScanalyzeGug274BootstrapApprovalIdentityProof`, and
`ScanalyzeGug274BootstrapApplyIdentityProof`. The human Apply-policy renderer
accepts the exact fresh bound Plan and emits only the qualified executor `:1`,
bounded verification reads, explicit effect denies, and a deny for every other
non-read/non-broker action.

The artifact fields `initiator_id`, `initiator_principal_digest`, `approver_id`,
and `approver_principal_digest` are not cryptographically correlated with the
live UserIds. They remain useful anchored attribution assertions, but the
authority decision must use fixed UserId bindings and identity-proof receipt
digests. Stronger correlation is a P2 follow-up, not a substitute for the live
proof boundary.

## State-machine invariant

```text
absent
  -> PLAN_ANCHORED  version=1 attempt_count=0
  -> APPROVED       version=2 attempt_count=0
  -> CLAIMED        version=3 attempt_count=1
```

Every arrow is conditional on the exact previous state, version, attempt count,
ledger digest, artifact projection, and trust-root generation. There is no
reverse transition, skip, reset, second claim, or active v1 import.

## Threats and controls

| Threat | Control | Fail-closed result |
|---|---|---|
| Rewrite both artifacts and recompute both hashes | Exact external Plan and Approval projections plus CAS state | Authentication denial; no Apply effect client |
| Same name, different valid UUID/full ARN | Full ARN, canonical name, UUID, account, partition, Region, and stack are anchored | Binding mismatch before claim |
| Substitute parameters or exploit a template default | Exact three-parameter projection, including retention `365`, is anchored and read twice | Parameter mismatch before effect/execute |
| Add a service role, capability, notification, nesting, import-existing behavior, `DeploymentMode`, rollback, parent/root, or alternate failure behavior | Canonical metadata requires `ROLLBACK`, no nesting, `ImportExistingResources=false`, empty capabilities/notifications, no role/deployment mode/parent/root, and absent-or-empty rollback config | Metadata mismatch before effect/execute |
| Change template or resource inventory and redigest | Original template and canonical resource-inventory digests are anchored | Artifact mismatch before claim |
| Splice Approval from another Plan | Approval transition binds the existing Plan anchor and both artifact digests | Approval/Plan binding mismatch |
| Use Plan v1, Approval v1, or a mixed pair | Active path accepts v2/v2 only | Downgrade rejected before provider access |
| Supply another table, key, Region, generation, or service alias | Coordinate and qualified versions derive from reviewed immutable binding | Request authority rejected |
| Treat the table resource policy as a positive grant or add DynamoDB access outside the three service-role identity policies | The table resource policy contains only Deny statements. The sole positive DynamoDB Allow for each service is in that execution role's identity policy, constrained to its exact action/table/key and exact unqualified `lambda:SourceFunctionArn`; separate controls enforce qualified `:1` | IAM, resource-policy, deployment, or runtime denial |
| Plan writer mints Approval | Separate execution-role identity policies, deny-only table policy, versions, and CAS transition ownership | IAM/resource-policy or transition denial |
| Approver replaces Plan | Approval writer cannot create and transition requires unchanged Plan projection/digest | Conditional failure |
| Apply human performs PAB or Execute directly | Human Apply policy is read-only/invoke-only; only the service role owns effects | IAM denial and no alternate execution route |
| Apply executor writes Plan/Approval authority | Its identity policy has only the exact claim read/update grant, with source-function/table/key conditions, plus post-CAS effects; the deny-only table policy supplies no alternate Allow | IAM/resource-policy or transition denial |
| Human writes ledger directly | Human roles have no DynamoDB write authority, the table policy grants no access, and its explicit Denies reject foreign principals | DynamoDB denial |
| User A self-approves or receives a user-B role | Immutable distinct Identity Store users and operation-specific proof-role trust | Identity proof/assignment failure |
| Approval grant is replayed as Apply or for another role | Fresh code-plus-PKCE grant and operation-specific execution/proof roles | Code exchange or STS proof denial |
| Code or PKCE verifier arrives via file/terminal or is persisted | CLI accepts only pipe/socket, consumes once, clears memory, and returns no secret | Local denial before service invocation |
| Replay an old but structurally valid pair | Exact generation, nonce, freshness, state, version, and one attempt | Stale/superseded/claimed denial |
| Reuse a consumed approval | `CLAIMED` version 3/attempt 1 is terminal | No second claim or execution |
| Race two Apply requests | Conditional `APPROVED` version 2/attempt 0 comparison | At most one executor reaches `CLAIMED` |
| Effect client is created before claim | Effects factory exists behind terminal CAS only | Zero CloudFormation/S3 Control clients before claim |
| Ambiguous Plan/Approval/claim response | No retry, no success claim, no effect client; independent exact ledger reconciliation is required but not implemented | Terminal stop or controlled generation retirement |
| Partial or malformed ledger item | Closed ledger validation and complete canonical digest | Item quarantined; no transition |
| Mutable alias or unqualified writer version | Exact published versions in reviewed binding and readback | Activation or invocation denied |
| Revoked/rotated generation is reused | Generation is exact and old generation becomes read/reconcile-only | New transition denied |
| Dirty or untracked tree, replacement ref, caller Git config/env/PATH, or package bytes differ from reviewed commit | Builder resolves reviewed absolute Git, uses a closed env/config and `--no-replace-objects`, rejects every `refs/replace`, requires empty tracked/untracked status, compares HEAD/Git objects, and fixes the file set/archive | Packaging denied |
| A GUG-274 CLI is launched without isolated Python, with `site` enabled, an external `pycache_prefix`, Python path overrides, or a hostile repository `.pyc` | All three entry points require `env -u PYTHONPATH -u PYTHONHOME python3 -I -S ...`, reject non-null `sys.pycache_prefix`, and directly compile the UTF-8 bytes of `tooling/platform_authority_source_only_import.py` before repository import. Its finder compiles exact repository `.py` bytes and never reads or writes repository bytecode | `ISOLATED_PYTHON_REQUIRED`, `PYTHON_BYTECODE_PREFIX_FORBIDDEN`, or repository-source denial; no provider construction |
| Missing, relative, repository/local-`.venv`, shared, untrusted-owner, or group/world-writable SDK runtime root/ancestor; shadow/preloaded closure module; symlink; SDK `.pyc`; unsafe site entry; or extra `site-packages` file | Normal/verifier require a dedicated external `SCANALYZE_GUG274_SDK_RUNTIME_ROOT`. Root and every POSIX ancestor must be owned by root/effective user and group/world non-writable, except a root-owned sticky ancestor; the complete site tree has trusted ownership and safe modes, accepts only regular files/directories, and receives no sticky exception. The loader then authenticates the complete pinned closure, every recorded file, and exact origin; bytecode writes are disabled | `SDK_RUNTIME_PATH_UNSAFE` or SDK authentication denial before provider construction |
| Mutable wheel `RECORD` is rewritten together with installed files | The loader canonicalizes the wheel-owned package/stable-metadata rows and requires their source-pinned installed-manifest SHA-256, then verifies every authoritative file digest/size and denies unrecorded package-tree extras. Raw installation-specific `RECORD` bytes are not authority | `SDK_DISTRIBUTION_RECORD_MISMATCH` or file mismatch; no import |
| Caller changes SDK version flags or host SDK drifts | Source-reviewed constants require `boto3==1.42.57` and `botocore==1.42.97`; caller flags are equality assertions, while the embedded runtime lock and deployed services repeat exact version checks | `SDK_RUNTIME_VERSION_UNREVIEWED` or service denial before provider authority |
| AWS-managed Lambda SDK drifts from the reviewed pins | ZIP excludes SDK wheels; future Lambda `python3.12` must match template environment pins, embedded lock, and managed-module `__version__` before provider construction; current CFN lock prevents activation | Inactive now; after future activation the service fails closed and repository/workstation rollback cannot alter AWS runtime |
| Hostile `PATH`, unsafe executable/ancestor, or digest-time path replacement selects fake Git, AWS CLI, or GitHub CLI | Resolution uses only reviewed absolute candidates. The regular executable and every directory ancestor require root/euid ownership and no group/world write, except a root-owned sticky ancestor. The complete check is repeated after hashing, stable executable metadata must match, and a non-root binary also needs its reviewed digest | Trusted executable unavailable; no provenance/provider command. Current Homebrew `gh` fails on `/opt/homebrew/Cellar` mode `0775` |
| Runtime source or provider configuration drifts | Embedded source/SDK lock and exact version checks; `AWS_DATA_PATH` and other provider overrides are denied | Service fails before provider authority |
| Unsigned `unsigned_archive_code_sha256` is passed as deployment proof | Manifest marks the local ZIP non-deployable; deployment target accepts only a future verified Signer destination digest/receipt | Activation blocked |
| Caller self-declares `SignedAuthorityArtifactCodeSha256`, `AuthoritySigningReceiptDigest`, or a redigested receipt | Receipt digest is unkeyed integrity only; consumption requires fresh GitHub+Signer+S3 evidence and exact immutable-projection equality | Provider-refresh mismatch; no CloudFormation parameters |
| Source is not merged to protected `main` with every exact required check green | Read-only verifier binds source commit/tree, merged PR, branch protection, and GitHub Actions check provenance | `SOURCE_RELEASE_NOT_VERIFIED`; no receipt |
| Receipt is older than 15 minutes or Signer/S3/GitHub changed after creation | TTL plus mandatory same-flow refresh before consumption | Expiry/readback drift; no parameters |
| Wrong-signer or mutable signed object reaches the handoff | Fixed configured contract, exact Signer job/profile version, single versioned destination object, checksummed bytes, and signed-ZIP validation | Receipt construction/refresh denied |
| Caller attempts activation while the signer trust root is not configured | Fixed Git contract is `NOT_CONFIGURED`; CLI requires configured contract; CFN permits lock `false` only while its Rule requires `true` | `SIGNING_TRUST_ROOT_NOT_CONFIGURED`; Change Set creation impossible |
| Stack rollback is treated as undoing account PAB | Executor writes all-true account PAB before `ExecuteChangeSet`; `OnStackFailure=ROLLBACK`/`DisableRollback=false` governs stack resources only | PAB remains enabled; containment/recovery must not weaken it |
| Alias, `$LATEST`, or published version other than generation-1 `:1` is invoked | Exact qualified ARN and actual published-version readback | Activation/invocation denied |
| Provider outage or permission drift | Unavailable identity/CAS/effect provider is denial or terminal uncertainty | No alternate authority or retry |
| Diagnostics leak artifacts or principals | Stable error codes and sanitized output; records remain private | Publication blocked |
| Normal path retires a Change Set | Explicit absence of `DeleteChangeSet`; GUG-215 remains sole authority | Local/IAM denial |

## Canonicalization and cross-protocol controls

Plan, Approval, ledger, receipt, and authority-key projections use the exact
domains `scanalyze.platform-authority.bootstrap.plan.v2`,
`scanalyze.platform-authority.bootstrap.approval.v2`,
`scanalyze.platform-authority.bootstrap.artifact-authority.v1`,
`scanalyze.platform-authority.bootstrap.authority-receipt.v1`, and
`scanalyze.platform-authority.bootstrap.authority-key.v1`. Strict canonical JSON
rejects duplicate keys, unknown fields, non-finite values, ambiguous timestamps,
and type confusion. A digest produced for one record type cannot be accepted as
another. All exact bindings are validated before the ledger read, then
revalidated against the external item.

The external record fixes trust contract `1`, generation `1`, and algorithm
`AWS_DYNAMODB_STRONGLY_CONSISTENT_CAS_SHA256`. A future algorithm or schema
needs a new explicit version and migration decision; rotation cannot
reinterpret existing bytes or silently enable a fallback.

## Ordering and TOCTOU boundary

All provider-independent failures are rejected before identity/ledger provider
construction. Identity Center/OIDC, STS proof, and DynamoDB are authentication
providers, not effect clients. After live user-B proof and exact ledger read,
freshness/separation validation and the one-shot CAS claim occur before any
CloudFormation or S3 Control client is constructed.

After CAS, the executor validates the empty shell, exact full ARN/UUID,
parameters, tags, status, resource inventory, request metadata, and `Original`
template, then revalidates freshness before PAB. It repeats the shell,
full-ARN/UUID, exact parameters/metadata, `Original` template, and freshness
after PAB. Only then may it derive the bare name and issue one
`ExecuteChangeSet` against the exact stack.

This ordering does not eliminate provider-state change; it makes the claim
single-use and preserves the final full-ARN readback. A post-claim mismatch or
CloudFormation ambiguity is terminal, permits only existing separately
authorized read-only CloudFormation inspection, and cannot reset the claim.

## Why KMS signatures are not the sole trust root

Asymmetric signatures can authenticate immutable bytes, and the repository has
reviewed KMS-verification patterns. A signature alone does not atomically prove
that one approval is current, unsuperseded, and consumed exactly once. Adding a
separate replay ledger would split authority and recovery across two systems.
GUG-274 therefore selects the CAS ledger as the single artifact-authentication
and consumption root. This does not weaken or modify GUG-221/GUG-273 signed
evidence. The target uses AWS Signer separately to authenticate the Lambda
package. Its read-only destination verifier and short-lived receipt/refresh
flow are implemented, but they cannot operate until a separate reviewed commit
configures the fixed signer trust root; they do not authenticate Plan/Approval
or consume an approval.
Static secrets, local signing keys, CI signing keys, and shared HMAC material
remain forbidden.

## Package and runtime provenance boundary

The package builder accepts only an exact clean HEAD and verifies every closed
source path against the same Git commit object. The Git subprocess uses a
closed environment/config/locale, `--no-replace-objects`, explicitly enumerates
and rejects `refs/replace`, resolves Git through a reviewed absolute candidate
rather than caller `PATH`, and accepts neither caller Git config nor any dirty
tracked/untracked worktree state. Fixed ZIP metadata and ordering produce deterministic bytes,
per-file digests, archive digest, and `unsigned_archive_code_sha256`. That last
field names an unsigned, explicitly non-deployable source ZIP; it is not Lambda
deployment evidence. The embedded runtime lock binds source commit, generation,
and exact `boto3==1.42.57`/`botocore==1.42.97` versions; caller flags must equal
those constants. `AWS_DATA_PATH`, configured endpoint, credential-file,
profile, CA, and other provider overrides are rejected.

All three CLIs require `env -u PYTHONPATH -u PYTHONHOME python3 -I -S ...`. The
`-S` boundary prevents automatic `site`, `.pth`, and `sitecustomize` execution.
Before any repository import, each entry point opens
`tooling/platform_authority_source_only_import.py` as UTF-8 source and compiles
those bytes directly. The installed finder handles repository `tooling` modules
only, compiles their exact `.py` bytes, and neither consumes nor emits repository
`.pyc`; repository bytecode writes remain disabled.

The normal CLI and verifier require `SCANALYZE_GUG274_SDK_RUNTIME_ROOT` to name
an absolute root outside the repository/local `.venv`; its direct
`site-packages/` is dedicated to and contains only the fixed closure. The root
and every directory in its POSIX ancestor chain must be owned by root or the
effective user and group/world non-writable; only a root-owned sticky directory
in that chain may be writable. The complete `site-packages/` tree must also have
trusted ownership and safe modes and contain only regular files/directories, so
it has no sticky-directory exception. The loader
admits that path explicitly and authenticates before import. The environment
path locates candidate bytes but grants no authority; source-pinned official
wheel identities and canonical installed-manifest hashes do. The closure is
fixed to
`boto3==1.42.57`, `botocore==1.42.97`, `s3transfer==0.16.1`,
`jmespath==1.1.0`, `python-dateutil==2.9.0.post0`, `urllib3==2.7.0`, and
`six==1.17.0`. Each installed-manifest digest covers the wheel-owned package
and stable metadata rows; the loader then verifies every authoritative file
size/digest and import origin. Preloaded modules, symlinks, `.pyc`,
unsafe/mismatched or unrecorded import-tree files fail closed, external
`pycache_prefix` is forbidden, and bytecode writes are disabled. The raw local
`RECORD` is parsed but neither pinned nor
caller-controlled authority.

The ZIP itself excludes SDK wheels. Future Lambda `python3.12` compares
template pins with the embedded lock and checks AWS-managed module versions
before provider construction. This is a distinct managed-runtime boundary, not
an extension of host closure authentication, and is currently inactive because
the CFN activation lock is impossible.

The repository emits only an unsigned archive and manifest. A separate
authorized lane must sign the exact bytes with the fixed
`scanalyze_gug274_bootstrap_artifact_authority` profile and immutable profile
version and upload the AWS Signer destination object. The implemented read-only
verifier rebuilds the exact package, proves the source commit is merged to
protected `main` with all exact required GitHub Actions checks green, and reads
the verifier STS identity, completed Signer job, versioned unsigned source, and
single versioned signed destination from S3. It validates the signed ZIP and
derives only the signed destination digest and closed CloudFormation parameter
projection. The receipt expires within 15 minutes.

A receipt and its unkeyed domain digest are evidence containers, not authority.
The consumption boundary must refresh GitHub, Signer, and S3 in the same flow,
rebuild the receipt, and compare every immutable field before using any
parameter. Raw parameters, a local redigest, a manifest, or template output do
not authenticate the tuple.

The verifier loads only
`bootstrap/platform-authority-bootstrap-artifact-signing-trust-root.json`.
That contract is deliberately `NOT_CONFIGURED`, with null signer version and
activation denied, so the CLI returns
`SIGNING_TRUST_ROOT_NOT_CONFIGURED` before provider verification. The template
also admits only `AuthoritySigningTrustRootConfigured=false` while a Rule
requires `true`; Change Set creation is therefore impossible. A separate
reviewed commit must pin the exact signer version ID/ARN and contract digest in
the fixed contract and template allowlists before unlocking it. The declared
`UntrustedArtifactOnDeployment=Enforce` and the implemented verifier do not
prove live signer enforcement, publication, or deployment.

Repository rollback before activation is a reviewed revert of source, SDK pins,
executable policy, and documentation; it neither installs nor downgrades host
tooling. After signing or deployment, an out-of-band wheel/executable change or
rebuild is not rollback. Revoke the affected generation/version, preserve the
immutable receipt and ledger evidence, and select a separately reviewed
known-good signed artifact or forward fix through the same controls.

## Rotation, revocation, and uncertain outcomes

A new trust-root generation uses a newly reviewed clean-commit package, runtime
lock, immutable signer profile version, exact service versions, identity
topology, and assignments. New plans cannot target an old generation. Old
records remain immutable and read/reconcile-only; they are not copied into an
active state. Revocation blocks every new transition and retains records for
investigation.

No ambiguous create, approval, or claim result is retried or called successful.
The current three-service package has no independent read-only ledger endpoint
or human reconciliation role. The Apply invocation that received an ambiguous
claim constructs zero CloudFormation/S3 Control clients. A separately reviewed,
strongly consistent exact-item reconciliation capability is a live-activation
prerequisite, is currently **NOT_IMPLEMENTED**, and is tracked as a P2 recovery
follow-up; do not manufacture it with ad hoc IAM. Until then, controlled
generation retirement is the only safe
disposition. A `CLAIMED` item is terminal even if later execution evidence is
absent.

## Required causal validation

Tests must demonstrate behavior, not only static policy strings:

- a complete same-name/different-UUID Plan and Approval rewrite is accepted by
  the historical digest-only boundary and rejected by external authentication;
- missing, foreign, stale, malformed, partially written, replayed, superseded,
  or already claimed records make zero Apply effect-client constructions;
- user A/user B equality, wrong operation role, wrong proof role, stale proof,
  persisted grant input, and cross-operation grant replay fail;
- actor overlap, direct human effects, and every unauthorized transition fail;
- two concurrent claims yield at most one `CLAIMED` record;
- an ambiguous claim never constructs effect clients and is not retried;
- active v1 and mixed-version pairs are rejected;
- parameter substitution and noncanonical RoleARN/capabilities/notifications/
  rollback/nesting/import-existing/parent/root/OnStackFailure metadata fail
  both readbacks;
- GUG-210 full-ARN/`Original`/freshness/PAB/final-full-ARN/`Original`/
  freshness/bare-name ordering remains;
- the effect-client factory is called only after successful CAS;
- dirty or untracked source, commit drift, package tampering,
  non-isolated Python, enabled `site` startup, repository bytecode import/write,
  missing/unsafe/shared
  `SCANALYZE_GUG274_SDK_RUNTIME_ROOT`, repo/local-`.venv` SDK,
  untrusted SDK runtime/ancestor/site ownership, unsafe group/world-write mode,
  preloaded/shadow closure modules,
  wrong SDK pins or transitive version, source-pinned installed-manifest drift,
  authoritative-file digest/size drift, external `pycache_prefix`, symlink,
  `.pyc` or extra import-tree file,
  hostile `PATH`, unreviewed executable/ancestor ownership or mode, digest-time
  executable replacement, unreviewed digest,
  runtime-lock drift, replacement refs/Git env, `AWS_DATA_PATH` or another provider override,
  unsigned-digest-as-signed confusion, self-declared signing receipt, wrong
  signer/profile/object/digest, receipt expiry, refresh drift, unconfigured Git
  trust root, attempted CFN-lock bypass, `DeploymentMode`, and non-`:1`
  activation fail;
- normal cancellation remains zero-AWS; and
- GUG-215 retirement and GUG-273 contracts remain unchanged.

Strict fake adapters are local test evidence only. They cannot be described as
live DynamoDB, IAM, Identity Center, Signer, Lambda, S3, or CloudFormation
validation.

## Severity calibration

- **Critical:** an alternate human/direct effect path or service-role bypass
  that can execute a foreign Change Set or mutate another account in an
  authorized production context.
- **High / P1:** complete artifact substitution, user-A/user-B collapse,
  identity-proof type confusion, effect-client construction before CAS,
  Change Set parameter/request-metadata substitution, treating the unsigned
  digest or caller-declared signing fields as verified Signer evidence, or
  reusable persisted PKCE material.
- **Medium:** sanitized evidence or recovery behavior that leaks enough private
  binding data to aid replay but still lacks an effect authority.
- **Low:** repository-only documentation or diagnostic drift that cannot alter
  the active fail-closed path. It still blocks readiness until reconciled.

## Residual risks and activation blockers

- The table, deny-only resource policy, execution-role identity policies, exact
  `:1` services, signed object, signer profile version, code-signing
  configuration, runtime lock, logging/recovery controls,
  and user-A/user-B assignments have not been deployed or read back.
- The read-only collector/verifier, 15-minute receipt, merged-main source review,
  and provider-refresh logic are implemented repository controls. No actual
  profile version is pinned, however: the fixed Git contract is deliberately
  `NOT_CONFIGURED`, and the CloudFormation Rule is deliberately impossible.
  **SIGNING_TRUST_ROOT_NOT_CONFIGURED** blocks Change Set creation and live
  activation until a separate reviewed commit pins the exact version and
  contract digest.
- No live authorization-code exchange, Identity Center context, deny-all STS
  proof, ledger transition, PAB write, or Change Set execution was observed.
- Repository declarations do not prove that no alternative human, role,
  administrator, session, or service can write the table or invoke conflicting
  versions.
- Repository validation does not provision the host interpreter, SDK wheels, or
  Git/AWS/GitHub executables. Missing/mismatched host tooling is a fail-closed
  availability risk; changing it is a separately controlled host action, while
  changing pins/bindings requires a reviewed repository revision and new
  build/sign/validation evidence. The currently observed Homebrew `gh` is one
  such availability stop because `/opt/homebrew/Cellar` is group-writable mode
  `0775`; its reviewed binary digest does not authorize that ancestor.
- The Lambda ZIP does not own the AWS-managed Python 3.12 SDK, and the current
  CFN lock means this managed boundary is not active. After future activation,
  its lock/version guard converts managed-runtime drift into a fail-closed
  availability risk; neither repository nor operator-host rollback can restore
  that AWS-owned dependency.
- GUG-119 independent-review enforcement and an available independent P0
  reviewer remain blocking.
- A broad authority-account administrator can bypass intended least privilege;
  live activation requires explicit inventory and negative authority probes.
- Post-claim CloudFormation uncertainty still requires exact read-only
  reconciliation; it cannot be solved by retrying or resetting the ledger.
- Independent strongly consistent ledger reconciliation is
  **NOT_IMPLEMENTED** and tracked as a P2 recovery follow-up. Repository code
  must not be activated live until that gap is separately reviewed and closed,
  or the generation-retirement posture is explicitly accepted by authorized
  owners.
- Candidate attribution labels/principal digests are not cryptographically
  correlated with the live fixed UserIds. Proof receipts remain authoritative;
  stronger correlation is a P2 follow-up.

## Evidence boundary

This package can establish **Documented**, **Implemented**, locally tested, and
exact-head CI evidence for repository behavior only. Deterministic clean-commit
packaging produces an unsigned non-deployable artifact only. Live signing,
real provider receipt/refresh, operational CloudFormation handoff,
signed-object upload, Lambda deployment/version publication, Identity Center
proof, DynamoDB transitions, PAB, and
CloudFormation execution are **NOT_OBSERVED**. AWS access and cloud mutations by
this documentation lane are **NONE**. Live activation requires separate
authorization, exact resource/policy/signer/package/version/assignment readback,
configuration of the fixed signing trust root, the missing independent ledger
reconciliation capability, causal negative probes, and independent P0 review.

Production remains **NO-GO**.

## References

- [ADR-048](../../ADR/ADR-048-platform-authority-bootstrap-artifact-authentication.md)
- [ADR-038](../../ADR/ADR-038-cloudformation-changeset-iam-binding.md)
- [ADR-041](../../ADR/ADR-041-retained-change-set-retirement.md)
- [Platform-authority bootstrap](../deployment/platform-authority-bootstrap.md)
- [Bootstrap recovery](../operations/platform-authority-bootstrap-recovery.md)
