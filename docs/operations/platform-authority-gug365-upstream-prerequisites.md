# Runbook: GUG-376 upstream prerequisites for GUG-365

## Current status and hard boundary

This runbook records two deliberately separate repository boundaries:

- the GUG-376 v1 runner remains an inert
  `STOP_UPSTREAM_SOURCE_CONTRACT_GAP` shim; and
- GUG-377 adds v2 inventory, plan and final-handoff records plus a
  repository-only materializer. Its default adapter is inert and its scripted
  adapter is a deterministic test double, not an AWS/provider adapter.
- GUG-384 adds only the authority-account policy, session, capture and private
  custody contracts. Its checked-in CLI has no provider factory and remains
  inert; repository tests inject deterministic fakes only.
- GUG-385 adds the inert management-account Identity Center contract: bounded discovery precedes exact reads of the fixed targets, and only the pre-approved UserId can be described.
- GUG-386 adds an offline-only composer for two terminal receipts and one
  independently pinned private-run envelope. It emits only a digest-bound
  public record and cannot capture, log in, construct clients or call AWS.
- GUG-392 adds a separate attested boto3 read-only provider and private request
  materializer for those two inventory domains. It does not modify any legacy
  STOP entrypoint or authorize a mutation phase.

The GUG-376/GUG-377/GUG-384/GUG-385/GUG-386/GUG-387 paths above remain inert
or synthetic and still stop live-adapter requests. Only the dedicated GUG-392
entrypoint may construct an SDK client, and only after the private materialized
request, clean source, UTC window, profile metadata and STS-first gates pass.
Do not translate the reserved future steps below into ad hoc AWS CLI/SDK calls.

Repository validation is offline and makes **zero AWS calls and zero provider
network calls**. A separately activated GUG-392 run performs only the closed
read-only inventory calls. Neither the PR, ADR, Linear status, upstream plan,
inventory request nor owner-decision approval authorizes AWS writes.
Every live phase requires a new exact phase-specific owner authorization.
Production remains **NO-GO**.

The runbook never executes GUG-365, GUG-357, GUG-215, GUG-206 or GUG-361.

## Preparation gates

### Source and routing

Before private or AWS work:

1. revalidate GUG-376 as the single upstream issue and GUG-365 as its blocked
   consumer;
2. revalidate current `main`, exact PR review/check evidence and branch
   protection;
3. use one clean isolated checkout fixed to the reviewed merge/tree;
4. run the service-role, entrypoint, bootstrap, docs and security gates with
   the repository-pinned toolchain; and
5. stop on source advance, dirty tracked state, failed gate or review drift.

The primary dirty checkout is never cleaned, reset, stashed or reused.

### Private custody

The owner must explicitly authorize a new absolute upstream root. Reject the
existing GUG-365 root, synced/FileProvider paths, symlinks and broad modes.
Required controls are directory `0700`, regular one-link files `0600`, same-
directory atomic writes, file and directory `fsync`, and owner-only ancestry.

Create or resume exactly one upstream run and one CAS ledger. Never replace a
partial or `in-flight` ledger, reseal history, or start a second run to regain
an attempt.

### Closed-world derivation and owner decisions

Derive every fixed name, policy, tag, key pattern, parameter and constraint
from current source. Build the private `OWNER_DECISIONS_REQUIRED` record for
only the source-permitted choices. Stable read-only collision evidence must
accompany every proposed value. Stop until the owner approves the exact record
digest; that response is not a phase authorization.

### Read-only inventory

Every new or renewed SSO session is short-lived and unchained. Its first signed
AWS call is `sts:GetCallerIdentity`; validate the private account/caller/expiry
binding before constructing another client.

Use distinct read-only authority for:

- authority-account S3, KMS, Lambda, Signer and CSC inventory; and
- management/delegated-administrator Identity Center and Identity Store
  inventory.

The reviewed least-privilege templates are respectively
`policies/iam/platform-authority-gug376-authority-inventory-read-only.json`
and
`policies/iam/platform-authority-gug376-identity-center-inventory-read-only.json`.
Render every placeholder from the private owner-approved target set, bind the
same window used by the inventory request, and compare the canonical rendered
policy digest before opening either session. The templates grant no write,
session-chaining or generic administration action.

The GUG-384 authority child exposes only `capture` and `certify`. `capture`
must pass the local target, policy-digest, environment and custody gates before
an injected typed factory can be called. The checked-in wrapper injects none
and stops with `STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED`; `certify` is offline,
requires an independently pinned runtime-target digest, and exact-present requires a closed external verifier with digest-only output.
This child does not relax or populate the existing nine-surface envelope.

Never use Audit, Log Archive, customer, generic administrator or default
profiles. Collect two complete, stable, paginated snapshots. `AccessDenied`,
timeout, incomplete pagination, repeated tokens and provider errors are
`NOT_AUTHORIZED` or `UNCERTAIN_RECONCILE_ONLY`, never absence.

Classify every target as:

```text
ABSENT_READY
EXACT_PRESENT_NO_TOUCH
PREEXISTING_NO_TOUCH
DRIFT_BLOCKED_NO_REPAIR
UNCERTAIN_RECONCILE_ONLY
NOT_AUTHORIZED
```

Only approved causal provenance plus complete stable equality can produce
`EXACT_PRESENT_NO_TOUCH`.

### Runtime-version evidence

Select the owner-approved pre-existing published Lambda version. In two stable
read-only observations require Python 3.12, `x86_64`, manual runtime management
and the same runtime-version ARN. Bind the version identity and normalized
responses privately and expose only the evidence digest.

Do not create/update a Lambda, use `$LATEST`, copy an ARN from a fixture or
accept automatic runtime management. If no eligible source is available,
return `STOP_RUNTIME_PIN_SOURCE_NOT_PROVEN` with the minimum missing read-only
authority/evidence.

### Reserved deterministic private package build

These steps are reserved for a separately reviewed future private/live lane.
The GUG-377 scripted materializer does not build or persist packages and never
creates or accesses a private root. With all AWS credential variables absent
and network/provider construction blocked, that future lane must:

1. rebuild the GUG-215 package only through
   `scripts/deployment/platform-authority-change-set-retirement-package.py`;
2. rebuild the ledger-factory package only through
   `scripts/deployment/platform-authority-retirement-entrypoint-service-role.py package`;
3. validate source commit/tree, manifests, member names and bytes, archive
   determinism, archive SHA-256, Lambda `CodeSha256`, runtime binding,
   exception/broker bindings and zero AWS calls; and
4. store packages and manifests only in the approved private root.

Synthetic fixtures are negative-test inputs, never live packages.

## Repository materializer and reserved common phase protocol

GUG-377 compiles a repository-only v2 plan containing exactly 30 ordered
operations in nine phases. The scripted adapter can exercise the closed
operation/result, bounded-polling, one-attempt CAS and reconciliation
contracts without provider I/O:

| Phase | Ordered operations |
|---|---:|
| `IDENTITY_CENTER_FOUNDATION` | 14 |
| `KMS_FOUNDATION` | 3 |
| `S3_ARTIFACT_FOUNDATION` | 7 |
| `SIGNER_PROFILE_FOUNDATION` | 1 |
| `LAMBDA_CSC_FOUNDATION` | 1 |
| `BROKER_UNSIGNED_PUBLISH` | 1 |
| `BROKER_SIGNING_JOB` | 1 |
| `LEDGER_FACTORY_UNSIGNED_PUBLISH` | 1 |
| `LEDGER_FACTORY_SIGNING_JOB` | 1 |

The global operation sequence is `1..30`; each operation has one immediate
predecessor except the first, a unique operation ID/kind, `attempt_limit=1`,
`sdk_retry_count=0`, `retry_permitted=false` and
`ambiguous_outcome=UNCERTAIN_RECONCILE_ONLY`. Polling is allowed only for the
closed Identity Center assignment/provisioning and Signer job kinds, with
finite attempts, elapsed time and backoff plus closed terminal statuses.

This is synthetic repository execution only. It neither simulates AWS truth
nor proves provider certification, private custody, owner authorization or a
durable live ledger. The following sequence remains reserved design input for
a future separately reviewed private live orchestrator. Before its first
phase, that orchestrator must compile an immutable private upstream plan with
the same nine-phase graph and typed provider slots. Every phase remains
present; exact preexisting state produces a zero-write
`EXACT_PRESENT_NO_TOUCH` receipt. For each mutation phase and contiguous exact
request batch:

1. refresh source, owner-decision, before-state and predecessor-slot evidence;
2. render the phase's sole identity policy and identical maximum-permissions
   cap; prove no additive grants or role chaining;
3. emit a phase authorization request binding the complete template write-set
   digest, exact request/configuration/readback digests for the current batch,
   caller/session evidence, private ledger root and maximum fifteen-minute
   window;
4. stop and accept only a response naming the exact phase and authorization
   digest, verified by an owner-controlled out-of-band channel; the repository
   ships no permissive or self-approving verifier;
5. start a fresh phase-specific SSO session, make STS the first call and have
   the pinned external provider verifier attest the preflight transcript before
   the first CAS;
6. repeat complete before-state and effective-authority readback;
7. revalidate the authorization immediately before each write;
8. validate the complete append-only ledger history, then CAS the exact
   operation to `in-flight` before calling AWS;
9. make the write once with SDK retries disabled;
10. perform exact readback and have the provider verifier attest the operation
    transcript, including typed response/readback projections; a missing or
    invalid receipt after the write becomes ambiguous;
11. durably record only the digest-bound verification and resolve provider
    slots once;
12. persist the phase receipt and close/expire the session; and
13. if a provider output resolves a later request in the same phase, close the
    batch and obtain a new owner checkpoint before that request; otherwise
    obtain the next phase checkpoint.

A previous phase authorization, “continue”, a merge, a plan digest by itself
or approval of the selected names is invalid.

The exported GUG-376 v1 runner entry point still stops before validation, CAS
or a provider callback with `STOP_UPSTREAM_SOURCE_CONTRACT_GAP`. GUG-377 does
not weaken or replace that stop. Its separate v2 materializer closes the
repository source contracts for typed asynchronous Identity Center results,
generated role projections, KMS/S3/Signer target records and causal object/job
results. It accepts only the inert adapter or an explicitly injected scripted
adapter; the adapter contract exposes typed operations, not a generic
`execute` or raw `payload` escape hatch.

Before a scripted write, the repository `AttemptLedger` performs one CAS from
unclaimed to in-flight. A typed successful result may then complete the
operation once. An ambiguous result consumes that sole attempt, rejects rerun
and permits only read-only reconciliation. This ledger demonstrates the
contract; it is not the owner-only append-only durable ledger required for
live execution.

The missing live products remain explicit: a provider-backed adapter, private
root/raw bundle, external owner/provider/final verifiers and durable private
ledger. Consequently v2 fixes `deployment_authorized=false`,
`owner_authorization_issued=false`, `live_provider_evidence=false` and all AWS
and downstream effect counters to zero.

A future separately reviewed private orchestrator must supply four trusted
adapters in one raw-bundle verification call: an external owner-authorization
verifier, an external provider-transcript verifier, an owner-only
append-only/CAS ledger store and a final negative-evidence verifier. It must
also bind an out-of-band trust anchor and the complete causal history. An
unkeyed canonical digest proves record integrity and binding; it authenticates
neither the owner nor the provider.

## Phase 1 — `IDENTITY_CENTER_FOUNDATION`

### Before-state

Prove the exact application, permission sets, same-user assignments and
generated roles are absent and that no conflicting application label,
redirect, grant, scope or permission-set name exists. Privately bind the one
approved immutable UserId. Never publish the UserId or email.

### Closed writes

The complete ordered set contains only:

- exact application creation and its authentication method, grant, access
  scope and assignment configuration;
- one direct application assignment to the approved user;
- creation of `ScanalyzeAuthorityRetireClass` and
  `ScanalyzeAuthorityRetireApprove` with exact tags/session settings;
- one repository-rendered inline policy per permission set;
- one account assignment per permission set to the same immutable UserId; and
- one provisioning request per permission set to the authority account.

No group, second user, managed policy, customer-managed reference, boundary,
relay state, `ScanalyzeGug357IdentityAudit` or non-Identity-Center action is
allowed.

### Readback and slots

Resolve the application ARN, both permission-set ARNs, asynchronous assignment
and provisioning request IDs, and both generated `AWSReservedSSO_*` role ARNs.
Poll only the exact request IDs. Require terminal success and two stable full
snapshots of application configuration, policies, assignments, provisioning
and IAM roles.

Record `two_human_status=NOT_PROVEN` and
`independent_approval_present=false`. Distinct roles do not alter those facts.

### Recovery boundary

On ambiguity, stop and reconcile using a new read-only management session.
Never repeat a create/assignment/provision request. Removal or deprovisioning
is a separate owner-authorized recovery package.

## Phase 2 — `KMS_FOUNDATION`

### Before-state

Prove the selected alias has no current, previous or pending-deletion target
and no exact-looking key is being adopted. The plan fixes key policy, key
usage/spec, origin, single-Region state, description, tags and rotation.

### Closed writes

Create one key, establish exact rotation and create one alias. Include policy
and tags in the create request where supported. The key ARN is filled only
from the create response plus exact readback.

### Readback and recovery

Read key metadata, policy, tags, rotation and alias twice. Any partial response
is reconcile-only. Do not create another key or alias, disable/schedule-delete
the key or rewrite policy/tags automatically.

## Phase 3 — `S3_ARTIFACT_FOUNDATION`

### Before-state

Prove the globally selected bucket name is absent and not ambiguously owned.
Bind the resolved KMS key slot and the exact bucket configuration/request
digests.

### Closed writes

Create one `us-east-1` bucket and set exact bucket-owner enforced ownership,
full public-access block, enabled versioning, KMS default encryption and bucket
key state, bucket policy and tags. No ACL, website, replication or public/
cross-account access is permitted.

### Readback and recovery

Read location, ownership, public access, versioning, encryption, policy, tags
and closed auxiliary inventory twice. A partially configured bucket is not
repairable in this run. Do not delete the bucket, suspend versioning or make a
second create/configuration call after ambiguity.

## Phase 4 — `SIGNER_PROFILE_FOUNDATION`

### Before-state

Prove the approved profile name is absent across active, canceled and historical
versions and that no conflicting signing job exists in the closed projection.

### Closed write and slots

Create one immutable signing-profile version on
`AWSLambda-SHA384-ECDSA` with exact validity and tags. Resolve its version ID
and ARN from response plus readback.

### Recovery boundary

Do not create an additional version, cancel/revoke a version or reuse another
profile after ambiguity. Reconcile profile/version inventory read-only.

## Phase 5 — `LAMBDA_CSC_FOUNDATION`

### Before-state and write

Prove no eligible CSC already exists. Create one config with
`UntrustedArtifactOnDeployment=Enforce` and exactly the resolved Signer
profile-version ARN. Include exact description and tags.

### Readback and recovery

Resolve the CSC ARN once. Read policy, allowed publishers, description and
tags twice. `Warn`, zero/multiple publishers or another profile version is
drift. Never update, delete or create a substitute CSC in this run.

## Phase 6 — `BROKER_UNSIGNED_PUBLISH`

### Before-state and write

Prove the fixed GUG-215 unsigned key has no version or delete marker. Perform
one `PutObject` with bytes identical to the deterministic broker ZIP, exact
KMS key, checksum, content length, metadata and tags. Versioning must already
be enabled.

### Readback and recovery

Resolve one non-null version ID and read exact bytes, checksum, size,
encryption, metadata and tags. Never overwrite/copy the object or issue another
put after an uncertain result.

## Phase 7 — `BROKER_SIGNING_JOB`

### Before-state and write

Bind the broker unsigned version, exact profile version and exact signed-output
prefix. Prove no job or destination can be mistaken for this request. Start
one signing job and resolve its job ID.

### Readback and recovery

Poll only that job. On `Succeeded`, resolve the exact signed key/version and
prove job owner/invoker/platform/profile, signature expiry, same bucket/KMS,
distinct outer archive digest and semantic ZIP-member equality. Any unknown,
failed or timed-out outcome is reconcile-only and never starts another job.

## Phase 8 — `LEDGER_FACTORY_UNSIGNED_PUBLISH`

Repeat the unsigned-object protocol for the deterministic GUG-365
ledger-factory archive and its fixed key. The key, S3 version, manifest,
archive digest and `CodeSha256` must differ from the broker's. Use the same
bucket and KMS key. One put, one resolved version, no overwrite or retry.

## Phase 9 — `LEDGER_FACTORY_SIGNING_JOB`

Start exactly one different job for the ledger-factory unsigned version using
the same Signer profile version. Resolve a different job ID and signed
destination. Require `Succeeded`, semantic ZIP equivalence, unexpired
signature and complete S3/KMS readback. Re-read the CSC and prove it still
enforces exactly the shared profile-version ARN.

The final closed inventory must contain the two expected unsigned versions and
two expected signed versions with no unexpected version/delete-marker in their
closed keys.

## Ambiguous outcomes and reconciliation

Any timeout, connection loss, malformed response, expired authorization after
`in-flight`, or uncertain provider status produces:

```text
STATE=UNCERTAIN_RECONCILE_ONLY
```

Close the mutation session. Under a separate read-only session, use the
consumed request digest, provider request token/ID where available, exact tags,
target constraints and before-state to find at most one causal result. Resolve
slots only after unique exact evidence. Preserve unresolved ambiguity; never
blind retry, repair, delete, recreate or start a second upstream run.

In the repository materializer, the one-attempt CAS occurs before the scripted
write. An ambiguous scripted result therefore consumes the attempt; calling
the operation again is rejected. Only the typed read-only reconciliation path
may classify the existing result. `UNKNOWN`, timeout or an unrecognized poll
status never becomes success and never schedules another write.

## Post-phase signed readback

After Phase 9, independently rebuild and verify both archives and signing
contracts. Require exact unsigned versions, distinct successful jobs, exact
profile version, exact signed destinations, checksums/sizes/KMS, outer digest
difference, semantic ZIP-member equivalence, unexpired signatures and one
enforcing CSC publisher. Negative tests are offline/read-only only.

Then build privately:

1. the GUG-363 intent;
2. the GUG-363 plan using the existing `plan` command;
3. the ledger-factory signing contract; and
4. independently delivered expected digests.

Do not run GUG-363 `apply` and do not compile the GUG-365 plan.

## Rollback and revocation matrix

| State | Permitted response | Prohibited response |
|---|---|---|
| Repository scripted materialization | Emit a distinct digest-bound completion package, an empty/non-executable rollback package and a STOP handoff | Treat scripted results as provider evidence or run rollback |
| Before any phase write | Expire session; reviewed Git revert | Any AWS cleanup |
| Conclusive exact phase | Preserve state/evidence; continue only with next fresh authorization | Reuse session or phase authorization |
| Partial phase | Stop; open separately reviewed recovery/revocation package | Inline repair or compensating delete |
| Ambiguous phase | Read-only reconciliation only | Retry, substitute target or new run |
| Exact completed upstream | Fresh read-only consumer checkpoint; separately authorize any future revocation | Treat handoff as GUG-365 authority |

KMS disable/deletion, bucket/object deletion, versioning suspension, Signer
revocation, CSC deletion and Identity Center deassignment/deprovisioning are
new mutations. None is automatic rollback.

## Terminal checkpoint

The GUG-376 v1 CLI may still publish only the zero-effect
`STOP_UPSTREAM_SOURCE_CONTRACT_GAP` checkpoint, classified
`REPOSITORY_VALIDATED_NO_LIVE_EXECUTION`.

The separate GUG-377 v2 CLI may report
`REPOSITORY_SOURCE_CONTRACTS_CLOSED`; a fully successful scripted run may
report `SYNTHETIC_MATERIALIZATION_COMPLETE`. Its final handoff nevertheless
remains `STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED`, with
`state=SOURCE_CONTRACTS_CLOSED_REPOSITORY_ONLY`,
`evidence_scope=REPOSITORY_VALIDATED_SYNTHETIC_ONLY`,
`provider_certification_complete=false`,
`live_provider_evidence=false`, `deployment_authorized=false`,
`consumer_fresh_checkpoint_required=true`,
`two_human_status=NOT_PROVEN` and
`independent_approval_present=false`.

The GUG-386 wrapper is also inert by default: `capture` always returns
`STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED`. Operators may inspect the explicit
offline `compose` inputs with:

```bash
python3 scripts/deployment/platform-authority-gug383-dual-domain-inventory-handoff.py compose --help
```

Composition requires independently expected source commit/tree, window,
authorization, run-id and private-run digests. It rejects receipt substitution,
cross-run bindings, overlapping snapshot/session sets and incomplete or
unstable evidence. The private envelope is read-only input and is never emitted
wholesale, persisted or removed; only its approved SHA/digest projections are
emitted. The public result contains no account, ARN, profile,
UserId, name, email, path, filename, request ID, token or provider payload.
This repository checkpoint does not close GUG-383 or GUG-376 and authorizes no
live inventory, deployment, staging or production action.

## GUG-387 operator checkpoint

The new GUG-387 wrapper is inert unless a reviewed Python caller injects a
synthetic provider and supplies the exact opt-in. This repository slice rejects
`LIVE` before constructing a provider; enabling live collection requires a
separate repository-attested adapter and fresh UTC clock contract. The core
rejects default, duplicate or chained profiles and all ambient credentials or
endpoint overrides before the factory is called. It verifies the expected
account, Region and principal by making STS the first signed operation, then
admits only the closed
List/Get/Describe ledger with zero retries and at most 50 complete pages per
stream.

Do not place private evidence in this repository, a Git worktree, a symlink or
a File Provider path. Use a pre-existing owner-only `0700` root; the executor
writes new `0600` artifacts atomically and never overwrites them. Two stable
snapshots per domain are mandatory. Any access denial, partial page, repeated
token, retry, unstable result or cross-domain receipt/session substitution
stops with read-only reconciliation only.

CI exercises only injected synthetic providers. Its handoff must remain
`LIVE_INVENTORY_NOT_PROVEN`, `AWS_CALLS=0`, `AWS_MUTATIONS=0`,
`NOT_DEPLOYED`, `two_human_status=NOT_PROVEN` and production `NO-GO`. The
existing GUG-384/GUG-385/GUG-386 v1 wrappers retain
`STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED` unchanged.

## GUG-392 attested read-only operator checkpoint

GUG-392 is a separate entrypoint; it does not enable `LIVE` in the GUG-387
wrapper. Before materializing anything, use an absolute, pre-existing,
owner-owned `0700` directory outside this repository, every Git worktree and all
File Provider or synchronization locations. Place the two complete private plan
input JSON files there as owner-owned `0600` regular files. The examples are
synthetic and authorize nothing: use the
[absence authority input](platform-authority-gug392-authority-plan-input.example.json)
with the
[absence Identity Center input](platform-authority-gug392-identity-center-absent-plan-input.example.json),
or the paired
[exact authority input](platform-authority-gug392-authority-exact-plan-input.example.json)
and
[exact Identity Center input](platform-authority-gug392-identity-center-exact-plan-input.example.json).
Replace every example account, ARN, identifier, timestamp and digest through the
owner-controlled channel. Do not set ambient
`AWS_*`, endpoint or CA-bundle SDK overrides for the command.

The request binds two distinct non-default direct-SSO profiles. The authority
profile must be least-privilege read-only in the authority account; the
Identity Center profile must be a separate least-privilege read-only profile in
the management account. Administrator, bootstrap, seed, deploy and destroy
permission sets are not substitutes. Both SSO sessions must already be valid,
and the corresponding plans must contain the exact expected account and
principal.
The effective authority and management accounts must be different. The private
Identity Center `authority_account_arn` must equal the authority plan's exact
account; two aliases of one principal are not two domains.

The profile names are rejected if they are `default` or duplicates. Both
profile names and exact SSO role names are rejected if they contain the
normalized fragments `administrator`, `admin`, `bootstrap`, `seed`, `deploy` or
`destroy`. Each profile must be direct SSO. Do not use static access
keys/session tokens, `credential_process`,
`credential_source`, `role_arn`, `source_profile`, web identity, `external_id`,
`mfa_serial`, endpoint or CA overrides, or named service overrides. The profile
document may contain only the direct-SSO fields plus the accepted Region/output
metadata.

Bootstrap both SSO sessions before the GUG-392 `live` command, for example with
`aws sso login --profile '<exact-profile>'` for each profile. This browser/cache
bootstrap can call the SSO/OIDC control plane and remains outside the GUG-392
provider transcript. During `live`, the botocore session is fixed to one total
attempt before credential resolution. The effective vend-client configuration
is verified at call time. Credential resolution permits at most one observed
`sso:GetRoleCredentials` vend per collector session; an OIDC refresh, any other
pre-STS AWS operation, a retriable vend or a second vend stops the attempt. The
temporary credentials are then copied into a non-refreshable in-memory client
session that retains the same reviewed profile binding, so it cannot fall back
to transport settings from `default`. Every STS and inventory client explicitly
uses `verify=true`; the authenticated botocore CA bytes are loaded into a fresh
TLS context from memory and the mutable CA path is never reopened. Optional
`certifi`, profile/ambient CA overrides and custom proxy-TLS settings are
excluded, so an unselected profile cannot change TLS roots after validation. Their access-key
digest, real expiry and bootstrap-call count are committed in the private
session digest; keys and tokens are never written or printed. Credential vending is excluded from
inventory `provider_calls` and `aws_calls`. The first ledgered signed inventory
call is `sts:GetCallerIdentity`; bounded List/Get/Describe calls remain blocked
until the exact account and principal pass.

Botocore may legitimately reuse the same unexpired cached SSO role credential
for both captures. Each private session digest therefore binds both that real
credential fingerprint and a module-minted domain, capture, stage, policy and
session ordinal. This distinguishes two separately ledgered capture sessions
without claiming that cached credential reuse constitutes a second human or a
second IAM identity.

First run the offline materializer. It performs no AWS call and publishes one
new request and checkpoint with create-only semantics. Review their digests
through the owner-controlled channel before invoking the live command. The
live command re-reads and reconstructively validates both files, verifies a
clean exact source commit/tree and fresh activation window, and only then loads
the AWS SDK. It performs STS-first List/Get/Describe inventory only, with no SDK
retry and no mutation API in the closed operation set.

S3 object-version evidence requests only the non-paginated ETag, checksum,
storage-class and object-size attributes. It never requests `ObjectParts`; an
unexpected parts payload, including `IsTruncated=true`, fails closed instead of
sealing partial multipart evidence.

The Identity Center discovery stage additionally needs the reviewed GUG-392
`sso:DescribePermissionSet` supplement, scoped to both required instance and
permission-set resource classes, `us-east-1` and the same absolute window. AWS
also declares `kms:Decrypt` as a dependent action for `ListApplications`,
`ListPermissionSets` and `DescribePermissionSet`. The supplement permits that
dependency only on the exact private KMS key, through the `us-east-1` Identity
Center service, for the
management account, an Identity Center instance encryption context and the
same absolute window. The KMS key policy must admit the same direct-SSO
principal and conditions. The adapter never dispatches `kms:Decrypt` directly.
This resolves names from the ARN-only `ListPermissionSets` response without
changing the legacy v1 policy. In the live rendering only,
`ListPermissionSets` is narrowed from the legacy wildcard to the IAM Identity
Center instance resource class. Exact presence additionally requires the live
`DescribeInstance` encryption details to be `CUSTOMER_MANAGED_KEY`, the exact
owner-reviewed KMS key ARN and `ENABLED`; absence or drift blocks certification.

Use the dedicated help to obtain the exact argument contract:

```bash
GUG392_BASE_PYTHON='/absolute/path/to/reviewed-python-3.11.14'
GUG392_RUNTIME_ROOT='/absolute/new/owner-controlled/gug392-runtime'
test ! -e "$GUG392_RUNTIME_ROOT"
test "$("$GUG392_BASE_PYTHON" -c 'import platform; print(platform.python_version())')" = '3.11.14'
mkdir -m 700 "$GUG392_RUNTIME_ROOT"
mkdir -m 700 "$GUG392_RUNTIME_ROOT/site-packages"
GUG392_PYTHON="$GUG392_BASE_PYTHON"
PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_INPUT=1 \
  "$GUG392_PYTHON" -m pip install \
  --target "$GUG392_RUNTIME_ROOT/site-packages" \
  --no-compile --require-hashes --only-binary=:all: \
  --requirement scripts/deployment/platform-authority-gug392-live-provider.requirements.lock
test "$("$GUG392_PYTHON" -c 'import platform; print(platform.python_version())')" = '3.11.14'
GUG392_RUNTIME_ROOT="$GUG392_RUNTIME_ROOT" "$GUG392_PYTHON" -I -S -c "import os,re; from importlib.metadata import distributions; expected={'boto3':'1.42.57','botocore':'1.42.97','jmespath':'1.1.0','python-dateutil':'2.9.0.post0','s3transfer':'0.16.1','six':'1.17.0','urllib3':'2.7.0'}; path=os.path.join(os.environ['GUG392_RUNTIME_ROOT'],'site-packages'); observed={re.sub(r'[-_.]+','-',d.metadata['Name']).lower():d.version for d in distributions(path=[path])}; assert observed == expected"
for GUG392_PRUNE_PATH in \
  "$GUG392_RUNTIME_ROOT/site-packages/bin" \
  "$GUG392_RUNTIME_ROOT/site-packages/boto3-1.42.57.dist-info" \
  "$GUG392_RUNTIME_ROOT/site-packages/botocore-1.42.97.dist-info" \
  "$GUG392_RUNTIME_ROOT/site-packages/jmespath-1.1.0.dist-info" \
  "$GUG392_RUNTIME_ROOT/site-packages/python_dateutil-2.9.0.post0.dist-info" \
  "$GUG392_RUNTIME_ROOT/site-packages/s3transfer-0.16.1.dist-info" \
  "$GUG392_RUNTIME_ROOT/site-packages/six-1.17.0.dist-info" \
  "$GUG392_RUNTIME_ROOT/site-packages/urllib3-2.7.0.dist-info"
do
  test -e "$GUG392_PRUNE_PATH"
  find "$GUG392_PRUNE_PATH" -depth -delete
done
unset GUG392_PRUNE_PATH
GUG392_RUNTIME_ROOT="$GUG392_RUNTIME_ROOT" "$GUG392_PYTHON" -I -S -c "import os; from pathlib import Path; root=Path(os.environ['GUG392_RUNTIME_ROOT'])/'site-packages'; expected={'boto3','botocore','dateutil','jmespath','s3transfer','six.py','urllib3'}; assert {item.name for item in root.iterdir()} == expected"
"$GUG392_PYTHON" -I -S scripts/deployment/platform-authority-gug392-live-provider.py materialize-plans --help
"$GUG392_PYTHON" -I -S scripts/deployment/platform-authority-gug392-live-provider.py materialize-request --help
"$GUG392_PYTHON" -I -S scripts/deployment/platform-authority-gug392-live-provider.py live --help
"$GUG392_PYTHON" -I -S scripts/deployment/platform-authority-gug392-live-provider.py validate-run-v2 --help
"$GUG392_PYTHON" -I -S scripts/deployment/platform-authority-gug392-live-provider.py validate-handoff-v2 --help
"$GUG392_PYTHON" -I -S scripts/deployment/platform-authority-gug392-live-provider.py validate-evidence-v2 --help
```

Do not install the operational SDK from `pyproject.toml` or an unconstrained
index command. The dedicated lock contains one reviewed pure-Python wheel hash
for each direct and transitive runtime distribution. After the exact
pre-prune version check, remove only the generated `bin` directory and seven
exact `.dist-info` directories shown above; they are not part of the immutable
execution runtime. At live startup the provider requires `-I -S`, accepts only
the seven import roots, rejects every `.pth`, cache/bytecode file, symlink or
extra top-level entry, and checks both the lock bytes and the complete immutable
package-content manifest before importing boto3. It then verifies all seven
module `__version__` values. The dedicated root is bound into the private
request/checkpoint. SDK source is compiled only from authenticated in-memory
bytes. Botocore service, endpoint and retry models are served by a closed
in-memory loader, so neither `~/.aws/models` nor an ambient data path
participates. Optional `certifi`/`awscrt` imports and a post-install package edit
fail closed. Treat this pruned root as disposable; do not use it for package
inspection, uninstallation or redistribution.

The complete operator sequence is materialize, owner readback, one live capture,
then public-v2 and physical private-evidence validation. Replace every shell
placeholder and every synthetic value in the selected JSON pair. Use a new
absolute private root and a new activation window for every attempt:

The inventory plan window may be at most 60 minutes. The one-shot request window
must be wholly contained in that plan and may be at most 15 minutes; neither
window is renewable in place.

```bash
GUG392_PRIVATE_ROOT="/absolute/owner-only/gug392-<run-id>"
umask 077
set -o noclobber
mkdir -m 700 "$GUG392_PRIVATE_ROOT"

# Deliver the two owner-reviewed inputs through the private channel. They must
# be owner-owned 0600 regular files and must not be copied into the repository.
install -m 600 '<approved-authority-input>' \
  "$GUG392_PRIVATE_ROOT/authority-input.json"
install -m 600 '<approved-identity-center-input>' \
  "$GUG392_PRIVATE_ROOT/identity-center-input.json"

"$GUG392_PYTHON" -I -S scripts/deployment/platform-authority-gug392-live-provider.py \
  materialize-plans \
  --private-root "$GUG392_PRIVATE_ROOT" \
  --authority-input-file authority-input.json \
  --identity-center-input-file identity-center-input.json \
  --authority-plan-file authority-plan.json \
  --identity-center-plan-file identity-center-plan.json \
  > "$GUG392_PRIVATE_ROOT/plan-materialization-result.json"

"$GUG392_PYTHON" -I -S scripts/deployment/platform-authority-gug392-live-provider.py \
  materialize-request \
  --private-root "$GUG392_PRIVATE_ROOT" \
  --authority-plan-file authority-plan.json \
  --identity-center-plan-file identity-center-plan.json \
  --authority-profile '<authority-direct-sso-read-only-profile>' \
  --identity-center-profile '<identity-center-direct-sso-read-only-profile>' \
  --authority-sso-role-name '<exact-authority-role-name>' \
  --identity-center-sso-role-name '<exact-identity-center-role-name>' \
  --sdk-runtime-root "$GUG392_RUNTIME_ROOT" \
  --run-id '<opaque-run-id>' \
  --not-before '<UTC-RFC3339>' \
  --expires-at '<UTC-RFC3339-no-more-than-15-minutes-later>' \
  --approval-reference-digest 'sha256:<64-lowercase-hex>' \
  > "$GUG392_PRIVATE_ROOT/materialization-result.json"

# Compare the emitted request/checkpoint digests through the owner-controlled
# approval channel. Copy the exact reviewed values below; do not derive or
# substitute them inside the live invocation.
GUG392_EXPECTED_REQUEST_DIGEST='sha256:<reviewed-request-64-lowercase-hex>'
GUG392_EXPECTED_CHECKPOINT_DIGEST='sha256:<reviewed-checkpoint-64-lowercase-hex>'

"$GUG392_PYTHON" -I -S scripts/deployment/platform-authority-gug392-live-provider.py \
  live \
  --private-root "$GUG392_PRIVATE_ROOT" \
  --request-file gug376-live-request.json \
  --approval-reference-digest 'sha256:<same-64-lowercase-hex>' \
  --expected-request-digest "$GUG392_EXPECTED_REQUEST_DIGEST" \
  --expected-checkpoint-digest "$GUG392_EXPECTED_CHECKPOINT_DIGEST" \
  > "$GUG392_PRIVATE_ROOT/live-result.json"

jq -c '.run_record' "$GUG392_PRIVATE_ROOT/live-result.json" \
  > "$GUG392_PRIVATE_ROOT/run-v2.json"
jq -c '.public_handoff' "$GUG392_PRIVATE_ROOT/live-result.json" \
  > "$GUG392_PRIVATE_ROOT/handoff-v2.json"
"$GUG392_PYTHON" -I -S scripts/deployment/platform-authority-gug392-live-provider.py \
  validate-run-v2 "$GUG392_PRIVATE_ROOT/run-v2.json"
"$GUG392_PYTHON" -I -S scripts/deployment/platform-authority-gug392-live-provider.py \
  validate-handoff-v2 \
  "$GUG392_PRIVATE_ROOT/run-v2.json" \
  "$GUG392_PRIVATE_ROOT/handoff-v2.json"
"$GUG392_PYTHON" -I -S scripts/deployment/platform-authority-gug392-live-provider.py \
  validate-evidence-v2 \
  --private-root "$GUG392_PRIVATE_ROOT" \
  --evidence-file gug376-live-evidence-manifest.json \
  "$GUG392_PRIVATE_ROOT/run-v2.json" \
  "$GUG392_PRIVATE_ROOT/handoff-v2.json"
```

`authority-input.json` has exactly `targets`, `not_before`, `not_after`,
`expected_account_id`, `expected_principal_arn`,
`authority_verification_digest` and
`expected_generated_role_trust_policy_digests`. `targets` is the closed
twelve-target set accepted by the GUG-384 collector. For absence, both generated
role ARNs use the fixed all-zero suffix shown in the example as non-existent
collision sentinels, and the trust digests are the fixed not-applicable values.
The provider still examines every listed role with either fixed permission-set
prefix; any real suffix is drift. For exact presence, use the observed full role
ARNs and owner-reviewed `GetRole` trust-policy digests. These digests pin the
expected provider-generated trust; unlike the three repository policies below,
they are not source-certified.
`identity-center-input.json` has exactly
`private_targets`, the same two window fields, `expected_account_id`,
`expected_principal_arn`, `authority_verification_digest` and
`expected_state`. For a reviewed empty GUG-376 target, `expected_state` binds
the one already-active management-account instance exactly as
`{"classification":"ABSENT_READY","instance":{"identity_store_id":"...",
"instance_arn":"arn:aws:sso:::instance/ssoins-...",
"owner_account_id":"<12 digits>","status":"ACTIVE"}}`. Absence means no
matching application and no matching permission sets; it never means that IAM
Identity Center itself is absent. For a reviewed pre-existing target it
is exactly `{"classification":"EXACT_PRESENT_NO_TOUCH","targets":{...},
"facts":{...}}`; the facts must satisfy the live-v2 collector contract and
the operator fact is exactly `{"UserId":"<approved-user-id>"}`. Never place
`UserName`, `Emails`, Lambda environment variables or credentials in either
input. The command computes the authority policy digest, the GUG-392 live
Identity Center discovery-policy digest, and the exact target/facts/policy
digests. It rejects unknown fields, inconsistent accounts/windows, malformed
exact facts, pre-existing outputs, or a legacy GUG-385 discovery digest.

`EXACT_PRESENT_NO_TOUCH` is a closed application contract, not a name match.
The application must be `ENABLED` in the reviewed ACTIVE instance and management
account, use the reviewed custom provider ARN, have the exact description
`GUG-376 non-production authority application`, and expose only the reviewed
loopback PKCE callback `http://127.0.0.1:<1024-65535>/callback`. Its portal URL
is that callback without `/callback`. The only grant is `authorization_code`,
the only scope is `sts:identity_context` authorized to the reviewed instance,
the only authentication method is IAM with the reviewed actor policy, direct
assignment is required, and exactly the approved user is assigned.

The application and both permission sets have exactly
`managed_by=identity-center`, `service=scanalyze-platform-authority`,
`work_package=GUG-376`, `environment=non-production` and `production=false`.
Both permission sets use `PT1H`, the fixed GUG-215 descriptions, one inline
policy each, and no managed/customer-managed policy, permissions boundary or
relay state. Each is provisioned `SUCCEEDED` only to the reviewed authority
account and assigned only to the same approved user. `materialize-plans` pins
the raw repository sources for the actor, classifier and approver policies,
renders every placeholder from the two plans, and requires the owner-provided
and observed canonical digests to equal those renderings. A caller-supplied
digest cannot select alternate policy content. Live projection canonicalizes
the boto mapping and JSON-string policy response shapes through the same strict
parser; duplicate keys or malformed IAM policy documents stop the run.

`validate-handoff-v2` validates the exact run-to-handoff projection as one
bundle. A self-sealed handoff with a substituted or nonexistent `run_digest`
is rejected; standalone handoff shape validation is not causal proof.

`validate-evidence-v2` is archival and performs no AWS call. It custody-checks
and reconstructively validates the manifest-named request and owner checkpoint,
the fixed consumption claim, all four physical snapshots, the evidence manifest
and the supplied run/handoff. It evaluates the historical request at its
attested start, so an expired activation window does not invalidate archived
evidence. Missing, tampered, substituted, cross-root or non-owner artefacts fail
closed. It also replays STS-first exactly once per session and each digest-bound
pagination stream, including token continuity, the 50-page ceiling and terminal
closure. Preserve the request, checkpoint, claim, manifest and four snapshots
together in the same private root. The manifest alone is insufficient.
Canonical self-digests prove integrity and binding, not external owner/provider
authenticity, a second human, deployment authorization or production acceptance.

The CLI rejects a dirty or replaced checkout before repository imports and
again before each provider call. It also compares the action-time private
request/checkpoint digests with the pair accepted at startup. Do not set Git
directory/worktree overrides; the CLI intentionally ignores inherited Git
configuration and local replacement refs (`GIT_NO_REPLACE_OBJECTS=1`) and
validates the exact reported worktree root. The two public validation commands
use the same exact Python, clean-source and reviewed-loader gates as
materialization and live execution.

`live` publishes the create-only
`gug376-live-consumption-claim.json`, bound to the reviewed request/checkpoint
digests, before the provider is constructed. The claim consumes the request even
if SSO credentials have expired, STS fails, no inventory call completes, or the
command otherwise returns an error. All four private snapshots are also
create-only. Preserve the private root for reconciliation; every later attempt
requires a new root, request, checkpoint, activation window and owner-reviewed
digest pair. Never delete or overwrite the claim or ambiguous evidence.

Both clocks are real action-time gates. The request must satisfy
`not_before <= now < expires_at` at startup, before and after every provider
response, and immediately before the public bundle is sealed. A response that
returns at or after `expires_at` is ledgered as an error and cannot be published
as live evidence. The cached SSO credentials expose their own expiry and must
remain valid through the complete plan window. Logging in again does not renew
or make an existing request/claim reusable; materialize and review a new pair
instead.

The only successful public status is `LIVE_READ_ONLY_CAPTURED` with
`provider_calls=aws_calls>=1`, `aws_mutations=0` and a schema-valid v2 handoff.
The authority collector can causally publish only `ABSENT_READY` or
`PREEXISTING_NO_TOUCH` in this lane. Identity Center `ABSENT_READY` requires
exactly two discovery-only sessions and `EXACT_PRESENT_NO_TOUCH` requires four
discovery-plus-exact sessions. `DRIFT_BLOCKED_NO_REPAIR` admits two or four
sessions according to the stage that observed drift. Every other pairing is
rejected even when resealed.
Identity Center `ABSENT_READY` also requires an empty generated-role surface;
any `AWSReservedSSO_ScanalyzeAuthorityRetireApprove_*` or
`AWSReservedSSO_ScanalyzeAuthorityRetireClass_*` suffix is a collision. Exact
presence requires authority `PREEXISTING_NO_TOUCH` and exactly the two reviewed
roles. Each role has a 3600-second maximum session, the owner-pinned trust-policy
digest, no permissions boundary, attached managed policy or tags, and exactly
one inline policy whose digest equals both the corresponding permission set and
its rendered repository source. Missing, extra or mismatched roles fail closed;
this lane never treats them as eventual consistency and never repairs them.
That is inventory proof, not deployment or production acceptance. The handoff
still states `deployment_authorized=false`, `two_human_status=NOT_PROVEN`,
`independent_approval_present=false` and `production_status=NO-GO`.

The inventory, plan, completion, rollback and handoff are separate
digest-bound records. The rollback package is empty, non-automatic and
non-executable; it does not imply any compensating provider mutation. The v1
path never emits or accepts `LIVE`; the v2 path is limited to the GUG-392
read-only inventory contract. A future separately reviewed private orchestrator
must still rebuild all nine certifications from a private raw causal bundle;
repository or GUG-392 inventory evidence cannot be promoted. Offline CI records:

```text
GUG365_AWS_WRITES=0
GUG357_CREATE_STACK=0
GUG215_EFFECTS=0
GUG206_EFFECTS=0
AWS_CALLS_PERFORMED=0
AWS_MUTATIONS=0
PROVIDER_NETWORK_CALLS=0
production=NO-GO
```

A successful GUG-392 live run instead records a positive, transcript-equal
`AWS_CALLS_PERFORMED` count while retaining `AWS_MUTATIONS=0` and production
`NO-GO`.

GUG-377 repository completion neither marks GUG-376 Done nor unblocks or
executes GUG-365. It has zero effects on GUG-365, GUG-357, GUG-215 and GUG-206.
GUG-365 remains In Progress and must refresh provider state before compiling
its own fresh plan. GUG-392 can provide provider-backed read-only inventory and
owner checkpoint inputs, but live completion still requires the independently
reviewed mutation orchestrator, phase-specific authorization/verifier
checkpoints and consumer refresh. Preserve every legacy STOP code and
production **NO-GO**.

## References

- [ADR-053](../../ADR/ADR-053-gug365-upstream-prerequisites-materialization.md)
- [ADR-054](../../ADR/ADR-054-gug377-provider-backed-upstream-materializer.md)
- [Deployment contract](../deployment/platform-authority-gug365-upstream-prerequisites.md)
- [Threat model](../security/gug376-upstream-prerequisites-threat-model.md)
