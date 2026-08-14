# Runbook: GUG-376 upstream prerequisites for GUG-365

## Current status and hard boundary

This runbook records the GUG-376 repository contract and its mandatory source
gap stop. The current branch intentionally has no executable/live runner,
provider callback, AWS client or live ledger adapter; its runner module is an
inert STOP shim. Do not translate the reserved future steps below into ad hoc
AWS CLI/SDK calls.

This PR is offline and makes **zero AWS calls**. Neither the PR, ADR, Linear
status, upstream plan nor an owner-decision approval authorizes AWS writes.
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

### Deterministic package build

With all AWS credential variables absent and network/provider construction
blocked:

1. rebuild the GUG-215 package only through
   `scripts/deployment/platform-authority-change-set-retirement-package.py`;
2. rebuild the ledger-factory package only through
   `scripts/deployment/platform-authority-retirement-entrypoint-service-role.py package`;
3. validate source commit/tree, manifests, member names and bytes, archive
   determinism, archive SHA-256, Lambda `CodeSha256`, runtime binding,
   exception/broker bindings and zero AWS calls; and
4. store packages and manifests only in the approved private root.

Synthetic fixtures are negative-test inputs, never live packages.

## Reserved common phase protocol

The current branch does not execute or simulate this protocol. The following
sequence is reserved design input for a future separately reviewed private
live orchestrator after current-main source gaps are closed. Before its first
phase, that orchestrator must compile the
immutable private upstream plan with the exact nine-phase graph and typed
provider slots. Every phase remains present; exact preexisting state produces
a zero-write `EXACT_PRESENT_NO_TOUCH` receipt. For each mutation phase and
contiguous exact request batch:

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

The exported runner entry point stops before validation, CAS or a provider
callback with `STOP_UPSTREAM_SOURCE_CONTRACT_GAP`. The module contains no
private write-capable simulation helper. Supplying an external/live transcript
additionally remains blocked by `STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED`.

The missing source contracts are explicit: asynchronous Identity Center
request/poll results and both generated role ARNs; exact KMS artifact-use and
S3 bucket policies; causal S3 VersionId, Signer jobId, signed-key and signed
VersionId projections; and a private raw-bundle orchestrator. Consequently the
public phase-authorization schema is a STOP checkpoint only and fixes
`deployment_authorized=false`, `owner_authorization_issued=false` and all AWS
effect counters to zero.

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
| Before any phase write | Expire session; reviewed Git revert | Any AWS cleanup |
| Conclusive exact phase | Preserve state/evidence; continue only with next fresh authorization | Reuse session or phase authorization |
| Partial phase | Stop; open separately reviewed recovery/revocation package | Inline repair or compensating delete |
| Ambiguous phase | Read-only reconciliation only | Retry, substitute target or new run |
| Exact completed upstream | Fresh read-only consumer checkpoint; separately authorize any future revocation | Treat handoff as GUG-365 authority |

KMS disable/deletion, bucket/object deletion, versioning suspension, Signer
revocation, CSC deletion and Identity Center deassignment/deprovisioning are
new mutations. None is automatic rollback.

## Terminal checkpoint

Repository tests may publish only the zero-effect
`STOP_UPSTREAM_SOURCE_CONTRACT_GAP` checkpoint. It is classified
`REPOSITORY_VALIDATED_NO_LIVE_EXECUTION`; `LIVE` is neither emitted nor
accepted. Its write-count list is empty, its total is zero, and it explicitly
records zero signing jobs and no distinct-job/object proof. A future separately
reviewed private orchestrator must rebuild all nine certifications from the raw
causal bundle; this checkpoint cannot be promoted. It records:

```text
GUG365_AWS_WRITES=0
GUG357_CREATE_STACK=0
GUG215_EFFECTS=0
GUG206_EFFECTS=0
production=NO-GO
```

GUG-376 may move to Done only after the private handoff and sanitized manifest
are complete. GUG-365 remains In Progress and must refresh provider state
before compiling its own fresh plan. If any gate remains incomplete, preserve
GUG-376 In Progress, retain GUG-365 as blocked and report the exact stop code
and one next required action.

## References

- [ADR-053](../../ADR/ADR-053-gug365-upstream-prerequisites-materialization.md)
- [Deployment contract](../deployment/platform-authority-gug365-upstream-prerequisites.md)
- [Threat model](../security/gug376-upstream-prerequisites-threat-model.md)
