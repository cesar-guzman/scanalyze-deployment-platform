# GUG-376 threat model: upstream prerequisites for GUG-365

## Scope

This model covers the proposed GUG-376 control plane for creating and
certifying the non-production Identity Center, KMS, S3, AWS Signer, Lambda Code
Signing Config and signed-package prerequisites consumed by GUG-365. It also
covers the GUG-377 repository-only v2 inventory, 30-operation/nine-phase plan,
scripted materialization and final handoff. The GUG-376 v1 STOP contracts remain
unchanged and are not interchangeable with v2 records.

GUG-377 exercises typed provider-generated projections, bounded polling,
one-attempt CAS, uncertainty reconciliation and separate completion/rollback/
handoff records using only an inert default adapter or deterministic scripted
test adapter. It does not implement private causal custody, provider-backed
execution or live certification.

It excludes GUG-365 IAM/Lambda/Logs/DynamoDB materialization, GUG-357
`CreateStack`, GUG-215 broker invocation or Change Set effects, GUG-206,
GUG-361, Terraform, customer accounts/data, staging and production.

The repository artifacts are proposed controls only. This PR has no AWS
authority, performs no AWS call or provider network call, and neither creates
nor reads a private evidence root. Production is **NO-GO**.

## Security objectives

1. Create only the exact upstream resources required by current reviewed
   source, under non-overlapping least-privilege authorities.
2. Prevent caller-chosen or stale provider identifiers from entering the
   GUG-365 plan.
3. Preserve at-most-once evidence across every provider write and ambiguous
   response.
4. Authenticate the two deterministic source archives through one exact
   KMS/S3/Signer/CSC foundation without confusing unsigned and deployable
   artifacts.
5. Bind Identity Center to the one real single operator without claiming
   independent human approval.
6. Keep raw provider identity, topology and evidence outside Git and Linear.
7. Hand provider facts to GUG-365 without transferring mutation authority.

## Protected assets

- exact reviewed source commit/tree and repository policy/template bytes;
- owner-decision and phase-authorization digests;
- private account, caller, UserId, application, permission-set and role data;
- KMS key policy/material boundary and S3 encrypted/versioned object custody;
- immutable Signer profile version and both signing jobs;
- enforcing single-publisher Code Signing Config;
- provider-backed Python 3.12 runtime-version evidence;
- both deterministic unsigned manifests/archives and signed destinations;
- provider-generated slot records and the private CAS attempt ledger;
- GUG-363 intent/plan, ledger-factory signing contract and independent expected
  digests; and
- the terminal GUG-365 handoff.

## Trust boundaries

### Repository to private custody

Git contains source contracts and tests, not live identifiers, owner
authorizations, provider responses or signed artifacts. The exact clean Git
object is rebuilt into one owner-only, non-synced root. The existing GUG-365
root is a separate read-only consumer boundary.

### Owner decision to mutation authorization

Approval of names/parameters establishes intent only. Each mutation phase has
a different short-lived authorization bound to its exact write set, session,
before-state, resolved predecessor slots and ledger root. A plan cannot
authorize itself.

### Identity Center management boundary to authority account

Application, permission-set and provisioning writes occur only under the
management/delegated-administrator boundary. KMS, S3, Signer, CSC and Lambda
readback occur under the authority account. No phase session spans both
boundaries or combines their permissions.

### Provider response to provider-generated slot

An AWS-returned identifier is untrusted until an external verifier pinned by
identity and attestation-root digests proves the exact producer transcript and
matching typed projections from both its permitted write response and complete
readback. The private ledger resolves its typed slot once. Later phases accept
the slot-record digest, not a raw caller value.

### Repository adapter to live provider

The v2 `ProviderAdapter` is a closed typed interface for before-state
observation, one mutation result, polling and read-only reconciliation. It has
no generic `execute` method or raw `payload` channel. The inert adapter is the
default; the scripted adapter is admitted only as a deterministic repository
test double. Construction of a live adapter always stops with
`STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED`. Scripted result digests are never
provider identity, authorization, runtime or private-root evidence.

### Runtime evidence boundary

The runtime-version ARN comes only from stable read-only Lambda evidence for
one approved pre-existing published Python 3.12 version under manual runtime
management. GUG-376 has no runtime-probe mutation path.

### Unsigned to signed artifact boundary

Unsigned ZIPs are deterministic signing inputs. Only exact Signer outputs that
pass byte/member, version, KMS, job, profile and CSC readback are eligible for
GUG-363/GUG-365. Outer signed bytes are expected to differ from source bytes.

### Upstream handoff to GUG-365

The handoff contains facts and digests. The original GUG-365 run independently
refreshes provider state and compiles a fresh plan; it cannot inherit GUG-376
authorization or attempt state.

## Principal attack paths

### Identifier substitution

An attacker replaces a plan field with another key, bucket, profile, CSC,
application, role, job or object version that satisfies a superficial ARN or
name pattern. Typed single-assignment slots, producer/request binding and
complete readback reject the substitution before any consumer phase.

### Authority union

A broad profile could create Identity Center topology and artifact/signing
resources in one session, bypassing phase causality and making unexpected
state difficult to attribute. The design requires a fresh SSO session, sole
phase identity grant and identical maximum-permissions cap for every phase.

### Ambiguous retry

A lost response after a successful create could cause a second key, job,
assignment, object version or other effect. The private ledger records
`in-flight` before the call, SDK retries are disabled and unknown outcomes are
read-only reconcile-only.

### False two-human claim

The two distinct permission sets and generated role suffixes could be reported
as duty separation even though one human owns both assignments. The contract
requires the same immutable UserId and persists `two_human_status=NOT_PROVEN`
and `independent_approval_present=false` in every downstream record.

### Runtime pin laundering

A copied fixture or newly created probe function could supply a syntactically
valid runtime ARN without reviewed provenance. The source must be an approved
pre-existing published Lambda version, read twice under manual Python 3.12
runtime management. No GUG-376 mutation can create the evidence source.

### Synthetic evidence promotion

An attacker labels a scripted completion or synthetic object/job projection as
provider-backed. The v2 handoff fixes
`evidence_scope=REPOSITORY_VALIDATED_SYNTHETIC_ONLY`,
`provider_certification_complete=false`, `live_provider_evidence=false` and a
live STOP. Its two synthetic signing jobs validate only inequality and
operation contracts; live job/object proof remains false.

## Threats and controls

| Threat | Control | Failure behavior |
|---|---|---|
| Source advances or reviewed tree is replaced | Exact remote/local source, review/check and clean-tree binding | `STOP_SOURCE_DRIFT` before AWS login |
| Private evidence is written into the GUG-365 root or synced storage | New explicitly approved root; owner/mode/link/atomic-write checks | `STOP_UPSTREAM_PRIVATE_ROOT_NOT_AUTHORIZED` |
| Owner-selected name collides with existing state | Two stable complete inventory snapshots and decision-record digest | `PREEXISTING_NO_TOUCH` or drift stop |
| Plan invents an ARN/ID that AWS has not returned | Typed empty provider slot with one producer and no default | Plan validation failure |
| Lost response is used to fill a slot from a list result | Unique causal request/readback proof and CAS resolution required | Slot remains unresolved; reconcile-only |
| Slot is overwritten after a later list/read | Single-assignment slot record and ledger-root chaining | Replay/drift rejection |
| Generic administrator or union profile is substituted | Exact phase policy as sole identity grant and identical cap; effective-authority readback | Stop before ledger claim |
| A process fabricates the deterministic owner response locally | Owner-controlled external-channel verifier receipt bound to owner identity, phase, response, authorization and validity window; no permissive repository verifier | Stop before ledger claim |
| A caller wires the v1 runner or v2 materializer to AWS | The v1 runner remains an unconditional source-gap STOP; v2 accepts only inert/scripted typed adapters and live construction always stops | `STOP_UPSTREAM_SOURCE_CONTRACT_GAP` or `STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED` before provider I/O |
| A process fabricates provider session, response or readback digests | Scripted outputs are causal digest projections with repository-only classification; external/live transcripts require a future private raw-bundle verifier/orchestrator | Handoff remains live STOP; no provider certification |
| Synthetic fixtures are promoted as provider/runtime/private-root proof | Inventory, completion and handoff identify scripted/synthetic scope, zero calls/network and absent live evidence/private root | Claim rejected; production remains `NO-GO` |
| A generic adapter method smuggles an unreviewed action or raw payload | Closed adapter methods and typed operation/result projections; no generic `execute` or `payload` interface | Contract/test failure before materialization |
| An operation is skipped, duplicated or reordered | Exact nine-phase/30-operation global sequence, unique operation ID/kind and immediate-predecessor dependency | Plan or materialization failure before later operation |
| A v1 record is substituted for v2, or a future version is accepted | Distinct record types and `schema_version`; v1/v2 cross-substitution and unsupported versions are rejected | Validation failure; no migration-by-guessing |
| A terminal ledger is resealed or its in-flight boundary is hidden | Trusted owner-only append-only store, full history validation, predecessor hash chain and CAS read-after-write | Stop before any provider callback |
| STS identity is not the first signed call | Session protocol and client-construction guard | No provider client/write |
| Phase authorization is stale or belongs to another phase | Exact phase/digest/window/caller/write-set binding; revalidate before each write | Stop with current state preserved |
| SDK/provider retries duplicate a write | Per-operation attempt limit one, SDK retry count zero and CAS consumed before the scripted/live call | `UNCERTAIN_RECONCILE_ONLY`; rerun rejected |
| Exact-looking pre-existing resource is adopted | Approved causal provenance required for `EXACT_PRESENT_NO_TOUCH` | `PREEXISTING_NO_TOUCH` |
| Partial bucket/key/application/permission-set state is repaired inline | Closed before-state classifications and no repair/delete authority | `DRIFT_BLOCKED_NO_REPAIR` |
| KMS policy grants unrelated principal/action | Canonical complete policy digest, exact phase principals and full readback | No certification; separate recovery |
| Bucket permits public, ACL, unencrypted, unversioned or foreign access | Bucket-owner enforcement, full PAB, versioning, KMS encryption and exact policy/readback | No object phase begins |
| Signer profile uses wrong platform/version or extra version | One immutable `AWSLambda-SHA384-ECDSA` version slot and closed inventory | No CSC/job phase |
| CSC uses `Warn` or multiple publishers | Exact `Enforce` and one resolved profile-version ARN | No artifact handoff |
| Unsigned object is passed as deployable code | Separate source/destination types and schema-constrained signed keys | Contract validation failure |
| Object is overwritten or null-versioned | Versioning gate, fixed key, one put, non-null version slot and exact bytes | Reconcile-only or drift stop |
| Both packages reuse a job or signed object | Cross-contract inequality for job IDs, keys and version IDs | Terminal signing validation failure |
| Signed archive contents are changed | Outer digest/readback plus semantic member-name/byte equality | No signing contract |
| Signature expires before downstream window | Exact expiry bound to later authorization window | Handoff blocked/refresh through new reviewed lane |
| Runtime ARN is copied from fixture/docs | Pre-existing published-version provider evidence and exact digest | `STOP_RUNTIME_PIN_SOURCE_NOT_PROVEN` |
| Probe Lambda is created to discover runtime | No Lambda write in any phase policy/plan | AWS deny and contract failure |
| Identity Center binds two users in exception mode | Same immutable UserId invariant across application and both assignments | Phase/readback failure |
| Roles are treated as proof of two humans | Explicit non-independence fields and one-user evidence | Claim rejected |
| Extra group/user/application assignment exists | Closed assignment inventory and direct-user count | `DRIFT_BLOCKED_NO_REPAIR` |
| Permission set gains managed/additive policy | Exact inline source, empty attachment/reference/boundary sets and IAM role readback | No certification |
| Async Identity Center or Signer output is inferred from a digest | v2 provides typed result projections and closed polling policies with finite attempts/time/backoff and closed statuses | `UNKNOWN`, failure or timeout is reconcile-only; never inferred success |
| Synthetic KMS/S3/Signer target state is treated as provider truth | v2 closes repository target/result contracts but marks before/target/results synthetic and provider certification false | Live STOP; AWS mutations remain zero |
| GUG-357 audit permission set is created | Explicit resource/action exclusion | Authorization/plan failure |
| Private UserId, email, ARN or payload reaches Git/Linear | Private/public schemas and sanitized digest-only manifest | Publication blocked; incident handling required |
| A local absolute path, account ID, UserId, ARN, signed URL or provider payload leaks through v2 output | Public records are closed and digest-only; forbidden value scans cover `/Users/`, account/identity values, `arn:`, signed URLs and payload fields | Serialization/validation failure; artifact not published |
| A rollback record is interpreted as authority to delete provider state | Completion and rollback/revocation packages are distinct; v2 rollback is empty, non-automatic, non-executable and unauthorized | No cleanup; separately reviewed recovery lane required |
| GUG-376 handoff is treated as GUG-365 authorization | Consumer must run a fresh checkpoint and plan; explicit zero-effect flags | GUG-365 remains blocked |
| Cleanup destroys ambiguous evidence | No automatic rollback/delete and separate recovery authorization | Preserve state and ledger |

## Mandatory negative tests

GUG-377 repository tests are offline, make no provider connection and cover the
v2 contracts below. Future live tests remain separately reviewed and
read-only where possible:

- wrong account, Region, issue, source head/merge/tree or private-root digest;
- missing, expired, wrong-phase, replayed or self-derived authorization;
- additive executor policy, role chaining, session reuse or authority overlap;
- slot type/producer/consumer mismatch, second assignment, unresolved slot,
  response/readback mismatch and resealed ledger;
- absent/incomplete pagination, repeated token, AccessDenied and timeout
  misclassified as absence;
- wrong KMS policy/alias/rotation/tag, bucket owner/PAB/versioning/encryption/
  policy/tag, or unexpected access surface;
- wrong Signer platform/profile/version, second profile version, failed/foreign/
  reused job or expired signature;
- CSC `Warn`, zero publishers, extra publisher or a different profile version;
- wrong key/version/KMS/checksum/size, null version, delete marker, ZIP tampering,
  unsigned-as-signed, reused signed destination and extra closed-scope object;
- runtime `$LATEST`, auto management, wrong runtime/architecture, fixture ARN,
  changed snapshots or unapproved source version;
- alternate application/redirect/grant/scope/actor, extra assignment, group,
  different UserIds, false two-human claim or wrong generated role;
- managed/customer policy attachment, permission boundary, relay state or
  additional permission-set provision;
- ambiguous response followed by a retry, repair, delete, substitute target or
  second run;
- GUG-365/GUG-357/GUG-215/GUG-206 action appearing in any phase policy or
  request;
- skipped, duplicated, reordered or dependency-invalid operations across the
  exact 30-operation/nine-phase sequence;
- unbounded polling, unknown terminal state, timeout, SDK retry or second CAS
  attempt;
- inert-default and live-construction stops, any generic adapter action/payload
  escape hatch and any socket/SDK/provider import side effect;
- v1/v2 cross-substitution, unsupported schema versions and digest mismatch;
- public ARN/account/UserId/signed URL/provider payload/private-root leakage;
  and
- completion/rollback digest substitution or executable/automatic rollback.

## Residual risks

- Many provider APIs do not accept an idempotency token. The consumed ledger
  and reconciliation rules limit retries but cannot make an AWS create
  transactionally atomic with the local CAS record.
- S3, IAM Identity Center, IAM role provisioning, Signer and tag/list APIs may
  be eventually consistent. Two stable reads reduce but do not eliminate this
  risk.
- A pre-existing Lambda version is a trusted provenance dependency. Its
  runtime-version ARN is provider-backed but the function was not created by
  this run; owner approval and stable evidence remain essential.
- Direct provider creates cannot enforce a local request digest server-side.
  Short-lived least-privilege authority, exact target constraints, CloudTrail
  and readback are the governance boundary.
- A control-plane administrator can later alter resources. GUG-365 must refresh
  every prerequisite immediately before compiling its own plan.
- Single-operator mode deliberately lacks independent human approval. It is
  accepted only for the bounded internal non-production path and is never
  sufficient for production.
- Recovery may leave non-effect-capable but billable provider resources. Any
  cleanup requires a new reviewed destructive lane.

None of these residual risks is accepted for production.

## Evidence and stop classification

- GUG-376 v1 documentation, CLI and repository tests:
  `REPOSITORY_VALIDATED_NO_LIVE_EXECUTION` and
  `STOP_UPSTREAM_SOURCE_CONTRACT_GAP` at most.
- GUG-377 v2 source contracts: `REPOSITORY_SOURCE_CONTRACTS_CLOSED`; a
  successful scripted run may be `SYNTHETIC_MATERIALIZATION_COMPLETE` only.
- GUG-377 final handoff:
  `status=STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED`,
  `state=SOURCE_CONTRACTS_CLOSED_REPOSITORY_ONLY`,
  `provider_certification_complete=false` and
  `live_provider_evidence=false`.
- Local unmerged source contract: repository evidence only; no live authority,
  private custody or provider truth.
- Missing separately reviewed private live orchestrator:
  `STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED`.
- Missing approved runtime source: `STOP_RUNTIME_PIN_SOURCE_NOT_PROVEN`.
- Missing private root: `STOP_UPSTREAM_PRIVATE_ROOT_NOT_AUTHORIZED`.
- Ambiguous consumed write: `UNCERTAIN_RECONCILE_ONLY`.
- Partial/drifted target: `DRIFT_BLOCKED_NO_REPAIR`.
- AWS calls, AWS mutations, provider network calls and
  GUG-365/GUG-357/GUG-215/GUG-206 effects: zero and blocked.
- Human separation: `two_human_status=NOT_PROVEN` and
  `independent_approval_present=false`.
- Production: **NO-GO**.

## References

- [ADR-053](../../ADR/ADR-053-gug365-upstream-prerequisites-materialization.md)
- [ADR-054](../../ADR/ADR-054-gug377-provider-backed-upstream-materializer.md)
- [Deployment contract](../deployment/platform-authority-gug365-upstream-prerequisites.md)
- [Operations runbook](../operations/platform-authority-gug365-upstream-prerequisites.md)
