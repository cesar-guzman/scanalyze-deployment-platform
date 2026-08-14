# ADR-053: GUG-365 Upstream Prerequisite Materialization

- **Status:** Proposed repository contract; not deployed
- **Date:** 2026-08-13
- **Implementation issue:** GUG-376
- **Consumer issue:** GUG-365
- **Amends:** ADR-051 and ADR-052 only for their external prerequisite handoff
- **AWS live validation:** None
- **Production:** **NO-GO**

## Context

GUG-365 compiles a deterministic plan for the bounded GUG-357 service-role
bundle. Its compiler deliberately consumes, but does not create, several live
provider inputs: an encrypted and versioned artifact bucket, a KMS key, one
AWS Signer profile version, one enforcing Lambda Code Signing Config, a manual
Python 3.12 runtime-version ARN, the two source IAM Identity Center permission
sets and their provisioned roles, the GUG-215 signed broker package, and a
separately signed GUG-365 ledger-factory package.

The consumer schemas validate those facts after they exist. They do not define
an authority that may improvise their creation. Treating an accepted name, a
repository digest or an exact-looking resource as sufficient live provenance
would let GUG-365 adopt unrelated state and would collapse source review,
mutation authorization and provider readback into one unauditable step.

GUG-376 therefore owns one upstream run that materializes and certifies only
those prerequisites. It does not compile or execute the GUG-365 bundle, run
the GUG-357 stack, invoke the GUG-215 broker or execute GUG-206.

## Decision

### 1. Keep the upstream product closed and non-production

The terminal GUG-376 handoff contains exactly:

1. one authority-owned S3 bucket with exact ownership controls, public-access
   block, versioning, KMS default encryption, bucket policy and tags;
2. one exact KMS key and alias with exact policy, rotation state and tags;
3. one immutable AWS Signer profile version for
   `AWSLambda-SHA384-ECDSA`;
4. one Lambda Code Signing Config with
   `UntrustedArtifactOnDeployment=Enforce` and exactly that profile-version
   ARN as its only allowed publisher;
5. one provider-backed Python 3.12 runtime-version ARN;
6. the exact Identity Center application, two fixed source permission sets,
   same-user assignments, provisioning receipts and generated
   `AWSReservedSSO_*` roles required by the single-operator mode;
7. one deterministic GUG-215 unsigned ZIP, one successful signing job and one
   distinct signed S3 object version;
8. one deterministic GUG-365 ledger-factory unsigned ZIP, a different
   successful signing job and a different signed S3 object version;
9. one private GUG-363 intent and one private GUG-363 plan that both retain
   `deployment_authorized=false` and `production=false`;
10. one private ledger-factory signing contract and an independently delivered
    expected digest; and
11. one digest-bound handoff to the original GUG-365 run.

Repository review, this ADR and the upstream plan are not AWS authorization.
The implementation PR must make no AWS call and must produce no live or private
customer evidence.

### 2. Separate owner-selected values from provider-generated values

A private `OWNER_DECISIONS_REQUIRED` record binds every value that current
source permits the owner to select, including the bucket name, KMS alias,
Signer profile name, Identity Center application label and loopback redirect
URI. Each entry contains the proposed value, source/schema constraints,
collision and no-touch evidence, impact, rollback or revocation boundary and a
canonical digest. Approval of this record approves parameters only. It does
not authorize a provider write.

AWS-generated identifiers are represented by typed **provider-generated
slots** in the immutable upstream plan. A slot declares:

- its stable name, type and validation pattern;
- the one phase and one canonical request allowed to produce it;
- the response and readback fields that must agree;
- all later consumers;
- whether the value is private and the digest projection permitted outside
  private custody; and
- its causal predecessor and expected readback digest.

A slot is empty when the plan is approved, is filled at most once, and becomes
usable only after an external transcript verifier proves matching typed
projections from both the write response and exact provider readback. The
private CAS ledger persists the digest-only verification record and projection
digests; the raw value remains transient. A later phase binds the
resolved-slot-record digest, not a caller-supplied replacement. Lost responses
do not permit another write.
Read-only reconciliation may fill a slot only when one unique provider object
is causally attributable to the consumed request and satisfies the complete
contract. Ambiguity leaves the slot unresolved and stops the run.

The principal slots are the KMS key ARN, application ARN, both permission-set
ARNs, assignment and provisioning request identifiers, both generated
`AWSReservedSSO_*` role ARNs, Signer profile version ID and ARN, Code Signing
Config ARN, both unsigned S3 version IDs, both signing-job IDs, and both signed
destination keys and version IDs. The runtime-version ARN is a separately
classified read-only provider fact, not the output of a GUG-376 mutation.

### 3. Execute exactly nine non-overlapping mutation phases

The upstream plan contains this ordered phase graph:

| Order | Phase | Closed effect surface | Required terminal output |
|---|---|---|---|
| 1 | `IDENTITY_CENTER_FOUNDATION` | Exact application configuration, fixed classifier/approver permission sets, inline policies, same-user assignments and provisioning only | Exact application, permission-set, assignment, provisioning and generated-role readback |
| 2 | `KMS_FOUNDATION` | One key, exact key policy, rotation, alias and tags only | Stable key/alias/policy/rotation/tag evidence |
| 3 | `S3_ARTIFACT_FOUNDATION` | One bucket and its exact ownership, public-access, versioning, encryption, policy and tags only | Stable complete bucket evidence bound to the KMS slot |
| 4 | `SIGNER_PROFILE_FOUNDATION` | One immutable signing-profile version only | Active exact version on `AWSLambda-SHA384-ECDSA` |
| 5 | `LAMBDA_CSC_FOUNDATION` | One enforcing Code Signing Config only | Exact single-publisher CSC evidence |
| 6 | `BROKER_UNSIGNED_PUBLISH` | One `PutObject` for the deterministic GUG-215 ZIP | Exact immutable unsigned object version |
| 7 | `BROKER_SIGNING_JOB` | One Signer job for the GUG-215 object | One successful job and exact distinct signed version |
| 8 | `LEDGER_FACTORY_UNSIGNED_PUBLISH` | One `PutObject` for the deterministic ledger-factory ZIP | Exact immutable unsigned object version |
| 9 | `LEDGER_FACTORY_SIGNING_JOB` | One different Signer job for the ledger-factory object | One successful job and exact distinct signed version |

A phase entry is never omitted. When two stable, complete snapshots plus
approved causal provenance prove exact state, the entry is sealed as
`EXACT_PRESENT_NO_TOUCH` with an empty write set and a no-touch receipt. An
exact-looking but non-causal resource is `PREEXISTING_NO_TOUCH` and blocks the
run. Partial, drifted, inaccessible or ambiguous state is never adopted or
repaired.

Each phase uses a new short-lived, unchained SSO session whose sole identity
grant and maximum-permissions cap are the phase policy. Identity Center
authority is never united with KMS, S3, Signer or Lambda authority. No phase
contains a GUG-365 IAM, Lambda, Logs or DynamoDB write.

### 4. Derive the runtime pin from a pre-existing Lambda version

GUG-376 must not create a probe function. The runtime-version source is one
owner-approved, pre-existing, published Lambda version in the same authority
account and `us-east-1`. Two stable read-only observations must prove:

- a published qualifier, never `$LATEST`;
- `Runtime=python3.12` and the package architecture required by both manifests;
- `RuntimeManagementConfig.UpdateRuntimeOn=Manual`;
- one non-empty `RuntimeVersionArn` returned by Lambda for that exact version;
- unchanged function/version identity and runtime configuration between
  snapshots; and
- approved provenance showing why this version is an eligible runtime source.

The private runtime-evidence record binds the source version, both observation
times, normalized provider facts and the runtime-version ARN. Public output
contains only its digest. A fixture, copied ARN, documentation example,
unqualified function or automatically managed runtime is invalid. If no
approved source exists, the only result is
`STOP_RUNTIME_PIN_SOURCE_NOT_PROVEN`.

### 5. Preserve the single-operator truth in Identity Center

The two source permission sets are exactly
`ScanalyzeAuthorityRetireClass` and `ScanalyzeAuthorityRetireApprove`. Their
inline policies are rendered only from the repository policy sources. The
application actor policy is rendered only from its repository template.
Managed-policy attachments, customer-managed policy references, permission
boundaries, group assignments, additional users and additive grants are
forbidden.

Under `SINGLE_OPERATOR_NONPROD_EXCEPTION`, both permission sets and the exact
application assignment bind the same immutable Identity Store UserId. The two
permission sets and generated account-local roles remain distinct. Every plan,
receipt and handoff records:

```text
authorization_mode = SINGLE_OPERATOR_NONPROD_EXCEPTION
two_human_status = NOT_PROVEN
independent_approval_present = false
production = false
```

Two sessions, two permission sets or two role suffixes do not prove two people.
GUG-376 does not materialize `ScanalyzeGug357IdentityAudit`, execute GUG-361 or
claim normal `TWO_HUMAN` readiness.

### 6. Bind both signed packages to one supply-chain foundation

Both unsigned packages are rebuilt from the exact clean reviewed commit with
their existing repository entrypoints. The build has zero AWS calls. Their
manifests bind the same reviewed runtime-version ARN but distinct source sets,
handlers, archive digests and Lambda `CodeSha256` values.

The two signing contracts require:

- the same bucket and KMS key for source and destination;
- the same exact Signer profile version and enforcing Code Signing Config;
- different unsigned keys and version IDs;
- different signing-job IDs;
- different signed destination keys and version IDs;
- each job `Succeeded`, with exact owner, invoker, platform and unexpired
  signature evidence;
- unsigned and signed outer ZIP digests to differ while member names and
  member bytes remain semantically equivalent; and
- no extra object versions, delete markers, publishers or jobs in the closed
  target projection.

Unsigned objects are signing inputs only. GUG-363 and GUG-365 may consume only
the exact signed destinations.

### 7. Keep private custody causal and single-run

GUG-376 uses one owner-authorized absolute local root outside Git and synced
storage. The root is owner-owned mode `0700`; files are regular, one-link mode
`0600`; paths contain no symlink; and updates use a same-directory temporary
file, flush, `fsync`, atomic replacement and directory `fsync`.

The existing GUG-365 evidence root is reference-only. It is never used for new
upstream artifacts. Exactly one upstream run and one append-only/CAS attempt
ledger are allowed. A partial or uncertain run is resumed or reconciled; a
second run cannot be opened to regain an attempt.

Private records contain raw provider identifiers and responses only when
required for verification. GitHub, Git and Linear receive sanitized digests,
counts and classifications, never UserIds, emails, account identifiers,
private ARNs, tokens or provider payloads.

### 8. Stop before every phase and consume one attempt before every write

Every planned write binds its phase, sequence, API action, canonical request
digest, target and configuration digests, expected readback digest,
executor-policy digest, phase-operation digest, phase-mutation digest, causal
predecessor and rollback or revocation boundary.

Immediately before a phase's next executable request batch, the operator
obtains a fresh owner authorization valid for no more than fifteen minutes and
bound to the resolved slots, exact session/caller evidence, exact request
digests and the complete template write-set digest. A provider output needed
by a later operation ends the current batch; readback and CAS slot resolution
precede a new authorization for that later request in the same phase. A valid
response names the exact phase and authorization digest. “Proceed”, a merge,
an earlier authorization or approval of owner decisions is invalid.

The current branch never reaches this response/CAS boundary. Public operation,
authority and authorization builders stop with
`STOP_UPSTREAM_SOURCE_CONTRACT_GAP`, and the runner module contains no provider
callback, credential adapter, CAS adapter or write-capable simulation helper.

A future separately reviewed private orchestrator must receive the complete
raw causal bundle, opaque provider receipts, an injected external verifier and
an out-of-band trust anchor in the same call. It must make
`sts:GetCallerIdentity` the first signed call, consume one attempt in a durable
ledger before each write, disable SDK retries and persist response/readback
evidence before continuing. Until that source change exists, no owner response
can authorize a GUG-376 write and any live promotion also remains blocked by
`STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED`.

A timeout, lost connection, malformed response or stale `in-flight` record is
`UNCERTAIN_RECONCILE_ONLY`. A different read-only session may reconcile the
consumed request. The runner never blindly retries, repairs, deletes, recreates
or automatically rolls back a provider resource.

### 9. Hand off facts, never authority

Only after all nine phases and complete signed readback may the same private
run build the GUG-363 intent, build the GUG-363 plan with its existing
repository command and build the ledger-factory signing contract. Expected
digests are delivered over an independent channel. The GUG-363 plan retains:

```text
deployment_authorized = false
production = false
authorization_mode = SINGLE_OPERATOR_NONPROD_EXCEPTION
two_human_status = NOT_PROVEN
independent_approval_present = false
```

The terminal handoff binds the upstream run/plan/final/ledger digests, source,
owner decisions, runtime evidence, Identity Center readback, KMS/S3/Signer/CSC
readbacks, both package/job/signing-contract digests and the original GUG-365
run/gap digests. It explicitly records zero GUG-365, GUG-357, GUG-215 and
GUG-206 effects.

The original GUG-365 run must perform a fresh read-only checkpoint before it
compiles its own plan. This handoff is not authorization for that plan or for
any later AWS write.

## Rollback and recovery

Before a live authorization, rollback is an ordinary reviewed Git revert and
has no AWS effect. After a phase writes, there is no automatic rollback.
Disable or expire the phase session, preserve the private ledger and provider
state, and classify the result through read-only reconciliation.

Removing an Identity Center assignment, disabling a KMS key, deleting an
alias, bucket, object, signing profile or Code Signing Config, or otherwise
contracting provider state is a new mutation package with a fresh owner
decision, complete blast-radius evidence and its own authorization. GUG-376
does not delete signed evidence, schedule key deletion, suspend versioning,
overwrite objects, revoke a profile version or recreate an ambiguous target.

An exact completed prerequisite may be revoked only through such a separately
reviewed forward action. A partial or uncertain state leaves GUG-376 In
Progress and GUG-365 blocked.

## Rejected alternatives

- **Create a probe Lambda to discover a runtime ARN.** Rejected because it adds
  an unreviewed mutation and circular runtime provenance.
- **Use one broad administrator or union phase session.** Rejected because it
  defeats least privilege and phase attribution.
- **Adopt an exact-looking pre-existing resource.** Rejected without complete
  approved causal provenance.
- **Treat two roles as two humans.** Rejected; the accepted exception requires
  the same UserId and records independence as not proven.
- **Let the plan fill arbitrary provider identifiers.** Rejected in favor of
  typed, single-assignment provider slots.
- **Retry an ambiguous write or start another run.** Rejected because it breaks
  at-most-once evidence.
- **Reuse the GUG-365 private root.** Rejected because producer and consumer
  custody must remain distinct.
- **Compile or apply GUG-365 in the upstream task.** Rejected as an ownership
  and authorization violation.

## Consequences

- GUG-376 becomes the sole owner of the upstream live foundation and signed
  package handoff.
- The current implementation is intentionally a source-gap checkpoint, not an
  executable materializer. A future complete implementation must add the
  reviewed missing contracts and a separate runner before any live phase can
  be considered executable.
- The public CLI accepts only zero-effect phase-authorization and final-handoff
  STOP checkpoints. Other serialized records are schema/test scaffolding and
  cannot establish provider, runtime or private-root authority; the CLI reports
  each as `NOT_PROVEN`, and their public Python builders and validators stop.
  `LIVE` is a reserved future state and is neither emitted nor accepted by this
  branch.
- The workflow is slower because every phase has a new session and owner
  checkpoint, but ambiguous effects cannot silently gain another attempt.
- Provider-generated values remain usable without pretending they were known
  before creation.
- Production and normal two-human operation remain blocked.

## Evidence classification

- This ADR and its companion documents: `PROPOSED`.
- Repository review and tests: `REPOSITORY_VALIDATED_NO_LIVE_EXECUTION` at
  most.
- Phase authorization/execution: `STOP_UPSTREAM_SOURCE_CONTRACT_GAP`.
- Live evidence promotion: `STOP_LIVE_ORCHESTRATOR_NOT_IMPLEMENTED` pending a
  separately reviewed private causal verifier/orchestrator.
- Upstream provider state: `NOT_PROVEN` until separately authorized phases and
  terminal readback complete.
- GUG-365, GUG-357, GUG-215 and GUG-206 effects: `BLOCKED` / none.
- Production: **NO-GO**.

## References

- [ADR-050](ADR-050-single-operator-nonprod-change-set-retirement.md)
- [ADR-051](ADR-051-direct-retirement-entrypoint-materialization.md)
- [ADR-052](ADR-052-gug357-cloudformation-service-role-boundaries.md)
- [GUG-376 deployment contract](../docs/deployment/platform-authority-gug365-upstream-prerequisites.md)
- [GUG-376 operations runbook](../docs/operations/platform-authority-gug365-upstream-prerequisites.md)
- [GUG-376 threat model](../docs/security/gug376-upstream-prerequisites-threat-model.md)
