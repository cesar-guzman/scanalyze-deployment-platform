# ADR-030: Deployment Registry, Account Baseline, Backend, and Locking

- **Status:** Proposed; accepted only after reviewed merge and main verification
- **Date:** 2026-07-14
- **Work package:** GUG-122
- **Baseline:** `82fd2c7156f88897ca78af3ba0b54ee8921a4f40`
- **Program:** GUG-115
- **Upstream:** GUG-84, GUG-109, GUG-121, ADR-003, ADR-004
- **Downstream gates:** GUG-123, GUG-124, GUG-125
- **Live validation:** No
- **AWS activity:** None

Production: **NO-GO**

## Context

The legacy deployment manifest accepted a caller-supplied Terraform bucket,
key prefix, lock table, and KMS alias. Most roots did not declare an S3 backend,
the local plan wrapper initialized with `-backend=false`, and backend examples
still selected the deprecated DynamoDB locking path even though ADR-003 chose
S3-native lockfiles. `ACCOUNT_READY` v1 did not bind customer, environment,
state security controls, role customer tags, or exact state coordinates.

Those gaps allowed a valid-looking request to select an unapproved account,
region, bucket, key, or legacy lock mechanism. The registry IAM fixture also
permitted table scans and the recovery role could delete arbitrary objects
below a deployment prefix.

## Decision

### 1. Requests never establish backend authority

Deployment manifest v2 contains intent and target assertions, but no
`terraform_backend` field. Manifest v1 remains parseable only for explicit
legacy analysis; the operational backend authorizer accepts v2 exclusively.
Account, region, customer, deployment, and environment assertions must equal
the approved deployment target and `ACCOUNT_READY` v2.

### 2. Registry records are content-addressed and externally anchored

An approved deployment target binds the exact customer, deployment, account,
region, environment, lifecycle status, registry version, ACCOUNT_READY digest,
state bucket ARN, and KMS key ARN. Its canonical digest must equal a separate
anchor retrieved from the approved registry path. A self-consistent request
record without that independent version/digest anchor is denied.

Registry creation uses `attribute_not_exists(deployment_id)`. Updates use an
exact version/digest compare-and-swap, increment by one, preserve every
ownership/backend field, and follow the reviewed status state machine. Table
scan, delete, ownership reassignment, silent re-registration, and arbitrary
attributes are not authorized.

### 3. ACCOUNT_READY v2 proves the baseline

`ACCOUNT_READY` v2 binds both customer and deployment plus account, region,
environment, baseline version, eight role ARNs and their customer, deployment,
account, region, and environment resource tags, the three buckets, the three
KMS keys, and these exact state controls:

- versioning enabled;
- default SSE-KMS with bucket keys;
- all public access blocked;
- Object Lock disabled on the state bucket so native lockfiles can be deleted;
- S3-native lockfiles enabled.

Missing, legacy, malformed, foreign, ambiguous, or conflicting baseline
evidence is denied. No bucket name, prefix, role, or KMS key is inferred.

### 4. Backend configuration is derived, private, and temporary

The canonical DAG owns each state-key template. The authorizer permits exactly
one Terraform layer and derives its key from the approved deployment and region.
The generated backend uses `encrypt=true`, the exact KMS key, S3-native
`use_lockfile=true`, and one `allowed_account_ids` entry. It never emits a
DynamoDB lock table.

The backend file and full binding are owner-only temporary files outside the
repository. The plan wrapper deletes them on success, error, or signal and
does not print bucket names, state keys, KMS ARNs, registry contents, or lock
records.

### 5. Locking has two independent scopes

The S3 `.tflock` object protects each Terraform state key. A deployment-level
execution lock additionally prevents two release executions from operating on
the same deployment across layers. It is bound to the deployment, account,
region, execution ID, owner, registry digest, expiry, version, and canonical
lock digest.

Acquisition is conditional. Locks have a five-to-sixty-minute TTL, cannot be
future-dated, and must be time-zone aware. An unexpired held lock denies a
concurrent run. An expired held lock is not stolen or cleared automatically;
reviewed stale-lock recovery is mandatory. A released lock may be reacquired
only with the exact prior version. The live conditional storage adapter remains
part of GUG-125; GUG-122 defines and tests the contract and fail-closed
transition model.

The v2 target and baseline schemas accept AWS partition prefixes with multiple
segments, including `aws-us-gov`; no commercial-partition ARN is inferred.

### 6. Recovery cannot become deployment authority

StateRecovery can list/read/restore only bound state objects, and it can delete
only the exact `.tflock` object under recovery session tags. Every session
requires an incident identifier; `.tflock` deletion additionally requires
`recovery_approved=true`. It cannot delete state, scan the registry, reassign
ownership, apply Terraform, or automatically force-unlock. State restoration
always requires a subsequent reviewed reconciliation plan. GUG-123 must prove
which identity may issue the approval tag before this becomes a live control.
ADR-031 now defines that candidate human-only trust; live issuance remains
unvalidated.

## Security consequences

- Cross-customer, cross-deployment, cross-account, cross-region, and
  cross-environment backend selection fails before Terraform initialization.
- A forged but internally consistent registry record fails its independent
  anchor check.
- A key collision or path traversal cannot be materialized from the DAG.
- A missing, released, expired, foreign, or altered execution lock denies the
  operation without revealing backend coordinates.
- Hashes prove integrity, not writer identity. ADR-031 defines the candidate
  OIDC, Environment, platform-authority, and IAM chain; authorized live GitHub
  and AWS validation is still required before a runner may consume these
  contracts.

## Migration and compatibility

No automatic conversion of manifest v1, `ACCOUNT_READY` v1, legacy DynamoDB
lock tables, unbound state buckets, or pre-existing state keys is permitted.
Classify each as bound, partially bound, ambiguous, orphaned, or inconsistent.
Normal execution denies every class except fully bound v2. Migration requires
report-only inventory, explicit owner review, collision analysis, a recovery
point, and a separately approved change.

## Rollout and rollback

Merge does not initialize a backend, create a registry, acquire a distributed
lock, touch AWS, restore state, or authorize deployment. Rollback is a normal
revert of GUG-122 while execution remains disabled. Do not fall back to
manifest-supplied backend fields, v1 baseline inference, DynamoDB locking, or
automatic force-unlock.

## Evidence classification

- **Implemented:** candidate schemas, pure registry/lock models, backend
  authorizer, root/backend integration, least-privilege policy fixtures, tests,
  migration/recovery runbook, and threat delta.
- **Locally validated:** only named offline commands for the candidate tree.
- **CI validated:** pending the exact PR commit.
- **Live validated:** no.
- **Blocked:** reviewed PR, main verification, GUG-123 through GUG-125, and
  authorized non-production recovery evidence.
- **Production:** **NO-GO**.
