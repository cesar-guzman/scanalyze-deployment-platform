# GUG-382 threat-model delta: protected non-production live orchestration

Status: `REPOSITORY_CANDIDATE / LIVE_NOT_PROVEN`. Production and staging are
**NO-GO**. This delta covers repository code, synthetic tests, and CI structure
only. GUG-382 executed no AWS action and does not prove OIDC, STS, IAM, KMS, S3,
DynamoDB, a remote Terraform plan/apply, health, reconciliation, or rollback.

## Assets and trust boundaries

Protected assets are the exact main SHA and workflow run; deployment/customer/
account/region/environment tuple; platform-authority and destination roles;
registry, ACCOUNT_READY v2, backend, execution lock and resolution v3 records;
release and toolchain digests; state lineage/serial; saved-plan binary, digest,
exact key, S3 VersionId, size and expiry; independent approval; execution
ledger; health and reconciliation receipts.

Trust boundaries exist between GitHub and the separate Scanalyze
platform-authority account, platform authority and the destination account,
Plan and Apply terminal roles, S3 plan storage and durable execution records,
one deployment and another, and one workflow run and another. No repository or
Environment variable is itself deployment authority.

## Threats and repository controls

The rows below are implemented repository controls exercised with synthetic
records and fake adapters. They are not connected deployment authority until
the protected Environment/App, IAM and AWS paths are configured and observed.

| Threat | Repository/CI control | Current failure behavior |
|---|---|---|
| An incomplete live-input path reaches cloud credentials | the sole protected job performs two complete App-backed GitHub snapshots and two private materializations, compares stable claim/authority projections, revokes the App token, and only then becomes OIDC-eligible | pre-OIDC denial |
| OIDC permission spreads to unrelated jobs | structural validator allowlists only the canonical `live-layer` caller and `live_saved_plan` reusable job; the pinned credential action is allowed only in the latter | repository validation fails |
| Plan and apply collapse into one approval window | dispatch requires exactly one `plan` or `apply` phase; apply references one exact saved-plan record digest from a later run | dispatch denied |
| A mutable path or workflow artifact substitutes a plan | plan metadata binds the dedicated versioned saved-plan bucket, exact key, required S3 VersionId, SHA-256, size, KMS key, tuple, exact state VersionId/hash/size and expiry | validation/readback denied |
| Apply replans or changes the reviewed binary | the controller accepts only the exact immutable plan, requires durable approval/ledger readback and an `APPROVED -> APPLYING` CAS, and consumes one apply attempt | transition denied or `UNCERTAIN` |
| Approval is self-issued or reused | the verified App token reads exact run and Environment approval history; digest-addressed evidence binds numeric initiator/approver, run, Environment and reviewer packet and allows only a fresh attempt-1 selection | pre-OIDC or CAS denial |
| Durable control evidence is substituted | plan, approval, health and reconciliation documents are create-only table records with consistent schema/digest/tuple readback | transition denied |
| A destination role writes its own approval | destination plan storage and platform-authority control storage use disjoint adapters and exact terminal/orchestrator roles | adapter/IAM denial |
| Terminal credentials leak or persist | one-hour role session bounded above the 45-minute job timeout, exact source identity/tags, ephemeral environment mapping, suppressed child output, and local/profile rejection | terminal phase denied and credentials cleared |
| An uncertain apply is retried | `APPLYING` is single-use; lost response becomes `UNCERTAIN` and only read-only classification is allowed | retry denied; reconciliation required |
| Platform authority is conflated with destination | exact accounts must differ and the orchestrator role name is deployment-scoped | context/session denied |
| Local, staging, or production execution is attempted | runner requires protected main GitHub Actions `workflow_dispatch`, exact `dev`, and no ambient profiles/credentials | denied before Terraform/AWS |
| Repository evidence is misreported as deployment | Make target and documents emit `REPOSITORY_CANDIDATE / LIVE_NOT_PROVEN` and enumerate unproven connected controls | no deployment claim |

## Required negative evidence

- Changing workflow permissions, OIDC action SHA/location, Environment binding,
  repository numeric identity, exact main SHA, role ARN, account separation, or
  phase must fail repository tests.
- Ambient AWS/Terraform variables, local execution, non-main refs, staging,
  production, non-canonical role/session inputs, and replan attempts must fail
  before the Terraform operation.
- Foreign deployment tuples, changed plan version/digest/key/KMS binding,
  stale approval, mismatched durable record, consumed ledger, and post-CAS
  drift must fail closed.
- A second OIDC/Environment job, automatic workflow token, partial App
  permission map, repository/organization variable-value drift, extra private
  transport name, or token surviving into OIDC must fail structural tests.

## Residual blockers

The following are **NOT_PROVEN**: connected configuration of the protected
Environment and exact GitHub App installation; exact separate platform-
authority account/read profile/backend and deployed
orchestrator; destination baseline/state resources/terminal roles; reviewed
non-overlapping dev CIDR or exact existing VPC; protected deployment Environment
configuration; connected second-P0 approval evidence; effective IAM/KMS/S3/
DynamoDB/SSM behavior; remote backend locking; real protected-workflow adapters
for the implemented health/reconciliation core; connected cleanup and rollback.

Before the gate can be removed, separately reviewed connected work must:

- configure and prove the exact protected Environment and collector App,
  including independent approval, complete permission readback and token
  revocation before OIDC;
- deploy and verify the exact OIDC, STS, IAM, KMS, dedicated versioned plan
  bucket, state bucket, DynamoDB and SSM controls represented by the repository
  contracts;
- wire real post-apply state, no-change, health, contract-publication and
  durable receipt adapters into the already typed controller, then prove the
  `APPLIED`/`UNCERTAIN` resumptions without a second apply;
- execute one separately authorized connected DEV plan and later one separately
  approved exact-binary apply, including exact readback and no-change evidence;
- preserve the current absence of a stale-`APPLYING` workflow recovery route;
  any future recovery authority requires its own design and independent review;
  and
- satisfy the remaining GUG-124/GUG-125 release and live-engine prerequisites,
  followed by the separate staging and production gates. Repository completion
  alone is never a production authorization.

An `AccessDenied` result in later read-only reconciliation must be classified as
unknown, never as absence. Removing the pre-OIDC stop or claiming deployment
before those blockers and an exact immutable plan are independently reviewed is
a P0 governance failure.

## Rollback

Before activation, disable live dispatch or revert the GUG-382 repository
change. No AWS cleanup is required because this candidate executed no AWS
action. After any separately authorized plan exists, first disable dispatch,
preserve sanitized ledger evidence, classify every exact plan version, and use
only the pre-approved plan-specific rollback. Never retry an uncertain apply,
replan during apply, force-unlock, destroy, or fall back to local execution.
