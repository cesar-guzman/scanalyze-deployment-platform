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
version and expiry; independent approval; execution ledger; health and
reconciliation receipts.

Trust boundaries exist between GitHub and the separate Scanalyze
platform-authority account, platform authority and the destination account,
Plan and Apply terminal roles, S3 plan storage and durable execution records,
one deployment and another, and one workflow run and another. No repository or
Environment variable is itself deployment authority.

## Threats and repository controls

Only the first row below is an active runtime control in this repository
candidate. The remaining rows describe reviewed activation invariants exercised
with synthetic records and fake adapters. They are not connected deployment
authority while the materialization gate remains closed.

| Threat | Repository/CI control | Current failure behavior |
|---|---|---|
| An incomplete live-input path reaches cloud credentials | an unprivileged prerequisite job stops unconditionally, so the OIDC-capable job is never scheduled | `LIVE_INPUT_MATERIALIZATION_NOT_PROVEN` |
| OIDC permission spreads to unrelated jobs | structural validator allowlists only the canonical `live-layer` caller and `live_saved_plan` reusable job; the pinned credential action is allowed only in the latter | repository validation fails |
| Plan and apply collapse into one approval window | dispatch requires exactly one `plan` or `apply` phase; apply references one exact saved-plan record digest from a later run | dispatch denied |
| A mutable path or workflow artifact substitutes a plan | plan metadata binds the canonical state bucket, derived key, required S3 version, SHA-256, size, KMS key, tuple, state and expiry | validation/readback denied |
| Apply replans or changes the reviewed binary | the runner contract accepts an exact saved plan and its intent requires an `APPROVED -> APPLYING` CAS; the connected controller and durable CAS readback are not implemented | materialization gate remains closed |
| Approval is self-issued or reused | the synthetic receipt contract binds numeric initiator/approver identities, exact run, Environment configuration, main SHA and plan digest; authenticated GitHub approval provenance is not implemented | materialization gate remains closed |
| Durable control evidence is substituted | plan, approval, health and reconciliation documents are create-only table records with consistent schema/digest/tuple readback | transition denied |
| A destination role writes its own approval | destination plan storage and platform-authority control storage use disjoint adapters and exact terminal/orchestrator roles | adapter/IAM denial |
| Terminal credentials leak or persist | 900-second role session, exact source identity/tags, ephemeral environment mapping, suppressed child output, and local/profile rejection | terminal phase denied and credentials cleared |
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
- No repository or Environment variable can make the current materializer gate
  succeed; a separately reviewed typed materializer must replace it.

## Residual blockers

The following are **NOT_PROVEN**: the authenticated live-input materializer;
exact separate platform-authority account/read profile/backend and deployed
orchestrator; destination baseline/state resources/terminal roles; reviewed
non-overlapping dev CIDR or exact existing VPC; protected deployment Environment
configuration; second P0 reviewer and independent approval evidence; effective
IAM/KMS/S3/DynamoDB behavior; remote backend locking; connected health,
reconciliation, cleanup and rollback.

Before the gate can be removed, a separately reviewed change must also:

- execute plan, immutable upload, record persistence, CAS, exact-binary apply,
  outcome classification, and terminal receipt through one typed controller
  that preserves the required terminal/orchestrator authority boundaries;
- consume DynamoDB consistent readbacks rather than caller-supplied JSON and
  prohibit a generic transition to `APPLIED` without authenticated apply
  outcome evidence;
- bind `github.run_attempt` and a single-use execution nonce through context,
  approval, intent, ledger, and reconciliation so a rerun cannot reuse an
  authorization;
- ingest authenticated GitHub Environment/deployment-review evidence for the
  independent plan-specific approval instead of accepting asserted reviewer
  identifiers or timestamps;
- eliminate saved-plan and control-record pathname reopen races by consuming
  identity-stable private snapshots;
- run all dependency materialization outside the `id-token: write` job, then
  use only an immutable hash-verified toolchain in the minimal OIDC job; and
- update and jointly validate the destination state-key policy for the exact
  Plan, Apply, Identity-Plan, and Identity-Apply cryptographic operations. That
  policy is outside the GUG-382 file allowlist and is not changed here.

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
