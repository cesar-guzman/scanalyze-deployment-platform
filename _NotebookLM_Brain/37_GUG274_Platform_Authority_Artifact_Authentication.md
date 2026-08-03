# GUG-274 — Platform-Authority Bootstrap Artifact Authentication

## Executive statement

GUG-274 replaces digest-only authority in the normal GUG-206 bootstrap with
Plan v2, Approval v2, live proof of two fixed Identity Store users, and one
service-owned DynamoDB CAS record. Local digests still detect corruption, but
only the exact external record and its proof-receipt bindings authenticate
origin, independent approval, and one-shot Apply consumption.

The human Apply role is read-only plus invocation of one exact service version.
Only `scanalyze-platform-authority-bootstrap-apply-executor:1` may claim the
approval and, after an unambiguous CAS, construct CloudFormation/S3 Control
clients, set account Public Access Block, and execute the exact Change Set.

This is repository implementation evidence only. Deterministic packaging,
signing, deployment, identity proof, ledger transitions, PAB, and
CloudFormation execution are **NOT_OBSERVED** live. The required independent
read-only ledger reconciliation capability is **NOT_IMPLEMENTED**. Production
remains **NO-GO**.

## Problem closed by GUG-274

Plan v1 and Approval v1 contain unkeyed SHA-256 hashes. An actor who can replace
both files can substitute another syntactically valid full Change Set ARN with
the same name and a different UUID, update every binding, and recompute both
hashes. The pair is internally consistent but not authenticated.

A second hash, local HMAC, checked-in/CI key, Git commit, username, profile
name, or file permission does not establish operational authority. Active
Apply rejects v1 and mixed versions without fallback.

## Fixed trust root and state machine

The table is exactly:

```text
scanalyze-platform-authority-bootstrap-artifacts
```

Its key schema is partition key `trust_root_id` and sort key
`authority_record_id`. Both coordinates and generation 1 derive from immutable
service configuration; no artifact, caller, CLI option, environment variable,
or AWS profile may select them. The trust contract is generation 1, version 1,
with algorithm `AWS_DYNAMODB_STRONGLY_CONSISTENT_CAS_SHA256`.

The exact service versions and roles are:

| Transition/effect owner | Exact function | Exact execution role |
|---|---|---|
| Plan anchor | `scanalyze-platform-authority-bootstrap-plan-authority:1` | `ScanalyzeGug274BootstrapPlanAuthority` |
| Approval transition | `scanalyze-platform-authority-bootstrap-approval-authority:1` | `ScanalyzeGug274BootstrapApprovalAuthority` |
| Apply claim and effects | `scanalyze-platform-authority-bootstrap-apply-executor:1` | `ScanalyzeGug274BootstrapApplyExecutor` |

Aliases, unqualified ARNs, `$LATEST`, and any generation-1 published version
other than actual `:1` are invalid.

The DynamoDB table resource policy is deny-only and supplies no positive grant.
Each service receives its sole positive DynamoDB Allow through its own execution
role identity policy, constrained to that operation's exact action/table/key and
the exact unqualified source-function ARN through
`lambda:SourceFunctionArn`. AWS supplies this condition key without a version
suffix; qualified human invocation, Lambda permission, deployment/readback, and
runtime controls enforce the exact `:1` version separately.

| State | Ledger `version` | Attempt count | Sole writer |
|---|---:|---:|---|
| `PLAN_ANCHORED` | 1 | 0 | Exact Plan authority version |
| `APPROVED` | 2 | 0 | Exact Approval authority version |
| `CLAIMED` | 3 | 1 | Exact Apply executor version |

Creation requires an absent item. Each transition compares the complete prior
projection, state, ledger digest, generation, version, and attempt count. There
is no skip, reverse transition, reset, second claim, or v1 import.

## Human identity proof and attribution

Real Identity Store user A owns only the Plan permission set. A different real
user B owns separate Approval and Apply permission sets. User B is the same
second person in those two roles, but their policies, grants, service calls,
and deny-all proof roles remain distinct:

```text
ScanalyzeGug274BootstrapPlanIdentityProof
ScanalyzeGug274BootstrapApprovalIdentityProof
ScanalyzeGug274BootstrapApplyIdentityProof
```

Each operation consumes a new authorization code and PKCE verifier only from a
non-persistent pipe or socket descriptor. Regular files and terminals are
rejected. The exact service exchanges through the fixed Identity Center
application, uses the returned context only with its operation-specific
deny-all proof role, and clears tokens, assertions, STS credentials, raw
UserIds, and provider responses. None is persisted or logged.

The Apply-policy renderer accepts the exact still-fresh Plan and matching
account/Region/destination bindings. It fixes only the executor `:1` ARN,
bounded verification reads, explicit direct-effect denies, and a final deny for
every other non-read/non-broker action; the caller cannot select another
function or effect permission.

Candidate `initiator_id`, `initiator_principal_digest`, `approver_id`, and
`approver_principal_digest` fields are anchored attribution assertions, not
cryptographically correlated live UserId authority. Authority comes from the
fixed UserId topology and identity-proof receipt digests. Stronger correlation
is a P2 follow-up and does not reopen the P1 boundary.

## Complete authenticated binding

The record binds the exact account, partition, Region, canonical stack, full
Change Set ARN/name/UUID and `CREATE` type; original-template and planned
resource-inventory digests; state bucket/key; artifact digests and validity
windows; identity topology and proof-receipt digests; attribution assertions;
trust-root coordinate/generation; state/version/attempt; and these exact
Change Set inputs:

- parameters `AuthorityAccountId`, `StateKey`, and
  `NoncurrentVersionRetentionDays=365`;
- `OnStackFailure=ROLLBACK`;
- `IncludeNestedStacks=false`;
- `ImportExistingResources=false`;
- `Capabilities=[]` and `NotificationARNs=[]`;
- absent `RoleARN`, `DeploymentMode`, and parent/root metadata; and
- absent or empty default `RollbackConfiguration`.

Cross-protocol type confusion is prevented with closed schemas and the exact
domains:

```text
scanalyze.platform-authority.bootstrap.plan.v2
scanalyze.platform-authority.bootstrap.approval.v2
scanalyze.platform-authority.bootstrap.artifact-authority.v1
scanalyze.platform-authority.bootstrap.authority-receipt.v1
scanalyze.platform-authority.bootstrap.authority-key.v1
```

Approval binds the authenticated Plan anchor, not a Plan digest supplied by the
caller. A complete rewrite/redigest or same-name/different-UUID substitution
therefore cannot match the external record.

## Fixed Apply order

1. Strictly parse and validate Plan v2/Approval v2, local digests, all bindings,
   exact parameters/request metadata, identity topology, and freshness.
2. Consume the Apply-specific code-plus-PKCE grant and prove fixed user B.
3. Strongly read the exact DynamoDB item and authenticate its complete
   Plan/Approval/proof projection.
4. CAS `APPROVED` version 2/attempt 0 to `CLAIMED` version 3/attempt 1.
5. Only after unambiguous CAS success construct CloudFormation and S3 Control
   clients.
6. Validate the exact empty shell, full ARN/UUID, parameters, metadata,
   tags/status/resources, `Original` template, and freshness.
7. Set all-true account PAB.
8. Repeat that entire full-ARN/UUID/`Original`/parameters/metadata/freshness
   readback.
9. Issue one `ExecuteChangeSet` with only the helper-derived bare name and exact
   stack.

Any unavailable, foreign, stale, malformed, partial, replayed, already claimed,
or ambiguous authority stops. No direct human effect path exists. GUG-210
continues to own full-ARN/UUID request parity; GUG-215 remains the sole retained
Change Set retirement path and receives no authority from GUG-274.

## Package, signing, and activation boundary

One closed unsigned ZIP is built only from the exact bytes of an exact clean Git
commit. File set/order, permissions, timestamps, ZIP metadata, per-file
digests, archive digest, and `unsigned_archive_code_sha256` are deterministic.
The Git subprocess closes config/environment/locale, uses
`--no-replace-objects`, resolves Git through a reviewed absolute binding rather
than caller `PATH`, rejects every `refs/replace` and any tracked or untracked
working-tree change, and reads the closed file set from exact commit objects.
The unsigned ZIP is explicitly non-deployable. An embedded runtime lock binds
the source commit, generation, and exact pins `boto3==1.42.57` and
`botocore==1.42.97`; caller flags must equal those constants. `AWS_DATA_PATH`
and other provider overrides are rejected.

The normal bootstrap, package-builder, and signed-artifact-verifier CLIs require
`env -u PYTHONPATH -u PYTHONHOME python3 -I -S ...`. For normal-bootstrap/verifier
imports, each of the three entry points first opens
`tooling/platform_authority_source_only_import.py` as UTF-8 source and compiles
those bytes before repository modules become importable. Its finder compiles
exact repository `.py` bytes for `tooling` modules directly and neither consumes
nor emits repository `.pyc`; repository bytecode writes stay disabled.

For normal-bootstrap/verifier SDK imports,
`SCANALYZE_GUG274_SDK_RUNTIME_ROOT` names an absolute root outside the
repo/local `.venv`; its direct `site-packages/` is dedicated to and contains only
the fixed operational closure. The root and every directory in its POSIX
ancestor chain must be owned by root or the effective user and group/world
non-writable; only a root-owned sticky directory in that chain may be writable.
Every `site-packages/` entry must likewise have a trusted owner and safe mode,
with no symlink or non-regular/non-directory entry and no sticky-root exception.
`-S` prevents automatic `site`, `.pth`, and
`sitecustomize` execution. The loader admits the candidate path explicitly, but
the path grants no authority: source-reviewed official wheel identities and
canonical installed-manifest hashes authenticate the complete closure before import:
`boto3==1.42.57`, `botocore==1.42.97`,
`s3transfer==0.16.1`, `jmespath==1.1.0`,
`python-dateutil==2.9.0.post0`, `urllib3==2.7.0`, and `six==1.17.0`.
Each manifest is a source-pinned projection of the wheel-owned package and
stable metadata rows. The loader verifies that projection plus every declared
file digest/size before import; external `pycache_prefix`, preloads, symlinks,
`.pyc`, unsafe/mismatched or extra import-tree files fail closed, and bytecode
writes are disabled. Raw,
installation-specific `RECORD` bytes are neither pinned nor authority. Git,
AWS CLI, and GitHub CLI resolution ignores caller `PATH` and uses
only source-reviewed absolute executable bindings. The resolved file and every
ancestor must be owned by root or the effective user. The file must be
regular/executable and group/world non-writable; ancestor directories must be
group/world non-writable except for a root-owned sticky ancestor. The complete
path check repeats after the digest read, and stable executable metadata must
match. Non-root executables also require an exact digest, but a matching digest
cannot override an unsafe path; only the reviewed GitHub CLI digest is currently
allowed. The currently inspected Homebrew `gh` fails closed because
`/opt/homebrew/Cellar` is group-writable mode `0775`.
The repository authenticates this contract but does not install or roll back
host Python, wheels, or executables; mismatch is a fail-closed tooling stop.

The ZIP excludes SDK wheels. Lambda `python3.12` supplies the AWS-managed SDK;
all three functions compare template environment pins with the embedded lock
and then check managed-module `__version__` before client construction. The
operator-host closure authenticator does not extend into Lambda; this managed
boundary is not active while CFN activation remains impossible. After future
activation, AWS-managed runtime drift cannot be reversed by repository or
workstation rollback.

Packaging is not signing. A separately authorized AWS Signer lane must sign the
exact bytes with fixed profile
`scanalyze_gug274_bootstrap_artifact_authority` and an immutable profile
version. The implemented read-only verifier rebuilds the package, proves the
source commit is merged to protected `main` with all exact required checks
green, and reads STS, the completed Signer job, and the exact versioned S3
source/destination bytes. It validates the signed ZIP and emits a receipt with a
maximum 15-minute TTL containing the exact object tuple,
`SignedAuthorityArtifactCodeSha256`, `AuthoritySigningReceiptDigest`, and
`AuthoritySigningTrustRootContractDigest`.

The receipt digest is unkeyed integrity, not authority. Before consuming any
CloudFormation parameter, the same flow must refresh GitHub, Signer, and S3 and
require the immutable receipt projection to match. Raw parameters, local
redigestion, the manifest, and the unsigned digest are not proof.

The fixed Git contract
`bootstrap/platform-authority-bootstrap-artifact-signing-trust-root.json` is
deliberately `NOT_CONFIGURED`, so the verifier stops with
`SIGNING_TRUST_ROOT_NOT_CONFIGURED`. CloudFormation permits only lock value
`false` while a Rule requires `true`; it cannot create a Change Set. A separate
reviewed commit must pin the exact signer version ID/ARN and contract digest in
both the contract and template allowlists before unlocking. The template's
`UntrustedArtifactOnDeployment=Enforce` declaration is not live evidence.

## Rotation, revocation, and recovery

Rotation creates a separately reviewed generation with a new exact package,
runtime lock, signer profile version, service versions, and identity topology.
Old items remain immutable evidence and are never copied into active approval
state. Revocation blocks new transitions; `CLAIMED` never resets.

An ambiguous Plan anchor, Approval transition, or Apply claim is terminal: no
retry, no success claim, and no effect client. The current three-service
package has no fourth function, independent ledger reader, or human
reconciliation role. The missing strongly consistent exact-item read-only
capability is a live-activation prerequisite marked **NOT_IMPLEMENTED**. Never
add ad hoc IAM/DynamoDB access or invoke a mutating service to diagnose it. It
is tracked as a P2 recovery follow-up. Until the capability exists, only
separately authorized controlled generation
revocation/retirement is available, while preserving all records.

Post-claim CloudFormation uncertainty also remains terminal. Existing,
separately authorized read-only CloudFormation inspection may examine only the
original target; it cannot reset the ledger or authorize another execution.

Before activation, rollback is a reviewed atomic repository revert and leaves
host tooling unchanged. After signing or deployment, do not rebuild under a
different host and call it rollback: revoke the affected generation/version,
preserve receipts and ledger evidence, and use a reviewed known-good immutable
signed artifact or forward fix.

Stack `ROLLBACK`/`DisableRollback=false` does not reverse the account PAB that
the executor writes before Execute. PAB remains enabled during containment and
recovery.

## Activation gates and evidence

Live activation requires separately authorized exact deployment/readback of
the table, deny-only resource policy, execution-role identity policies,
encryption/retention/logging, fixed identity application and users,
execution/proof roles, signed object and signer profile
version, a configured fixed signing contract and freshly refreshed receipt,
code-signing
enforcement, actual `:1` functions, independent reconciliation capability,
causal negative probes, exact-head CI, independent P0 review, and completion of
the GUG-119 governance dependency.

Until then:

- deterministic package/signing/deployment: **NOT_OBSERVED**;
- read-only verifier/receipt/provider refresh: repository implementation only;
- signer trust root and Change Set activation:
  **SIGNING_TRUST_ROOT_NOT_CONFIGURED**;
- live Identity Center proof and user assignments: **NOT_OBSERVED**;
- Plan anchor, Approval, claim, PAB, and execution: **NOT_OBSERVED**;
- independent ledger reconciliation capability: **NOT_IMPLEMENTED**;
- AWS access and mutation by this documentation lane: **NONE**; and
- production: **NO-GO**.

## Canonical references

- [ADR-048](../ADR/ADR-048-platform-authority-bootstrap-artifact-authentication.md)
- [GUG-274 threat-model delta](../docs/security/gug-274-platform-authority-artifact-authentication-threat-model-delta.md)
- [Platform-authority bootstrap](../docs/deployment/platform-authority-bootstrap.md)
- [Dedicated account bootstrap](../docs/deployment/platform-authority-account-bootstrap.md)
- [Bootstrap recovery](../docs/operations/platform-authority-bootstrap-recovery.md)
