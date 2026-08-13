# GUG-363 threat-model delta: retirement entrypoint materialization

## Scope

This delta covers the repository mechanism that may create the one dedicated
non-production ADR-050/GUG-215 retirement PEP stack through a direct,
one-attempt `CreateStack` request. It covers offline plan construction, the
external GUG-357 authorization boundary, the fixed pre-existing CloudFormation
service role, owner-local attempt ledger, exact unsigned-source-to-signed-
destination verification, readback, retained logging and reconcile-only
recovery.

It excludes GUG-365 creation or mutation of the CloudFormation service role and
its managed boundary bundle, the operator policy and `iam:PassRole` grant;
artifact upload/copy; creation, retry,
cancellation or mutation of Signer jobs/profiles or Lambda Code Signing Configs;
Identity Center provisioning; broker invocation; `DeleteChangeSet`; stack
update/deletion; cleanup; customer scope and production. No live deployment is
proved by this repository change. Production remains **NO-GO** and two-human
approval remains `NOT_PROVEN`.

## Security objective

Permit at most one reviewed request to create the exact dedicated entrypoint
stack, only after an external short-lived authorization binds the exact plan,
caller, fixed service role and action. The operator must not receive direct
provider mutation authority. Any substitution, drift, replay or ambiguous
outcome must remove create from the allowed next actions and preserve only
read-only reconciliation.

## Assets

- exact reviewed Git commit/tree and CloudFormation template bytes;
- deterministic GUG-215 unsigned Signer-source ZIP, manifest and source-byte
  digest;
- distinct exact versioned source and signed-destination S3 objects, checksums,
  sizes and KMS-encryption evidence;
- completed Signer job and exact signing-profile-version evidence;
- exact Code Signing Config policy `Enforce` and exact
  `AllowedPublishers.SigningProfileVersionArns` evidence;
- signed-destination Lambda `CodeSha256`, the only code digest eligible for the
  CloudFormation request;
- private materialization intent, plan and independent expected plan digest;
- fixed stack/account/Region and CloudFormation service-role ARN;
- fresh service-role policy/trust, exact GUG-365 service/workload boundaries
  and operator PassRole evidence;
- private GUG-357 execution authorization and independent expected digest;
- caller digest, owner authorization and ADR-050 exception digests;
- owner-local consumed-attempt ledger;
- exact fourteen-resource graph, exact precreated-function binding and retained
  log-group contract; and
- sanitized materialization/reconciliation receipts plus private AWS readback.

## Trust boundaries

### Repository and private-input boundary

The materializer reads template bytes from an exact Git object and requires a
clean matching worktree. Private JSON, package and output files must be regular,
one-link, owner-only objects outside the repository. Duplicate JSON keys,
unknown fields, changed inodes, symlinks, hard links, oversized inputs and
existing output paths fail closed.

### Plan and external-authorization boundary

The offline plan is deterministic integrity evidence and explicitly says
`deployment_authorized=false`. `apply` also requires a separately delivered
expected plan digest and a distinct GUG-357 execution authorization whose exact
digest is supplied separately. The latter alone carries the bounded
`deployment_authorized=true` statement, binds `live_checkpoint_digest`,
`live_before_state_digest`, `service_role_evidence_digest` and
`operator_authority_evidence_digest`, and expires within fifteen minutes.

Both `apply` and read-only `reconcile` additionally require a separately
supplied expected artifact-signing-contract digest. It must match the sealed
plan and authorization and cannot be sourced from either file at runtime.

The authorization also binds the complete source-to-signed-destination contract
and its fresh Signer, S3 and Code Signing Config evidence. A digest over the
unsigned package alone cannot authorize deployment.

### Signed-artifact boundary

The GUG-215 packager emits a deterministic unsigned AWS Signer source ZIP. Its
historically named `lambda_code_sha256` field hashes those unsigned source bytes
only and is not a deployable Lambda code hash. An external, separately
authorized process must already have uploaded the exact source, completed one
Signer job owned and invoked by the authority account with platform
`AWSLambda-SHA384-ECDSA` and the exact reviewed signing-profile version, and
produced one distinct immutable signed destination. Source and destination must
use the same version-enabled bucket and KMS key but different keys and versions.
The profile must be active/non-revoked with no overrides or signing parameters;
the signed key must have exactly one latest version and no delete marker.

Only the signed destination S3 coordinates and signed-byte `CodeSha256` project
into CloudFormation. Runtime preflight reads the Signer job, both exact S3
versions and the Code Signing Config and fails before the ledger claim unless:

- the successful job exactly connects the reviewed source, destination and
  signing-profile version;
- both S3 objects independently match their version, checksum, size and
  KMS-encryption bindings; and
- safe in-memory ZIP parsing proves exact member-name and member-payload equality
  without extraction, despite different outer ZIP digests; and
- the config policy is `Enforce` and its allowed publisher set equals only the
  reviewed signing-profile-version ARN.

GUG-363 has no S3 write/copy, Signer mutation or Code Signing Config/profile
mutation capability. It cannot turn an unsigned ZIP into a signed artifact or
repair an incomplete handoff.

### Operator and CloudFormation service-role boundary

The operator may request the exact stack but must not hold direct IAM, Lambda,
DynamoDB or Logs provider write authority. The `CreateStack` request contains
the code-owned, pre-existing authority-account role
`scanalyze-platform-authority-gug363-cfn-materializer`; stack readback must
report its exact ARN as `RoleARN`. GUG-363 never creates or updates that role
and never grants `iam:PassRole`.

GUG-357 must separately prove the exact service-role trust, policies, boundary,
tags and the operator's one-role-only PassRole edge before issuing the execution
authorization. The current temporary GUG-357 audit permission-set package lacks
those IAM reads, so another explicitly authorized read-only evidence path is a
live prerequisite.

ADR-052/GUG-365 makes the service role, five workload roles, proof-bound
factory role, six managed policies, two precreated functions and retained
ledger a separate repository-owned prerequisite bundle. The
GUG-363 template has no IAM or DynamoDB resources. Boundary absence, an inline
policy, a missing/wrong attachment or ledger-policy drift is a hard stop. If
the bundle can create effective permissions beyond the reviewed graph, or if
the operator can pass the role to a different service/request, live execution
is blocked.

### One-attempt boundary

Fresh caller, target, Signer, source/destination S3 and Code Signing Config
checks precede the write. The materializer then reserves a create-only
owner-local ledger before one `CreateStack` call; the SDK has zero retries. The
deterministic client token and fixed stack name add provider-side
collision/idempotency boundaries. A timeout or malformed response after the
ledger claim is `UNCERTAIN_RECONCILE_ONLY`.

The pre-ledger API order is closed for every apply: STS caller identity; first
CloudFormation stack read; Signer job read; signing-profile read; bucket
versioning read; unsigned head/body reads; signed version-list/head/body reads;
Code Signing Config read; and a second stack read. This complete sequence also
precedes no-touch classification. A disappearing/replaced first target becomes
ambiguous. Authorization and signature time windows are revalidated only after
those reads, and only two absence observations can reach the ledger claim. No
`CreateStack` can precede it. Post-write readback is stack, template, resources
and events, in that order.

The ledger is host-local, not a distributed lock. A second host is an explicit
residual risk; operational authorization must name one operator/workstation and
exclude concurrent execution.

### Readback and recovery boundary

The create response is non-terminal. Exact readback binds the stack ID,
`RoleARN`, template, parameters, resource set and status. Existing targets are
no-touch. `OnFailure=DO_NOTHING` and termination protection preserve partial
evidence; GUG-363 offers no update, rollback or delete adapter. Reconciliation
after a consumed attempt is read-only.

The receipt is explicitly scoped to `CLOUDFORMATION_CONTROL_PLANE_ONLY`; it
cannot set provider certification complete and always requires subsequent
GUG-357 certification. Direct Lambda, IAM, DynamoDB, Logs, Function URL and
account-wide authority checks remain outside GUG-363, preventing a green stack
readback from being overclaimed as complete Phase 9 certification.

The separate `artifact_signing_readback_complete` signal covers only live
Signer/S3/Code Signing Config verification for apply/no-touch/reconcile.
Complete readback requires it, but it does not widen the post-create scope or
certify the deployed Lambda.

### Logging boundary

The stack owns a retained 365-day log group with AWS-owned encryption at rest.
Lambda platform logging is JSON, application `ERROR` and system `WARN`; broker
source emits no application log calls and accepts an empty request only. The
execution role can create streams and put events only under the exact group and
is denied log-group/KMS/retention/resource-policy control-plane mutations.
Logs remain sensitive operational evidence and never authorize an effect.

## Threats and controls

| Threat | Control | Failure behavior |
|---|---|---|
| Plan self-authorizes by recomputing its digest | Plan fixes `deployment_authorized=false`; expected plan digest and distinct fresh GUG-357 authorization digest arrive separately | Block before AWS client construction |
| Caller substitutes stack, account, Region or mode | Code-owned constants and closed target object; dedicated stack differs from retained shell | `TARGET`/scope validation failure |
| Caller substitutes the CloudFormation service role | Fixed role ARN is bound into plan/request/authorization and read back as stack `RoleARN` | Block before create or classify readback as drift |
| Operator bypasses CloudFormation with direct provider APIs | Operator policy must lack IAM/Lambda/DynamoDB/Logs writes; CloudFormation uses the fixed service role | GUG-357 checkpoint blocked |
| Operator uses a broad or foreign `iam:PassRole` edge | Fresh GUG-357 evidence requires one exact role and reviewed caller policy | No execution authorization issued |
| External service role is broadened after review | Fresh trust/effective-policy/boundary/tag digest is required and bound to the checkpoint; stack readback proves RoleARN | Drift or stale evidence blocks |
| Operator sends another template through a raw CloudFormation client | The service role has no IAM, DynamoDB or Lambda function-create authority, while every precreated workload role retains its exact role/class-specific boundary | The alternate stack cannot create or mutate roles, attached policies, boundaries, the retained table, its resource policy or a Lambda function |
| Retained shell is used as the target | Dedicated fixed stack name and explicit retained-shell deny | Block before AWS write |
| Unsigned GUG-215 source ZIP is projected as Lambda code | Source manifest semantics are explicitly unsigned/non-deployable; only distinct signed-destination fields project to CloudFormation | Offline plan failure |
| Source or destination is uploaded/copied, or `latest` is substituted | GUG-363 has no S3 mutation; both exact object versions/byte digests/sizes/encryption bindings are read back, and any full-object provider checksum supplied by AWS must match | Block before ledger claim |
| Signer job is pending, failed, names another source/destination, or uses another profile version | Exact successful job evidence and live readback bind the full source-to-destination edge | Block before ledger claim |
| Code Signing Config ARN is correct but policy is `Warn` or allows another publisher | Runtime reads policy and exact `AllowedPublishers`; ARN-only evidence is insufficient | Block before ledger claim |
| Signing evidence is stale or replaced after authorization | Authorization binds the exact signing contract/evidence; runtime re-reads Signer, S3 and Code Signing Config before claiming the attempt | Block before ledger claim; remaining read-to-create race is residual |
| Dirty or replaced source changes template authority | Exact clean HEAD/tree, `git show` bytes, worktree equality and template digest | Offline plan failure |
| Normal and single alias families coexist | Exact fourteen-resource single-mode graph and condition/resource readback | Plan or readback failure |
| Stack targets a foreign or replacement broker function | Every version, alias, URL and permission uses the exact literal GUG-365 function name or closed ARN; the template cannot create a function | Offline plan failure or prerequisite-certification failure |
| `$LATEST`, public Function URL or foreign permission is introduced | Published version, exact aliases, `AWS_IAM` URLs and exact role principals are closed bindings | Drift; no completion receipt |
| Automatic rollback deletes evidence | Request uses `OnFailure=DO_NOTHING` and omits the mutually exclusive `DisableRollback`; readback requires rollback disabled; no update or delete path; termination protection enabled | Partial state retained for separate recovery |
| A create is replayed after timeout | Ledger consumed before effect, one SDK call, zero retries, deterministic client token | Reconcile only; never another create |
| Existing exact stack triggers a second create | Preflight and repeated absence checks return no-touch/readback | Zero mutation |
| Pre-existing stack copies the visible projection digest while private `NoEcho` values differ | A visible digest is only a drift guard; masked parameters require the validated local ledger, exact plan and request-token event from GUG-363's own create chain | Pre-existing target remains ambiguous and no-touch; GUG-357 provider certification required |
| Logs leak request or private evidence | Empty broker request, no application logging, sanitized statuses and fixed platform log levels | Treat unexpected content as incident; revoke/contain separately |
| Broker mutates log-group controls | Execution role allows only exact stream writes and explicitly denies group/KMS/retention/policy mutations | AWS deny |
| Passing tests is reported as live success | Evidence classes separate repository, CI, authorization, API response and terminal readback | Live status remains `NOT_PROVEN` |

## Abuse cases

1. An operator edits both plan and expected digest. The execution authorization
   still fails to bind the reviewed digest delivered through the separate
   channel.
2. An operator uses `--allow-create-stack` without a fresh authorization. The
   closed authorization validation fails before AWS.
3. A profile resolves to the wrong account or caller. Exact STS identity and
   caller digest fail before target mutation.
4. A role administrator broadens the external service role between evidence
   and execution. GUG-357 evidence is stale; any detected mismatch blocks. The
   remaining time-of-check/time-of-use window is a residual control-plane risk.
5. An operator points the intent at the unsigned package as both source and
   destination. Closed source/destination semantics and the distinct signed-byte
   digest prevent a CloudFormation projection.
6. A Signer or Lambda administrator changes the Code Signing Config to `Warn`,
   adds an allowed publisher or replaces a job/output after review. Fresh live
   readback disagrees with the authorization-bound evidence and blocks before
   the ledger claim.
7. CloudFormation accepts the request but the response is lost. The local
   ledger remains consumed and only `reconcile` is permitted.
8. `DO_NOTHING` leaves a partial log group, role or table. GUG-363 does not
   delete or adopt it; a new destructive recovery issue is required.
9. A second workstation has a copied authorization but no ledger. This is not
   prevented by the host-local guard; the owner must revoke the authorization,
   prohibit concurrency and rely on stack-name/provider evidence. No second
   attempt is acceptable.

## Residual risks

- The fixed CloudFormation service role, its six managed policies and the
  operator PassRole policy are external prerequisites, not materialized by this
  GUG-363 package; GUG-365 owns the IAM bundle.
- The source upload, Signer job/profile, signed destination and Code Signing
  Config are external prerequisites, not created or repaired by GUG-363.
- IAM cannot make a local wrapper the only possible CloudFormation client. The
  GUG-365 service-role and child-role boundaries therefore constrain raw-client
  use server-side; CloudTrail and the wrapper remain evidence controls.
- The owner-local attempt ledger is not a cross-host CAS service.
- Service-role or caller-policy drift can race the last read-only evidence.
- Signer, S3 or Code Signing Config state can race the last read-only evidence
  and the `CreateStack` call; exact version IDs, `Enforce` and Lambda signature
  enforcement reduce but do not erase that provider control-plane window.
- `OnFailure=DO_NOTHING` may retain billable or privilege-bearing partial
  resources until separately authorized recovery.
- CloudFormation and IAM readback can be eventually consistent.
- One human reviews and executes the bounded path; independence is not proved.

None of these residuals is accepted for production.

## Evidence and stop classification

- **SOURCE_OBSERVED:** repository source, template, tests and gate outputs for
  an exact commit.
- **PROPOSED:** future AWS materialization under an exact GUG-357 checkpoint.
- **NOT_PROVEN:** live service role, PassRole, stack absence, AWS behavior,
  deployment and independent human approval until fresh evidence exists.
- **RECONCILE_ONLY:** any consumed attempt with non-terminal or ambiguous
  readback.
- **NO-GO:** production, second create, update/delete/cleanup, broker invocation
  or `DeleteChangeSet` under GUG-363.
