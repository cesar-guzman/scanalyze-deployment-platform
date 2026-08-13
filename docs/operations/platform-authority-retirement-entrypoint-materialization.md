# Runbook: GUG-363 retirement entrypoint materialization

## Status and authorization boundary

This runbook documents a future, separately authorized non-production
materialization of the dedicated ADR-050 retirement PEP entrypoint. It does not
authorize AWS login, artifact upload/copy, a Signer job or profile/configuration
mutation, `iam:PassRole`, `CreateStack`, broker invocation, `DeleteChangeSet`,
cleanup or production use.

Current repository evidence proves only offline contracts. No live GUG-363
stack, execution service role, operator `iam:PassRole`, create attempt or
readback is asserted here. Production is **NO-GO** and two-human approval is
`NOT_PROVEN`.

## Fixed boundaries

| Boundary | Required value |
|---|---|
| Implementation issue | GUG-363 |
| Live execution authorization | GUG-357, fresh and plan-specific |
| Stack | `scanalyze-platform-authority-gug357-retirement-entrypoint` |
| Retained shell | `scanalyze-platform-authority-state-backend`; never the target |
| Region | `us-east-1` |
| Mode | `SINGLE_OPERATOR_NONPROD_EXCEPTION` |
| CloudFormation authority | GUG-365-certified role `scanalyze-platform-authority-gug363-cfn-materializer` and its exact managed boundary bundle |
| Allowed mutation | One `cloudformation:CreateStack` attempt |
| Signer source | Exact version of the deterministic unsigned GUG-215 ZIP; never deployed |
| Signed destination | Separate exact version produced externally; only object projected to CloudFormation |
| Signing policy | Existing Code Signing Config with `Enforce` and exact `AllowedPublishers` |
| Failure mode | `DO_NOTHING`; reconcile only, no cleanup |

Do not substitute an AWS profile, Signer profile version, similarly named stack,
service role, source/destination object version, Code Signing Config or
hand-edited plan.

## Required private artifacts

All raw identifiers and AWS evidence remain in an approved owner-only evidence
root outside the repository. Directories must already be owned by the operator
with mode `0700`; input and output files use mode `0600`, are regular one-link
files and are never symlinks.

Required inputs are:

- the exact clean reviewed repository commit/tree;
- the canonical GUG-215 unsigned source ZIP and manifest from that commit;
- exact private evidence for the external completed Signer job, its source and
  signed-destination object versions, and its one reviewed signing-profile
  version;
- exact source and signed-destination S3 size, checksum, version and
  KMS-encryption evidence;
- exact Code Signing Config evidence proving policy `Enforce` and an
  `AllowedPublishers.SigningProfileVersionArns` set containing only the reviewed
  profile-version ARN;
- a closed private GUG-363 materialization intent binding every parameter,
  artifact, template, target and ADR-050 digest;
- separately reviewed expected plan and artifact-signing-contract digests;
- fresh GUG-357 read-only evidence for the fixed CloudFormation service role,
  all six GUG-365 managed policies, all seven role terminal states, both
  functions, operator policy and exact
  `iam:PassRole` edge;
- a fresh closed GUG-357 execution authorization, no longer than fifteen
  minutes, bound to the exact plan, caller, service role, complete artifact
  signing contract/evidence and sole allowed action; and
- the independently delivered expected execution-authorization digest.

The current `ScanalyzeGug357IdentityAudit` repository package does not include
IAM role/policy reads. It cannot by itself produce the service-role or
`iam:PassRole` evidence. Stop until an explicit read-only evidence path is
authorized; do not add AdministratorAccess or broaden the temporary auditor.

## Phase 0 — Offline repository gate

From the exact issue-scoped worktree:

```bash
git status --short --branch
git diff --check
make platform-authority-retirement-entrypoint-check
make platform-authority-bootstrap-check
make docs-check
make security-check
```

The tree used by `plan` must be clean, so merge/review the implementation before
creating an operational plan. Local success is not CI success, live
authorization or deployment evidence.

## Phase 1 — GUG-357 read-only preflight

This phase is external to GUG-363 and requires an explicitly approved read-only
identity. Confirm the caller before collecting evidence and keep raw responses
private.

The checkpoint must prove:

1. exact authority account and `us-east-1`;
2. the dedicated stack is absent, or already exists and must be handled as a
   no-touch readback rather than a second create;
3. the exact unsigned source S3 object version is present and byte-identical to
   the reviewed GUG-215 package;
4. one completed successful Signer job owned and invoked by the authority
   account uses platform `AWSLambda-SHA384-ECDSA` and names that exact source,
   the distinct signed destination and exact reviewed historical
   signing-profile version, with no overrides or signing parameters; the named
   profile remains active on the same platform, though its current version may
   be newer;
5. the exact signed destination S3 object version is present and matches its
   independently reviewed signed byte digest and size; any full-object provider
   SHA-256 that AWS supplies must also match; source and destination use
   the same version-enabled bucket and KMS key but distinct keys and versions,
   the signed key is derived from the job ID, and it has exactly one latest
   version with no delete marker;
6. safe in-memory ZIP parsing proves exact member-name and member-payload
   equality between unsigned source and signed destination even though their
   outer ZIP byte digests differ;
7. the existing Code Signing Config policy is `Enforce` and its exact allowed
   publisher set contains only that signing-profile-version ARN;
8. `scanalyze-platform-authority-gug363-cfn-materializer` exists in the exact
   authority account;
9. its trust policy names only the CloudFormation service principal and its
   boundary is the exact GUG-365 service-role boundary;
10. all seven roles have zero inline policies and exact reviewed tags; the six
    main roles have exactly one attached managed policy identical to their
    boundary, while the factory role is proof-bound with zero attachments;
    every managed-policy default version matches its plan-bound document
    digest and the two proof roles share only the deny-all proof policy;
11. the operator has no direct IAM, Lambda, DynamoDB, Logs, S3 or Signer writes;
12. the operator's CloudFormation create/read authority is restricted to the
   dedicated stack and its `iam:PassRole` grant names only the fixed service
   role; and
13. the role/policy/PassRole and signing state is fresh and complete, and the
   execution authorization binds its exact `service_role_evidence_digest`,
   `operator_authority_evidence_digest`, `live_before_state_digest` and overall
   `live_checkpoint_digest` alongside the plan-bound role ARN and exact signing
   evidence.

An access denial, incomplete pagination, unknown policy, extra attachment,
wildcard PassRole, wrong trust principal, mutable role boundary, pending/failed
Signer job, extra allowed publisher, signing policy other than `Enforce`, source
or destination drift, existing foreign stack or stale observation is `BLOCKED`.
Absence and signature validity cannot be inferred.

GUG-363 is a consumer of this handoff, never its producer. Do not use this
runbook to upload/copy either object, start/retry/cancel a signing job, or
create/update a Signer profile or Code Signing Config. Those are separately
authorized external operations and must finish before the GUG-363 plan and
execution authorization are closed.

## Phase 2 — Build the private plan offline

Set task-specific variables only to already existing private paths. The command
below performs no AWS call:

```bash
GUG363_PRIVATE_INTENT='<private-0600-gug363-intent.json>'
GUG363_UNSIGNED_PACKAGE_MANIFEST='<private-0600-gug215-unsigned-source-manifest.json>'
GUG363_UNSIGNED_PACKAGE_ARCHIVE='<private-0600-gug215-unsigned-source.zip>'
GUG363_PLAN_OUT='<new-private-gug363-plan.json>'

python3 scripts/deployment/platform-authority-retirement-entrypoint-materializer.py \
  plan \
  --intent "$GUG363_PRIVATE_INTENT" \
  --unsigned-package-manifest "$GUG363_UNSIGNED_PACKAGE_MANIFEST" \
  --unsigned-package-archive "$GUG363_UNSIGNED_PACKAGE_ARCHIVE" \
  --plan-out "$GUG363_PLAN_OUT"
```

The package arguments are the unsigned source only; they are never projected as
the Lambda deployment object. The closed intent separately identifies the exact
Signer job/profile, source object, signed destination and Code Signing Config.
Only signed-destination S3 coordinates and signed-byte `CodeSha256` may appear in
the generated `CreateStack` projection.

The output path must not exist. The command fails on a dirty tree, mismatched
Git object, template drift, unsigned package/archive mismatch, unexpected
field, conflated source/destination, incorrect private-file mode or any
target/parameter/service-role/signing-contract substitution.

Publish only the sanitized CLI result. Keep the plan, parameter values,
artifact locator, role ARN and all raw bindings private.

## Phase 3 — Owner checkpoint; no AWS mutation

The owner compares the complete private plan to the exact reviewed commit,
GUG-357 service-role evidence and ADR-050 exception. Record separately:

- exact `plan_digest`, `artifact_signing_contract_digest` and
  `create_stack_request_digest`;
- exact fixed target and CloudFormation service-role ARN;
- exact `service_role_evidence_digest`, `operator_authority_evidence_digest`,
  `live_before_state_digest` and `live_checkpoint_digest`;
- template and unsigned source package manifest/archive digests;
- the distinct exact source and signed-destination S3 versions, checksums, sizes
  and encryption bindings;
- completed Signer job, exact signing-profile version and their evidence;
- signature expiry later than or equal to the execution-authorization expiry;
- Code Signing Config `Enforce` policy and exact `AllowedPublishers` evidence;
- the signed destination code digest projected to CloudFormation and the runtime
  pin;
- all ordered CloudFormation parameters and the exact visible
  `PrivateParameterProjectionSha256` commitment over every other parameter;
- the exact fourteen expected resources and log-group contract;
- `OnFailure=DO_NOTHING`, termination protection and the deterministic request
  token; and
- `production=false`, `two_human_status=NOT_PROVEN` and
  `independent_approval_present=false`.

The plan must still state `deployment_authorized=false`. The owner then creates
or approves, outside this repository workflow, one fresh GUG-357 execution
authorization that states `deployment_authorized=true` and binds only this
plan, caller, service role, artifact signing contract/evidence, `CreateStack`
action and fifteen-minute-or-shorter window. Review and deliver its expected
digest through a separate channel.

Do not proceed if the plan is allowed to recompute its own expected digest or
if the same file is treated as both plan and authorization.

## Phase 4 — Future exact CreateStack attempt; currently NO-GO

The following command shape is documentation, not current authority to run it.
It may be used only in a task that explicitly authorizes the exact profile,
account, Region, plan digest, artifact-signing-contract digest, authorization
digest and one `cloudformation:CreateStack` attempt:

```bash
GUG363_PLAN='<private-0600-reviewed-plan.json>'
GUG363_EXECUTION_AUTHORIZATION='<private-0600-gug357-authorization.json>'
GUG363_EXPECTED_PLAN_DIGEST='<separately-reviewed-sha256-digest>'
GUG363_EXPECTED_AUTHORIZATION_DIGEST='<separately-reviewed-sha256-digest>'
GUG363_EXPECTED_ARTIFACT_SIGNING_CONTRACT_DIGEST='<separately-reviewed-sha256-digest>'
GUG363_APPROVED_PROFILE='<explicit-approved-profile>'
GUG363_RECEIPT_OUT='<new-private-gug363-materialization-receipt.json>'

python3 scripts/deployment/platform-authority-retirement-entrypoint-materializer.py \
  apply \
  --plan "$GUG363_PLAN" \
  --authorization "$GUG363_EXECUTION_AUTHORIZATION" \
  --expected-plan-digest "$GUG363_EXPECTED_PLAN_DIGEST" \
  --expected-authorization-digest "$GUG363_EXPECTED_AUTHORIZATION_DIGEST" \
  --expected-artifact-signing-contract-digest \
    "$GUG363_EXPECTED_ARTIFACT_SIGNING_CONTRACT_DIGEST" \
  --profile "$GUG363_APPROVED_PROFILE" \
  --region us-east-1 \
  --receipt-out "$GUG363_RECEIPT_OUT" \
  --allow-create-stack
```

Before this command, the fixed local directory
`~/.scanalyze-private-evidence/gug-363-live-v1` must already exist, be owned by
the operator and have mode `0700`. The CLI reserves the canonical create-only
execution-ledger file there before the AWS write. Never remove, replace, edit or
copy that ledger to make another attempt possible.

The command rejects static AWS credential variables, web-identity variables,
role override variables, endpoint overrides and custom CA variables. Its exact
call order before any possible ledger claim is:

1. `sts:GetCallerIdentity`;
2. `cloudformation:DescribeStacks`;
3. `signer:DescribeSigningJob`;
4. `signer:GetSigningProfile`;
5. `s3:GetBucketVersioning`;
6. unsigned `s3:HeadObject` and `s3:GetObject`;
7. signed `s3:ListObjectVersions`, `s3:HeadObject` and `s3:GetObject`;
8. `lambda:GetCodeSigningConfig`; and
9. a second `cloudformation:DescribeStacks`.

Signing preflight and the second stack read occur even if the first read finds a
target. A disappearing/replaced first target is ambiguous and blocks mutation;
a stable pre-existing second observation is no-touch but remains ambiguous
because CloudFormation masks private parameters and no GUG-363 execution ledger
causally binds it. Only if
both observations prove absence does the command revalidate the authorization
and signature windows, persist the create-only ledger, and make its sole
`cloudformation:CreateStack` call.
Post-write calls are exactly `DescribeStacks`, `GetTemplate`,
`ListStackResources` and `DescribeStackEvents`. Object bodies are used only for
digest and safe in-memory ZIP-member equality verification; they are never
logged, persisted or extracted. The runtime never uploads, copies, signs or
repairs an artifact. The SDK is configured for zero retries.

## Phase 5 — Interpret the receipt

Only these broad classes are meaningful:

| Status family | Meaning | Next action |
|---|---|---|
| `READBACK_VERIFIED` | A GUG-363 create/reconcile chain with consumed ledger, exact request-token event and complete control-plane readback matched | Preserve evidence; continue only to separately authorized provider certification |
| `CREATESTACK_ACCEPTED_RECONCILE_REQUIRED` | AWS accepted the request but terminal state is not proven | Reconcile only |
| `READBACK_PENDING_NO_MUTATION` | Existing/observed state is not terminal or its masked parameters lack a causal GUG-363 ledger | Reconcile only; pre-existing targets require GUG-357 provider evidence |
| `NONDESTRUCTIVE_RECOVERY_REQUIRED` | Target is absent after a consumed attempt, partial or failed | Stop; open a separate recovery issue |
| `BLOCKED_DRIFT` | Stack, role, template or resource graph differs | Stop; no update/delete |
| `UNCERTAIN_RECONCILE_ONLY` | Outcome after the consumed write is ambiguous | Never retry create; reconcile only |

The CLI's sanitized stdout does not contain raw role, stack, artifact or caller
identifiers. Preserve the private receipt and AWS evidence outside Git.
`READBACK_VERIFIED` remains limited to
`CLOUDFORMATION_CONTROL_PLANE_ONLY`; the receipt always records
`provider_certification_complete=false` and
`gug357_certification_required=true`. Do not treat it as Phase 9 provider
certification or permission to invoke the broker.

When true, `artifact_signing_readback_complete` means only that the pre-create
or no-touch/reconcile Signer job, exact S3 source/destination and Code Signing
Config checks matched. Complete readback requires it, but it does not mean the
deployed Lambda or any other provider resource has received GUG-357 post-create
certification.

The visible `PrivateParameterProjectionSha256` detects accidental projection
drift but does not prove masked values on an arbitrary pre-existing stack.
Completion accepts CloudFormation asterisks only when a validated consumed
ledger, exact plan and stack-event request token establish the materializer's
own causal create chain.

## Phase 6 — Read-only reconciliation

After a consumed attempt, use only the same plan, authorization, expected plan,
authorization and artifact-signing-contract digests, approved profile and
canonical execution ledger. The authorization may be expired for reconciliation
but must remain structurally and digest exact.

```bash
GUG363_RECONCILE_RECEIPT_OUT='<new-private-gug363-reconcile-receipt.json>'

python3 scripts/deployment/platform-authority-retirement-entrypoint-materializer.py \
  reconcile \
  --plan "$GUG363_PLAN" \
  --authorization "$GUG363_EXECUTION_AUTHORIZATION" \
  --expected-plan-digest "$GUG363_EXPECTED_PLAN_DIGEST" \
  --expected-authorization-digest "$GUG363_EXPECTED_AUTHORIZATION_DIGEST" \
  --expected-artifact-signing-contract-digest \
    "$GUG363_EXPECTED_ARTIFACT_SIGNING_CONTRACT_DIGEST" \
  --profile "$GUG363_APPROVED_PROFILE" \
  --region us-east-1 \
  --receipt-out "$GUG363_RECONCILE_RECEIPT_OUT"
```

`reconcile` repeats the full preflight order through the second
`DescribeStacks`, then uses `GetTemplate`, `ListStackResources` and
`DescribeStackEvents`. It is read-only and can never call `CreateStack`,
`UpdateStack`, `DeleteStack` or broker aliases. A nonzero result is not
permission to retry or clean up.

## Required terminal readback

Completion requires exact private evidence for:

1. full dedicated stack ID and `CREATE_COMPLETE`;
2. the fixed stack `RoleARN`, template body/digest, parameters and termination
   protection;
3. exactly fourteen expected resources with no normal-mode aliases;
4. exact retained log group and 365-day retention;
5. separate GUG-365 certification of the exact precreated Lambda function,
   role, signed-destination version and signed code SHA, completed Signer
   source/destination/profile binding, Code Signing Config `Enforce`, exact
   `AllowedPublishers`, manual runtime pin and `LoggingConfig`;
6. exact alias targets, `AWS_IAM` Function URLs and invoke permissions; and
7. sanitized receipt digests bound to the plan, authorization and observed
   resource set.

This proves only the materialized entrypoint. It does not authorize or prove a
broker invocation, `DeleteChangeSet`, Identity Center assignment, revocation,
production readiness or human independence.

## Stop and recovery conditions

Stop before create, or remain reconcile-only after a consumed attempt, for any:

- wrong account, Region, caller, stack or service role;
- unsigned source used as deployment code, same source/destination, wrong object
  version/checksum/size/encryption, or signed destination absent;
- Signer job incomplete/failed/mismatched, wrong historical signing-profile
  version, inactive/wrong-platform current profile, Code Signing Config not
  `Enforce`, or missing/extra allowed publisher;
- missing/extra service-role policy, boundary, tag, trust or PassRole edge;
- operator provider write authority or wildcard `iam:PassRole`;
- existing foreign/drifted stack or incomplete absence proof;
- dirty source, changed template, unsigned package/archive mismatch or unreviewed
  signing/evidence digest;
- inactive/overlong execution authorization or authorization overclaim;
- static credentials, endpoint override, custom CA or unexpected SDK retry;
- response loss, timeout, malformed StackId or invisible/in-progress stack;
- missing/extra resource, wrong `RoleARN`, alias-family crossover or logging
  drift; or
- any consumed local ledger, even when the stack appears absent.

GUG-363 does not authorize `DeleteStack`, `UpdateStack`, resource adoption,
manual deletion or recreation. Retained or partial resources require a new
issue, fresh inventory, explicit destructive scope and rollback/readback plan.
