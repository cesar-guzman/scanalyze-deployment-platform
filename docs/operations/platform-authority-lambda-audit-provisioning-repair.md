# GUG-221 server-side repair operations runbook

## Status and authorization boundary

This runbook describes the future, separately authorized non-production
operation of the GUG-221 server-side PEP. It is not authority to deploy either
CloudFormation stack, change Identity Center, invoke a live Lambda alias or
repair AWS state.

Current evidence is repository-only unless a later record explicitly proves
otherwise. Production is **NO-GO**.

## Operator model

The current roster contains one person. That person may perform sequential
logins when an exact non-production change is separately authorized. Multiple
profiles, roles or sessions held by the same person do not constitute an
independent approver. Record this fact in every plan, change and closeout.

Future steady-state operation should assign these duties to different people:

| Duty | Required authority |
|---|---|
| Repository reviewer | Reviews source, IaC, policies, hashes and test evidence |
| Management deployer | Deploys only the reviewed delegation stack |
| Authority deployer | Deploys only the reviewed PEP stack and version aliases |
| Repair invoker | Invokes exact private aliases with `{}` only |
| Evidence reviewer | Performs independent read-only SSO/IAM/ledger verification |

Until independent personnel exist, mark separation of duties **not met** and do
not convert technical controls into a production approval claim.

## Required artifacts

- exact reviewed GUG-221 commit with green required CI;
- reviewed Lambda deployment package digest and code-signing configuration;
- `bootstrap/cfn-platform-authority-lambda-audit-repair-pep.yaml`;
- `bootstrap/cfn-platform-authority-lambda-audit-repair-delegation.yaml`;
- exact standalone policy digests;
- the reviewed pre-Phase-B broker package, exact qualified alias, invoke-only
  SSO policy, application actor policy, deny-all proof role, broker service
  role, one-shot ledger and provider readback receipts;
- private, validated installation bindings for instance/store, immutable
  `USER`, permission-set ARN/tags, SAML provider, KMS mode/key and account roles;
- sanitized proof that the GUG-220 ledger remains consumed and unchanged;
- an exact, time-bounded non-production change authorization; and
- an approved evidence location outside Git with owner-only access.

Do not place live IDs, ARNs, policies, provider responses or receipts in the
repository, comments, shell history or NotebookLM.

## Phase 0 — Offline repository gate

From a clean worktree at the exact reviewed commit:

```bash
git status --short --branch
git diff --check
make platform-authority-bootstrap-check
make security-check
make docs-check
```

Classify each result separately. Local success is not CI success, deployment or
live validation.

## Phase 1 — Read-only identity and state preflight

After login with explicitly approved profiles:

1. call `sts:GetCallerIdentity` for each profile and confirm exact account and
   Region;
2. read the active Identity Center instance and Identity Store;
3. enumerate the collector permission set with complete pagination;
4. prove the exact eligible partial state;
5. inspect the authority-account IAM role namespace completely;
6. read the original GUG-220 ledger evidence without changing it; and
7. inventory both prospective stacks and all conflicting aliases, roles,
   tables, keys and assignments.

Any access denial, repeated pagination token, unexpected resource, partial
response, conflicting binding or stale source stops the workflow. Do not infer
absence and do not proceed to deployment.

## Phase 2 — Review immutable deployment inputs

Before creating any Change Set, independently compare the proposed parameters
and derived artifacts against the reviewed commit:

- both account IDs and `us-east-1`;
- the exact Phase B creator session plus separately bound invoke-only SSO,
  broker and deny-all proof authorities;
- exact principal type `USER` and private principal ID;
- exact collector permission-set ARN/name/tags;
- source commit, Lambda package SHA-256 and code-signing config;
- published numeric versions and alias mapping;
- repair ID and a validity interval no longer than 15 minutes;
- collector and human repair-invoker policy digests;
- original GUG-220 ledger digest;
- SAML provider/audience and KMS mode/key/context; and
- exact cross-account service-role trust.

The repair event is not an input surface. Every mode expects exactly `{}`.

## Phase 2A — Build, sign and independently bind the exact artifact

This phase requires separate authorization for the S3 upload and AWS Signer
job. The verifier itself is read-only. Run it only from a clean checkout of the
exact reviewed commit; do not copy a manifest from another workstation or
provide hand-edited AWS readback JSON.

The signed verifier runs only after merge. Fetch `main`, authenticate `gh`
read-only, and require the clean local `HEAD`, `origin/main`, current GitHub
`main`, merged PR commit and PR tree to converge. It also reads the current
required-status policy and accepts only the six reviewed successful check runs
issued by the GitHub Actions App. A stale main ref, unprotected branch,
homonymous third-party check or changed required-check set blocks the handoff.

Build the deterministic unsigned package into a new private directory outside
the repository:

```bash
SOURCE_COMMIT="$(git rev-parse HEAD)"
PRIVATE_BUILD_DIR="$(mktemp -d /tmp/scanalyze-gug221-build.XXXXXX)"
chmod 700 "$PRIVATE_BUILD_DIR"

python scripts/deployment/platform-authority-lambda-audit-repair-package.py \
  --source-commit "$SOURCE_COMMIT" \
  --expected-boto3-version '<reviewed Lambda runtime boto3 version>' \
  --expected-botocore-version '<reviewed Lambda runtime botocore version>' \
  --output-directory "$PRIVATE_BUILD_DIR/package"
```

Under a separately approved non-production change, upload that exact unsigned
ZIP once to the versioned private authority bucket with an S3 SHA-256 checksum,
start one `AWSLambda-SHA384-ECDSA` signing job using the reviewed profile, and
record only its job ID in private evidence. Do not deploy the unsigned object.
Do not overwrite either source or destination key.

After the job reports `Succeeded`, authenticate the exact read-only verifier
profile and let the verifier obtain `GetCallerIdentity`, `DescribeSigningJob`,
bucket versioning, version inventory, and exact-version Head/Get responses
directly from AWS:

```bash
aws sso login --profile 042360977644_ReadOnlyAccess

python scripts/deployment/platform-authority-lambda-audit-repair-signed-artifact.py \
  --profile 042360977644_ReadOnlyAccess \
  --region us-east-1 \
  --source-commit "$SOURCE_COMMIT" \
  --expected-boto3-version '<same reviewed boto3 version>' \
  --expected-botocore-version '<same reviewed botocore version>' \
  --job-id '<exact successful Signer job UUID>' \
  --expected-profile-version-arn '<exact reviewed Signer profile version ARN>' \
  --output-receipt "$PRIVATE_BUILD_DIR/gug221-signed-artifact-receipt.json"
```

The command fails closed unless it can rebuild the same source bytes, prove one
signed object version named by the job ID, require SHA-256 readback, reject any
additional ZIP entry and produce one receipt binding the same signed tuple to
Plan, repair and reconcile. The command performs no S3 or Signer mutation. Never use
the unsigned archive digest as `RepairArtifactCodeSha256` or
`ReconcileArtifactCodeSha256`.

If AWS Signer or S3 does not expose the required exact version/checksum, stop.
Do not substitute an ETag, latest-object read, local download or manual digest.

## Phase 2B — Prepare and verify Phase A delegation only

The deployment contract contains only accounts, reviewed source commit,
15-minute repair window and exact Change Set creator/executor identities. It must not
contain principal, instance/store, SAML/KMS, collector/invoker permission-set
ARN, policy digest, GUG-220 ledger digest or repair ID.

Log in only to the fixed read-only profiles. The command performs two complete
provider snapshots, with pending-operation reads before and after each, and
writes separate create-only mode-`0600` evidence and ten-parameter handoff
files outside Git:

```bash
python scripts/deployment/platform-authority-lambda-audit-repair-change-set.py \
  prepare-delegation \
  --authority-profile 042360977644_ReadOnlyAccess \
  --management-profile 839393571433_ReadOnlyAccess \
  --region us-east-1 \
  --deployment-contract '<private owner-only GUG-221 deployment contract>' \
  --gug220-intent '<exact private GUG-220 intent>' \
  --gug220-ledger '<exact private consumed GUG-220 ledger>' \
  --gug220-receipt '<exact private UNCERTAIN_RECONCILE_ONLY receipt>' \
  --output-gug220-evidence "$PRIVATE_BUILD_DIR/gug221-gug220-live-evidence.json" \
  --output-parameters "$PRIVATE_BUILD_DIR/gug221-delegation-parameters.json"
```

The provider receipt derives instance/store/SAML/KMS/principal/collector state
from AWS and proves the partial permission set has no inline policy,
attachments, boundary, assignments, provisioning or generated collector role.
Malformed extra entries, incomplete pagination, provider drift or a pending
operation blocks preparation. The handoff is non-authoritative and does not
authorize any CloudFormation call.

After a separately authorized system creates the exact Phase A Change Set,
verify that Change Set only:

```bash
aws sso login --profile 042360977644_ReadOnlyAccess
aws sso login --profile 839393571433_ReadOnlyAccess

python scripts/deployment/platform-authority-lambda-audit-repair-change-set.py \
  verify-delegation \
  --authority-profile 042360977644_ReadOnlyAccess \
  --management-profile 839393571433_ReadOnlyAccess \
  --region us-east-1 \
  --deployment-contract '<same private deployment contract>' \
  --gug220-intent '<same intent>' --gug220-ledger '<same ledger>' \
  --gug220-receipt '<same receipt>' \
  --gug220-evidence "$PRIVATE_BUILD_DIR/gug221-gug220-live-evidence.json" \
  --parameter-handoff "$PRIVATE_BUILD_DIR/gug221-delegation-parameters.json" \
  --change-set-arn '<exact delegation Change Set ARN including UUID>' \
  --output-receipt "$PRIVATE_BUILD_DIR/gug221-delegation-change-set-verification.json"
```

The verifier refreshes the GUG-220 provider snapshot in the same invocation,
then binds exact CloudFormation metadata/template/parameters/tags/resources and
the unique CloudTrail `CreateChangeSet` event. `RoleARN`, notifications,
nested/import/deployment-mode options, rollback drift or masked values block.
The receipt also contains the only eligible Phase A `client_request_token`;
it is derived from the reviewed receipt and is not an operator choice.

## Phase 2C — Read back executed Phase A, then prepare/verify Phase B

Execution remains separately authorized. The separately reviewed executor
must use all three exact values from the receipt: UUID-bearing Change Set ARN,
stack ARN and `execution_contract.client_request_token`. Omitting or replacing
any value makes later readback fail closed. A representative command shape is:

```bash
# Mutation: run only under a separate, explicit authorization.
aws cloudformation execute-change-set \
  --profile '<contract-bound Phase A executor profile>' \
  --region us-east-1 \
  --change-set-name "$(jq -r '.change_set.arn' "$PRIVATE_BUILD_DIR/gug221-delegation-change-set-verification.json")" \
  --stack-name "$(jq -r '.change_set.stack_arn' "$PRIVATE_BUILD_DIR/gug221-delegation-change-set-verification.json")" \
  --client-request-token "$(jq -r '.execution_contract.client_request_token' "$PRIVATE_BUILD_DIR/gug221-delegation-change-set-verification.json")"
```

After execution, run `readback-delegation` with the same
chain/evidence/handoff, the immutable Change Set review receipt and fixed
read-only profiles:

```bash
python scripts/deployment/platform-authority-lambda-audit-repair-change-set.py \
  readback-delegation \
  --authority-profile 042360977644_ReadOnlyAccess \
  --management-profile 839393571433_ReadOnlyAccess \
  --region us-east-1 \
  --deployment-contract '<same private deployment contract>' \
  --gug220-intent '<same intent>' --gug220-ledger '<same ledger>' \
  --gug220-receipt '<same receipt>' \
  --gug220-evidence "$PRIVATE_BUILD_DIR/gug221-gug220-live-evidence.json" \
  --parameter-handoff "$PRIVATE_BUILD_DIR/gug221-delegation-parameters.json" \
  --delegation-change-set-receipt "$PRIVATE_BUILD_DIR/gug221-delegation-change-set-verification.json" \
  --output-execution-receipt "$PRIVATE_BUILD_DIR/gug221-delegation-execution-trace.json" \
  --output-live-receipt "$PRIVATE_BUILD_DIR/gug221-delegation-live-readback.json"
```

The verifier requires one exact CloudTrail `ExecuteChangeSet` event and
complete `DescribeStackEvents` evidence using the derived token. It rejects a
foreign executor, arbitrary token, duplicate event, pagination anomaly,
rollback/failure transition, missing terminal resource or a state-equivalent
stack with no reviewed execution lineage. The create-only execution and live
receipts then prove the exact stack, outputs, permission-set
metadata/policy/tags, no extra attachment/boundary, its sole USER assignment
to account `7644`, and the exact management roles. Only its provider-derived
invoker ARN can enter Phase B.

Run `prepare-pep` with the signed-artifact receipt, chain, GUG-220 evidence and
Phase A live receipt. Run `verify-pep` against the one existing PEP CREATE
Change Set. That verifier refreshes Signer/S3, GUG-220 and the entire Phase A
live state before inspecting Phase B. Never pass a raw invoker ARN.

The reviewed Phase B receipt must contain exactly 23 ordered resource changes,
the UUID-bearing Change Set and stack ARNs, and one deterministic
`gug221-b-*` execution contract bound to the exact broker operation. A receipt
carrying the former 18-resource inventory, another broker, a Phase A token or
an operator-selected token is ineligible.

Do not execute Phase B until a separate reviewed pre-Phase-B infrastructure
change has deployed the broker handler from the same immutable signed ZIP and
direct-provider readback has verified all of the following:

- one ordinary SSO role with only direct `lambda:InvokeFunction` on the exact
  qualified private broker alias;
- one reviewed IAM Identity Center application using Authorization Code + PKCE,
  its exact application actor policy and no alternate grant or redirect;
- one deny-all proof role whose trust accepts exactly one STS
  `ProvidedContext` for the exact identity and operation;
- one broker service role with only the exact Phase B CloudFormation and
  downstream `aws:CalledVia` authority;
- one durable one-shot ledger with the exact unconsumed operation binding; and
- complete revocation topology with no alternate alias, Function URL, async
  path or foreign assignment.

The nine-resource authority-account template does not create the first two
items in that list. `IdentityCenterApplicationArn` and `InvokerPrincipalArn`
are inputs, not evidence: do not copy them from a console, shell variable,
deployment contract or prior receipt. A separate management/Identity Center
change must create and provision the application/permission-set/assignment
topology, then emit a typed direct-provider receipt that binds those values.
That materialization and receipt are not implemented in this repository-only
change. Until they exist, classify Phase B as
`BLOCKED_IDENTITY_PRECONDITION_NOT_MATERIALIZED`; do not create the
pre-Phase-B Change Set or attempt the broker flow.

Do not hand-author that receipt. Schema conformance and a canonical self-digest
are not authentication. The current command path validates the target shape
and then fails closed because no live provider/KMS-authenticated producer is
implemented. The only permitted order is identity materialization receipt,
PEP handoff/receipt, PRE_B handoff/receipt, then execution/effect/readback.
Omitting or changing either PRE_B artifact blocks before STS, CloudFormation,
DynamoDB or any effect client.

For the authority-account portion, generate only the typed
`phase_b_precondition_parameters.v1` handoff. It must rebuild the signed
package from the exact Git commit, match the signed manifest, render the four
effective policy documents, and contain exactly 37 ordered parameters. Review
only the exact nine-resource CREATE Change Set and persist only
`phase_b_precondition_change_set_receipt.v1`. Either artifact remains
read-only evidence and must never be treated as execution authority.

Do not place the provider receipt in CloudFormation parameters or Lambda
environment variables. Create the immutable alias from the static topology
binding and KMS verification key/algorithm, then collect and sign fresh
provider evidence and supply it only as `broker_topology_evidence` in the exact
synchronous invocation payload.

Before signing topology evidence, inspect direct `GetFunctionConfiguration`
readback for the immutable published version. The response is acceptable only
when `Environment` contains exactly one member, `Variables`, and that map is
the exact 37-variable projection returned by
`PhaseBIdentityBinding.broker_environment_variables`. Do not reconstruct,
merge or normalize this map from shell variables, profiles, payloads, prior
receipts or operator input.

The canonical projection covers account/region, Identity Center application
and store, redirect/operator, all three roles, ledger, exact stack/Change Set/
token/window/execution ID, intent and receipt digests, template/parameter/
inventory/ledger/OAuth digests, four policy digests, immutable artifact tuple,
Code Signing Config, topology signing key/algorithm and expected static
topology digest. Its exact key list is defined in the deployment guide. Any
missing `Environment`, omitted key, additional key, non-string entry or value
drift is terminal `BROKER_TOPOLOGY_LAMBDA_ENVIRONMENT_MISMATCH`; do not sign,
invoke, retry or repair in place.

Confirm that the provider-state Lambda subtree contains
`environment_variables_sha256` for the canonical projection, not its raw
values. Confirm that changing any projected value changes
`topology_state_digest`, and that the receipt digest/KMS signature binds that
state digest. Fresh topology evidence and its digest must remain absent from
the environment and appear only in the one-shot synchronous invocation.

The invoker preserves the exact `ClientContext` custom map (`transport`,
`execution_id`, `broker_topology_sha256`). Missing or extra event fields, an
evidence object larger than 4 KiB, stale/future evidence, a different static or
policy digest, key/algorithm, canonical digest or KMS signature are terminal
denies. Do not retry. These checks and `kms:Verify` precede creation of
OIDC/STS/DynamoDB/CloudFormation clients and the one-shot CAS.

Ledger readback must also prove that the exact resource policy denies every
principal from `PutResourcePolicy`, `DeleteResourcePolicy`, `DeleteTable`,
`UpdateTable`, `CreateBackup`, `ExportTableToPointInTime`,
`RestoreTableToPointInTime`, `UpdateContinuousBackups`, `UpdateTimeToLive`,
auto-scaling, streaming and tag mutations. It must also reject
PartiQL/batch/query/scan access and transactional use of the broker's direct
item permissions through `dynamodb:EnclosingOperation`.
`DescribeTimeToLive` must return exactly `DISABLED` and omit `AttributeName`.
Any different, incomplete or unreadable result blocks before ledger access;
do not repair the ledger in place or relax its policy.

Do not treat this receipt as an account-wide guardrail for legacy
global-table APIs, imports or restore-from-backup; DynamoDB does not support
those APIs in table resource policies. Their absence from the broker role is
necessary but not sufficient. Production requires a separate reviewed
account/organization guardrail and live proof.

The deterministic ZIP already closes over the Phase B handler, its pure PEP,
the managed-policy snapshot and all four reviewed policy contracts. This PR
does not deploy or activate those controls. When a future change
authorizes their live use, the operator authenticates through the reviewed
Authorization Code + PKCE helper and invokes only the qualified broker alias
through the signed Lambda API. The one-call payload helper is
`tooling/platform_authority_lambda_audit_repair_phase_b_invoker.py`; it does not
claim the receipt is authenticated locally because the broker owns KMS
verification. The authorization helper must bind a loopback callback, use a
cryptographically random PKCE verifier/state, accept one callback, and keep the
authorization code, verifier, tokens, opaque identity context and STS
credentials out of arguments, shell history, files, receipts and logs.

The broker must pass the opaque context to exactly one STS `ProvidedContext`
for the deny-all proof role, bind that proof to the exact receipt, consume the
one-shot CAS gate and only then let its separate service role call the exact
`ExecuteChangeSet`. The proof role never mutates AWS. Record
`native_on_behalf_of = false`; the human proof and broker effect actors are
separate. There is no direct `aws cloudformation execute-change-set` operator
command and no Function URL fallback.

After the operation reaches a terminal state, use only the fixed read-only
profiles to prove the execution lineage and the live 23-resource stack:

```bash
python scripts/deployment/platform-authority-lambda-audit-repair-change-set.py \
  readback-pep \
  --authority-profile 042360977644_ReadOnlyAccess \
  --region us-east-1 \
  --deployment-contract '<same private deployment contract>' \
  --gug220-intent '<same intent>' --gug220-ledger '<same ledger>' \
  --gug220-receipt '<same receipt>' \
  --gug220-evidence "$PRIVATE_BUILD_DIR/gug221-gug220-live-evidence.json" \
  --signed-receipt "$PRIVATE_BUILD_DIR/gug221-signed-artifact-receipt.json" \
  --delegation-live-receipt "$PRIVATE_BUILD_DIR/gug221-delegation-live-readback.json" \
  --pep-parameter-handoff "$PRIVATE_BUILD_DIR/gug221-pep-parameters.json" \
  --pep-change-set-receipt "$PRIVATE_BUILD_DIR/gug221-pep-change-set-verification.json" \
  --broker-effect-receipt "$PRIVATE_BUILD_DIR/gug221-phase-b-broker-effect.json" \
  --output-cloudformation-trace-receipt "$PRIVATE_BUILD_DIR/gug221-pep-execution-trace.json" \
  --output-effective-state-receipt "$PRIVATE_BUILD_DIR/gug221-pep-effective-state.json"
```

`readback-pep` has no mutation API. It fails unless CloudTrail identifies the
exact broker service-role actor and token, StackEvents prove the root plus all
23 resources reached `CREATE_COMPLETE`, and live template, parameters, tags,
outputs and resource inventory still equal the reviewed contract. That receipt
is a CloudFormation execution trace, not effective-state proof. The command
also performs the separate direct-provider readback and writes it to the
explicit effective-state output; either output is withheld if the complete
chain cannot be proven.

A separate direct-provider readback must then inspect IAM, Lambda, DynamoDB,
KMS and CloudWatch Logs with only Get/List/Describe operations, derive physical
IDs only from trusted stack metadata, compare two complete snapshots and prove
all 23 controls. Never emit raw physical IDs. Missing, duplicated, foreign,
rolled-back, unstable, paginated-incompletely or access-denied evidence remains
`BLOCKED`.

Do not accept two identical snapshots as sufficient proof. Resolve the reviewed
template with the exact 29-parameter PEP handoff and require
`expected_state_sha256 == observed_state_sha256` for each ordered resource.
Treat extra Lambda aliases/versions/async configs, DynamoDB global or restore
state, throughput/stream drift, IAM boundaries, KMS algorithms/aliases and Logs
data-protection inheritance as `EFFECTIVE_STATE_CONFORMANCE_DRIFT`.

The broker runtime receipt may state only that the execution gate was consumed
and closure is pending. Classify revocation as verified only after provider
readback proves the SSO assignment and invoke edge were removed, no Identity
Center operation is pending, all possible sessions expired and the durable
gate remains consumed. Until then, no execution or revocation success claim is
eligible.

Fresh readback will legitimately change the outer live receipt timestamp and
the nested execution receipt `evaluated_at`. The verifier excludes only those
observation timestamps from equality and digest binding. Do not manually edit
them or remove any provider event, token, actor, resource, digest or verifier
field; any such change is drift and remains blocked.

The reviewed parameters are identifiers, digests and ARNs, not credentials,
so both templates intentionally omit `NoEcho` and the private handoff/receipt
files remain mode `0600` outside Git. If CloudFormation nevertheless returns
`****`, verification is **BLOCKED**; never compare a masked value by inference
or treat the preparation digest as live proof. The verifier has no Create,
Execute or Delete path and uses SDK retries disabled.

## Phase 3 — Provider-specific post-deployment validation

Phase 2C is the only phase in this runbook that describes separately
authorized execution of the reviewed Phase A and Phase B Change Sets. Phase 3
does not deploy, update, retry or repair either stack. Enter it only when both
Phase 2C readbacks are eligible and bind the exact execution lineage. If either
stack is absent, incomplete, failed or not bound to its reviewed receipt, stop;
do not use this phase to create or execute another Change Set.

Use fresh read-only provider APIs to corroborate controls that generic
CloudFormation stack readback cannot prove by itself:

1. in the management account ending in `1433`, read back the
   mutation/readback service-role trust and effective inline policies;
2. in the authority account ending in `7644`, read back KMS, DynamoDB, all
   three functions, published versions, code hashes, code signing, execution
   roles, the invocation inspector, aliases and retained log groups; and
3. confirm the human permission set can invoke only the three exact aliases.

Do not call CloudFormation Create, Execute, Update or Delete operations in this
phase. Do not use direct IAM edits to make a failed template appear valid. Do
not repoint an alias to `$LATEST` or an unreviewed version.

The reviewed management-first dependency is intentional and has no circular
principal dependency. Before the authority execution roles existed, IAM could
resolve the authority account root used in each management trust policy. That
root is not broad execution authority: `aws:PrincipalAccount` plus `ArnEquals
aws:PrincipalArn` restricts assumption to the one exact Lambda execution-role
ARN. Provider validation must prove both caller and target policies allow the
paired `sts:AssumeRole` and `sts:SetSourceIdentity` actions on that exact edge.
Never remove the ARN condition to resolve a deployment failure.

The authority stack must prove:

- complete, replay-safe pagination of regional `ListFunctions` with
  `FunctionVersion=ALL`, plus `ListVersionsByFunction` and `ListAliases` for
  all three reviewed functions;
- exactly `$LATEST` and one reviewed published version per function, exactly
  `repair-v1`, `plan-v1` and `reconcile-v1` with their reviewed targets, and no
  other function using any protected execution role;
- DynamoDB `Retain`, deletion protection, PITR and KMS encryption;
- table resource-policy allow only Plan `PutItem` and repair `UpdateItem`, with
  unsupported write APIs and all foreign writers denied;
- no Lambda URL, public permission or event source;
- exact `AWS::Lambda::EventInvokeConfig` on all three aliases with zero
  retries, maximum event age 60 seconds and no destination;
- invoker/runtime readback of the required synchronous-only `ClientContext`
  marker before provider or ledger access;
- repair reserved concurrency of one; and
- Plan/repair/reconcile roles and functions remain separate; and
- the path-scoped inspector is trusted only by those three roles, has complete
  account-wide IAM/Lambda inventory reads, and explicitly denies invocation,
  mutation and role chaining.

Also verify the fixed runtime envelope: Plan and reconcile `Timeout: 300`,
repair `Timeout: 600`, and `MemorySize: 1024` for all three. The wrapper must
use CLI/process timeouts `315/330` for Plan/reconcile and `615/630` for repair.
Repair must preserve the 660-second immutable-window start gate, the
480-second pre-claim Lambda gate, the 75-second dispatch reserve and the
60-second inventory/polling reserve. Changing these values requires a new
reviewed package and Change Set; never lengthen only the client timeout.

An extra version or alias, changed alias target, protected-role reuse,
duplicate entry, inaccessible page or pagination-token replay is a hard
`BLOCKED` result. Do not infer exclusivity from `GetFunction` or the three
expected aliases alone.

### Failed Phase B with retained resources

The Phase B template intentionally retains the KMS key and alias, DynamoDB
ledger table and all three Lambda log groups on deletion, replacement or
rollback. A failed or rolled-back Phase B operation can therefore leave live
provider resources after CloudFormation stops managing some or all of them.
Classify that terminal condition as `FAILED_RETAINED_RESOURCES`; it is neither
a clean rollback nor authority to execute Phase B again.

Under the fixed read-only profiles, capture a complete, paginated inventory
that binds:

- the UUID-bearing stack and Change Set, terminal stack events and every
  observed physical resource identifier;
- the retained KMS key and alias, including key state, policy, rotation and
  tags;
- the DynamoDB table, including encryption, deletion protection, PITR,
  resource policy and tags; and
- the three log groups, including exact names, retention and tags.

Keep the complete inventory in private evidence and publish only sanitized
status, counts and digests. A matching name, alias, tag, template value or
expected configuration is discovery evidence only. It does not prove that a
resource belongs to this failed execution, is complete, is safe to reuse or
may be adopted. Missing physical IDs, denied reads, incomplete pagination or
conflicting provenance keeps the state `FAILED_RETAINED_RESOURCES`.

Quarantine every candidate retained resource and block another Phase B
creation while the canonical KMS alias, DynamoDB table name or log-group name
could collide. Do not import, rename, retarget, update, delete or silently
adopt a candidate to make a retry succeed. Retained KMS keys, DynamoDB storage
and CloudWatch Logs can continue to incur cost; record the owner, cost
exposure, retention requirement and next review time without treating cost as
destructive authorization.

Cleanup is not part of rollback or this runbook. Open a separate reviewed
child issue that names the exact KMS key/alias, DynamoDB table and log groups,
preserves ledger and audit requirements, evaluates dependencies and cost, and
defines explicit destructive authorization plus independent post-cleanup
readback. Until that child closes or a separately reviewed recovery proves an
exact non-destructive disposition, keep the resources quarantined, the
canonical names unavailable and production **NO-GO**.

## Phase 4 — Invoke the durable Plan gate

Only after both stacks pass readback, invoke the exact `plan-v1` alias with the
reviewed wrapper. The wrapper sends `{}`, forces `RequestResponse`, adds the
transport-only `ClientContext` marker, verifies the exact SSO session and
validates the complete public receipt:

```bash
python scripts/deployment/platform-authority-lambda-audit-provisioning-repair.py \
  plan \
  --profile '<approved ScanalyzeLambdaAuditRepair profile>' \
  --expected-source-commit '<reviewed 40-character commit>' \
  --expected-function-version '<published numeric version>'
```

The response is eligible only when it is bound to the exact published version
and reports `PLAN_VERIFIED`. `BLOCKED`, incomplete evidence, expired binding or
any non-empty request stops here. Plan performs no Identity Center write, but
it is intentionally not side-effect-free: only the Plan execution role may
conditionally create the durable `PLAN_VERIFIED` record with `PutItem`. The
record binds the planned provider-state digest and Plan/repair versions. A lost
Put response is reconciled by a strongly consistent read and is never retried.

Before that create, Plan must prove the exact account-wide invocation graph:
one reviewed SSO invoker role, exactly the three qualified alias edges, zero
foreign/unknown edges, zero mutating authority and complete provider coverage.
The plan must also report the exact reviewed Lambda-managed `boto3` and
`botocore` versions. Because those dependencies are bound but not vendored in
this package, run this plan immediately before repair; a version change
requires a new reviewed artifact rather than a retry.

## Phase 5 — Review the durable Plan and repair authorization

Before `repair-v1`, review the exact Plan receipt and strongly consistent
DynamoDB readback. The repair ID must contain the one matching, unconsumed
`PLAN_VERIFIED` record; absence is a blocker, not permission to let repair
create it. Grant a new, explicit authorization naming:

- exact commit, package hash, versions and aliases;
- exact accounts, Region, principal, permission set and policy digest;
- the three ordered Identity Center mutations;
- the repair ID and validity window; and
- the rule that any ambiguity ends in read-only reconciliation.

Do not reuse a plan after its validity window or after any provider change.
Freeze administrative Identity Center, IAM and Lambda-authority changes from
the final plan snapshot until `RECONCILE_VERIFIED`. The synchronous
`ClientContext` proves transport only and does not identify the human caller;
retain the exclusive Identity Center assignment, CloudTrail evidence and the
account-wide Lambda authority inventory as the caller-attribution boundary.

## Phase 6 — Invoke the one-shot repair

Invoke only the exact `repair-v1` alias through the same wrapper. The explicit
flag acknowledges only the client-side request; it cannot bypass the immutable
server binding or durable CAS:

```bash
python scripts/deployment/platform-authority-lambda-audit-provisioning-repair.py \
  repair \
  --profile '<approved ScanalyzeLambdaAuditRepair profile>' \
  --expected-source-commit '<reviewed 40-character commit>' \
  --expected-function-version '<published numeric version>' \
  --allow-server-side-repair
```

The PEP must re-prove the same provider state and exact account-wide invocation
graph, then consume the durable `PLAN_VERIFIED` record with one conditional
`UpdateItem` to `CLAIMED` / `BEFORE_FIRST_EFFECT`. It cannot use `PutItem` or
create missing Plan evidence. It then performs, at most once and in order:

1. `PutInlinePolicyToPermissionSet`;
2. `CreateAccountAssignment`; and
3. `ProvisionPermissionSet`.

The runtime re-reads the exact predecessor before each call and advances the
ledger only with compare-and-swap. Do not invoke the alias again, even when the
client times out or no receipt is returned.

## Phase 7 — Reconcile ambiguity or verify final state

Use `reconcile-v1` after any uncertain response and as the final read-only
readback:

```bash
python scripts/deployment/platform-authority-lambda-audit-provisioning-repair.py \
  reconcile \
  --profile '<approved ScanalyzeLambdaAuditRepair profile>' \
  --expected-source-commit '<reviewed 40-character commit>' \
  --expected-function-version '<published numeric version>'
```

Reconcile mode has no DynamoDB or Identity Center write authority. It reads the
durable record, complete Identity Center state and final account-local IAM
role. It may classify evidence, but cannot resume or retry repair.

Required final proof:

- exact collector policy digest;
- exact invoker permission-set metadata, tags, session duration, RelayState and
  invocation-only policy digest;
- exactly one direct immutable `USER` assignment;
- only the authority account provisioned;
- no managed/customer-managed attachment or boundary;
- one exact account-local collector role and one exact account-local repair
  invoker role under their distinct reviewed `AWSReservedSSO_*` prefixes;
- exact SAML trust/audience and inline policy for both roles; and
- unfiltered provisioned-account enumeration, assignments for every observed
  account using Organizations `State` (not the retired `Status` field), plus
  List-then-Describe of every `IN_PROGRESS` assignment-creation,
  assignment-deletion or permission-set-provisioning request ID and zero
  operation bound to either reviewed permission set; and
- no extra attachment, boundary or relay path.

## Fail-closed decision table

| Observation | Required action |
|---|---|
| Exact provider state, no durable Plan record | Stop; run a newly authorized Plan within its window |
| Exact unconsumed `PLAN_VERIFIED` record | Await exact repair authorization |
| Plan create or repair transition is ambiguous | Stop; strongly consistent readback / read-only reconcile; never retry |
| Provider response may represent a write | `UNCERTAIN_RECONCILE_ONLY`; never retry |
| CAS transition fails | Stop; read-only reconcile |
| Pagination/access is incomplete | `BLOCKED`; resolve read access only |
| Foreign principal/account/policy/role exists | `BLOCKED`; open containment issue |
| Phase B fails or rolls back with a retained KMS/DynamoDB/Logs candidate | `FAILED_RETAINED_RESOURCES`; inventory read-only and quarantine; do not redeploy, adopt or delete |
| A retained canonical name collides or continues to incur cost | Keep quarantined; record cost and open a separately authorized cleanup child |
| Final SSO and IAM readback exact | Record verified non-production evidence only |
| Independent reviewer absent | Governance remains blocked |

## Post-merge readback preflight

Before any newly authorized live non-production attempt, verify the exact
merged commit contains the GUG-221 post-merge regression coverage and that:

1. the CLI pagination tests prove a second SSO Admin page, a second IAM role
   page and a second IAM policy page are collected through
   `--starting-token`; the `list-tags-for-resource` case must omit unsupported
   `--page-size` while retaining the exact bounded `--max-items` value;
2. no tested invocation contains `--no-paginate`, `--next-token` or
   `--marker`;
3. the local control-plane snapshot accepts the exact operational `$LATEST`
   and immutable-version descriptions declared by CloudFormation; and
4. both a ledger carrying the canonical immutable Plan-binding digest and its
   durable public receipt pass JSON Schema plus semantic validation in Plan
   and advanced states, while modified binding data and the legacy unproven
   receipt fail.

Failure of any item is `BLOCKED`. Do not compensate with an AWS console query,
manual first-page inspection, relaxed description comparison, edited receipt,
ledger replay or direct provider mutation.

## Evidence handling

Private evidence must be create-only or versioned, owner-restricted and outside
Git. Public closeout may include only:

- commit and PR;
- named gate results;
- version/package/policy digests;
- account suffixes;
- sanitized status and counts; and
- explicit `Live validated: yes/no` and `Production: NO-GO`.

Never publish principal IDs, complete account IDs beyond already reviewed
repository contracts, permission-set/role ARNs, SAML provider, KMS key, session
identity, provider responses or rendered policies.

## Rollback and containment

There is no automatic repair rollback. Never delete the durable ledger to
repeat an operation. Assignment deletion, deprovisioning, policy removal,
permission-set deletion, table deletion, key deletion and stack deletion are
outside GUG-221 and require a new reviewed issue and explicit destructive
authorization.

A failed Phase B stack with a surviving retained KMS key/alias, DynamoDB table
or log group remains `FAILED_RETAINED_RESOURCES` even if CloudFormation reports
rollback completion. Preserve its complete read-only inventory and quarantine
the canonical names. Any cleanup must be the separately reviewed child
described above; name collision or continuing cost does not authorize deletion
or inferred adoption.

If excess authority is observed, stop all collector use, preserve evidence,
deny further repair invocations and open a containment package. Do not mutate
AWS while diagnosing under a read-only authorization.

## Closeout checklist

- [ ] Exact commit and required CI recorded.
- [ ] Management and authority identities independently read back.
- [ ] Both stack Change Sets and deployed resources match reviewed digests.
- [ ] `plan-v1` received `{}`, proved the exact invocation graph and created one
      exact `PLAN_VERIFIED` record.
- [ ] Plan and repair used the same reviewed Lambda-managed SDK versions.
- [ ] Administrative change freeze covered final plan through
      `RECONCILE_VERIFIED`.
- [ ] Every runtime snapshot proved the stable account-wide Lambda authority
      graph and no foreign same-account principal could invoke the aliases.
- [ ] Repair consumed, but did not create or replace, the exact durable Plan.
- [ ] Repair receipt and durable record agree on effect attribution.
- [ ] `reconcile-v1` proves final Identity Center and IAM state.
- [ ] Candidate A and Candidate B remain blocked until `RECONCILE_VERIFIED`
      and a dedicated collector SSO session are independently evidenced.
- [ ] GUG-220 evidence remains unchanged.
- [ ] Single-operator / no-independent-approval fact recorded.
- [ ] Live validation and production status classified without overclaim.

Passing this checklist is non-production evidence only. Production remains
**NO-GO** until the wider program gate is independently closed.
