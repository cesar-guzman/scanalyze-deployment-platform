# Bootstrap Plan permission repair runbook

## Scope and current status

This runbook operates the dedicated server-side PEP that can add the one
missing `ListOnlyExactBootstrapChangeSets` statement to the normal
`ScanalyzeAuthorityBootstrapPlan` policy and reprovision it to the authority
account.

This checked-in procedure is not deployment or mutation authorization. The
implementation iteration made nine bounded read-only AWS calls to establish
identity and inventory; it made zero AWS mutations and executed no live route.
The Signer inventory call was denied, so absence of a signing profile is not
claimed. Production remains **NO-GO**.

The reviewed AWS wrapper now binds the concrete zero-retry Identity Center,
effective-IAM and durable-ledger adapters in a deterministic source-closed
package. The repair materializer remains intentionally non-executable. The
separate connected artifact-bootstrap and route-provider CLIs expose only
closed AWS operations with action-time authorization and zero SDK retries. Do
not stage or deploy any stack from a working tree: package only the exact
merged commit, recompute its source attestation before every connected action,
authenticate its required review/checks, sign the immutable S3 source version
and use the read-back CloudFormation tuple.

## Non-negotiable stops

Stop with `HUMAN_DECISION_REQUIRED` if any of the following is true:

- the exact administrative seed or a protected effect is not separately
  authorized for its reviewed account, profile, Region, template, Change Set
  and time window;
- the caller profile or expected account/role is not exact and non-default;
- the reviewed source, artifact, parameter or live-state digest differs;
- the Plan policy differs from the target by anything other than the one
  allowed statement;
- pagination, provider state, CloudTrail attribution or collision evidence is
  incomplete;
- any retained resource, role, alias, assignment or stack name already exists
  without exact ownership evidence;
- any CloudFormation or SSO effect may already have been dispatched without a
  durable `*_DISPATCHED`/attempting record and exact UUID-bearing coordinates;
- an artifact-bootstrap recovery cannot prove the original write-once claim,
  exact CloudTrail mutation event and immutable provider effect identity;
- the artifact foundation, its access update, the pre-revocation foundation
  publish binding or the post-revocation bootstrap route release is missing;
- the artifact-bootstrap assignment is non-zero or any `PT1H` credential could
  still be valid when the normal route is materialized;
- the ledger is missing, changed, uncertain or not strongly read back; or
- Plan/reconcile has 60,000 milliseconds or less remaining at entry, repair has
  480,000 milliseconds or less, either write has 75,000 milliseconds or less
  before dispatch, or a provider read/poll has 60,000 milliseconds or less.

Never repair with `AWSAdministratorAccess`, a console edit, an `aws sso-admin`
command, the normal Plan role or the GUG-221 collector PEP.

## Phase 0 — Repository gate

Use a clean isolated worktree at the exact reviewed commit:

```bash
git status --short --branch
git diff --check
make platform-authority-bootstrap-plan-repair-check
make platform-authority-bootstrap-check
make docs-check
```

Record these as repository evidence only. Do not claim AWS, deployment or live
repair from local or CI success.

## Phase 1 — Read-only preflight

Using only explicitly approved read-only profiles and `AWS_REGION=us-east-1`:

1. make `sts:GetCallerIdentity` the first signed call for each session;
2. verify exact account, role and session type;
3. inspect the active Identity Center instance and Identity Store;
4. enumerate the exact normal Plan permission set, metadata, tags, inline
   policy, attachments, boundary, assignments and provisioned accounts with
   complete pagination;
5. enumerate pending provisioning and assignment operations;
6. inspect the generated authority-account IAM role, trust, policies and
   boundary;
7. prove the live policy is the exact canonical predecessor; and
8. collision-probe the route, broker, delegation and PEP stacks and every
   retained name.

Persist the existing Plan tags as the private
`ExpectedPlanPermissionSetTagsJson` value. Do not reuse them for the temporary
invoker: its seven-tag contract is derived independently from the exact merged
`SourceCommit` and fixed delegation-template values.

An `AccessDenied`, generic S3 response, repeated token or partial list is
uncertainty, not absence. No read-only preflight may repair or adopt a resource.

## Phase 2 — Build, authenticate and stage immutable inputs

Build only from the exact clean merged commit into a new mode-`0700` directory
outside Git and synced storage. The deterministic package must include the
reviewed runtime, renderer and lock file. Upload and AWS Signer actions require
their own exact authorization. Never deploy an unsigned object or an object
without an exact version and SHA-256 readback.

Before any route materialization, stage the exact Git-object bytes of the
route, delegation and PEP templates in approved versioned S3 buckets. Record
each exact HTTPS URL, key, `VersionId` and SHA-256 readback. The PEP template
object and signed Lambda ZIP must be different objects. Build the broker ZIP
separately from exact clean merged `main`, stage and sign that unsigned object,
then use the read-only broker attestor to bind the source version to the unique
signed output version. Only after that attestation exists may the parameterless
broker template be rendered and staged. An upload or signing job is a
separately authorized mutation; an unversioned URL, overwritten key, ETag-only
assertion or operator-supplied digest is a stop.

Build the unsigned artifact offline:

```bash
python3 scripts/deployment/platform-authority-plan-permission-repair-package.py \
  --source-commit "$SOURCE_COMMIT" \
  --expected-boto3-version "$EXPECTED_BOTO3_VERSION" \
  --expected-botocore-version "$EXPECTED_BOTOCORE_VERSION" \
  --output-directory "$PRIVATE_OUTPUT_DIRECTORY"
```

After a separately authorized immutable S3 upload and Signer job, use the exact
read-only verifier profile and write the private receipt outside the repository:

```bash
AWS_PROFILE=042360977644_ScanalyzeGug376ArtifactBootstrap AWS_REGION=us-east-1 \
python3 scripts/deployment/platform-authority-plan-permission-repair-signed-artifact.py \
  --profile 042360977644_ScanalyzeGug376ArtifactBootstrap \
  --region us-east-1 \
  --source-commit "$SOURCE_COMMIT" \
  --expected-boto3-version "$EXPECTED_BOTO3_VERSION" \
  --expected-botocore-version "$EXPECTED_BOTOCORE_VERSION" \
  --job-id "$SIGNING_JOB_ID" \
  --private-root "$PRIVATE_ARTIFACT_ROOT" \
  --bootstrap-intent-name "$BOOTSTRAP_INTENT_NAME" \
  --foundation-publish-binding-name "$FOUNDATION_PUBLISH_BINDING_NAME" \
  --output-receipt "$PRIVATE_SIGNED_RECEIPT"
```

The verifier makes STS caller identity its first signed call. A profile,
account, role, protected-main commit, review, required check, Signer coordinate,
S3 version or checksum mismatch stops before producing parameters.

The closed read-only verifier session must permit exactly the provider reads
used by this command: `sts:GetCallerIdentity`, `signer:DescribeSigningJob`,
`s3:GetBucketVersioning`, `s3:ListBucketVersions`, `s3:GetObject` and the
corresponding exact-version metadata read, `acm:GetCertificate`, and
`signer:GetRevocationStatus`. The SDK service name for the last call is
`signer-data`; its IAM action remains `signer:GetRevocationStatus`.
`revokedEntities` must be present as a list: an empty list is the only accepted
non-revoked result, while a missing field, non-empty list, malformed response
or `AccessDenied` stops the handoff. No alternate profile or broader mutation
role may be substituted.
Both operational signed-artifact CLIs require the direct
`042360977644_ScanalyzeGug376ArtifactBootstrap` SSO profile. The bridge policy
bounds `acm:GetCertificate` to authority-account `certificate/*` resources and
`signer:GetRevocationStatus` to the exact foundation signing-profile resource
plus authority-account signing-job resources in `us-east-1`. The read authority
ends at the sealed `RecoveryNotAfter` horizon, while route publication still
requires the verifier to prove the exact profile version and job before the
revocation call. The PEP signed-artifact, broker signed-artifact and template
readback product paths have no `AWSReadOnlyAccess` fallback. The separate
`042360977644_AWSReadOnlyAccess` session is permitted only for the connected,
read-only Plan seed snapshot inventory described below; it is never artifact
verification authority. Historical plan-derived constructors remain
test-only.

Only the AWS/Git-backed constructor is an operational entrypoint. It derives
the certificate hash, revocation evidence and both CloudFormation template
digests from exact readbacks and Git-object bytes. The private lower-level
constructor exists solely for hermetic contract tests; operator-supplied
digests or revocation assertions are not deployable evidence.

Independently verify:

- source commit and tree;
- package byte digest and contents;
- successful Signer job and profile version;
- source and signed S3 version IDs/checksums;
- Code Signing Config; and
- the exact numeric Lambda versions and aliases that will be created.

Keep all IDs, ARNs and receipts in owner-only private evidence, not this
repository, shell history or PR comments.

The broker build/sign/render order is strict:

1. `broker-seed.py build-package` emits the deterministic unsigned ZIP and
   source receipt;
2. a separately authorized upload and Signer job produce immutable AWS object
   versions;
3. `broker-signed-artifact.py` rebuilds the ZIP and derives all Signer, S3,
   certificate, revocation and SDK bindings read-only; and
4. `broker-seed.py materialize-template` consumes that exact private handoff
   and emits the parameterless template. It never accepts a manually asserted
   signed code SHA.

## Phase 3 — Create and close the artifact foundation

All artifact-bootstrap inputs and outputs are owner-only, single-link
mode-`0600` files directly under a mode-`0700` private root. The claim root is
also private and outside Git. The CLI reserves each output before any AWS call.
Its exact invocation shape is:

```bash
python3 scripts/deployment/platform-authority-plan-permission-repair-artifact-bootstrap.py \
  --private-root "$PRIVATE_ARTIFACT_ROOT" \
  --source-root "$SOURCE_ROOT" \
  materialize-intent \
  --bundle-name "$BUNDLE_NAME" \
  --output-name "$OUTPUT_NAME"

python3 scripts/deployment/platform-authority-plan-permission-repair-artifact-bootstrap.py \
  --private-root "$PRIVATE_ARTIFACT_ROOT" \
  --source-root "$SOURCE_ROOT" \
  dispatch-change-set \
  --bundle-name "$BUNDLE_NAME" \
  --output-name "$OUTPUT_NAME" \
  --profile 839393571433_AWSAdministratorAccess \
  --claim-root "$PRIVATE_CLAIM_ROOT"
```

The bundle supplies the exact private values; do not copy them into this
runbook or replace them on the command line. For each of `bridge-create` and
`foundation-create`, run the closed sequence `authorize-change-set`,
`dispatch-change-set`, `attest-change-set`, `authorize-change-set`,
`execute-change-set`, and `readback-stack`. Use
`839393571433_AWSAdministratorAccess` only for the bridge and
`042360977644_ScanalyzeGug376ArtifactBootstrap` only for the foundation and
the two closed signed-artifact verifier sessions that consume its publish
binding before revocation. The two
authorization records are distinct, expire within fifteen minutes and bind
respectively to `<operation>:dispatch` and `<operation>:execute`; their presence
in a bundle is not standing authorization. The exact authorization text is
`AUTHORIZE GUG-376 <operation>:<dispatch-or-execute> <SOURCE_COMMIT>`.

The artifact bridge and foundation expose their non-secret causal parameters
for exact provider readback: bootstrap principal ID, Signer profile version,
and route/delegation object-version IDs are not `NoEcho`. Treat `****`, `*****`,
missing values, duplicate `ParameterKey` entries and any non-exact value from
`DescribeChangeSet` or `DescribeStacks` as terminal evidence failure; do not
execute or continue the release.

Apply the identical rule to the broker-created delegation and PEP Change Sets.
Repair principal ID/user ARN, expected permission-set description/tags and the
immutable artifact version are not `NoEcho`. Each must be present once and
equal the sealed broker request; a mask, omission, duplicate or substitution
blocks create attestation, execution and recovery.

For updates, do not interpret `UsePreviousValue=true` as the effective value.
The broker reads the exact stable stack before execution, rejects a stack
snapshot newer than the Change Set, resolves every previous value and stores
only the canonical parameter-map digest in its private ledger. The execute
dispatch and any read-only recovery must carry that exact digest. Terminal
`DescribeChangeSet` may retain all prior-value flags or normalize all of them
to exact values. Never accept a mixture; normalized values must reproduce the
sealed digest and masks remain invalid. Terminal evidence must return the
executed `Stack.ChangeSetId`, the same unique unmasked
String-parameter digest, no non-null `ResolvedValue`, and two identical
`DescribeStacks` fingerprints around all intervening evidence reads. A mismatch
is terminal uncertainty. It must additionally contain one terminal root stack
event whose `ClientRequestToken`, stack identity and status bind the exact
`ExecuteChangeSet`, and whose timestamp is no earlier than execution. Use that
event—not `CreationTime`—as the CREATE causal clock. Preserve the ledger and do
not replay either mutation.
Before every AWS read and every pagination page, the continuation revalidates
the shared remaining-time budget. If fewer than 15 seconds remain,
`TIME_BUDGET_PENDING` is a typed read-only continuation result: stop that
invocation and retry only the same readback alias; do not advance the ledger or
replay a mutation.

After `readback-foundation`, materialize and execute `bridge-pin` through
`materialize-bridge-pin`, `authorize-mutation`, `dispatch-bridge-pin`, a fresh
`authorize-mutation`, `execute-bridge-pin`, and `readback-stack`. The mutation
authorizations must bind the exact pin intent digest and the exact operations
`bridge-pin:dispatch` and `bridge-pin:execute`. `recover-change-set`,
`recover-bridge-pin`, and `recover-access-update` recover only an ambiguous
CreateChangeSet dispatch. `recover-change-set-execution`,
`recover-bridge-pin-execution`, and `recover-access-update-execution` recover
only an ambiguous ExecuteChangeSet and close it through terminal readback.
These commands are read-only causal recovery, not retries. They accept no
authorization input: the provider revalidates the exact original sealed
authorization from the write-once claim at `claimed_at`, requires the unique
matching CloudTrail event, and never invokes the mutation again. Every mutation
authorization uses the exact text
`AUTHORIZE GUG-376 <operation> <TARGET_DIGEST>`.

The bridge derives `RecoveryNotAfter = AccessNotAfter + 24h`. Create/Execute,
S3 publication, KMS data-key generation and Signer start are explicitly denied
at `AccessNotAfter`; only causal read APIs remain eligible until
`RecoveryNotAfter`, when an explicit deny closes all actions. Existing SSO
credentials still expire independently and are never renewed by recovery.

Publish every reviewed template and unsigned package through the same closed
pattern: `materialize-object-intent`, a fresh `authorize-mutation` for
`publish-object`, `publish-object`, then `readback-object`. Build each signing
request with `materialize-signing-intent`, authorize the exact
`start-signing-job` digest, call `start-signing-job`, and close it with
`readback-signing-job`. `recover-object` and `recover-signing-job` only recover
an already-attributed effect. Never issue a second write after an ambiguous
response.

Once the exact route and delegation template receipts exist, run
`materialize-access-update`, authorize and perform
`dispatch-access-update`, attest it with `attest-change-set`, authorize and run
`execute-access-update`, and close it with `readback-access-update`. Then seal
the pre-revocation storage contract:

```bash
python3 scripts/deployment/platform-authority-plan-permission-repair-artifact-bootstrap.py \
  --private-root "$PRIVATE_ARTIFACT_ROOT" \
  --source-root "$SOURCE_ROOT" \
  materialize-publish-binding \
  --bundle-name "$BUNDLE_NAME" \
  --output-name "$OUTPUT_NAME"
```

The foundation publish binding must exist before any producer can become route
evidence. It binds clean Git-object bytes, terminal foundation and access
readbacks, immutable object versions and the generated Signer profile version.

Attest each exact template version with the foundation-mode product CLI:

```bash
python3 scripts/deployment/platform-authority-plan-permission-repair-template-readback.py \
  --source-root "$SOURCE_ROOT" \
  --source-commit "$SOURCE_COMMIT" \
  --private-root "$PRIVATE_ARTIFACT_ROOT" \
  --bootstrap-intent-name "$BOOTSTRAP_INTENT_NAME" \
  --foundation-publish-binding-name "$FOUNDATION_PUBLISH_BINDING_NAME" \
  --artifact-kind route_template \
  --version "$ROUTE_TEMPLATE_VERSION" \
  --aws-profile 042360977644_ScanalyzeGug376ArtifactBootstrap \
  --expected-account-id 042360977644 \
  --region us-east-1
```

Repeat with the exact artifact kind/version for delegation, PEP and broker
templates. The product CLI exposes no legacy storage-plan flags.

## Phase 4 — Publish the broker closure, revoke the bridge and release the route

Build the deterministic broker package offline, publish and sign it through the
artifact-bootstrap CLI, then use the read-only signed-artifact verifier. Build
the closed broker configuration only from its private input, the bootstrap
intent and the foundation publish binding:

```bash
python3 scripts/deployment/platform-authority-plan-permission-repair-broker-seed.py \
  build-package \
  --source-root "$SOURCE_ROOT" \
  --private-root "$PRIVATE_ROUTE_ROOT" \
  --source-commit "$SOURCE_COMMIT"

python3 scripts/deployment/platform-authority-plan-permission-repair-broker-signed-artifact.py \
  --source-root "$SOURCE_ROOT" \
  --source-commit "$SOURCE_COMMIT" \
  --private-root "$PRIVATE_ROUTE_ROOT" \
  --output-name "$BROKER_SIGNED_HANDOFF_NAME" \
  --aws-profile 042360977644_ScanalyzeGug376ArtifactBootstrap \
  --expected-account-id 042360977644 \
  --region us-east-1 \
  --unsigned-bucket "$UNSIGNED_BUCKET" \
  --unsigned-key "$UNSIGNED_KEY" \
  --unsigned-version "$UNSIGNED_VERSION" \
  --signing-job-id "$SIGNING_JOB_ID" \
  --signed-version "$SIGNED_VERSION" \
  --pep-signed-artifact-receipt-name "$PEP_SIGNED_ARTIFACT_RECEIPT_NAME" \
  --bootstrap-intent-name "$BOOTSTRAP_INTENT_NAME" \
  --foundation-publish-binding-name "$FOUNDATION_PUBLISH_BINDING_NAME"

python3 scripts/deployment/platform-authority-plan-permission-repair-plan-seed-snapshot.py \
  --source-root "$SOURCE_ROOT" \
  --source-commit "$SOURCE_COMMIT" \
  --bootstrap-change-set-name "$BOOTSTRAP_CHANGE_SET_NAME" \
  --private-root "$PRIVATE_ROUTE_ROOT" \
  --output-name "$PLAN_SEED_SNAPSHOT_NAME" \
  --authority-profile 042360977644_AWSReadOnlyAccess \
  --management-profile 839393571433_ScanalyzeFounderPepIdentityAdmin \
  --region us-east-1

python3 scripts/deployment/platform-authority-plan-permission-repair-deployment-route.py \
  materialize-broker-config \
  --source-root "$SOURCE_ROOT" \
  --private-root "$PRIVATE_ROUTE_ROOT" \
  --input-name "$BROKER_CONFIG_INPUT_NAME" \
  --plan-snapshot-name "$PLAN_SEED_SNAPSHOT_NAME" \
  --artifact-bootstrap-intent-name "$BOOTSTRAP_INTENT_NAME" \
  --foundation-publish-binding-name "$FOUNDATION_PUBLISH_BINDING_NAME" \
  --output-name "$BROKER_SEED_INPUT_NAME"

python3 scripts/deployment/platform-authority-plan-permission-repair-broker-seed.py \
  materialize-template \
  --source-root "$SOURCE_ROOT" \
  --private-root "$PRIVATE_ROUTE_ROOT" \
  --input-name "$BROKER_SEED_INPUT_NAME"
```

The snapshot command is the mandatory connected producer for the broker
configuration. Run it after the exact bootstrap Change Set has produced the
Plan permission set and generated IAM role, but before
`materialize-broker-config`. It uses the authority and management profiles only
for read calls, writes no AWS state, and stores the private result with
write-once owner-only custody. Pass that exact receipt separately through
`--plan-snapshot-name`; the sealed `$BROKER_CONFIG_INPUT_NAME` draft must omit
`plan_snapshot`. The CLI rejects an embedded second authority, joins the exact
owner-only receipt, proves the same source commit and bootstrap Change Set
name, and reseals the complete input. Materialize within the sealed 15-minute
freshness interval. A stale snapshot requires a new read-only
capture and a new private output name; it never authorizes a write, deployment
or production claim.

The broker CLI writes fixed write-once package, template and receipt names in
the private root. Publish and read back the resulting parameterless broker
template through the artifact-bootstrap object commands. The complete template
readbacks, PEP signed-artifact receipt, broker seed input and broker
materialization receipt must all reconstruct from the same publish binding.

Only after that publication set is closed may the bridge be revoked. For
`bridge-revoke`, use fresh `authorize-change-set` records and the exact
`dispatch-change-set`, `attest-change-set`, `execute-change-set`, and
`readback-stack` sequence under
`839393571433_AWSAdministratorAccess`. Require zero assignments and wait until
both the bootstrap access window and one hour after terminal revocation have
elapsed. Then materialize the post-revocation release:

```bash
python3 scripts/deployment/platform-authority-plan-permission-repair-artifact-bootstrap.py \
  --private-root "$PRIVATE_ARTIFACT_ROOT" \
  --source-root "$SOURCE_ROOT" \
  materialize-route-release \
  --bundle-name "$BUNDLE_NAME" \
  --output-name "$OUTPUT_NAME"
```

The release is offline evidence, not deployment authority. It fails closed
unless the bridge readback proves zero assignment, the `PT1H` credential
boundary has expired and every publication receipt reconstructs exactly.
Broker signing freshness is checked against an explicit current time when the
connected handoff is admitted. Release and route reconstruction never compare
that pre-revocation receipt to a later wall clock; they bind its observation to
the sealed bootstrap access window and require signature validity through the
sealed route horizon.

## Phase 5 — Seed the route and broker, then enter the broker state machine

The route materializer consumes the post-revocation release and emits exactly
two seed targets: the management route and the authority broker. It cannot
express delegation, PEP or revocation operations.

```bash
python3 scripts/deployment/platform-authority-plan-permission-repair-deployment-route.py \
  materialize-seeds \
  --source-root "$SOURCE_ROOT" \
  --private-root "$PRIVATE_ROUTE_ROOT" \
  --input-name "$ROUTE_SEED_INPUT_NAME" \
  --output-name "$ROUTE_SEED_INTENT_NAME"

python3 scripts/deployment/platform-authority-plan-permission-repair-deployment-route.py \
  validate-intent \
  --source-root "$SOURCE_ROOT" \
  --private-root "$PRIVATE_ROUTE_ROOT" \
  --intent-name "$ROUTE_SEED_INTENT_NAME"
```

For each target, first seal the explicit action-time authorization for the exact
`CreateChangeSet`, then run `create-change-set`; after the unique CloudTrail
event and full UUID-bearing ARNs are available, run `attest-change-set`. Create
a separate execution authorization and execution intent, then execute and read
back the exact target:

Execution does not trust the JSON attestation by itself. The preceding
`attest-change-set` step proves the original dispatch claim and authorization,
resolves the unique `CreateChangeSet` CloudTrail event, and checks
`DescribeChangeSet` plus `GetTemplate`. Immediately before the sole execute
attempt, the provider reconstructs the seed from its exact private input and
clean merged Git source, reopens the durable create result, and requires the
attestation's stack ARN, change-set ARN and request ID to match that result
before STS. After STS it repeats the unique `CreateChangeSet` CloudTrail
readback, `DescribeChangeSet`, `GetTemplate` and exact resource-change
projection and compares the complete immutable attestation immediately before
the effect. The provider re-samples the authorization clock after STS and
again before the durable claim and `ExecuteChangeSet`. Any causal, caller, ARN,
request-ID, template, parameter, change-detail, replacement or time-window
drift stops before the mutation. Execution recovery reuses the same durable
claim and never accepts a fresh authorization or issues a second execute.
All route parameters are non-secret identifiers, ARNs, immutable versioned-S3
coordinates or bounded timestamps/flags. None is `NoEcho`; masked parameter
readback is invalid, and every `DescribeChangeSet`/`DescribeStacks` value must
equal the sealed request before execution.

```bash
python3 scripts/deployment/platform-authority-plan-permission-repair-deployment-route.py \
  authorize-creation \
  --source-root "$SOURCE_ROOT" \
  --private-root "$PRIVATE_ROUTE_ROOT" \
  --intent-name "$ROUTE_SEED_INTENT_NAME" \
  --target "$SEED_TARGET" \
  --authorization "$ACTION_TIME_CREATION_AUTHORIZATION" \
  --ttl-seconds "$AUTHORIZATION_TTL_SECONDS" \
  --output-name "$CREATION_AUTHORIZATION_NAME"

python3 scripts/deployment/platform-authority-plan-permission-repair-deployment-route-aws.py \
  create-change-set \
  --profile "$SEED_CREATOR_PROFILE" \
  --target "$SEED_TARGET" \
  --source-root "$SOURCE_ROOT" \
  --private-root "$PRIVATE_ROUTE_ROOT" \
  --receipt-name "$CREATE_DISPATCH_NAME" \
  --intent-name "$ROUTE_SEED_INTENT_NAME" \
  --authorization-name "$CREATION_AUTHORIZATION_NAME"

python3 scripts/deployment/platform-authority-plan-permission-repair-deployment-route-aws.py \
  attest-change-set \
  --profile "$SEED_CREATOR_PROFILE" \
  --target "$SEED_TARGET" \
  --source-root "$SOURCE_ROOT" \
  --private-root "$PRIVATE_ROUTE_ROOT" \
  --receipt-name "$CREATE_ATTESTATION_NAME" \
  --intent-name "$ROUTE_SEED_INTENT_NAME" \
  --dispatch-name "$CREATE_DISPATCH_NAME"

python3 scripts/deployment/platform-authority-plan-permission-repair-deployment-route.py \
  authorize-execution \
  --source-root "$SOURCE_ROOT" \
  --private-root "$PRIVATE_ROUTE_ROOT" \
  --intent-name "$ROUTE_SEED_INTENT_NAME" \
  --attestation-name "$CREATE_ATTESTATION_NAME" \
  --target "$SEED_TARGET" \
  --authorization "$ACTION_TIME_AUTHORIZATION" \
  --ttl-seconds "$AUTHORIZATION_TTL_SECONDS" \
  --output-name "$EXECUTION_AUTHORIZATION_NAME"

python3 scripts/deployment/platform-authority-plan-permission-repair-deployment-route.py \
  materialize-execution-intent \
  --source-root "$SOURCE_ROOT" \
  --private-root "$PRIVATE_ROUTE_ROOT" \
  --intent-name "$ROUTE_SEED_INTENT_NAME" \
  --attestation-name "$CREATE_ATTESTATION_NAME" \
  --authorization-name "$EXECUTION_AUTHORIZATION_NAME" \
  --output-name "$EXECUTION_INTENT_NAME"

python3 scripts/deployment/platform-authority-plan-permission-repair-deployment-route-aws.py \
  execute-change-set \
  --profile "$SEED_EXECUTOR_PROFILE" \
  --target "$SEED_TARGET" \
  --source-root "$SOURCE_ROOT" \
  --private-root "$PRIVATE_ROUTE_ROOT" \
  --receipt-name "$EXECUTION_RECEIPT_NAME" \
  --execution-intent-name "$EXECUTION_INTENT_NAME" \
  --intent-name "$ROUTE_SEED_INTENT_NAME"

python3 scripts/deployment/platform-authority-plan-permission-repair-deployment-route-aws.py \
  terminal-readback \
  --profile "$SEED_EXECUTOR_PROFILE" \
  --target "$SEED_TARGET" \
  --source-root "$SOURCE_ROOT" \
  --private-root "$PRIVATE_ROUTE_ROOT" \
  --receipt-name "$TERMINAL_READBACK_NAME" \
  --intent-name "$ROUTE_SEED_INTENT_NAME" \
  --execution-intent-name "$EXECUTION_INTENT_NAME" \
  --execution-receipt-name "$EXECUTION_RECEIPT_NAME"
```

For `route`, both profiles are exactly
`839393571433_AWSAdministratorAccess`; the creation phrase is
`I_AUTHORIZE_GUG376_ROUTE_SEED_CREATION` and the execution phrase is
`I_AUTHORIZE_GUG376_ROUTE_SEED_EXECUTION`. End that session after terminal
readback. The initial route has eight resources and exactly three temporary
`USER` assignments: broker seed Creator, broker seed Executor and broker
invoker. For `broker`, use exactly
`042360977644_ScanalyzeGug376BrokerSeedCreator` and
`042360977644_ScanalyzeGug376BrokerSeedExec`, with creation phrase
`I_AUTHORIZE_GUG376_BROKER_SEED_CREATION` and execution phrase
`I_AUTHORIZE_GUG376_BROKER_SEED_EXECUTION`. Every authorization expires in
60–900 seconds.

`recover-create-change-set` and `recover-execute-change-set` are the only
read-only ambiguity recovery commands for the original seed mutations. Both
accept no fresh mutation authorization. Create recovery validates the original
sealed creation authorization from the causal claim at the original claim
timestamp and may run only during the bounded 24-hour recovery horizon. Those
commands recover the original durable claim; they never authorize replay.

### Run the finite deployment-recovery lanes

The separate deployment-recovery CLI admits exactly two failed-CREATE lanes
for the `route` and `broker` targets. It is not an ambiguity retry path. Every
command consumes the same owner-only `$SEED_INPUT_NAME` and
`$ROUTE_SEED_INTENT_NAME`, reconstructs their binding against clean exact
`main`, and writes a distinct O_EXCL `$OUTPUT_NAME` under
`$PRIVATE_ROUTE_ROOT`. Offline authorize/materialize commands accept no
profile. Connected commands reject every profile except the exact mapping:

| Target | Creator and pre-execute attestor | Executor and failed-CREATE attestor | Failed-stack cleanup |
|---|---|---|---|
| `route` | `839393571433_AWSAdministratorAccess` | `839393571433_AWSAdministratorAccess` | `839393571433_ScanalyzeGug376RouteSeedCleanup` |
| `broker` | `042360977644_ScanalyzeGug376BrokerSeedCreator` | `042360977644_ScanalyzeGug376BrokerSeedExec` | `042360977644_ScanalyzeGug376BrokerSeedCleanup` |

The action-time phrases are exact and target-specific:

| Target | Re-entry create | Re-entry execute | Failed-stack cleanup |
|---|---|---|---|
| `route` | `I_AUTHORIZE_GUG376_ROUTE_SEED_CREATE_REENTRY_1` | `I_AUTHORIZE_GUG376_ROUTE_SEED_EXECUTE_REENTRY_1` | `I_AUTHORIZE_GUG376_ROUTE_SEED_STACK_CLEANUP_1` |
| `broker` | `I_AUTHORIZE_GUG376_BROKER_SEED_CREATE_REENTRY_1` | `I_AUTHORIZE_GUG376_BROKER_SEED_EXECUTE_REENTRY_1` | `I_AUTHORIZE_GUG376_BROKER_SEED_STACK_CLEANUP_1` |

Each authorization is a 60–900-second action-time grant. A later grant does
not reopen a consumed mutation key.

#### Pre-execute failure to one re-entry

Use this lane only after the primary `CreateChangeSet` has a durable dispatch
file and connected readback proves all of: `FAILED`, `UNAVAILABLE`, the exact
stack in `REVIEW_IN_PROGRESS`, zero resources, the exact original request and
one matching CloudTrail event. The complete causal file chain is:

```text
PRIMARY_CREATE_DISPATCH_NAME
  -> PREEXECUTE_FAILURE_ATTESTATION_NAME
  -> REENTRY_CREATION_AUTHORIZATION_NAME
  -> REENTRY_INTENT_NAME
  -> REENTRY_DISPATCH_NAME
  -> REENTRY_ATTESTATION_NAME
  -> REENTRY_EXECUTION_AUTHORIZATION_NAME
  -> REENTRY_EXECUTION_INTENT_NAME
  -> REENTRY_EXECUTION_RECEIPT_NAME
```

Run the commands in exactly this order:

```bash
python3 scripts/deployment/platform-authority-plan-permission-repair-deployment-recovery.py \
  attest-preexecute-failure \
  --source-root "$SOURCE_ROOT" \
  --private-root "$PRIVATE_ROUTE_ROOT" \
  --seed-input-name "$SEED_INPUT_NAME" \
  --seed-intent-name "$ROUTE_SEED_INTENT_NAME" \
  --target "$SEED_TARGET" \
  --output-name "$PREEXECUTE_FAILURE_ATTESTATION_NAME" \
  --profile "$SEED_CREATOR_PROFILE" \
  --primary-dispatch-name "$PRIMARY_CREATE_DISPATCH_NAME"

python3 scripts/deployment/platform-authority-plan-permission-repair-deployment-recovery.py \
  authorize-reentry \
  --source-root "$SOURCE_ROOT" \
  --private-root "$PRIVATE_ROUTE_ROOT" \
  --seed-input-name "$SEED_INPUT_NAME" \
  --seed-intent-name "$ROUTE_SEED_INTENT_NAME" \
  --target "$SEED_TARGET" \
  --output-name "$REENTRY_CREATION_AUTHORIZATION_NAME" \
  --failure-attestation-name "$PREEXECUTE_FAILURE_ATTESTATION_NAME" \
  --authorization "$ACTION_TIME_REENTRY_CREATION_AUTHORIZATION" \
  --ttl-seconds "$AUTHORIZATION_TTL_SECONDS"

python3 scripts/deployment/platform-authority-plan-permission-repair-deployment-recovery.py \
  materialize-reentry \
  --source-root "$SOURCE_ROOT" \
  --private-root "$PRIVATE_ROUTE_ROOT" \
  --seed-input-name "$SEED_INPUT_NAME" \
  --seed-intent-name "$ROUTE_SEED_INTENT_NAME" \
  --target "$SEED_TARGET" \
  --output-name "$REENTRY_INTENT_NAME" \
  --failure-attestation-name "$PREEXECUTE_FAILURE_ATTESTATION_NAME" \
  --authorization-name "$REENTRY_CREATION_AUTHORIZATION_NAME"

python3 scripts/deployment/platform-authority-plan-permission-repair-deployment-recovery.py \
  create-reentry \
  --source-root "$SOURCE_ROOT" \
  --private-root "$PRIVATE_ROUTE_ROOT" \
  --seed-input-name "$SEED_INPUT_NAME" \
  --seed-intent-name "$ROUTE_SEED_INTENT_NAME" \
  --target "$SEED_TARGET" \
  --output-name "$REENTRY_DISPATCH_NAME" \
  --profile "$SEED_CREATOR_PROFILE" \
  --reentry-intent-name "$REENTRY_INTENT_NAME" \
  --failure-attestation-name "$PREEXECUTE_FAILURE_ATTESTATION_NAME" \
  --reentry-authorization-name "$REENTRY_CREATION_AUTHORIZATION_NAME"

python3 scripts/deployment/platform-authority-plan-permission-repair-deployment-recovery.py \
  attest-reentry \
  --source-root "$SOURCE_ROOT" \
  --private-root "$PRIVATE_ROUTE_ROOT" \
  --seed-input-name "$SEED_INPUT_NAME" \
  --seed-intent-name "$ROUTE_SEED_INTENT_NAME" \
  --target "$SEED_TARGET" \
  --output-name "$REENTRY_ATTESTATION_NAME" \
  --profile "$SEED_CREATOR_PROFILE" \
  --reentry-intent-name "$REENTRY_INTENT_NAME" \
  --failure-attestation-name "$PREEXECUTE_FAILURE_ATTESTATION_NAME" \
  --reentry-authorization-name "$REENTRY_CREATION_AUTHORIZATION_NAME" \
  --reentry-dispatch-name "$REENTRY_DISPATCH_NAME"

python3 scripts/deployment/platform-authority-plan-permission-repair-deployment-recovery.py \
  authorize-reentry-execution \
  --source-root "$SOURCE_ROOT" \
  --private-root "$PRIVATE_ROUTE_ROOT" \
  --seed-input-name "$SEED_INPUT_NAME" \
  --seed-intent-name "$ROUTE_SEED_INTENT_NAME" \
  --target "$SEED_TARGET" \
  --output-name "$REENTRY_EXECUTION_AUTHORIZATION_NAME" \
  --reentry-intent-name "$REENTRY_INTENT_NAME" \
  --reentry-attestation-name "$REENTRY_ATTESTATION_NAME" \
  --reentry-dispatch-name "$REENTRY_DISPATCH_NAME" \
  --failure-attestation-name "$PREEXECUTE_FAILURE_ATTESTATION_NAME" \
  --reentry-creation-authorization-name "$REENTRY_CREATION_AUTHORIZATION_NAME" \
  --authorization "$ACTION_TIME_REENTRY_EXECUTION_AUTHORIZATION" \
  --ttl-seconds "$AUTHORIZATION_TTL_SECONDS"

python3 scripts/deployment/platform-authority-plan-permission-repair-deployment-recovery.py \
  materialize-reentry-execution \
  --source-root "$SOURCE_ROOT" \
  --private-root "$PRIVATE_ROUTE_ROOT" \
  --seed-input-name "$SEED_INPUT_NAME" \
  --seed-intent-name "$ROUTE_SEED_INTENT_NAME" \
  --target "$SEED_TARGET" \
  --output-name "$REENTRY_EXECUTION_INTENT_NAME" \
  --reentry-intent-name "$REENTRY_INTENT_NAME" \
  --reentry-attestation-name "$REENTRY_ATTESTATION_NAME" \
  --reentry-dispatch-name "$REENTRY_DISPATCH_NAME" \
  --failure-attestation-name "$PREEXECUTE_FAILURE_ATTESTATION_NAME" \
  --reentry-creation-authorization-name "$REENTRY_CREATION_AUTHORIZATION_NAME" \
  --authorization-name "$REENTRY_EXECUTION_AUTHORIZATION_NAME"

python3 scripts/deployment/platform-authority-plan-permission-repair-deployment-recovery.py \
  execute-reentry \
  --source-root "$SOURCE_ROOT" \
  --private-root "$PRIVATE_ROUTE_ROOT" \
  --seed-input-name "$SEED_INPUT_NAME" \
  --seed-intent-name "$ROUTE_SEED_INTENT_NAME" \
  --target "$SEED_TARGET" \
  --output-name "$REENTRY_EXECUTION_RECEIPT_NAME" \
  --profile "$SEED_EXECUTOR_PROFILE" \
  --execution-intent-name "$REENTRY_EXECUTION_INTENT_NAME" \
  --failure-attestation-name "$PREEXECUTE_FAILURE_ATTESTATION_NAME" \
  --reentry-creation-authorization-name "$REENTRY_CREATION_AUTHORIZATION_NAME" \
  --reentry-intent-name "$REENTRY_INTENT_NAME" \
  --reentry-attestation-name "$REENTRY_ATTESTATION_NAME" \
  --reentry-dispatch-name "$REENTRY_DISPATCH_NAME" \
  --execution-authorization-name "$REENTRY_EXECUTION_AUTHORIZATION_NAME"
```

`$REENTRY_DISPATCH_NAME` is mandatory causal evidence; the attestation alone
is insufficient. Before the executor makes its first STS call, it reopens the
durable result stored under
`reentry-create:<target>:<seed-intent-digest>` and requires that result, the
supplied re-entry dispatch, and the attestation to agree on the full stack ARN,
full Change Set ARN and CreateChangeSet request ID. The execution mutation is
then claimed once under
`reentry-execute:<target>:<seed-intent-digest>`. Re-sealing the failure or
issuing a new authorization cannot create a second attempt for that seed,
target and lane.

`execute-reentry` performs the complete file, source, seed, authorization,
intent, dispatch, attestation and durable create claim/result validation
locally before STS. After the exact executor identity is established, it
re-samples the clock and rechecks the active grant, then repeats all
authoritative creation evidence: exactly one matching `CreateChangeSet`
CloudTrail event, `DescribeChangeSet`, `GetTemplate` and the exact
resource-change projection. The newly observed CloudTrail-event digest,
describe digest, template digest, changes digest, `CREATE_COMPLETE` status and
`AVAILABLE` execution status must equal the corresponding fields sealed in
`$REENTRY_ATTESTATION_NAME`. A copied, stale or self-resealed attestation
cannot replace this live comparison.

After those reads, the executor re-samples the clock once more, rejects clock
regression, and rechecks the same 60–900-second execution grant immediately
before it writes the
`reentry-execute:<target>:<seed-intent-digest>` O_EXCL claim and makes the sole
`ExecuteChangeSet` call. `create-reentry` uses the same timing pattern: local
causal and grant validation before STS, a fresh sample/grant check after STS,
and another sample/grant check immediately before its write-once claim and
sole CreateChangeSet call. Expiry at any sample stops without the effect.

Both re-entry authorizations must expire no later than
`RouteNotAfter - 1,800 seconds`. `create-reentry` changes only the fixed
one-use Change Set name and deterministic client token; every other primary
request field stays byte-for-byte equal. A timeout, disconnect, provider
exception, invalid response or durability uncertainty after either mutation
is not retry authority: preserve the claim, output and causal files and stop.

#### Failed CREATE to one exact-stack cleanup

Use this lane only after a primary or re-entry ExecuteChangeSet receipt exists
and executor readback proves the CREATE stack is exactly `ROLLBACK_COMPLETE`
or `DELETE_FAILED`. The causal chain is:

```text
PRIMARY_OR_REENTRY_EXECUTION_INTENT_NAME
+ PRIMARY_OR_REENTRY_EXECUTION_RECEIPT_NAME
  -> FAILED_CREATE_ATTESTATION_NAME
  -> CLEANUP_AUTHORIZATION_NAME
  -> CLEANUP_INTENT_NAME
  -> CLEANUP_DISPATCH_NAME
  -> CLEANUP_ATTESTATION_NAME
```

Run the commands in exactly this order:

```bash
python3 scripts/deployment/platform-authority-plan-permission-repair-deployment-recovery.py \
  attest-failed-create \
  --source-root "$SOURCE_ROOT" \
  --private-root "$PRIVATE_ROUTE_ROOT" \
  --seed-input-name "$SEED_INPUT_NAME" \
  --seed-intent-name "$ROUTE_SEED_INTENT_NAME" \
  --target "$SEED_TARGET" \
  --output-name "$FAILED_CREATE_ATTESTATION_NAME" \
  --profile "$SEED_EXECUTOR_PROFILE" \
  --execution-intent-name "$PRIMARY_OR_REENTRY_EXECUTION_INTENT_NAME" \
  --execution-receipt-name "$PRIMARY_OR_REENTRY_EXECUTION_RECEIPT_NAME"

python3 scripts/deployment/platform-authority-plan-permission-repair-deployment-recovery.py \
  authorize-cleanup \
  --source-root "$SOURCE_ROOT" \
  --private-root "$PRIVATE_ROUTE_ROOT" \
  --seed-input-name "$SEED_INPUT_NAME" \
  --seed-intent-name "$ROUTE_SEED_INTENT_NAME" \
  --target "$SEED_TARGET" \
  --output-name "$CLEANUP_AUTHORIZATION_NAME" \
  --failure-attestation-name "$FAILED_CREATE_ATTESTATION_NAME" \
  --authorization "$ACTION_TIME_CLEANUP_AUTHORIZATION" \
  --ttl-seconds "$AUTHORIZATION_TTL_SECONDS"

python3 scripts/deployment/platform-authority-plan-permission-repair-deployment-recovery.py \
  materialize-cleanup \
  --source-root "$SOURCE_ROOT" \
  --private-root "$PRIVATE_ROUTE_ROOT" \
  --seed-input-name "$SEED_INPUT_NAME" \
  --seed-intent-name "$ROUTE_SEED_INTENT_NAME" \
  --target "$SEED_TARGET" \
  --output-name "$CLEANUP_INTENT_NAME" \
  --failure-attestation-name "$FAILED_CREATE_ATTESTATION_NAME" \
  --authorization-name "$CLEANUP_AUTHORIZATION_NAME"

python3 scripts/deployment/platform-authority-plan-permission-repair-deployment-recovery.py \
  delete-failed-stack \
  --source-root "$SOURCE_ROOT" \
  --private-root "$PRIVATE_ROUTE_ROOT" \
  --seed-input-name "$SEED_INPUT_NAME" \
  --seed-intent-name "$ROUTE_SEED_INTENT_NAME" \
  --target "$SEED_TARGET" \
  --output-name "$CLEANUP_DISPATCH_NAME" \
  --profile "$FAILED_STACK_CLEANUP_PROFILE" \
  --cleanup-intent-name "$CLEANUP_INTENT_NAME" \
  --failure-attestation-name "$FAILED_CREATE_ATTESTATION_NAME" \
  --cleanup-authorization-name "$CLEANUP_AUTHORIZATION_NAME"

python3 scripts/deployment/platform-authority-plan-permission-repair-deployment-recovery.py \
  attest-cleanup \
  --source-root "$SOURCE_ROOT" \
  --private-root "$PRIVATE_ROUTE_ROOT" \
  --seed-input-name "$SEED_INPUT_NAME" \
  --seed-intent-name "$ROUTE_SEED_INTENT_NAME" \
  --target "$SEED_TARGET" \
  --output-name "$CLEANUP_ATTESTATION_NAME" \
  --profile "$FAILED_STACK_CLEANUP_PROFILE" \
  --cleanup-intent-name "$CLEANUP_INTENT_NAME" \
  --failure-attestation-name "$FAILED_CREATE_ATTESTATION_NAME" \
  --cleanup-authorization-name "$CLEANUP_AUTHORIZATION_NAME" \
  --cleanup-dispatch-name "$CLEANUP_DISPATCH_NAME"
```

Cleanup is admitted during the half-open interval
`RouteNotBefore <= now < RecoveryNotAfter`, where
`RecoveryNotAfter = RouteNotAfter + 24h`; it is closed at the exact horizon.
The request contains only the attested full stack ARN and deterministic client
token—never `RoleARN`, `RetainResources` or force deletion—and is claimed once
under `cleanup:<target>:<seed-intent-digest>:<primary|reentry>`. The cleanup
identity is owned by the artifact-bootstrap bridge and pre-exists the stack it
may delete. The lane suffix permits at most one cleanup for the primary
execution and, if a separately authorized re-entry execution also fails, one
cleanup for that re-entry; neither lane can repeat. `attest-cleanup` binds the
execution lane, original delete claim and CloudTrail event, preserves the
failed-resource projection and its digest, proves the fixed stack name absent
and proves no active fixed-resource survivors. An ambiguous DeleteStack
response or result-durability failure is not retryable; do not create a new
authorization or repeat the delete.

The write-once cleanup claim and durable dispatch both seal
`failed_stack_attestation_digest` and `failed_resources_digest`.
`attest-cleanup` must reproduce those values and the complete resource list.
Do not remove a retained or pending-deletion physical resource from a terminal
record; re-entry reopens the journal and rejects that substitution before STS.
The terminal timestamp is sampled only after CloudTrail, stack, fixed-name and
survivor reads finish; a regressed clock or closed recovery window blocks the
record.

Before it opens the cleanup profile, `delete-failed-stack` validates all local
source, seed, failed-attestation, cleanup-authorization and cleanup-intent
bindings and reopens the causal durable ExecuteChangeSet journal. For a primary
or re-entry execution as applicable, both the write-once claim and durable
result must match the attested execution intent/receipt digest, full stack and
Change Set ARNs, request token, request digest, caller digest, request ID,
lane-specific record shape and timing, and `retry_permitted=false`. A missing
or inconsistent claim or result stops before STS.

After STS, cleanup re-samples the clock and rechecks the active 60–900-second
grant. It then requires exactly one matching `ExecuteChangeSet` CloudTrail
event reconstructed from that journal, canonical `responseElements=null`, and
requires its event digest to equal the `execute_cloudtrail_event_digest`
sealed in `$FAILED_CREATE_ATTESTATION_NAME`. Only then does it re-run
`DescribeStacks`
and `ListStackResources` against the attested full stack ARN. The returned
stack ID, fixed name, exact attested `ROLLBACK_COMPLETE` or `DELETE_FAILED`
status, complete normalized resource projection and resources digest must all
remain byte-equivalent to the failure attestation. Any event, stack, status or
resource drift blocks DeleteStack.

After those reads, cleanup re-samples the clock again, rejects clock
regression, and rechecks the grant immediately before the lane-specific
`cleanup:<target>:<seed-intent-digest>:<primary|reentry>` claim and sole
DeleteStack call. The half-open recovery horizon and grant must both still be
active at that final sample.

Before `create-reentry` opens an AWS session, it validates the complete local
chain and reopens the exact immutable failure journal. A pre-execute failure
must match the primary CreateChangeSet claim/result; a cleanup terminal must
match its lane-specific DeleteStack claim/result and retain the exact failed
resources; a broker-protection rollback must match its ExecuteChangeSet
claim/result. Only then may STS run. After STS, the provider repeats the
corresponding unique CloudTrail event, validates that event's caller against
the exact target/phase role pattern as well as the journal digest, and repeats
the authoritative CloudFormation and exact-resource proof:

- pre-execute: failed/unavailable Change Set, review-in-progress stack and zero
  resources;
- cleanup terminal: DeleteStack event, exact stack/fixed-name absence and the
  fixed-resource survivor proof; or
- protection rollback: ExecuteChangeSet event, update-rollback-complete stack
  and resources, and unchanged live ledger properties.

The clock and active grant are checked again after STS and once more after
those reads immediately before the write-once re-entry claim. A copied or
re-sealed terminal JSON cannot substitute for either durable or live proof.

After the broker terminal readback, all delegation, PEP and shutdown mutations
move to the broker's qualified aliases with the literal payload `{}`. The
ordered state machine is seed revocation, delegation create and execute, PEP
create and execute, closeout gate, delegation revocation, and final route
revocation. Each create/execute pair has its own sealed request, attempting
state, provider attribution and terminal readback.

Do not retire the artifact bridge cleanup identities during `bridge-revoke`.
That UPDATE removes only the ArtifactBootstrap assignment and leaves the two
bridge-owned cleanup assignments plus the read-only
`ScanalyzeGug376RouteBrokerRecovery` role available under their independent
outer guard. `CleanupNotAfter` is derived exactly as
`AccessNotAfter + 48h`, one day after the artifact `RecoveryNotAfter`; the route
intent must bind a recovery horizon no later than this value.

After the route, broker-create and broker-protection terminal receipts have
closed successfully, materialize `bridge-cleanup-retire` in `SUCCESS` mode.
The owner-only bundle must include the exact bootstrap release, seed input,
seed intent, three terminal receipts, and each target's original execution
intent and receipt. The artifact CLI reconstructs the seed from the private
input and clean exact `main`, then performs just-in-time terminal readback with
exactly `839393571433_AWSAdministratorAccess` for `route` and
`042360977644_ScanalyzeGug376BrokerSeedExec` for `broker` and
`broker-protection`. A terminal receipt copied or resealed by an operator is
never sufficient. If successful closure was not obtained, the only other mode
is `EXPIRED`, admitted at or after `CleanupNotAfter`; its bundle must set all
route success evidence and terminal revalidation material to null, and the CLI
must not open either secondary profile.

Execute the fixed sequence `materialize-cleanup-retire`,
`authorize-cleanup-retire` for dispatch, `dispatch-cleanup-retire`,
`attest-cleanup-retire`, a separate authorization for execute,
`execute-cleanup-retire`, and `readback-cleanup-retire`. The literal action-time
phrase is
`AUTHORIZE GUG-376 bridge-cleanup-retire:<dispatch-or-execute> <INTENT_DIGEST>`.
Only `recover-cleanup-retire` and
`recover-cleanup-retire-execution` may close ambiguous provider responses; both
are read-only, require the original durable claim and authorization, and never
repeat CreateChangeSet or ExecuteChangeSet. The final readback must observe the
two cleanup permission sets, their assignments and the management recovery
role absent, with only the unassigned ArtifactBootstrap permission set left in
the bridge stack. Preserve the receipt; no reopen transition exists.

The materialized route and broker seal
`RecoveryNotAfter = RouteNotAfter + 24h`; both windows are half-open. At
`RouteNotAfter`, IAM blocks Create/Execute and provider writes. Before any
post-window cross-account session, the runtime reads the authority ledger and
requires the invoked alias to match its exact `*_DISPATCHED` state. Only
provider/CloudTrail readback plus the exact ledger completion or uncertainty
CAS can then run. A new stage, initialization, closeout or any non-dispatched
state stops without assuming the management role. At `RecoveryNotAfter`, an
explicit deny closes all actions, including readback and invocation. Do not
treat an existing SSO session as extending either horizon.

### Invoke the qualified aliases with private, fail-closed custody

After broker terminal readback, log in to the two direct invoke-only profiles.
The account number and permission-set names below come from the exact route and
PEP templates; neither profile is a default or an administrator profile.

```bash
set -euo pipefail
umask 077
test "$(stat -f '%Lp' "$PRIVATE_ROUTE_ROOT")" = 700

BROKER_PROFILE=042360977644_ScanalyzeGug376BrokerInvoker
REPAIR_PROFILE=042360977644_ScanalyzeBootstrapPlanRepair
CREATOR_FUNCTION=scanalyze-platform-authority-gug376-route-creator
EXECUTOR_FUNCTION=scanalyze-platform-authority-gug376-route-executor

aws sso login --profile "$BROKER_PROFILE"
BROKER_IDENTITY_FILE="$(mktemp "$PRIVATE_ROUTE_ROOT/broker-identity.XXXXXX")"
chmod 600 "$BROKER_IDENTITY_FILE"
AWS_RETRY_MODE=standard AWS_MAX_ATTEMPTS=1 aws sts get-caller-identity \
  --profile "$BROKER_PROFILE" --region us-east-1 --no-cli-pager \
  --cli-connect-timeout 5 --cli-read-timeout 30 --output json \
  >"$BROKER_IDENTITY_FILE"
jq -e '.Account == "042360977644" and
  (.Arn | test("^arn:aws:sts::042360977644:assumed-role/AWSReservedSSO_ScanalyzeGug376BrokerInvoker_[0-9A-Fa-f]{16}/[A-Za-z0-9+=,.@_-]{1,64}$"))' \
  "$BROKER_IDENTITY_FILE" >/dev/null

BROKER_COMPLETION_MAX_ATTEMPTS=90
BROKER_COMPLETION_BACKOFF_SECONDS=20
BROKER_COMPLETION_BUDGET_SECONDS=1800
BROKER_ROUTE_NOT_AFTER="$(jq -er '
  .route_not_after |
  select(type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))
' "$PRIVATE_ROUTE_ROOT/$BROKER_SEED_INPUT_NAME")"
BROKER_ROUTE_DEADLINE_EPOCH="$(jq -nr --arg value \
  "$BROKER_ROUTE_NOT_AFTER" '$value | fromdateiso8601')"
BROKER_RECOVERY_NOT_AFTER="$(jq -er '
  .broker_config.recovery_not_after |
  select(type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))
' "$PRIVATE_ROUTE_ROOT/$BROKER_SEED_INPUT_NAME")"
BROKER_RECOVERY_DEADLINE_EPOCH="$(jq -nr --arg value \
  "$BROKER_RECOVERY_NOT_AFTER" '$value | fromdateiso8601')"

invoke_broker_once() {
  function_name="$1" alias_name="$2" expected_state="$3"
  payload_file="$(mktemp "$PRIVATE_ROUTE_ROOT/${alias_name}.payload.XXXXXX")"
  metadata_file="$(mktemp "$PRIVATE_ROUTE_ROOT/${alias_name}.metadata.XXXXXX")"
  chmod 600 "$payload_file" "$metadata_file"
  AWS_RETRY_MODE=standard AWS_MAX_ATTEMPTS=1 aws lambda invoke \
    --function-name "$function_name" \
    --qualifier "$alias_name" \
    --payload '{}' \
    --cli-binary-format raw-in-base64-out \
    --profile "$BROKER_PROFILE" \
    --region us-east-1 \
    --no-cli-pager --cli-connect-timeout 5 --cli-read-timeout 900 \
    "$payload_file" >"$metadata_file"
  jq -e '.StatusCode == 200 and (has("FunctionError") | not) and
    (.ExecutedVersion | type == "string")' "$metadata_file" >/dev/null
  jq -e --arg alias "$alias_name" --arg state "$expected_state" \
    '.alias == $alias and .state == $state and
     .aws_mutations == 1 and .retry_permitted == false and
     .production_authorized == false and .production_status == "NO-GO"' \
    "$payload_file" >/dev/null
  LAST_BROKER_PAYLOAD_FILE="$payload_file"
}

complete_broker_bounded() {
  function_name="$1" alias_name="$2" dispatched_state="$3" expected_state="$4"
  deadline_mode="$5"
  case "$deadline_mode" in
    route) absolute_deadline_epoch="$BROKER_ROUTE_DEADLINE_EPOCH" ;;
    recovery) absolute_deadline_epoch="$BROKER_RECOVERY_DEADLINE_EPOCH" ;;
    *) return 1 ;;
  esac
  jq -e --arg alias "$alias_name" --arg state "$dispatched_state" '
    .alias == $alias and .state == $state and .aws_mutations == 1 and
    .retry_permitted == false
  ' "$LAST_BROKER_PAYLOAD_FILE" >/dev/null
  attempt=1
  local_deadline_epoch="$(($(date -u +%s) + BROKER_COMPLETION_BUDGET_SECONDS))"
  while [ "$attempt" -le "$BROKER_COMPLETION_MAX_ATTEMPTS" ]; do
    now_epoch="$(date -u +%s)"
    test "$now_epoch" -lt "$((absolute_deadline_epoch - 60))"
    test "$now_epoch" -lt "$local_deadline_epoch"
    payload_file="$(mktemp "$PRIVATE_ROUTE_ROOT/${alias_name}.completion.payload.XXXXXX")"
    metadata_file="$(mktemp "$PRIVATE_ROUTE_ROOT/${alias_name}.completion.metadata.XXXXXX")"
    chmod 600 "$payload_file" "$metadata_file"
    AWS_RETRY_MODE=standard AWS_MAX_ATTEMPTS=1 aws lambda invoke \
      --function-name "$function_name" --qualifier "$alias_name" \
      --payload '{}' --cli-binary-format raw-in-base64-out \
      --profile "$BROKER_PROFILE" --region us-east-1 \
      --no-cli-pager --cli-connect-timeout 5 --cli-read-timeout 900 \
      "$payload_file" >"$metadata_file"
    if jq -e '.StatusCode == 200 and (has("FunctionError") | not) and
      (.ExecutedVersion | type == "string")' "$metadata_file" >/dev/null; then
      jq -e --arg alias "$alias_name" --arg state "$expected_state" '
        .alias == $alias and .state == $state and .aws_mutations == 0 and
        .retry_permitted == false and .production_authorized == false and
        .production_status == "NO-GO"
      ' "$payload_file" >/dev/null
      LAST_BROKER_PAYLOAD_FILE="$payload_file"
      return 0
    fi
    jq -e '.StatusCode == 200 and .FunctionError == "Unhandled" and
      (.ExecutedVersion | type == "string")' "$metadata_file" >/dev/null
    jq -e '.errorType == "RouteBrokerReadOnlyPending" and
      (.errorMessage | test("^GUG376_ROUTE_BROKER_READ_ONLY_PENDING:[A-Z][A-Z0-9_]{2,95}$"))' \
      "$payload_file" >/dev/null
    test "$attempt" -lt "$BROKER_COMPLETION_MAX_ATTEMPTS"
    sleep "$BROKER_COMPLETION_BACKOFF_SECONDS"
    attempt="$((attempt + 1))"
  done
  return 1
}

invoke_broker_once "$CREATOR_FUNCTION" seed-revoke-create-v1 SEED_REVOKE_CREATE_DISPATCHED
complete_broker_bounded "$CREATOR_FUNCTION" seed-revoke-create-v1 SEED_REVOKE_CREATE_DISPATCHED SEED_REVOKE_CREATED route
invoke_broker_once "$EXECUTOR_FUNCTION" seed-revoke-execute-v1 SEED_REVOKE_EXECUTE_DISPATCHED
complete_broker_bounded "$EXECUTOR_FUNCTION" seed-revoke-execute-v1 SEED_REVOKE_EXECUTE_DISPATCHED SEED_REVOKED route
invoke_broker_once "$CREATOR_FUNCTION" delegation-create-v1 DELEGATION_CREATE_DISPATCHED
complete_broker_bounded "$CREATOR_FUNCTION" delegation-create-v1 DELEGATION_CREATE_DISPATCHED DELEGATION_CREATED route
invoke_broker_once "$EXECUTOR_FUNCTION" delegation-execute-v1 DELEGATION_EXECUTE_DISPATCHED
complete_broker_bounded "$EXECUTOR_FUNCTION" delegation-execute-v1 DELEGATION_EXECUTE_DISPATCHED DELEGATION_TERMINAL route
invoke_broker_once "$CREATOR_FUNCTION" pep-create-v1 PEP_CREATE_DISPATCHED
complete_broker_bounded "$CREATOR_FUNCTION" pep-create-v1 PEP_CREATE_DISPATCHED PEP_CREATED route
invoke_broker_once "$EXECUTOR_FUNCTION" pep-execute-v1 PEP_EXECUTE_DISPATCHED
complete_broker_bounded "$EXECUTOR_FUNCTION" pep-execute-v1 PEP_EXECUTE_DISPATCHED PEP_TERMINAL route

# The exact local SSO profile must already be configured outside the repo.
# It can resolve credentials only after delegation terminal readback proves
# the ScanalyzeBootstrapPlanRepair assignment.
aws sso login --profile "$REPAIR_PROFILE"
REPAIR_IDENTITY_FILE="$(mktemp "$PRIVATE_ROUTE_ROOT/repair-identity.XXXXXX")"
chmod 600 "$REPAIR_IDENTITY_FILE"
AWS_RETRY_MODE=standard AWS_MAX_ATTEMPTS=1 aws sts get-caller-identity \
  --profile "$REPAIR_PROFILE" --region us-east-1 --no-cli-pager \
  --cli-connect-timeout 5 --cli-read-timeout 30 --output json \
  >"$REPAIR_IDENTITY_FILE"
jq -e '.Account == "042360977644" and
  (.Arn | test("^arn:aws:sts::042360977644:assumed-role/AWSReservedSSO_ScanalyzeBootstrapPlanRepair_[0-9A-Fa-f]{16}/[A-Za-z0-9+=,.@_-]{1,64}$"))' \
  "$REPAIR_IDENTITY_FILE" >/dev/null
```

`invoke_broker_once` invokes each mutating alias exactly once and requires its
private `*_DISPATCHED` receipt with `aws_mutations=1`.
`complete_broker_bounded` revalidates that receipt before every completion
sequence. Because the ledger is already dispatched, those invocations can run
only provider/CloudTrail readback and the single control-ledger completion CAS;
they cannot call the provider effect again and return `aws_mutations=0`.
The helper polls only the distinct Lambda `RouteBrokerReadOnlyPending` type and
exact sanitized prefix. All completions except final
`route-revoke-execute-v1` stop before `RouteNotAfter - 60s`; only that final
readback may use `RecoveryNotAfter - 60s`. Each is also bounded by 90 attempts,
20-second backoff and a 1,800-second local budget. A nonzero CLI exit, untyped
`FunctionError`, unexpected/uncertain receipt, timeout or disconnect stops;
preserve every `0600` file and never repeat the mutation.

Only after the broker reaches the required PEP terminal state, invoke the Plan,
repair and reconcile aliases in that order. The success path requires exactly
one `reconcile-v1` invocation after `REPAIR_VERIFIED` and exact sealed
`RECONCILE_VERIFIED` readback. An ambiguous result stops for the separately
reviewed recovery branch; it never authorizes a second reconcile invocation.

```bash
invoke_repair() {
  function_name="$1" alias_name="$2" expected_mode="$3" expected_status="$4"
  payload_file="$(mktemp "$PRIVATE_ROUTE_ROOT/${alias_name}.payload.XXXXXX")"
  metadata_file="$(mktemp "$PRIVATE_ROUTE_ROOT/${alias_name}.metadata.XXXXXX")"
  chmod 600 "$payload_file" "$metadata_file"
  AWS_RETRY_MODE=standard AWS_MAX_ATTEMPTS=1 aws lambda invoke \
    --function-name "$function_name" \
    --qualifier "$alias_name" \
    --payload '{}' \
    --cli-binary-format raw-in-base64-out \
    --profile "$REPAIR_PROFILE" \
    --region us-east-1 \
    --no-cli-pager --cli-connect-timeout 5 --cli-read-timeout 900 \
    "$payload_file" >"$metadata_file"
  jq -e '.StatusCode == 200 and (has("FunctionError") | not) and
    (.ExecutedVersion | type == "string")' "$metadata_file" >/dev/null
  jq -e --arg mode "$expected_mode" --arg status "$expected_status" \
    '.mode == $mode and .status == $status and .retry_permitted == false and
     .direct_human_sso_mutations == 0 and .production_status == "NO-GO"' \
    "$payload_file" >/dev/null
}

invoke_repair scanalyze-platform-authority-plan-policy-plan plan-v1 plan PLAN_VERIFIED
invoke_repair scanalyze-platform-authority-plan-policy-repair repair-v1 repair REPAIR_VERIFIED
invoke_repair scanalyze-platform-authority-plan-policy-reconcile reconcile-v1 reconcile RECONCILE_VERIFIED

# Prove the repaired authority with a new normal Plan SSO session. This exact
# local profile is configured outside the repository. The GUG-274 runtime path
# is reviewed executable material, not a secret or an ambient Python fallback.
NORMAL_PLAN_PROFILE=042360977644_ScanalyzeAuthorityBootstrapPlan
PLAN_SEED_SNAPSHOT_FILE="$PRIVATE_ROUTE_ROOT/$PLAN_SEED_SNAPSHOT_NAME"
NORMAL_PLAN_GENERATED_ROLE_NAME="$(jq -er '
  .generated_role_name |
  select(test("^AWSReservedSSO_ScanalyzeAuthorityBootstrapPlan_[0-9A-Fa-f]{16}$"))
' "$PLAN_SEED_SNAPSHOT_FILE")"
NORMAL_PLAN_GENERATED_ROLE_ARN="$(jq -er --arg role "$NORMAL_PLAN_GENERATED_ROLE_NAME" '
  .generated_role_arn |
  select(. == ("arn:aws:iam::042360977644:role/aws-reserved/sso.amazonaws.com/" + $role))
' "$PLAN_SEED_SNAPSHOT_FILE")"
export SCANALYZE_GUG274_SDK_RUNTIME_ROOT='<absolute-reviewed-gug274-sdk-runtime-root>'
PINNED_GUG274_PYTHON="$SCANALYZE_GUG274_SDK_RUNTIME_ROOT/bin/python3"
test -x "$PINNED_GUG274_PYTHON"
aws sso login --profile "$NORMAL_PLAN_PROFILE"
NORMAL_PLAN_IDENTITY_FILE="$(mktemp "$PRIVATE_ROUTE_ROOT/normal-plan-identity.XXXXXX")"
NORMAL_PLAN_PREFLIGHT_FILE="$(mktemp "$PRIVATE_ROUTE_ROOT/gug214-preflight.XXXXXX")"
chmod 600 "$NORMAL_PLAN_IDENTITY_FILE" "$NORMAL_PLAN_PREFLIGHT_FILE"
AWS_RETRY_MODE=standard AWS_MAX_ATTEMPTS=1 aws sts get-caller-identity \
  --profile "$NORMAL_PLAN_PROFILE" --region us-east-1 --no-cli-pager \
  --cli-connect-timeout 5 --cli-read-timeout 30 --output json \
  >"$NORMAL_PLAN_IDENTITY_FILE"
NORMAL_PLAN_CALLER_ARN_DIGEST="sha256:$(
  jq -ecj --arg role "$NORMAL_PLAN_GENERATED_ROLE_NAME" '
  select(.Account == "042360977644") |
  .Arn as $arn |
  select($arn | startswith("arn:aws:sts::042360977644:assumed-role/" + $role + "/")) |
  ($arn | split("/") | .[2]) as $session |
  select($session | test("^[A-Za-z0-9+=,.@_-]{1,64}$")) |
  {caller_arn:$arn}
' "$NORMAL_PLAN_IDENTITY_FILE" |
  shasum -a 256 | awk '{print $1}'
)"
AWS_RETRY_MODE=standard AWS_MAX_ATTEMPTS=1 \
AWS_PROFILE="$NORMAL_PLAN_PROFILE" AWS_REGION=us-east-1 \
env -u PYTHONPATH -u PYTHONHOME "$PINNED_GUG274_PYTHON" -I -S \
  scripts/deployment/platform-authority-bootstrap.py preflight-recovery \
  --authority-account-id 042360977644 \
  --region us-east-1 \
  --destination-account-id 839393571433 \
  >"$NORMAL_PLAN_PREFLIGHT_FILE"
grep -Fx 'PASS: exact empty platform-authority review shell verified' \
  "$NORMAL_PLAN_PREFLIGHT_FILE" >/dev/null
grep -Fx 'PASS: zero active Change Sets verified across all pages' \
  "$NORMAL_PLAN_PREFLIGHT_FILE" >/dev/null
grep -Fx 'NO_CHANGE: recovery preflight performed no AWS mutation' \
  "$NORMAL_PLAN_PREFLIGHT_FILE" >/dev/null

# Only after independent repair/reconcile evidence and the new normal-Plan
# GUG-214 read-only functional proof. CloudTrail delivery may lag, so only this
# zero-mutation closeout read is retried. The literal NORMAL_PLAN_PROOF_PENDING
# error is emitted only after the broker has read and required PEP_TERMINAL.
CLOSEOUT_MAX_ATTEMPTS=24
CLOSEOUT_BACKOFF_SECONDS=20
CLOSEOUT_PROOF_BUDGET_SECONDS=780
CLOSEOUT_ROUTE_NOT_AFTER="$(jq -er '
  .route_not_after |
  select(type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))
' "$PRIVATE_ROUTE_ROOT/$BROKER_SEED_INPUT_NAME")"
CLOSEOUT_ROUTE_DEADLINE_EPOCH="$(
  env -u PYTHONPATH -u PYTHONHOME "$PINNED_GUG274_PYTHON" -I -S -c '
from datetime import datetime
import sys
value = datetime.fromisoformat(sys.argv[1][:-1] + "+00:00")
if value.microsecond:
    raise SystemExit(1)
print(int(value.timestamp()))
' "$CLOSEOUT_ROUTE_NOT_AFTER"
)"
CLOSEOUT_PROOF_DEADLINE_EPOCH="$(($(date -u +%s) + CLOSEOUT_PROOF_BUDGET_SECONDS))"

invoke_closeout_bounded() {
  attempt=1
  while [ "$attempt" -le "$CLOSEOUT_MAX_ATTEMPTS" ]; do
    now_epoch="$(date -u +%s)"
    test "$now_epoch" -lt "$((CLOSEOUT_ROUTE_DEADLINE_EPOCH - 60))"
    test "$now_epoch" -lt "$CLOSEOUT_PROOF_DEADLINE_EPOCH"
    payload_file="$(mktemp "$PRIVATE_ROUTE_ROOT/closeout-gate-v1.payload.XXXXXX")"
    metadata_file="$(mktemp "$PRIVATE_ROUTE_ROOT/closeout-gate-v1.metadata.XXXXXX")"
    chmod 600 "$payload_file" "$metadata_file"
    AWS_RETRY_MODE=standard AWS_MAX_ATTEMPTS=1 aws lambda invoke \
      --function-name "$CREATOR_FUNCTION" --qualifier closeout-gate-v1 \
      --payload '{}' --cli-binary-format raw-in-base64-out \
      --profile "$BROKER_PROFILE" --region us-east-1 \
      --no-cli-pager --cli-connect-timeout 5 --cli-read-timeout 900 \
      "$payload_file" >"$metadata_file"
    if jq -e '.StatusCode == 200 and (has("FunctionError") | not) and
      (.ExecutedVersion | type == "string")' "$metadata_file" >/dev/null; then
      jq -e '
        .alias == "closeout-gate-v1" and
        .state == "CLOSEOUT_PREREQUISITES_VERIFIED" and
        .aws_mutations == 0 and .retry_permitted == false and
        .production_authorized == false and .production_status == "NO-GO"
      ' "$payload_file" >/dev/null
      LAST_BROKER_PAYLOAD_FILE="$payload_file"
      return 0
    fi
    jq -e '.StatusCode == 200 and .FunctionError == "Unhandled" and
      (.ExecutedVersion | type == "string")' "$metadata_file" >/dev/null
    jq -e '.errorType == "RouteBrokerReadOnlyPending" and
      .errorMessage == "GUG376_ROUTE_BROKER_READ_ONLY_PENDING:NORMAL_PLAN_PROOF_PENDING"' \
      "$payload_file" >/dev/null
    test "$attempt" -lt "$CLOSEOUT_MAX_ATTEMPTS"
    sleep "$CLOSEOUT_BACKOFF_SECONDS"
    attempt="$((attempt + 1))"
  done
  return 1
}

invoke_closeout_bounded
jq -e --arg digest "$NORMAL_PLAN_CALLER_ARN_DIGEST" '
  .normal_plan_caller_arn_digest == $digest and
  (.receipt_digest | test("^sha256:[0-9a-f]{64}$"))
' "$LAST_BROKER_PAYLOAD_FILE" >/dev/null
invoke_broker_once "$CREATOR_FUNCTION" delegation-revoke-create-v1 DELEGATION_REVOKE_CREATE_DISPATCHED
complete_broker_bounded "$CREATOR_FUNCTION" delegation-revoke-create-v1 DELEGATION_REVOKE_CREATE_DISPATCHED DELEGATION_REVOKE_CREATED route
invoke_broker_once "$EXECUTOR_FUNCTION" delegation-revoke-execute-v1 DELEGATION_REVOKE_EXECUTE_DISPATCHED
complete_broker_bounded "$EXECUTOR_FUNCTION" delegation-revoke-execute-v1 DELEGATION_REVOKE_EXECUTE_DISPATCHED DELEGATION_REVOKED route
invoke_broker_once "$CREATOR_FUNCTION" route-revoke-create-v1 ROUTE_REVOKE_CREATE_DISPATCHED
complete_broker_bounded "$CREATOR_FUNCTION" route-revoke-create-v1 ROUTE_REVOKE_CREATE_DISPATCHED ROUTE_REVOKE_CREATED route
invoke_broker_once "$EXECUTOR_FUNCTION" route-revoke-execute-v1 ROUTE_REVOKE_EXECUTE_DISPATCHED
complete_broker_bounded "$EXECUTOR_FUNCTION" route-revoke-execute-v1 ROUTE_REVOKE_EXECUTE_DISPATCHED ROUTE_REVOKED recovery
```

The normal Plan identity gate derives the exact generated role name and IAM ARN
from the sealed connected snapshot. Closeout accepts only fresh post-reconcile
`ListChangeSets` events from one full STS session with that exact session issuer
ARN, name and account. The raw session ARN remains only in the owner-only local
identity file: `jq -cj` streams the validated single-key canonical JSON
directly into SHA-256, without copying the ARN into a shell variable or command
argument. The broker public receipt and ledger contain only that canonical
digest. The operator must compare the independently computed local digest with
`normal_plan_caller_arn_digest` before revocation. A Lambda caller, foreign
account, role/suffix drift, stale event or multiple eligible sessions stops the
route. Immediately before sealing the receipt and ledger CAS, closeout
rechecks that the latest accepted event is still no more than 900 seconds old;
crossing that boundary during pagination stops without CAS or mutation.

Only `invoke_closeout_bounded` may repeat an invocation, and only when Lambda
returns the exact typed and sanitized `NORMAL_PLAN_PROOF_PENDING` error. That error is
reachable only after the broker requires `PEP_TERMINAL`; the alias performs
zero mutations. The helper keeps every attempt's payload and metadata at
`0600`, caps attempts and backoff, and stops before both its local proof budget
and `RouteNotAfter - 60s`. Any other `FunctionError`, including
`CLOSEOUT_EVIDENCE_PENDING`, is terminal for this procedure. Plan, repair,
reconcile and every mutating broker alias remain one-attempt only.

The GUG-274 wrapper bounds each read request to 5 seconds to connect, 30
seconds to read and 45 seconds for the subprocess. Waiters use their separate
5/900/930-second budget. Both paths use standard retry mode and one attempt, so
a stuck read cannot consume the 900-second normal-Plan evidence freshness
window.

Independently read the sealed ledger/public receipt after each terminal state
before advancing. These invocations are non-production only and never prove a
production deployment.

## Phase 6 — Plan

Start a fresh invoke-only SSO session. Invoke only the qualified `plan-v1`
alias with the literal JSON object `{}`. The function must:

- verify its version, alias mode and execution role;
- read the exact provider and invocation graph state;
- prove the sole eligible predecessor;
- reserve the immutable intent; and
- create `PLAN_VERIFIED` with conditional `PutItem`.

The invocation must enter with more than 60,000 milliseconds remaining. The
bound adapter re-checks that same read reserve before every provider call
rather than relying only on the entry check.

Independently read the ledger and public receipt. A blocked or uncertain Plan
does not authorize repair.

## Phase 7 — One-shot repair

Require an explicit, time-bounded authorization for the two exact effects and
the exact `PLAN_VERIFIED` digest. Use a fresh invoke-only session and invoke only
`repair-v1` with `{}`.

The function claims the ledger before any write. It must record the attempting
state before each one-attempt provider call, require exact readback, and always
run `ProvisionPermissionSet` after a confirmed policy update. The operator does
not retry a timeout, disconnect, provider error or non-terminal response.

Repair must enter with more than 480,000 milliseconds remaining. The bound
adapter requires more than 75,000 milliseconds immediately before each write
and more than 60,000 milliseconds before each read or provisioning poll.
Crossing a threshold stops before the next provider call; it never authorizes
a retry.

Independently, the immutable intent must retain at least 660 seconds before the
Plan claim and more than 75 seconds immediately before each write. These
wall-clock guards do not substitute for the Lambda millisecond reserves.

## Phase 8 — Reconcile and functional proof

Invoke `reconcile-v1` with `{}` even after apparent success. It performs no
Identity Center, IAM, Lambda or CloudFormation mutation and must enter with
more than 60,000 milliseconds remaining. After exact convergence it performs
one conditional control-metadata write to
`<repair-id>#reconcile-v1`, then strongly reads back the exact sealed
attestation. Require convergence of:

- desired inline policy digest;
- unchanged metadata, tags, attachments, boundary and assignment;
- only the authority account provisioned;
- zero relevant pending operation;
- exact generated role trust and `AwsSSOInlinePolicy`; and
- CloudTrail attribution of both effects to the mutation service role and
  repair source identity.

Require the original base ledger to remain `REPAIR_VERIFIED`,
`FINAL_READBACK_VERIFIED`, attempted/completed `2/2`. Independently validate
the suffixed attestation's source, intent, base-ledger, final-state,
invocation-authority and published-function bindings. Do not treat a public
`RECONCILE_VERIFIED` receipt, equivalent provider state or an uncertain base
ledger as closeout evidence. A second reconcile invocation is a replay and
must fail closed.

Then start a completely new normal Plan SSO session and run the bounded GUG-214
read-only recovery preflight. Successful `ListChangeSets` pagination is the
functional proof. It is not production certification.

## Phase 9 — Revoke temporary access

Use only the broker aliases `delegation-revoke-create-v1` and
`delegation-revoke-execute-v1` against the same management stack. The sealed
broker request uses the exact same versioned template and prior parameters,
changing only `RepairInvokerAssignmentEnabled` from `true` to `false`. Its
resource change set must contain exactly one change:

```text
Action=Remove
LogicalResourceId=RepairInvokerAssignment
ResourceType=AWS::SSO::Assignment
```

Each alias accepts only `{}`. The creator must authenticate the unique
CloudTrail event and prove this exact single removal before the executor can
advance the broker ledger. Read back
`RepairInvokerAssignmentMode=false`, zero assignments for the temporary
`ScanalyzeBootstrapPlanRepair` permission set, and a terminal assignment
deletion state with no relevant pending operation. After Identity Center
converges, prove the corresponding
`AWSReservedSSO_ScanalyzeBootstrapPlanRepair_*` role is absent. The two service
roles and the invoke-only permission-set configuration must remain unchanged;
do not delete them or any authority-stack evidence resource.

Do not set the parameter back to `true` for the same repair. Any later temporary
assignment requires a new repair ID, window, artifact binding, reviewed Change
Set and explicit authorization. Preserve the ledger, KMS key, function
versions, logs, signed artifact and sanitized receipts according to the
evidence-retention policy.

### Close the ADR-058 route

After the repair-invoker assignment is absent and the broker closeout gate is
sealed, use only `route-revoke-create-v1` and `route-revoke-execute-v1`. The
route was already reduced by `seed-revoke-create-v1` and
`seed-revoke-execute-v1`, which removed the broker seed Creator and Executor
assignments before any delegation or PEP Change Set. The final route Change Set
therefore removes exactly one remaining assignment:

```text
Action=Remove
ResourceType=AWS::SSO::Assignment
LogicalResourceId=BrokerInvokerAssignment
```

The creator authenticates the new CloudTrail event and the exact one-removal
inventory; the executor requires terminal readback with
`SeedAssignmentMode=false`, `BrokerInvokerAssignmentMode=false`, zero
assignments in the broker-invoker scope and terminal deletion state. Then prove
the corresponding generated `AWSReservedSSO_*` role is absent after Identity
Center converges. Assignment deletion does not revoke already-issued
credentials immediately: wait for the maximum session lifetime or use a
separately reviewed session-revocation control before declaring
`ROUTE_CLOSED`.

Retain the inactive permission sets and route stack as evidence. Their deletion
would require a separate administrator change and is not part of the repair.

## Uncertainty and recovery

After any possible dispatch:

1. do not invoke repair again;
2. do not edit the permission set from a console or CLI;
3. do not delete or rewrite the ledger;
4. invoke only the provider-read-only reconcile alias, which may append the
   one exact durable attestation after a terminal verified repair;
5. preserve exact CloudTrail and provider readback; and
6. request a new reviewed recovery decision.

Equivalent final provider state is insufficient if the ledger cannot attribute
both effects. A new attempt requires a new repair ID, window, artifact binding
and explicit authorization.

If the attempt to seal an uncertain state is itself unproven, the function
emits no public receipt and returns `UNCERTAINTY_LEDGER_UNPROVEN`. The existing
attempting state still blocks repair replay; preserve it and stop for a new
reviewed recovery decision.

## Rollback boundary

Stack rollback may remove only resources whose retention policy and evidence
contract permit it. KMS, ledger and logs remain retained. The repaired desired
Plan policy is not reverted automatically to the known-bad predecessor.

```text
REPOSITORY_VALIDATED=NOT_LIVE_EVIDENCE
RUNTIME_PORTS=BOUND_IN_SOURCE_CLOSED_PACKAGE
TEMPORARY_ROUTE_SEED=NOT_EXECUTED
SIGNED_ARTIFACT=NOT_BUILT
AWS_CALLS=9
AWS_MUTATIONS=0
DEPLOYMENT=NOT_EXECUTED
REPAIR=NOT_EXECUTED
PRODUCTION=NO-GO
```

## References

- [ADR-057](../../ADR/ADR-057-bootstrap-plan-permission-repair-pep.md)
- [ADR-058](../../ADR/ADR-058-gug376-temporary-changeset-route.md)
- [Deployment contract](../deployment/platform-authority-bootstrap-plan-permission-repair.md)
- [Bootstrap recovery](platform-authority-bootstrap-recovery.md)
- [Retained Change Set retirement](platform-authority-retained-change-set-retirement.md)
