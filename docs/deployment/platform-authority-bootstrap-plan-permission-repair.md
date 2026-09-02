# Platform-Authority Bootstrap Plan permission repair

## Purpose

This contract defines a dedicated server-side policy-enforcement point (PEP)
for repairing one exact predecessor of the normal
`ScanalyzeAuthorityBootstrapPlan` Identity Center permission set. It does not
grant a person `sso-admin` or IAM mutation authority and it does not reuse the
GUG-221 collector repair.

Repository implementation is AWS-free evidence. It does not authorize a
deployment or repair. Production remains **NO-GO**.

## Current implementation boundary

This iteration provides the infrastructure, IAM, state machine, concrete AWS
runtime, deterministic artifact contracts and the route-specific collision
admission. Before every expansive effect, the source-closed runtime
materializes the exact 73-target catalog and opens ten fresh read-only sessions
across the two domains. Local bootstrap CLIs derive them from two sealed
read-only SSO sources; deployed broker effects use ten unique 900-second reader
role sessions. It derives candidate-detail policy from sealed inventory
evidence and accepts only the operation-specific stable
`PRESENT_OWNED`/`ABSENT` state. Its one-shot effect grant is bound into the
durable attempt claim and dispatched receipt, then consumed and revalidated
immediately before the provider call. Missing, stale, partial, colliding,
uncertain or lineage-changed evidence fails closed before the new effect.

Read-only causal recovery and exact bounded cleanup remain available so an
already-dispatched call can complete without replay and a previously revoked
bridge can finish bounded cleanup. Reducing and readback-only operations do not
initiate a new collision scan. The reviewed Lambda entrypoint installs
zero-retry `IdentityCenterPort` and `LedgerPort` adapters only inside the
source-closed package. The repair materializer CLI remains offline and can
never install or call those ports. Separate connected artifact-bootstrap and
route-provider CLIs expose only their closed, action-authorized AWS boundaries;
they cannot invoke the repair PEP directly.

Before its first SDK client, the runtime validates every static ARN, ID,
digest, tag, window, reviewed policy digest, runtime-lock field and exact SDK
version. It then proves the local and assumed caller identities; all six local
and delegated IAM roles; the three published functions and aliases; the full
invocation graph; the retained DynamoDB/KMS controls; and the complete
Identity Center state. The effective-IAM guard reruns immediately before each
protected effect. Provider output, pagination and public errors are bounded and
fail closed.

This source-closed repository path is still not deployment or repair authority.
No package has been signed or staged from this unmerged worktree, no stack has
been deployed and production remains **NO-GO**.

ADR-058 adds the missing repository-side deployment route as an attested
broker. Before that route can be materialized, one separately authorized
management-account administrator creates only the artifact-bootstrap bridge.
Its temporary authority-account assignment creates the retained, dedicated
KMS/S3/Signer/Lambda code-signing foundation, publishes and authenticates the
exact artifacts, and is then revoked. A post-revocation release binds the
closed publication evidence before a second separately authorized
management-account administrator session may create only the temporary route
stack. Two short-lived seed assignments can then
create and execute only one parameterless, versioned broker template. After
the broker proves its own terminal state, it removes those seed assignments
before creating either target Change Set. All later requests are selected by
qualified Lambda alias and carry the literal payload `{}`; sealed broker
configuration supplies the account, role, template, parameters and operation
order. Creator and Executor authority remains disjoint, provider mutations are
usable only through CloudFormation forward access, every template is bound to
an exact S3 version, and target Change Sets omit `RoleARN`. Repository presence
does not authorize or prove any seed, broker invocation or target deployment.

## Dedicated artifact foundation and two-stage release

The product path has no implicit artifact-store discovery. It accepts only
`scanalyze-platform-authority-gug376-artifact-foundation`, whose reviewed
CloudFormation template contains the exact retained KMS key/alias, private
versioned bucket, AWS Signer profile and enforcing Lambda code-signing
configuration. Historical GUG-363/GUG-365 storage is test compatibility only
and cannot be selected by a production CLI.

The temporary artifact-bootstrap bridge is a separate management-account
stack. It creates one `PT1H` Identity Center permission set and, only while its
required flag is `true`, one assignment to the private bootstrap principal.
Its inline policy is bounded to the exact names, source commit, Region and
absolute window. The initial version cannot start a signing job. After exact
foundation readback, a reviewed bridge update pins the generated Signer profile
version before any signing mutation is possible.

The bridge principal ID and Signer profile version, plus the foundation route
and delegation object-version IDs, are non-secret causal coordinates. Their
parameters are deliberately visible: neither template marks them `NoEcho`.
Connected `DescribeChangeSet` and `DescribeStacks` evidence must contain each
key exactly once with the exact sealed value. A mask such as `****` or `*****`,
a duplicate key, an omitted key or any substituted value fails closed.

The first causal closure is the foundation publish binding. It is materialized
before bridge revocation and binds:

1. the exact clean merged `main` Git-object bytes for the bridge, foundation,
   route and delegation templates;
2. terminal bridge and foundation readbacks;
3. exact KMS key/alias, bucket controls, Signer profile version and code-signing
   configuration;
4. exact versioned route and delegation template receipts; and
5. the foundation access-update request, Change Set evidence and terminal
   readback that open only those reviewed cross-account reads.

All template and signed-artifact producers must consume that same binding. The
second closure is the artifact bootstrap route release. It is materialized only
after the complete template, signed-artifact and broker-seed receipt set
exists, the bridge readback proves zero assignments, and the `PT1H` credential
boundary has expired. Only this post-revocation release may authorize local
materialization of the normal route seed. Neither closure authorizes
production.

The checked-in handler contract already rejects exhausted invocations: Plan
and reconcile require more than 60,000 milliseconds remaining at entry, while
repair requires more than 480,000 milliseconds before it can consume a Plan.
The immutable intent window separately requires at least 660 seconds before
the Plan claim and more than 75 seconds before either SSO write.
The concrete adapter adds operation-level guards of more than 75,000
milliseconds before either SSO mutation and more than 60,000 milliseconds
before every provider read or provisioning poll. Equality with a threshold is
insufficient and fails closed.

## Eligible predecessor

The desired policy is always rendered from reviewed source by
`tooling/platform_authority_bootstrap.py`. The only eligible live predecessor
is that same canonical document with the single
`ListOnlyExactBootstrapChangeSets` statement removed. All other statements,
the exact Change Set name, resource bindings and explicit denials must match.

The surrounding permission-set state must also be exact:

The normal Plan tags and the temporary invoker tags are separate contracts.
`ExpectedPlanPermissionSetTagsJson` describes only the already-existing Plan
permission set. The invoker tags are derived exclusively from the reviewed
source commit and the fixed CloudFormation values; they are never copied from
or required to equal the Plan tags. The closed seven-tag invoker contract also
contains `component=plan-repair-delegation` so the temporary deployment
Executor cannot manage any route permission set.

| Surface | Required state |
|---|---|
| Permission set | `ScanalyzeAuthorityBootstrapPlan`, active instance, reviewed metadata and tags |
| Inline policy | Exact canonical predecessor only |
| Attachments and boundary | None |
| Assignment | One immutable `USER` assignment to account ending `7644` |
| Provisioned accounts | Only account ending `7644` |
| Pending operations | None |
| Generated IAM role | Exactly one expected `AWSReservedSSO_ScanalyzeAuthorityBootstrapPlan_*` role |
| Role policy | Existing predecessor through `AwsSSOInlinePolicy`, no additional authority |

Denied access, incomplete pagination, a repeated token, stale evidence or a
similar name never proves this state. Any second difference is blocked rather
than repaired.

## Two-account control plane

### Management account ending `1433`

The delegation stack owns:

- one mutation service role trusted only by the exact authority-account repair
  execution role;
- one readback service role trusted only by the exact authority-account Plan
  and reconcile roles;
- the invoke-only `ScanalyzeBootstrapPlanRepair` permission set; and
- when explicitly enabled, one reviewed temporary `USER` assignment targeting
  only the authority account.

The required `RepairInvokerAssignmentEnabled` parameter has no default.
`true` creates the temporary assignment for the separately authorized execution
window; `false` removes only that assignment while retaining the permission set
and both service roles. The same reviewed template bytes support both states.

The mutation role may read the exact Identity Center state and perform only:

```text
sso:PutInlinePolicyToPermissionSet
sso:ProvisionPermissionSet
```

It cannot create or update permission-set metadata, create/delete assignments,
attach policies, set boundaries, tag resources, delete resources, mutate IAM
or chain roles. The readback role has the same bounded inventory surface and no
write action.

### Authority account ending `7644`

The PEP stack owns:

- retained KMS and DynamoDB evidence resources;
- separate Plan, repair, reconcile and invocation-inspector roles;
- three private code-signed Lambda functions;
- one published numeric version and qualified alias per mode;
- zero-retry alias-level asynchronous configuration; and
- retained log groups.

Each function also has an explicit `AWS::Lambda::RuntimeManagementConfig` with
`UpdateRuntimeOn=FunctionUpdate`. CloudFormation establishes that control
before publishing the numeric version. The runtime reads the qualified
version's management state and rejects anything other than the exact
`FunctionUpdate` mode and active runtime-version ARN. The reviewed package can
therefore use the managed boto3/botocore libraries without being silently
moved to a newer managed runtime between function updates.

The Plan role can create, but not update, one base ledger record. The repair
role can conditionally update, but not create, that record. Reconcile cannot
mutate provider state; after proving an original terminal `REPAIR_VERIFIED`
record and exact final readback, it can conditionally create only the separate
`<repair-id>#reconcile-v1` attestation. Both records use exact leading-key
conditions, strongly consistent readback and a table resource policy that
denies unsupported writers and cross-key writes.

There are no function URLs, resource-based public permissions, event sources,
destinations, alias routing weights or unqualified invocation grants.

## Human boundary

The only direct provider exception is the first administrative route-stack
Change Set. It requires a fresh, separately authorized
`839393571433_AWSAdministratorAccess` session and ends after exact terminal
route readback. That session cannot be reused as a broker or repair operator.

Two one-hour seed permission sets can create or execute only
`gug376-route-broker-create` against the exact versioned, parameterless broker
template. They are removed before the broker may create a delegation or PEP
Change Set. The retained broker-invoker permission set can invoke only the
eleven reviewed qualified aliases with `{}` and has no direct CloudFormation,
IAM, Identity Center, DynamoDB, KMS, S3, Logs or role-chaining authority.

The later temporary repair-invoker permission set invokes only:

```text
...:function:scanalyze-platform-authority-plan-policy-plan:plan-v1
...:function:scanalyze-platform-authority-plan-policy-repair:repair-v1
...:function:scanalyze-platform-authority-plan-policy-reconcile:reconcile-v1
```

Every invocation event must be exactly `{}`. A payload cannot select an
account, Region, permission set, policy, Change Set, source commit, repair ID,
mode or time window. Alias, published version and immutable deployment
configuration supply those bindings.

The repair invoker has no `sso:*`, `identitystore:*`, `iam:*`,
`sts:AssumeRole`, DynamoDB write or Lambda-management permission.

## Durable execution contract

The private intent binds:

- reviewed source commit and source bundle;
- desired-policy template bytes;
- predecessor, target and one-statement delta digests;
- Change Set name digest;
- exact instance, store, permission set, generated role and assignment digests;
- exact provisioned-account and invocation-authority graph digests; and
- account, Region, repair ID and maximum fifteen-minute window.

The separately materialized `ImmutableConfigurationDigest` is a canonical
projection of every operator-controlled runtime binding plus the fixed function
and resource identities. It is injected as `IMMU_CONFIG_DIGEST`, independently
recomputed before any SDK client is created, and included in every
`AWS::Lambda::Version` description. Any private parameter change with unchanged
ZIP bytes therefore replaces the numeric versions and moves the aliases only to
the newly bound configuration; an unverified digest is rejected.

Lambda environment size is the exact UTF-8 sum of every configured key and
value. The template constrains descriptions and tag JSON to printable ASCII,
caps tag JSON at 1,024 bytes and caps every variable-length parameter. The
worst-case reconcile environment is 3,940 bytes, below Lambda's 4,096-byte
limit, and the runtime repeats the exact calculation before SDK use.

The state machine records a conditional transition before each effect:

| Status | Stage | Attempted | Completed |
|---|---|---:|---:|
| `PLAN_VERIFIED` | `PLAN_STATE_VERIFIED` | 0 | 0 |
| `CLAIMED` | `BEFORE_FIRST_EFFECT` | 0 | 0 |
| `ATTEMPTING_1` | `BEFORE_PUT_INLINE_POLICY` | 0 | 0 |
| `COMPLETED_1` | `AFTER_PUT_INLINE_POLICY` | 1 | 1 |
| `ATTEMPTING_2` | `BEFORE_PROVISION_PERMISSION_SET` | 1 | 1 |
| `COMPLETED_2` | `AFTER_PROVISION_PERMISSION_SET` | 2 | 2 |
| `REPAIR_VERIFIED` | `FINAL_READBACK_VERIFIED` | 2 | 2 |

SDK retries are disabled. The provider re-observes exact state immediately
before dispatch, performs one call, and requires exact readback before
advancing. Provisioning polling is bounded by the immutable window and reserves
time for final readback.

Any ambiguity after dispatch becomes one of the terminal uncertain states only
when its CAS and readback are proven, and then requires read-only
reconciliation. If that seal is unproven, no public receipt is emitted and the
attempting state blocks replay. No uncertain record can re-enter repair.
Only the explicit state-machine edges are valid; a status skip, cross-effect
uncertainty stage, repeated claim timestamp or regressive update timestamp is
rejected before a replacement ledger is sealed.

Successful final reconciliation adds a closed, sealed attestation containing
the base repair ID, source commit, intent digest, terminal repair-ledger digest,
observed-state digest, invocation-authority graph digest, published reconcile
version/alias and timestamp. The write uses
`attribute_not_exists(repair_id)` and cannot be replayed. A write exception is
accepted only when a strongly consistent read returns the byte-equivalent
expected record. The broker closeout gate must require this attestation
in addition to the original `REPAIR_VERIFIED` 2/2 ledger; a public receipt or
equivalent provider state alone is insufficient.

## Public receipt boundary

The public receipt exposes only:

- source and contract digests;
- scalar effect counters;
- mutation-attribution classification;
- required next action;
- `retry_permitted=false`; and
- `production_status=NO-GO`.

It cannot contain raw account IDs, ARNs, principals, role/session names,
permission-set names, Change Set names, policy documents, request IDs, private
paths or provider payloads. Private intent, ledger and provider evidence remain
outside Git in owner-only custody. The semantic validator and JSON Schema share
the same exact closed field set, so a resealed record with an extra field is
still rejected.

## Deployment prerequisites

Before any stack is created, all of these facts must be reviewed and fresh:

1. exact merged source commit and successful required CI;
2. exact, separately authorized artifact-bootstrap bridge input, principal,
   source-attested template and absolute access window;
3. terminal foundation creation and readback for the exact retained KMS, S3,
   Signer and Lambda code-signing resources;
4. bridge update pinned to the exact generated Signer profile version;
5. deterministic signed Lambda artifacts and exact S3 versions/checksums;
6. exact Identity Center instance/store and Plan permission-set ARN;
7. immutable `USER` ID and existing assignment;
8. current predecessor and target policy digests;
9. generated Plan role and SAML provider;
10. KMS mode/key/context and code-signing configuration;
11. exact Change Set names, broker aliases, creator and executor identities;
12. collision-free names for the bridge, foundation, route, broker and target
    stacks and every retained resource;
13. a deterministic broker ZIP built from the exact clean merged commit, then
    staged, signed and read back by immutable S3 version and Signer evidence;
14. the parameterless broker template rendered only after that broker artifact
    and the PEP artifact/template coordinates are closed; and
15. exact zero-assignment bridge revocation, `PT1H` credential expiry and the
    post-revocation artifact bootstrap route release;
16. the ADR-058 temporary route materialized from this exact commit and a
    separately authorized administrative seed scoped to the exact route,
    delegation, broker-template and broker-code versions, both accounts and
    `us-east-1`.

Items 1–16 are descriptive prerequisites, not evidence that the connected
route is currently available. The implemented route-specific admission binds
the exact source commit, source tree, bootstrap intent, accounts, Region,
window and complete retained-name catalog. It rejects missing, stale, partial,
`UNCERTAIN` or `COLLISION` evidence, and its digest is part of every expansive
mutation claim and receipt. This implementation still requires review, merge,
signed-package readback and a separately authorized connected run before it can
support any live effect. `CreateChangeSet` does not reserve physical resource
names, and a negative S3 `HeadBucket` response is not collision evidence. The
artifact bucket instead uses the AWS account-regional namespace: the template
pins `BucketNamespace: account-regional`, the exact authority-account and
Region suffix, and an IAM deny outside that namespace. Because AWS reserves
that namespace to the owning account, a completely paginated `ListBuckets`
result from that account, bound to the exact Region and prefix, is the accepted
absence proof. See
[Namespaces for general purpose buckets](https://docs.aws.amazon.com/AmazonS3/latest/userguide/gpbucketnamespaces.html).

The authority PEP template is larger than CloudFormation's 51,200-byte direct
`TemplateBody` limit. More importantly, the route deliberately requires exact
versioned `TemplateURL` values for the route, delegation and parameterless
broker templates so a Creator cannot substitute different bytes. The broker
configuration separately binds the exact versioned PEP template and signed PEP
artifact. Every reviewed object must be staged in an approved versioned bucket
with exact version and digest readback. Each upload or signing job is a
separate authorized mutation. A CLI convenience command may not choose a
different bucket, overwrite a key or obscure the final version/checksum.

None of the pre-existing narrow profiles can bootstrap this path by itself.
The reviewed ADR-058 route resolves that dependency without making broad
administrator access the broker or repair executor. One explicit
`839393571433_AWSAdministratorAccess` session may create and execute only the
exact temporary route-stack Change Set. That session must end before either
broker-seed session begins. The broker then assumes only the exact temporary
management roles sealed for its aliases; delegation and PEP Change Sets must
contain no alternate `RoleARN`.

## Validation boundary

Repository validation must include:

```bash
make platform-authority-bootstrap-plan-repair-check
make platform-authority-bootstrap-check
make docs-check
```

After merge, use only the artifact-bootstrap CLI to create the bridge and
foundation, publish immutable objects, pin the Signer version, update the
foundation access policy and seal the publish binding. Its global options
precede the action, and every action consumes and writes owner-only private
files:

```bash
python3 scripts/deployment/platform-authority-plan-permission-repair-artifact-bootstrap.py \
  --private-root "$PRIVATE_ARTIFACT_ROOT" \
  --source-root "$SOURCE_ROOT" \
  materialize-intent \
  --bundle-name "$BUNDLE_NAME" \
  --output-name "$OUTPUT_NAME"
```

The closed foundation flow is:

1. for `bridge-create` and `foundation-create`, separately
   `authorize-change-set`, `dispatch-change-set`, `attest-change-set`,
   `authorize-change-set`, `execute-change-set`, and `readback-stack`;
2. `readback-foundation`, followed by `materialize-bridge-pin`, two fresh
   `authorize-mutation` records, `dispatch-bridge-pin`, `execute-bridge-pin`,
   and `readback-stack`;
3. for every template or package, `materialize-object-intent`, fresh
   `authorize-mutation`, `publish-object`, and `readback-object`; for signing,
   `materialize-signing-intent`, fresh `authorize-mutation`,
   `start-signing-job`, and `readback-signing-job`;
4. `materialize-access-update`, separately authorized
   `dispatch-access-update` and `execute-access-update`, then
   `readback-access-update`; and
5. `materialize-publish-binding` before bridge revocation.

Every connected artifact action additionally requires the exact allowed
`--profile` and `--claim-root`. Bridge operations use only
`839393571433_AWSAdministratorAccess`; authority-account foundation, object and
signing operations use only
`042360977644_ScanalyzeGug376ArtifactBootstrap`. An authorization file is valid
for one exact target and at most fifteen minutes. Documentation is never
action-time authorization. Change Set authorization text is exactly
`AUTHORIZE GUG-376 <operation>:<dispatch-or-execute> <SOURCE_COMMIT>`; mutation
authorization text is exactly
`AUTHORIZE GUG-376 <operation> <TARGET_DIGEST>`. `recover-change-set`,
`recover-bridge-pin`, and `recover-access-update` recover an ambiguous
**CreateChangeSet** dispatch. The separate `recover-change-set-execution`,
`recover-bridge-pin-execution`, and `recover-access-update-execution` actions
recover an ambiguous **ExecuteChangeSet** and continue only through terminal
readback. Object and Signer recovery use `recover-object` and
`recover-signing-job`. No recovery accepts a fresh authorization: it validates
the exact sealed original authorization persisted in the write-once claim,
performs no second mutation, and fails on absent or ambiguous causal evidence.

Every expansive connected artifact action also requires
`--collision-admission-root`, `--gug393-private-root` and
`--gug395-private-root`. Materialize a new four-root context only after the
exact action authorization exists, using `$PRIVATE_ARTIFACT_ROOT` as its effect
root and the authorization's digest/window plus the exact operation. Reuse the
immutable initial GUG-395/GUG-393 lineage roots; never reuse an admission root.
The protected CLI performs a new bounded 73-target live read-only scan and
requires the operation-specific current state before the effect. The accepted
operations are `bridge-create:dispatch|execute`,
`foundation-create:dispatch|execute`, `bridge-pin:dispatch|execute`,
`publish-object`, `start-signing-job`, and
`foundation-access-update:dispatch|execute`.

The reducing `bridge-revoke` and `bridge-cleanup-retire` actions, all readback
and attestation actions, and all ambiguity-recovery actions reject collision
roots. Their authority comes only from the original sealed causal record; they
cannot use a new context to widen or replay a mutation.
Before any artifact-bootstrap `ExecuteChangeSet`, the provider reopens the
original owner-only dispatch claim, validates its sealed action-time
authorization at `claimed_at`, matches the exact caller, request, request ID,
stack ARN and change-set ARN to the unique CloudTrail `CreateChangeSet` event,
and then repeats STS, `DescribeChangeSet` and `GetTemplate`. The supplied
attestation must match that fresh readback's complete template, parameter and
semantic-change projection. These verification calls are included in the
execution receipt's `aws_calls`; a forged or stale receipt reaches no execute
call.

`AccessNotAfter` is the absolute mutation deadline for CloudFormation, S3
publication, KMS data-key generation, and Signer start. The bridge derives and
seals `RecoveryNotAfter` as exactly 24 hours later. Only the bounded STS,
CloudTrail, CloudFormation and exact-resource reads needed for causal recovery
remain eligible in that interval; an explicit deny closes every action at the
recovery horizon. This interval does not renew an SSO session and never extends
write authority.

Template readback is also foundation-only on the product CLI. It accepts no
GUG-363/GUG-365 storage-plan flags and derives every coordinate from the exact
bootstrap intent and foundation publish binding:

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

The PEP and broker signed-artifact verifiers use that same direct artifact
bootstrap profile before bridge revocation. Their product CLIs have no
`AWSReadOnlyAccess` fallback: the verifier permission set contains the bounded
S3/Signer profile reads plus `acm:GetCertificate` and
`signer:GetRevocationStatus` needed to prove the exact job, certificate and
profile version while the access window is still open.

The separate `042360977644_AWSReadOnlyAccess` profile below is authorized only
for the connected read-only Plan seed snapshot inventory. It is not a fallback
for PEP signed-artifact, broker signed-artifact or template readback product
paths; their verifier remains the direct ArtifactBootstrap profile.

After the publish binding, build and sign the broker package, create its closed
configuration, and render the parameterless broker template:

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
  --management-profile 839393571433_ReadOnlyAccess \
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

The connected Plan seed snapshot is a required producer, not an optional
diagnostic. Run it only after the exact bootstrap Change Set has materialized
the Plan permission set and generated role, and before
`materialize-broker-config`. Both named SSO sessions are direct read-only SSO
sessions for this step: `042360977644_AWSReadOnlyAccess` observes the generated
IAM role and `839393571433_ReadOnlyAccess` observes Identity Center. Each must
resolve directly to `AWSReadOnlyAccess` in its named account and `us-east-1`.
Default, ambient, chained, administrator, bootstrap, seed, deploy and destroy
profiles fail closed before STS. Supply the write-once, owner-only output
independently through `--plan-snapshot-name`; the sealed
`$BROKER_CONFIG_INPUT_NAME` draft must omit `plan_snapshot`. The product CLI
rejects an embedded second authority, joins the exact separately read receipt,
verifies the same source commit and bootstrap Change Set name, and reseals the
complete broker input. Materialization must occur within the snapshot's
15-minute freshness window.
The command performs no AWS mutation and makes no deployment or production
claim.

Publish and read back that rendered broker template. The PEP signed-artifact
receipt, broker signed-artifact handoff, template readbacks and broker
materialization receipt must all reconstruct from the same foundation publish
binding. Then revoke the bridge through a fresh, separately authorized
`bridge-revoke` dispatch/attest/execute/readback sequence. Require zero
assignments and wait for both the absolute bridge window and one hour after
terminal revocation. Only then run `materialize-route-release`; the resulting
offline release is the sole artifact input accepted by the route seed.
The connected broker receipt is admitted against an explicit current time with
a 15-minute freshness limit before revocation. Post-revocation reconstruction
does not reapply that limit against wall-clock time: it requires the sealed
observation to remain inside the bootstrap access window and the signature to
remain valid through the sealed route horizon.

Materialize exactly the two initial seeds:

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

For target `route`, the connected provider profile is exactly
`839393571433_AWSAdministratorAccess`. For target `broker`, creation uses
`042360977644_ScanalyzeGug376BrokerSeedCreator` and execution/readback use
`042360977644_ScanalyzeGug376BrokerSeedExec`. The exact connected lifecycle is
the offline `authorize-creation`, `create-change-set`, `attest-change-set`, the offline
`authorize-execution` and `materialize-execution-intent`, then
`execute-change-set` and `terminal-readback`:

The execution provider reconstructs the complete seed from the exact private
input and clean merged Git source, then reopens the write-once create result.
It requires the attestation's UUID-bearing stack ARN, change-set ARN and create
request ID to match that persisted result before STS or any provider call.
After STS and immediately before the sole execute attempt, it repeats the
authoritative unique `CreateChangeSet` CloudTrail lookup, `DescribeChangeSet`,
`GetTemplate` and exact resource-change projection and compares every immutable
field with the supplied attestation. It also re-samples the authorization clock
after STS and again immediately before the write-once claim and provider call.
A route parameter is always a non-secret identifier, ARN, immutable S3 object
coordinate or bounded timestamp/flag. The route template therefore uses no
`NoEcho` parameters, and connected `DescribeChangeSet`/`DescribeStacks`
readback must return every exact value; a mask is never accepted as evidence.
A delegation or PEP Change Set is held to the same boundary: repair principal
ID/user ARN, expected permission-set description/tags and artifact version are
non-secret causal inputs, are not `NoEcho`, and must appear exactly once with
their sealed values. Missing, duplicate, masked or substituted entries block
both normal execution and recovery.
For every UPDATE, the creator resolves each `UsePreviousValue` entry from one
stable `DescribeStacks` snapshot whose update timestamp is no later than the
Change Set creation timestamp. It stores only the resulting canonical
effective-parameter digest in the private ledger. The executor must carry that
same digest before its write-once claim, and execution recovery must reproduce
it. AWS may return every previous entry either as `UsePreviousValue=true` or as
its normalized `ParameterValue`; only a complete single form is accepted, and
the normalized map must reproduce the sealed effective digest. Terminal
readback requires `Stack.ChangeSetId` to be the executed full ARN,
requires every unmasked String parameter to reproduce the digest, rejects
non-null `ResolvedValue`, and repeats `DescribeStacks` after all other evidence
reads. Any fingerprint change between those two terminal reads is uncertainty,
not success. It also requires exactly one terminal root `DescribeStackEvents`
record with the execute request's `ClientRequestToken`, exact stack identity and
status, and a timestamp no earlier than the authenticated `ExecuteChangeSet`.
That event supplies CREATE causality even though a CREATE stack's
`CreationTime` precedes execution.
Every continuation rechecks the common Lambda remaining-time budget before
each AWS read and every pagination page. Below 15 seconds it emits the typed
read-only `TIME_BUDGET_PENDING` outcome before another provider call, CAS or
effect, so a partially completed evidence chain is retried only as readback.
A coherently re-sealed attestation for another same-name change set, a stale
readback or an authorization that expires during validation is therefore not
executable.

### Materialize one atomic collision context per expansive local effect

`create-change-set` and `execute-change-set` accept no operator-supplied
collision digest. Each command reconstructs and consumes one atomic admission
from four distinct, absolute, non-symlink, owner-only mode-`0700` roots:

- `$GUG395_PRIVATE_ROOT` preserves the immutable initial GUG-395
  `ABSENT_READY_FOR_PROVIDER_IMPLEMENTATION` lineage, source and two exact
  read-only SSO identities. It is created once before the foundation exists;
- `$GUG393_PRIVATE_ROOT` preserves the corresponding validated GUG-393 private
  materialization and is reusable only with that exact GUG-395 lineage;
- `$PRIVATE_ROUTE_ROOT` is the effect root containing the exact route input,
  intent, action authorization and write-once effect claim; and
- a new, empty collision-admission root is consumed once by exactly one effect.

Never regenerate GUG-395 after the named resources have been created and never
treat its historical absence result as current state. The protected command
uses that result only as immutable lineage, then performs a fresh, bounded
73-target live read-only scan immediately before the effect. That per-effect
scan is authoritative and admits only the exact operation-specific mixture of
`PRESENT_OWNED` and `ABSENT`; a collision, uncertain read, lineage change,
expired action authorization, or reused admission root stops before mutation.

First create the exact 60-900 second action authorization. Then obtain
`$BOOTSTRAP_INTENT_DIGEST` from the exact
`artifact_bootstrap_intent.intent_digest` in `$ROUTE_SEED_INPUT_NAME`, and read
the authorization digest and window from the just-validated private
authorization record. Materialize and reopen the context without AWS calls.
The following create example uses the operation derived from the target; use a
new `$EXECUTE_COLLISION_ADMISSION_ROOT` and
`$SEED_TARGET:execute-change-set` for execution:

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

test -d "$PRIVATE_ROUTE_ROOT"
test -d "$GUG393_PRIVATE_ROOT"
test -d "$GUG395_PRIVATE_ROOT"
test -d "$CREATE_COLLISION_ADMISSION_ROOT"
test "$(stat -f '%Lp' "$PRIVATE_ROUTE_ROOT")" = 700
test "$(stat -f '%Lp' "$GUG393_PRIVATE_ROOT")" = 700
test "$(stat -f '%Lp' "$GUG395_PRIVATE_ROOT")" = 700
test "$(stat -f '%Lp' "$CREATE_COLLISION_ADMISSION_ROOT")" = 700
test "$(find "$CREATE_COLLISION_ADMISSION_ROOT" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')" = 0

CREATE_AUTHORIZATION_FILE="$PRIVATE_ROUTE_ROOT/$CREATION_AUTHORIZATION_NAME"
CREATE_APPROVAL_DIGEST="$(jq -er '.authorization_digest' "$CREATE_AUTHORIZATION_FILE")"
CREATE_AUTHORIZED_AT="$(jq -er '.authorized_at' "$CREATE_AUTHORIZATION_FILE")"
CREATE_EXPIRES_AT="$(jq -er '.expires_at' "$CREATE_AUTHORIZATION_FILE")"
CREATE_COLLISION_OPERATION="$SEED_TARGET:create-change-set"

env -i HOME="$HOME" PATH="$PATH" TMPDIR="${TMPDIR:-/tmp}" \
  python3 scripts/deployment/platform-authority-gug376-collision-admission.py \
  materialize-context \
  --admission-private-root "$CREATE_COLLISION_ADMISSION_ROOT" \
  --effect-private-root "$PRIVATE_ROUTE_ROOT" \
  --gug393-private-root "$GUG393_PRIVATE_ROOT" \
  --gug395-private-root "$GUG395_PRIVATE_ROOT" \
  --bootstrap-intent-digest "$BOOTSTRAP_INTENT_DIGEST" \
  --approval-reference-digest "$CREATE_APPROVAL_DIGEST" \
  --approved-operation "$CREATE_COLLISION_OPERATION" \
  --authorized-at "$CREATE_AUTHORIZED_AT" \
  --expires-at "$CREATE_EXPIRES_AT"

env -i HOME="$HOME" PATH="$PATH" TMPDIR="${TMPDIR:-/tmp}" \
  python3 scripts/deployment/platform-authority-gug376-collision-admission.py \
  validate-context \
  --admission-private-root "$CREATE_COLLISION_ADMISSION_ROOT" \
  --effect-private-root "$PRIVATE_ROUTE_ROOT" \
  --gug393-private-root "$GUG393_PRIVATE_ROOT" \
  --gug395-private-root "$GUG395_PRIVATE_ROOT"
```

The local CLIs use exactly two direct read-only SSO sources to construct ten
fresh SDK sessions (`LOCAL_DIRECT_SSO`); they do not assume the later broker
reader roles. Inline broker effects run only after deployment and use ten
900-second reader-role sessions (`POST_READER_RUNTIME`). This separation
matches the deployed trust graph and does not expand it. Both paths reserve
provider calls before invocation, account pages and bounded response bytes,
seal the transcript and budget event journals, and revalidate the one-shot
grant immediately before the protected effect. Complete the protected command
inside the authorization window; context validation does not extend it.

```bash
python3 scripts/deployment/platform-authority-plan-permission-repair-deployment-route-aws.py \
  create-change-set \
  --profile "$SEED_CREATOR_PROFILE" \
  --target "$SEED_TARGET" \
  --source-root "$SOURCE_ROOT" \
  --private-root "$PRIVATE_ROUTE_ROOT" \
  --receipt-name "$CREATE_DISPATCH_NAME" \
  --intent-name "$ROUTE_SEED_INTENT_NAME" \
  --input-name "$ROUTE_SEED_INPUT_NAME" \
  --authorization-name "$CREATION_AUTHORIZATION_NAME" \
  --collision-admission-root "$CREATE_COLLISION_ADMISSION_ROOT" \
  --gug393-private-root "$GUG393_PRIVATE_ROOT" \
  --gug395-private-root "$GUG395_PRIVATE_ROOT"

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

EXECUTE_APPROVAL_DIGEST="$(jq -er '.authorization_digest' \
  "$PRIVATE_ROUTE_ROOT/$EXECUTION_AUTHORIZATION_NAME")"
EXECUTE_AUTHORIZED_AT="$(jq -er '.authorized_at' \
  "$PRIVATE_ROUTE_ROOT/$EXECUTION_AUTHORIZATION_NAME")"
EXECUTE_EXPIRES_AT="$(jq -er '.expires_at' \
  "$PRIVATE_ROUTE_ROOT/$EXECUTION_AUTHORIZATION_NAME")"

env -i HOME="$HOME" PATH="$PATH" TMPDIR="${TMPDIR:-/tmp}" \
  python3 scripts/deployment/platform-authority-gug376-collision-admission.py \
  materialize-context \
  --admission-private-root "$EXECUTE_COLLISION_ADMISSION_ROOT" \
  --effect-private-root "$PRIVATE_ROUTE_ROOT" \
  --gug393-private-root "$GUG393_PRIVATE_ROOT" \
  --gug395-private-root "$GUG395_PRIVATE_ROOT" \
  --bootstrap-intent-digest "$BOOTSTRAP_INTENT_DIGEST" \
  --approval-reference-digest "$EXECUTE_APPROVAL_DIGEST" \
  --approved-operation "$SEED_TARGET:execute-change-set" \
  --authorized-at "$EXECUTE_AUTHORIZED_AT" \
  --expires-at "$EXECUTE_EXPIRES_AT"

python3 scripts/deployment/platform-authority-plan-permission-repair-deployment-route-aws.py \
  execute-change-set \
  --profile "$SEED_EXECUTOR_PROFILE" \
  --target "$SEED_TARGET" \
  --source-root "$SOURCE_ROOT" \
  --private-root "$PRIVATE_ROUTE_ROOT" \
  --receipt-name "$EXECUTION_RECEIPT_NAME" \
  --execution-intent-name "$EXECUTION_INTENT_NAME" \
  --intent-name "$ROUTE_SEED_INTENT_NAME" \
  --input-name "$ROUTE_SEED_INPUT_NAME" \
  --create-attestation-name "$CREATE_ATTESTATION_NAME" \
  --authorization-name "$EXECUTION_AUTHORIZATION_NAME" \
  --collision-admission-root "$EXECUTE_COLLISION_ADMISSION_ROOT" \
  --gug393-private-root "$GUG393_PRIVATE_ROOT" \
  --gug395-private-root "$GUG395_PRIVATE_ROOT"

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

The creation phrases are exactly
`I_AUTHORIZE_GUG376_ROUTE_SEED_CREATION` and
`I_AUTHORIZE_GUG376_BROKER_SEED_CREATION`; the execution phrases are exactly
`I_AUTHORIZE_GUG376_ROUTE_SEED_EXECUTION` and
`I_AUTHORIZE_GUG376_BROKER_SEED_EXECUTION`. Each authorization expires in
60–900 seconds. `recover-create-change-set` is read-only: it accepts no fresh
creation authorization, validates the original sealed authorization from the
causal claim at the original claim timestamp, and remains bound to the original
claim key, client token and dispatch receipt for at most 24 hours after the
route window closes.
`RecoveryNotAfter` is not operator input: the materializer derives it as
exactly `RouteNotAfter + 24h`, seals it into the route intent and broker config,
and passes it as the exact route parameter. Create/Execute, template-provider
reads required by those writes, SSO/IAM provisioning and ledger initialization
remain bounded by `RouteNotAfter`. Only causal CloudTrail/CloudFormation and
provider readback, the exact management readback session, invoker access and
the broker-ledger `GetItem`/completion CAS remain eligible before (never at)
`RecoveryNotAfter`. The broker reads and validates the ledger before any
cross-account session; post-window invocation proceeds only for the matching
`*_DISPATCHED` alias and can emit only a zero-mutation completion or seal a
terminal contradiction as `*_UNCERTAIN`. A provider `*_IN_PROGRESS` status is
retryable read-only and leaves the dispatched state unchanged; a rollback or
other terminal status outside the sealed expectation is not retryable.
The initial route has eight resources and three assignments. After broker
terminal readback, delegation, PEP and every revocation are broker state-machine
operations, never route CLI commands. The qualified aliases accept only `{}`.
They advance through seed revoke, delegation create/execute and PEP
create/execute; the separately qualified Plan, repair and reconcile aliases
plus a fresh normal-Plan GUG-214 proof must then converge before the broker
closeout gate, delegation revoke and route revoke. Seed revoke
removes the two seed assignments; final route revoke removes only the retained
broker-invoker assignment.

### Finite failed-deployment recovery

The normal read-only `recover-create-change-set` and
`recover-execute-change-set` commands resolve ambiguity in an original provider
call; they never issue a replacement mutation. A separate
`platform-authority-plan-permission-repair-deployment-recovery.py` CLI exposes
finite, separately authorized recovery paths for the `route`, `broker` and
broker-protection targets:

1. an exact pre-execute `FAILED`/`UNAVAILABLE` Change Set with its stack still
   in `REVIEW_IN_PROGRESS` and zero resources follows
   `attest-preexecute-failure` → `authorize-reentry` →
   `materialize-reentry` → `create-reentry` → `attest-reentry` →
   `authorize-reentry-execution` → `materialize-reentry-execution` →
   `execute-reentry`; and
2. an executed CREATE proven in `ROLLBACK_COMPLETE` or `DELETE_FAILED` follows
   `attest-failed-create` → `authorize-cleanup` → `materialize-cleanup` →
   `delete-failed-stack` → `attest-cleanup`; that lane-specific terminal
   cleanup can be the basis of one re-entry CREATE; and
3. a broker-protection UPDATE proven in `UPDATE_ROLLBACK_COMPLETE` follows the
   same re-entry chain from its protection-rollback attestation.

Every step consumes the same private seed input and seed intent. The first
lane additionally carries, without substitution, the primary dispatch,
pre-execute failure attestation, re-entry creation authorization, re-entry
intent, re-entry dispatch, re-entry attestation, execution authorization and
execution intent. `reentry_dispatch` is required by both execution
authorization/materialization and `execute-reentry`; the attestation is not a
replacement for it. Before STS, the re-entry executor reopens the durable
`reentry-create:<target>:<seed-intent-digest>` result and requires byte-exact
agreement with the supplied dispatch and attestation on the full stack ARN,
Change Set ARN and CreateChangeSet request ID.

Only after the complete local source, seed, causal-file, authorization and
durable-journal validation succeeds may `execute-reentry` call STS. After STS,
it repeats the unique authoritative `CreateChangeSet` CloudTrail lookup,
`DescribeChangeSet`, `GetTemplate` and the exact resource-change projection.
The live CloudTrail-event, describe, template and change-projection digests,
plus status and execution status, must equal their fields in the re-entry
attestation before the write-once execution claim or `ExecuteChangeSet` is
reachable.

The failed-CREATE lane carries the exact primary or re-entry execution intent
and receipt into its failure attestation, then binds that attestation into the
cleanup authorization, intent, dispatch and terminal attestation. Its
DeleteStack request contains only the attested full stack ARN and deterministic
client token; it cannot set `RoleARN`, `RetainResources` or force deletion.
Before STS, `delete-failed-stack` must reopen and validate the causal durable
ExecuteChangeSet claim and result, including their exact request, token,
receipt, digests and timing. After STS it requires exactly one matching
`ExecuteChangeSet` CloudTrail event whose digest equals the failed-CREATE
attestation and whose `responseElements` is canonically null, then re-reads the
exact stack ARN, fixed stack name, attested `ROLLBACK_COMPLETE` or
`DELETE_FAILED` status and complete resource projection. Any stack or resource
drift stops before DeleteStack.

The lane-specific cleanup claim and durable DeleteStack dispatch each seal the
failed-stack attestation digest and the complete failed-resource digest.
`attest-cleanup` carries that same resource projection into its terminal
record, and later re-entry requires all three bindings to agree before STS.
Re-sealing a terminal while omitting a physical KMS key, code-signing
configuration or any other failed resource is therefore rejected locally. Its
`attested_at` value is sampled after all live terminal/survivor reads, not from
the pre-STS clock; a regressed clock or expired recovery horizon fails closed.

| Target | Re-entry creator | Re-entry executor / failed-CREATE attestor | Failed-stack cleanup |
|---|---|---|---|
| `route` | `839393571433_AWSAdministratorAccess` | `839393571433_AWSAdministratorAccess` | `839393571433_ScanalyzeGug376RouteSeedCleanup` |
| `broker` | `042360977644_ScanalyzeGug376BrokerSeedCreator` | `042360977644_ScanalyzeGug376BrokerSeedExec` | `042360977644_ScanalyzeGug376BrokerSeedCleanup` |

The mutation lanes use distinct write-once keys per seed and target:
`reentry-create:<target>:<seed-intent-digest>`,
`reentry-execute:<target>:<seed-intent-digest>` and
`cleanup:<target>:<seed-intent-digest>:<primary|reentry>`. Each is attempt one
and sets `retry_permitted=false`; a new failure attestation, authorization or
output name cannot reopen it. The lane suffix permits one primary cleanup and,
only after a separately authorized re-entry execution fails, one re-entry
cleanup without allowing either DeleteStack effect to repeat. Re-entry create
and execute authorizations are fresh,
target-specific, 60–900 seconds long and must expire by
`RouteNotAfter - 1,800 seconds`. Failed-stack cleanup has its own fresh
60–900-second authorization and is admitted only in the half-open
`RouteNotBefore <= now < RecoveryNotAfter` interval. An uncertain provider or
durability result from `create-reentry`, `execute-reentry` or
`delete-failed-stack` is a stop, never retry authority. The later
`CleanupNotAfter` boundary belongs only to retirement of the bridge-owned
cleanup identities; it does not extend failed-stack deletion.

For every recovery mutation, local validation and an active grant check happen
before STS. Re-entry additionally reopens the immutable journal for its exact
failure basis before STS: primary CreateChangeSet claim/result for a
pre-execute failure; lane-specific DeleteStack claim/result for a cleanup
terminal; or broker-protection ExecuteChangeSet claim/result for a protection
rollback. After STS, the runtime repeats the corresponding unique CloudTrail
event, CloudFormation state and exact-resource proof. The event itself must
match the exact target/phase role pattern as well as the journal caller digest.
The runtime re-samples the clock and rechecks the same 60–900-second grant
immediately after STS, rejects clock regression, then re-samples again after
all live evidence reads and immediately before the write-once claim and sole
provider effect. Expiry at any sample fails closed.

Each expansive `create-reentry` and `execute-reentry` effect also consumes a
new four-root atomic collision context. Its approval digest/window must equal
the exact re-entry authorization, its source must equal the reconstructed seed
source, and its operation must equal the target plus the validated recovery
basis. Pass the new admission root together with the immutable
`--gug393-private-root` and `--gug395-private-root`. The provider repeats the
current 73-target read-only scan before the sole effect. Failed-stack cleanup
is strictly reducing and rejects all collision roots.

The artifact bridge deliberately keeps two cleanup assignments and the
read-only management recovery role after `bridge-revoke`; that revoke removes
only the ArtifactBootstrap assignment. The bootstrap intent derives and seals
`CleanupNotAfter = RecoveryNotAfter + 24h = AccessNotAfter + 48h`, and the route
seed must prove its own `RecoveryNotAfter` does not exceed that outer guard.
Retire this bridge-owned access through exactly one
`bridge-cleanup-retire` UPDATE. In `SUCCESS` mode, first require the exact
terminal route, broker-create and broker-protection readbacks from the same
seed and artifact release (`CREATE_COMPLETE`, `CREATE_COMPLETE`, and
`UPDATE_COMPLETE`). The private cleanup bundle also carries the original
seed input plus each target's execution intent and execution receipt. The
product CLI reconstructs the seed against clean exact `main` and re-runs all
three terminal readbacks just in time with only
`839393571433_AWSAdministratorAccess` and
`042360977644_ScanalyzeGug376BrokerSeedExec`; a supplied terminal JSON or a
self-resealed seed is not authority. In `EXPIRED` mode, all route evidence and
secondary profiles are forbidden and the action is admitted only at or after
the exact `CleanupNotAfter` boundary, when the cleanup permissions are already
inert.

For either mode, use `materialize-cleanup-retire`, a fresh
`authorize-cleanup-retire` for `dispatch`, `dispatch-cleanup-retire`,
`attest-cleanup-retire`, a distinct fresh authorization for `execute`,
`execute-cleanup-retire`, and `readback-cleanup-retire`. The authorization text
is exactly
`AUTHORIZE GUG-376 bridge-cleanup-retire:<dispatch-or-execute> <INTENT_DIGEST>`.
Ambiguous dispatch or execution is handled only by
`recover-cleanup-retire` or `recover-cleanup-retire-execution`, which reopen the
original O_EXCL claim and authorization and never issue a second mutation.
The terminal readback must prove both cleanup permission sets, both assignments
and `ScanalyzeGug376RouteBrokerRecovery` are absent. Only the unassigned
ArtifactBootstrap permission set remains. There is no operation that changes
`CleanupAssignmentsEnabled` back to `true`.

After broker terminal readback, invoke the qualified aliases with the three
exact direct SSO profiles and keep every AWS CLI metadata/payload file private:

```bash
set -euo pipefail
umask 077
test "$(stat -f '%Lp' "$PRIVATE_ROUTE_ROOT")" = 700

BROKER_PROFILE=042360977644_ScanalyzeGug376BrokerInvoker
BROKER_RECOVERY_PROFILE=042360977644_ScanalyzeGug376BrokerSeedCleanup
REPAIR_PROFILE=042360977644_ScanalyzeBootstrapPlanRepair
CREATOR_FUNCTION=scanalyze-platform-authority-gug376-route-creator
EXECUTOR_FUNCTION=scanalyze-platform-authority-gug376-route-executor
CREATE_RECOVERY_FUNCTION=scanalyze-platform-authority-gug376-route-create-dispatch-recovery
EXECUTE_RECOVERY_FUNCTION=scanalyze-platform-authority-gug376-route-execute-dispatch-recovery
RECOVERY_ALIAS=recover-v1
CREATE_RECOVERY_RECEIPT_ALIAS=create-dispatch-recovery-v1
EXECUTE_RECOVERY_RECEIPT_ALIAS=execute-dispatch-recovery-v1
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

aws sso login --profile "$BROKER_RECOVERY_PROFILE"
BROKER_RECOVERY_IDENTITY_FILE="$(mktemp "$PRIVATE_ROUTE_ROOT/broker-recovery-identity.XXXXXX")"
chmod 600 "$BROKER_RECOVERY_IDENTITY_FILE"
AWS_RETRY_MODE=standard AWS_MAX_ATTEMPTS=1 aws sts get-caller-identity \
  --profile "$BROKER_RECOVERY_PROFILE" --region us-east-1 --no-cli-pager \
  --cli-connect-timeout 5 --cli-read-timeout 30 --output json \
  >"$BROKER_RECOVERY_IDENTITY_FILE"
jq -e '.Account == "042360977644" and
  (.Arn | test("^arn:aws:sts::042360977644:assumed-role/AWSReservedSSO_ScanalyzeGug376BrokerSeedCleanup_[0-9A-Fa-f]{16}/[A-Za-z0-9+=,.@_-]{1,64}$"))' \
  "$BROKER_RECOVERY_IDENTITY_FILE" >/dev/null

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
    --function-name "$function_name" --qualifier "$alias_name" \
    --payload '{}' --cli-binary-format raw-in-base64-out \
    --profile "$BROKER_PROFILE" --region us-east-1 \
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
  recovery_function_name="$1" recovery_qualifier="$2" expected_receipt_alias="$3"
  dispatched_alias_name="$4" dispatched_state="$5" expected_state="$6"
  deadline_mode="$7"
  case "$deadline_mode" in
    route) absolute_deadline_epoch="$BROKER_ROUTE_DEADLINE_EPOCH" ;;
    recovery) absolute_deadline_epoch="$BROKER_RECOVERY_DEADLINE_EPOCH" ;;
    *) return 1 ;;
  esac
  jq -e --arg alias "$dispatched_alias_name" --arg state "$dispatched_state" '
    .alias == $alias and .state == $state and .aws_mutations == 1 and
    .retry_permitted == false
  ' "$LAST_BROKER_PAYLOAD_FILE" >/dev/null
  attempt=1
  local_deadline_epoch="$(($(date -u +%s) + BROKER_COMPLETION_BUDGET_SECONDS))"
  while [ "$attempt" -le "$BROKER_COMPLETION_MAX_ATTEMPTS" ]; do
    now_epoch="$(date -u +%s)"
    test "$now_epoch" -lt "$((absolute_deadline_epoch - 60))"
    test "$now_epoch" -lt "$local_deadline_epoch"
    payload_file="$(mktemp "$PRIVATE_ROUTE_ROOT/${dispatched_alias_name}.completion.payload.XXXXXX")"
    metadata_file="$(mktemp "$PRIVATE_ROUTE_ROOT/${dispatched_alias_name}.completion.metadata.XXXXXX")"
    chmod 600 "$payload_file" "$metadata_file"
    AWS_RETRY_MODE=standard AWS_MAX_ATTEMPTS=1 aws lambda invoke \
      --function-name "$recovery_function_name" --qualifier "$recovery_qualifier" \
      --payload '{}' --cli-binary-format raw-in-base64-out \
      --profile "$BROKER_RECOVERY_PROFILE" --region us-east-1 \
      --no-cli-pager --cli-connect-timeout 5 --cli-read-timeout 900 \
      "$payload_file" >"$metadata_file"
    if jq -e '.StatusCode == 200 and (has("FunctionError") | not) and
      (.ExecutedVersion | type == "string")' "$metadata_file" >/dev/null; then
      jq -e --arg alias "$expected_receipt_alias" --arg state "$expected_state" '
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
complete_broker_bounded "$CREATE_RECOVERY_FUNCTION" "$RECOVERY_ALIAS" "$CREATE_RECOVERY_RECEIPT_ALIAS" seed-revoke-create-v1 SEED_REVOKE_CREATE_DISPATCHED SEED_REVOKE_CREATED route
invoke_broker_once "$EXECUTOR_FUNCTION" seed-revoke-execute-v1 SEED_REVOKE_EXECUTE_DISPATCHED
complete_broker_bounded "$EXECUTE_RECOVERY_FUNCTION" "$RECOVERY_ALIAS" "$EXECUTE_RECOVERY_RECEIPT_ALIAS" seed-revoke-execute-v1 SEED_REVOKE_EXECUTE_DISPATCHED SEED_REVOKED route
invoke_broker_once "$CREATOR_FUNCTION" delegation-create-v1 DELEGATION_CREATE_DISPATCHED
complete_broker_bounded "$CREATE_RECOVERY_FUNCTION" "$RECOVERY_ALIAS" "$CREATE_RECOVERY_RECEIPT_ALIAS" delegation-create-v1 DELEGATION_CREATE_DISPATCHED DELEGATION_CREATED route
invoke_broker_once "$EXECUTOR_FUNCTION" delegation-execute-v1 DELEGATION_EXECUTE_DISPATCHED
complete_broker_bounded "$EXECUTE_RECOVERY_FUNCTION" "$RECOVERY_ALIAS" "$EXECUTE_RECOVERY_RECEIPT_ALIAS" delegation-execute-v1 DELEGATION_EXECUTE_DISPATCHED DELEGATION_TERMINAL route
invoke_broker_once "$CREATOR_FUNCTION" pep-create-v1 PEP_CREATE_DISPATCHED
complete_broker_bounded "$CREATE_RECOVERY_FUNCTION" "$RECOVERY_ALIAS" "$CREATE_RECOVERY_RECEIPT_ALIAS" pep-create-v1 PEP_CREATE_DISPATCHED PEP_CREATED route
invoke_broker_once "$EXECUTOR_FUNCTION" pep-execute-v1 PEP_EXECUTE_DISPATCHED
complete_broker_bounded "$EXECUTE_RECOVERY_FUNCTION" "$RECOVERY_ALIAS" "$EXECUTE_RECOVERY_RECEIPT_ALIAS" pep-execute-v1 PEP_EXECUTE_DISPATCHED PEP_TERMINAL route

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

invoke_repair() {
  function_name="$1" alias_name="$2" expected_mode="$3" expected_status="$4"
  payload_file="$(mktemp "$PRIVATE_ROUTE_ROOT/${alias_name}.payload.XXXXXX")"
  metadata_file="$(mktemp "$PRIVATE_ROUTE_ROOT/${alias_name}.metadata.XXXXXX")"
  chmod 600 "$payload_file" "$metadata_file"
  AWS_RETRY_MODE=standard AWS_MAX_ATTEMPTS=1 aws lambda invoke \
    --function-name "$function_name" --qualifier "$alias_name" \
    --payload '{}' --cli-binary-format raw-in-base64-out \
    --profile "$REPAIR_PROFILE" --region us-east-1 \
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

# A new normal Plan session is mandatory after the sealed reconciliation.
# The local profile is configured outside the repository. The SDK runtime path
# is reviewed GUG-274 material, not a secret and not an ambient Python fallback.
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

# Only after independent repair/reconcile ledger and receipt verification plus
# the fresh normal-Plan GUG-214 read-only functional proof. CloudTrail delivery
# may lag, so only this zero-mutation closeout read is retried. The literal
# NORMAL_PLAN_PROOF_PENDING error is emitted only after the broker has read and
# required PEP_TERMINAL. Every other FunctionError stops immediately.
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
complete_broker_bounded "$CREATE_RECOVERY_FUNCTION" "$RECOVERY_ALIAS" "$CREATE_RECOVERY_RECEIPT_ALIAS" delegation-revoke-create-v1 DELEGATION_REVOKE_CREATE_DISPATCHED DELEGATION_REVOKE_CREATED route
invoke_broker_once "$EXECUTOR_FUNCTION" delegation-revoke-execute-v1 DELEGATION_REVOKE_EXECUTE_DISPATCHED
complete_broker_bounded "$EXECUTE_RECOVERY_FUNCTION" "$RECOVERY_ALIAS" "$EXECUTE_RECOVERY_RECEIPT_ALIAS" delegation-revoke-execute-v1 DELEGATION_REVOKE_EXECUTE_DISPATCHED DELEGATION_REVOKED route
invoke_broker_once "$CREATOR_FUNCTION" route-revoke-create-v1 ROUTE_REVOKE_CREATE_DISPATCHED
complete_broker_bounded "$CREATE_RECOVERY_FUNCTION" "$RECOVERY_ALIAS" "$CREATE_RECOVERY_RECEIPT_ALIAS" route-revoke-create-v1 ROUTE_REVOKE_CREATE_DISPATCHED ROUTE_REVOKE_CREATED route
invoke_broker_once "$EXECUTOR_FUNCTION" route-revoke-execute-v1 ROUTE_REVOKE_EXECUTE_DISPATCHED
complete_broker_bounded "$EXECUTE_RECOVERY_FUNCTION" "$RECOVERY_ALIAS" "$EXECUTE_RECOVERY_RECEIPT_ALIAS" route-revoke-execute-v1 ROUTE_REVOKE_EXECUTE_DISPATCHED ROUTE_REVOKED recovery
```

`invoke_broker_once` invokes each mutating alias exactly once and must return
its exact `*_DISPATCHED` state with `aws_mutations=1`.
`complete_broker_bounded` first revalidates that private receipt, then uses only
the retained `042360977644_ScanalyzeGug376BrokerSeedCleanup` profile to invoke
the dedicated recovery function through its exact `recover-v1` alias. The
recovery handler binds the durable attempt claim to the original dispatched
operation and cannot call the provider effect again. Its receipt alias is
`create-dispatch-recovery-v1` or `execute-dispatch-recovery-v1`; the original
operation remains in the sealed attempt claim. It may poll only a Lambda
`RouteBrokerReadOnlyPending` error with the exact sanitized prefix. Success
performs provider/CloudTrail readback and one control-ledger completion CAS,
while the public receipt remains `aws_mutations=0`. Every
completion except final `route-revoke-execute-v1` stops before
`RouteNotAfter - 60s`, preserving time for the next mutation. Only that final
readback may use `RecoveryNotAfter - 60s`; all are additionally capped at 90
attempts, 20-second backoff and a 1,800-second local budget. A nonzero AWS CLI
exit, untyped FunctionError, unexpected/uncertain state, timeout or disconnect
stops the sequence without provider replay.
The sole bounded exception is an exact `NORMAL_PLAN_PROOF_PENDING`
`RouteBrokerReadOnlyPending` from `closeout-gate-v1`: that code is reachable only after the
broker requires `PEP_TERMINAL`, the alias performs zero mutations, and every
attempt keeps its payload and metadata at `0600`. Only
`invoke_closeout_bounded` may repeat that read before both its local proof
budget and `RouteNotAfter - 60s`. Any other `FunctionError`, including
`CLOSEOUT_EVIDENCE_PENDING`, stops immediately. Preserve the private files and
use only the reviewed recovery path; never repeat a mutation. On the success
path, invoke
`reconcile-v1` exactly once after `REPAIR_VERIFIED`, require the sealed
`RECONCILE_VERIFIED` attestation, then establish a new normal Plan SSO session
and run the canonical GUG-214 read-only recovery preflight. The preflight must
use the exact generated role name and IAM ARN sealed by the connected Plan seed
snapshot. The closeout accepts all eligible post-reconcile `ListChangeSets`
events only when they belong to one full STS session and every event has the
exact session issuer ARN, name and account. It stores only the canonical digest
of that caller ARN in the public receipt and ledger. The raw session ARN stays
inside the owner-only identity file: `jq -cj` streams the validated single-key
canonical JSON directly into SHA-256, without copying the ARN into a shell
variable or command argument. Compare the independently computed local
digest to `normal_plan_caller_arn_digest` before any revocation. Lambda callers,
foreign accounts, role-name or suffix drift, multiple sessions and stale events
stop the route. Immediately before sealing the receipt and ledger CAS, closeout
rechecks that the latest accepted event is still no more than 900 seconds old;
crossing that boundary during pagination stops without CAS or mutation. The
preflight must paginate all active Change Sets and use only
management account
`839393571433` as the destination contract; it does not inspect account `905`.
The GUG-274 wrapper pins each read request to a 5-second connect timeout,
30-second read timeout and 45-second subprocess ceiling. Its separate waiter
budget is 5/900/930 seconds. Both paths use standard retry mode with exactly one
attempt so a stalled read cannot consume the 900-second normal-Plan freshness
window.
Independently read the sealed ledger/public receipts before advancing. A
timeout or uncertainty follows only the separately reviewed recovery branch
and never authorizes a second reconcile or repair mutation. This procedure is
non-production and makes no production deployment claim.

All connected providers call STS first, reconstruct exact clean `main`, disable
SDK retries, reserve output and replay claims before provider work, authenticate
CloudTrail mutation attribution, paginate provider state and seal terminal
readback. An ambiguous response is `UNCERTAIN`; only the corresponding recovery
command may recover the original effect.

These commands use synthetic fixtures and injected providers only. Success
means the reviewed repository contract is internally consistent. It does not
mean that AWS state was read, that a stack was deployed, that the Plan policy
was repaired or that production is ready.

## Rollback

Before deployment, revert the repository change.

After stack deployment but before repair, use only the broker aliases
`delegation-revoke-create-v1` and `delegation-revoke-execute-v1` to update the
same management stack with the same reviewed template bytes and all other
parameter values unchanged, changing only `RepairInvokerAssignmentEnabled`
from `true` to `false`. The reviewed Change Set must remove only
`RepairInvokerAssignment`; its execution must read back
`RepairInvokerAssignmentMode=false`, zero temporary assignments and no relevant
pending deletion. Retain the permission set, service roles and all evidence
resources. After either SSO effect is attempted, do not issue a second write or
delete the ledger. Invoke reconcile, preserve the exact provider/CloudTrail
evidence and obtain a new reviewed recovery decision.

After the delegation assignment is removed and closeout is sealed, the broker
uses `route-revoke-create-v1` and `route-revoke-execute-v1`. The exact update
keeps `SeedAssignmentsEnabled=false` and changes only
`BrokerInvokerAssignmentEnabled` from `true` to `false`; it removes the one
remaining `BrokerInvokerAssignment`. Require zero assignments in that scope and
wait for any issued SSO credentials to expire or be explicitly invalidated
before classifying the route as closed. Retain the inactive permission sets and
route stack as evidence.

```text
AWS_CALLS=9
AWS_MUTATIONS=0
RUNTIME_PORTS_BOUND_IN_SOURCE_CLOSED_PACKAGE
SIGNED_ARTIFACT_NOT_BUILT
LIVE_RUN_NOT_EXECUTED
NOT_DEPLOYED
PRODUCTION_NO_GO
```

## References

- [ADR-057](../../ADR/ADR-057-bootstrap-plan-permission-repair-pep.md)
- [ADR-058](../../ADR/ADR-058-gug376-temporary-changeset-route.md)
- [Operations runbook](../operations/platform-authority-bootstrap-plan-permission-repair.md)
- [Canonical bootstrap contract](platform-authority-bootstrap.md)
- [GUG-221 separated repair](platform-authority-lambda-audit-provisioning-repair.md)
