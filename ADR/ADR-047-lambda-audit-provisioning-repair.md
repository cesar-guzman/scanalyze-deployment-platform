# ADR-047: Server-Side PEP for Lambda Audit Provisioning Repair

- **Status:** Accepted for repository implementation and non-production review
- **Date:** 2026-07-21
- **Work package:** GUG-221
- **Amends:** ADR-046
- **Depends on:** GUG-219 and GUG-220
- **Production:** **NO-GO**

## Context

GUG-220 consumed its one-shot execution window at an ambiguous AWS IAM Identity
Center boundary. Sanitized read-only reconciliation found an exact partial
state: `ScanalyzeAuthorityLambdaAudit` exists, while its reviewed inline
policy, direct `USER` assignment, target-account provisioning and account-local
collector role are absent or unverified. The GUG-220 ledger remains evidence of
the prior attempt and is never reset, deleted, overwritten or reused.

A direct human repair session is not a sufficient policy-enforcement point.
IAM can restrict actions and resources, but it cannot prove the complete
payload, ordered predecessor states, policy digest, principal identity,
one-shot execution or post-effect evidence needed by GUG-221. A host-local
file also cannot prevent replay from another workstation. Giving the human
session the three Identity Center mutations would therefore leave a bypass
around the runtime contract.

The current operating roster has one person. Separate profiles, roles or login
windows used by that person are not independent human approval.

## Decision

### 1. Put the authoritative PEP behind private, versioned Lambda aliases

The human permission set is `ScanalyzeLambdaAuditRepair`. It may invoke only
these exact private aliases in the authority account ending in `7644`, Region
`us-east-1`:

```text
scanalyze-authority-lambda-audit-plan:plan-v1
scanalyze-authority-lambda-audit-repair:repair-v1
scanalyze-authority-lambda-audit-reconcile:reconcile-v1
```

Every invocation payload must be exactly the empty JSON object `{}`. Request
headers, environment overrides, function names without qualifiers, arbitrary
aliases and request-supplied identifiers are non-authoritative. Functions have
no URL, public permission or event source. Because `lambda:InvokeFunction`
cannot be IAM-conditioned by invocation type, each alias has an explicit
asynchronous configuration with zero retries, a 60-second maximum event age
and no destination. Runtime additionally requires the reviewed synchronous-
only `ClientContext` marker before reading provider state or claiming the
ledger; asynchronous invocation cannot carry that marker and therefore cannot
reach a protected effect. The marker proves transport only: it does not select
an account, principal, permission set, policy, mode or action and is never an
authorization credential. Each alias points to a pinned published version whose
code hash, code-signing configuration and immutable environment are reviewed.

The human permission set has no `sso:*`, `identitystore:*`, `iam:*`,
`sts:AssumeRole` or DynamoDB mutation authority. A human can request a reviewed
operation; only the server-side PEP can evaluate and perform it.

### 2. Separate Plan, repair and reconciliation execution authorities

The authority account contains distinct Plan, repair and reconcile Lambda
functions, published versions, aliases and execution roles.

- The Plan execution role may only create the exact durable `PLAN_VERIFIED`
  record with `dynamodb:PutItem`, assume the management readback service role
  and read the authority control plane.
- The repair execution role may only advance that existing record with
  `dynamodb:UpdateItem` and assume the management mutation service role. It
  cannot create a record, so direct invocation cannot bypass Plan.
- The reconcile execution role has no DynamoDB write or Identity Center
  mutation authority. It assumes only the management readback service role and
  reads the exact authority-account IAM state required for evidence.
- A fourth authority-account role, the path-scoped invocation-authority
  inspector, is assumable only by those three execution roles. It can inventory
  the complete account-wide IAM and Lambda invocation graph but explicitly
  cannot invoke Lambda, mutate IAM or Lambda, or chain to another role.
- `repair-v1` is the only Identity Center mutation path.

The management account ending in `1433` contains two non-human service roles:

```text
ScanalyzeLambdaAuditRepairMutationServiceRole
ScanalyzeLambdaAuditRepairReadbackServiceRole
```

Their trust policies use the authority-account root only as a stable,
pre-creatable principal and require both the exact authority account and
`ArnEquals aws:PrincipalArn` for the corresponding Lambda execution role. This
breaks the management-first bootstrap cycle without allowing another root,
role, SSO session or IAM user to assume them. Both the caller policies and
target trusts bind `sts:SetSourceIdentity` to the same exact `sts:AssumeRole`
edge for durable attribution.
The mutation role exposes only the required reads and these three effects:

```text
sso:PutInlinePolicyToPermissionSet
sso:CreateAccountAssignment
sso:ProvisionPermissionSet
```

The readback role exposes only reviewed `List`, `Get` and `Describe` surfaces.
Neither role permits permission-set creation/deletion, assignment deletion,
managed-policy attachment, permissions-boundary mutation, relay, Lambda
invocation or customer/production deployment.

The complete service control plane has six roles: Plan, repair, reconcile,
invocation inspector, management mutation and management readback. The
materialized human SSO role is a separate invoke-only principal.

### 3. Derive authority exclusively from immutable server configuration

The pinned Lambda version binds the exact source commit, repair ID, validity
window, Identity Center instance, Identity Store, immutable `USER`, collector
permission-set ARN/name/tags, authority and management accounts, Region,
collector policy digest, repair-invoker policy digest, GUG-220 ledger digest, SAML
provider, KMS mode/key and service-role ARNs.

The PEP validates its qualified invocation ARN, local Lambda execution role,
numeric function version, alias-to-mode mapping and a validity window of at
most 15 minutes. It rejects missing, malformed, expired or conflicting
configuration. The empty event cannot select an account, principal, permission
set, policy, mode or action.

Because `lambda:SourceFunctionArn` is intentionally unqualified, the PEP also
enumerates the complete regional Lambda function inventory with all versions,
then independently enumerates every version and alias of all three reviewed
functions. It requires only `$LATEST` plus the one reviewed published version,
only the three reviewed aliases, exact alias targets, and exclusive use of the
three protected execution roles by the three reviewed functions. Any
additional version, alias, role reuse, missing page or malformed pagination
blocks before ledger access or provider dispatch.

The Lambda runtime does not receive the original IAM caller identity. It must
therefore assume the exact invocation-authority inspector role and use the
GUG-218 collector semantics to prove the complete account-wide IAM/Lambda
graph for all three aliases on every provider snapshot. Exactly one reviewed
`AWSReservedSSO_ScanalyzeLambdaAuditRepair_*` role and exactly three qualified
invoke edges may exist; foreign or unknown edges, mutation authority,
incomplete coverage, stale evidence or graph drift between snapshots blocks
before ledger access or a protected effect. `ClientContext` remains transport
evidence only and is never accepted as caller authorization.

### 3A. Bind deployment to a clean commit and one exact signed object version

Code signing alone proves that a ZIP was signed by an allowed publisher; it
does not prove that the ZIP contains the reviewed source. The deployment chain
therefore has two independent fail-closed anchors:

1. a deterministic builder proves a clean exact Git commit, tracked source
   bytes, a closed twenty-five-entry archive and an internal lock for the exact
   managed SDK versions; and
2. a read-only verifier rebuilds that package, reads the Signer job and exact
   S3 source/signed versions directly from AWS, requires versioning and
   SHA-256, rejects overwrites/delete markers/additional executable entries,
   and emits the only eligible CloudFormation parameter tuple.

Operator-supplied downloaded ZIPs, manifests, provider JSON, ETags and
`latest` reads are not authority. The signed destination key must end in the
exact Signer job ID and have exactly one version. Both Lambda functions must
use the same signed bucket, key, version and final signed `CodeSha256`. The
unsigned digest can never be substituted into the Change Set.

### 3B. Enforce a two-phase Change Set dependency boundary

The management delegation must exist before its provider-created repair
permission-set ARN can be an authority input to the authority PEP. GUG-221
therefore never emits or verifies both CREATE Change Sets concurrently.

Phase A uses only the fixed management and authority `ReadOnlyAccess` sessions
to enumerate the consumed GUG-220 chain twice. It derives the Identity Center
instance, store, encryption mode/key, exact principal, exact partial collector
permission set, SAML provider and absent collector role from AWS. Pending
assignment/provisioning operations are checked before and after each snapshot;
the two complete provider-state digests must agree. An operator-authored or
self-digested evidence file is never authority. The provider receipt and ten
delegation parameters are private, mode `0600`, create-only artifacts. The
deployment contract carries only source/window/creator choices and cannot
carry raw provider identifiers or GUG-220 authority.

After separately authorized execution of Phase A, exact stack, template,
outputs, resources, permission-set policy/tags/attachments/boundary/global
assignment state and management service roles are read back. The readback also
requires the immutable review receipt, its deterministic `ClientRequestToken`,
one exact CloudTrail `ExecuteChangeSet` event by the contract-bound executor,
and complete terminal `DescribeStackEvents` lineage carrying that token. A
state-equivalent stack without the reviewed execution lineage is rejected.
Only that live receipt supplies the repair-invoker ARN to Phase B. Phase B
refreshes both the GUG-220 provider snapshot and the complete Phase A live
state, then combines the provider-derived values with the provider-refreshed
signed-artifact tuple to verify the 29-value PEP CREATE Change Set.

The Phase A execution receipt preserves `evaluated_at` as observation evidence,
but its immutable binding digest excludes only that field. Phase B likewise
normalizes only the outer and nested observation timestamps before comparing
the supplied and freshly collected live receipts. All CloudTrail events,
StackEvents, actors, tokens, digests and verifier identities remain bound; a
later read-only observation cannot create false drift.

Each Change Set independently requires its canonical UUID-bearing ARN/name,
exact stack, `CREATE`/`CREATE_COMPLETE`/`AVAILABLE`, rollback-on-failure,
empty rollback triggers/notifications, no `RoleARN`, no import/nested/deployment
mode, exact unmasked parameters/tags/template/resource inventory and one exact
CloudTrail `CreateChangeSet` event. The tool contains no Create, Execute or
Delete operation. Repository and read-only evidence remain **NO-GO**.

### 3C. Bind Phase B execution to the reviewed 23-resource PEP

Phase B is not deployable merely because its CREATE Change Set passed read-only
review. Human identity and mutation authority are deliberately separate. An
ordinary, invoke-only SSO session may call only one exact qualified private
Lambda broker alias. It cannot call CloudFormation, assume the broker execution
role, use a Function URL or send an operator-selected target.

The broker performs the reviewed IAM Identity Center
`CreateTokenWithIAM` Authorization Code flow with PKCE and passes the opaque
identity context to one STS `AssumeRole` call with exactly one
`ProvidedContext`. The target proof role is deny-all: it proves the named
human and exact operation binding, but cannot execute the Change Set or any
downstream mutation. The resulting proof receipt records
`native_on_behalf_of = false`; human proof attribution and effect attribution
are intentionally different.

Fresh topology evidence is not a Lambda environment variable and is not part of
the published-version snapshot. The pre-Phase-B stack contains only the static
topology binding, exact KMS signing-key ARN and signature algorithm. After the
alias exists, read-only provider collection binds live state to that static
`broker_topology_sha256`; a separate KMS boundary signs its canonical digest.
The invoke-only client carries the complete receipt in the exact synchronous
payload while `ClientContext` remains the exact transport marker.

The immutable broker environment is itself an attested provider boundary, not
an unreviewed configuration channel. `PhaseBIdentityBinding` projects exactly
37 string variables into the published version. Readback accepts only an
`Environment` object whose sole member is `Variables` and whose key/value map
is exactly equal to that canonical projection. A missing `Environment`,
missing variable, additional variable, non-string entry or altered value is
`BROKER_TOPOLOGY_LAMBDA_ENVIRONMENT_MISMATCH`; no topology receipt becomes
eligible for signature.

The collector does not serialize those values into evidence. It computes
`environment_variables_sha256` over the versioned
`phase_b_broker_environment_projection` record and places that digest in the
Lambda subtree of provider state. The enclosing `topology_state_digest` covers
that subtree, and the receipt digest and KMS signature cover
`topology_state_digest`. This creates an explicit
environment-projection → topology-state → signed-receipt chain without
exposing identity or execution bindings in the receipt. Fresh topology JSON,
its provider digest, tokens and all other invocation-scoped evidence remain
outside the Lambda environment.

The broker rejects an async, missing or expanded request before creating any
AWS client. It then checks the 4 KiB evidence bound, schema, freshness, static
topology and policy digests, key and algorithm, and calls only `kms:Verify`.
Only after success may OIDC, STS, DynamoDB or CloudFormation clients exist. The
fresh receipt digest enters proof, ledger and effect receipts but is excluded
from immutable topology and binding digests; otherwise first readback would
depend on a Lambda version that already embedded that readback.

Before the first protected effect, the broker consumes the exact Phase B
execution binding through a durable one-shot compare-and-swap transition. Only
the separately scoped broker service role may then call `ExecuteChangeSet` for
the exact UUID-bearing Change Set ARN, stack ARN and derived
`gug221-b-*` `ClientRequestToken`. The broker role, not the SSO session or proof
role, is the effect actor. Because the reviewed Change Set rejects `RoleARN`,
CloudFormation uses that broker role's caller credentials; downstream
IAM/KMS/DynamoDB/Logs/Lambda/S3 actions remain restricted to the exact reviewed
inventory and `aws:CalledVia = cloudformation.amazonaws.com`.

The Phase B ledger is fail-closed at the DynamoDB resource-policy boundary.
It denies every principal from replacing or removing the policy, deleting or
structurally updating the table, creating a backup or export, restoring from
PITR, changing PITR/TTL/auto scaling/streaming destinations/tags, using
PartiQL, batch or query/scan access, or wrapping the exact item APIs in a
transaction. Provider readback requires TTL to be exactly `DISABLED` with no
`AttributeName`. Only Get/List/Describe operations and the broker's direct,
exact-key `GetItem`/`PutItem`/`UpdateItem` CAS remain available.

DynamoDB resource policies do not support legacy global-table APIs, imports or
restore-from-backup. The broker role grants none of those actions, but blocking
them for every other same-account principal requires a separately reviewed
account/organization guardrail. Until that guardrail and live readback exist,
this package cannot claim account-wide ledger immutability and production
remains NO-GO.

The reviewed PEP template contains exactly 23 resources. Its Change Set schema,
synthetic fixture and verifier must carry the same ordered logical-ID/type map;
an 18-resource legacy fixture, missing Plan resources, additional resource,
replacement or order drift is invalid. After the separately authorized
execution, a read-only verifier requires one matching CloudTrail
`ExecuteChangeSet` event, the exact actor and token, complete terminal
StackEvents for all 23 resources plus the stack root, the original template,
parameters and tags, and an exact live resource inventory. Rollback, partial
completion, duplicate events, pagination ambiguity or state equivalence without
execution lineage remains blocked. That CloudFormation trace is necessary but
not proof that provider controls are effective. A second read-only receipt
must query IAM, Lambda, DynamoDB, KMS and CloudWatch Logs directly, enumerate
all 23 physical resources from trusted stack metadata, compare two complete
snapshots and emit only resource/digest evidence. Raw physical IDs are private
inputs and never appear in receipts, logs or repository artifacts.
Snapshot stability alone is insufficient. The verifier resolves the reviewed
template with the exact 29-parameter PEP handoff, builds one expected semantic
contract per resource and requires its digest to equal the direct-provider
contract digest in both snapshots. Extra Lambda aliases, versions or async
configurations; DynamoDB global replicas, witnesses, restore/stream/throughput
state; IAM boundaries; KMS algorithms/replicas/aliases; and Logs data-protection
state are drift. Provider-assigned IAM role IDs are explicitly limited to
format validation plus two-snapshot stability and never treated as
template-derived configuration.
The Signer profile-version ARN is compared to the PEP handoff. The
provider-assigned signing-job ARN must be present, belong to the exact
account/Region and remain stable across both snapshots; this classifies the
observation but does not claim exact signing-job provenance without a separate
signed-artifact receipt.

The KMS key, KMS alias, DynamoDB table and log groups are retained so rollback
does not require destructive authority; only non-retained IAM/Lambda resources
receive exact rollback permissions.

That retention changes the failure contract. A failed or rolled-back Phase B
operation with any surviving key/alias, table or log group is
`FAILED_RETAINED_RESOURCES`, not a clean rollback and not a retryable empty
state. Read-only provider inventory must bind the candidates to the exact
Change Set, stack-event lineage and physical identifiers. Names, tags and
expected configuration are insufficient ownership evidence and never
authorize adoption. Candidates remain quarantined because their canonical
names may collide with another deployment and their KMS, DynamoDB or Logs
footprint may continue to incur cost. Cleanup of those resources belongs to a
separate reviewed child issue with exact destructive authorization and
post-cleanup readback.

The broker alias, application registration, invoke-only SSO authority, proof
role, broker execution role, one-shot ledger and revocation topology are
preconditions, not Phase B resources. They require reviewed changes and direct
provider readback before the protected Change Set can become eligible.

The authority-account pre-Phase-B template is deliberately narrower: its exact
nine-resource inventory creates the broker Lambda topology, broker/proof IAM
roles, one-shot ledger and log group. It includes one alias-bound
`AWS::Lambda::EventInvokeConfig` with zero retries, a 60-second maximum event
age and no destination. It accepts the Identity Center application ARN and
materialized invoker principal as inputs; it does **not** create the
application, permission set, assignment or provisioned `AWSReservedSSO_*`
role. Those management/Identity Center resources require a separate reviewed
materialization receipt. That layer is not implemented by this repository-only
change, so live Phase B remains blocked.

The accepted DAG is strictly:
provider-authenticated Identity materialization receipt → PEP parameter
handoff/Change Set receipt → PRE_B handoff/Change Set receipt →
execution/effect/readback. The deployment contract cannot supply the broker
role, topology digest, application ARN, invoker ARN, Code Signing Config or
topology signing key. A JSON document with valid shape and a self-consistent
digest is fabricable and is therefore rejected with
`BLOCKED_IDENTITY_PRECONDITION_NOT_MATERIALIZED`. Until a separate live
producer authenticates that receipt through direct provider revalidation or
an exact KMS-verifiable envelope, neither the PEP nor PRE_B builder can emit a
handoff.

The typed
`phase_b_precondition_parameters.v1` handoff rebuilds the deterministic package
from the exact Git commit, proves its manifest matches the signed-artifact
receipt, renders the four reviewed IAM policies with a closed placeholder set
and binds exactly 37 parameters. The
`phase_b_precondition_change_set_receipt.v1` verifier then accepts only the
exact nine-resource CREATE Change Set. Neither artifact is execution
authority. This PR deploys none of the topology and performs no AWS mutation.

The runtime result proves only that the exact execution gate was consumed and
that closure is pending. It must not claim provider revocation. Revocation is
verified only after read-only provider evidence proves removal of the human
assignment and alias invocation authority, absence of pending Identity Center
operations, expiry of all possible sessions and preservation of the consumed
one-shot ledger. No receipt contains authorization codes, PKCE verifiers,
access tokens, identity-context blobs, STS credentials, presigned values,
physical resource IDs or request payloads.

The design follows the AWS IAM Identity Center identity-enhanced session
contract: the identity context is opaque, is passed to STS as one
`ProvidedContext`, and does not make the proof role the native effect actor.
See [identity-enhanced IAM role sessions](https://docs.aws.amazon.com/singlesignon/latest/userguide/trustedidentitypropagation-identity-enhanced-iam-role-sessions.html),
[`CreateTokenWithIAM`](https://docs.aws.amazon.com/singlesignon/latest/OIDCAPIReference/API_CreateTokenWithIAM.html),
[application actor policies](https://docs.aws.amazon.com/singlesignon/latest/userguide/iam-auth-access-using-resource-based-policies.html)
and [`AssumeRole` `ProvidedContexts`](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html).

### 4. Require a durable Plan record before repair

`plan-v1` first proves the exact eligible provider state and complete
invocation-authority graph, then performs the only allowed DynamoDB conditional
create for the exact repair ID and intent digest:

```text
ConditionExpression: attribute_not_exists(repair_id)
status: PLAN_VERIFIED
stage: PLAN_STATE_VERIFIED
effects_attempted: 0
effects_completed: 0
```

The table is KMS encrypted, deletion protected, point-in-time recovery enabled
and retained on stack replacement/deletion. Its resource policy denies writes
except the exact Plan role for `PutItem` and the exact repair role for
`UpdateItem`; unsupported write APIs are denied to both. `repair-v1` cannot
create the item. It must re-prove the same provider-state and invocation graph,
then atomically consume the exact `PLAN_VERIFIED` record by transitioning it to
`CLAIMED` / `BEFORE_FIRST_EFFECT`. Subsequent stage transitions use
compare-and-swap conditions over repair ID, intent, source, Plan and repair
versions, planned-state digest, prior stage and effect counters.

Failure to create or read back the Plan record means no mutation begins. A
missing, conflicting, malformed, stale or already-consumed Plan is not adopted.
The provider-backed Plan/repair state machine is the live replay barrier;
host-local evidence is not mutation authority and cannot open another execution
window.

### 5. Preserve exact ordering and make ambiguity terminal

After the repair function atomically consumes the durable Plan, the PEP
re-reads the complete live state and exact invocation graph before every effect
and permits only:

1. the sealed collector inline policy;
2. the exact direct `USER` assignment to the authority account; and
3. explicit provisioning of that permission set to that account.

Any unexpected policy, principal, group, account, boundary, attachment,
pagination gap, role or predecessor state stops the sequence. There are no SDK
or orchestration retries for mutation. Provider-backed alias configuration
sets Lambda asynchronous retries to zero, bounds event age to 60 seconds and
has no destination. An async request can still be delivered and the service
may duplicate queued events, so the missing synchronous `ClientContext` marker
and durable CAS remain mandatory controls. Reserved concurrency limits the
repair function to one concurrent execution, but concurrency control does not
replace DynamoDB CAS.

The runtime budget is part of the authorization contract, not an availability
tuning knob. Plan and reconcile run with a 300-second timeout; repair runs with
600 seconds; all three use 1024 MiB. Repair requires at least 660 seconds left
in the immutable 15-minute window before preflight and at least 480 seconds of
Lambda runtime immediately before consuming `PLAN_VERIFIED`. It takes exactly
five complete authority epochs: initial, one immediately after each
`ATTEMPTING_n` CAS and before its provider effect, and final. Every account-wide
inventory provider call checks for a 60-second fail-closed reserve. Provider
dispatch requires 75 seconds and polling preserves 60 seconds so an ambiguous
result can still be committed to the durable ledger.

A timeout, transport loss, unknown asynchronous result, a failed post-effect
CAS transition or incomplete post-effect evidence becomes:

```text
UNCERTAIN_RECONCILE_ONLY
```

No mutation is retried or resumed. Only `reconcile-v1` may be invoked next.
A failed CAS before dispatch proves that no provider effect was attempted and
therefore returns `BLOCKED` with `REVIEW_BLOCKER`; it does not overclaim an
uncertain external write.

### 6. Require independent final SSO and IAM readback

Final success requires fresh read-only evidence from both boundaries:

- Identity Center: exact instance/store, collector metadata/tags, canonical
  inline policy, one direct `USER`, only the authority target, and no managed or
  customer-managed attachment or permissions boundary. Provisioned accounts
  are listed without status filtering, assignments are enumerated for every
  observed account using the current Organizations `State` contract (never the
  retired `Status` field), and every `IN_PROGRESS` assignment-creation,
  assignment-deletion and permission-set-provisioning request ID is described
  before requiring no operation bound to either exact permission set.
- Authority-account IAM: exactly one materialized collector role and one
  materialized repair-invoker role under their distinct reviewed
  `AWSReservedSSO_*` prefixes, exact SAML trust/audience and inline-policy name
  and digest for each, and no extra inline or managed policy, boundary or relay
  path.
- DynamoDB: the exact durable intent and monotonic effect attribution.

A successful API response, waiter, expected name prefix or Lambda completion is
not final evidence. Missing access or incomplete pagination yields a blocked or
incomplete result, never a verified receipt.

### 7. Keep governance and evidence claims explicit

The same person may perform the operational logins while the team has one
member, but that is a documented single-operator constraint. It does not
satisfy independent approval, separation of duties or production release
requirements.

Repository implementation, local validation, CI validation and live AWS
validation are separate evidence classes. This ADR authorizes none of the AWS
mutations described above. Deployment of either stack, invocation of any live
alias and repair of provider state require separate, exact authorization.

## Consequences

- Human credentials cannot call the Identity Center repair APIs directly.
- The server-side PEP, immutable version configuration and durable CAS record
  jointly bind the only mutation path.
- The deployment artifact is reproducible from a reviewed commit and the
  Change Set cannot consume an operator-asserted or extra-entry signed ZIP.
- Plan, repair and reconciliation cannot share write authority; repair cannot
  create or replace Plan evidence.
- The exact account-wide invocation graph is a runtime precondition on every
  snapshot, not an operator assertion or an offline report.
- An ambiguous effect is terminal for mutation and remains attributable to the
  durable claim.
- The design can be reproduced per installation by supplying reviewed bindings
  without accepting request-derived authority.
- The ZIP intentionally binds, but does not vendor, the Lambda-managed
  `boto3`/`botocore` versions. A managed-runtime update therefore blocks
  fail-closed. A fresh `PLAN_VERIFIED` receipt immediately before repair is a
  mandatory operational control until the SDK is vendored in a separately
  reviewed package or layer.
- The synchronous `ClientContext` proves transport only. The handler does not
  authenticate a named human; human attribution remains an outer IAM/Identity
  Center control and must be corroborated by the account-wide Lambda authority
  inventory.
- Runtime calls set deterministic `SourceIdentity`, but target trusts do not
  yet require its presence; this is a forensic-attribution hardening gap.
- DynamoDB cannot enforce the signed handler's exact `ConditionExpression`
  through IAM. The empty payload, exact aliases, code signing, role isolation,
  `lambda:SourceFunctionArn` and complete CAS remain the enforcement set.
- A guard failure after `ATTEMPTING_n` and before provider dispatch consumes
  the repair conservatively. Reconciliation and a new reviewed repair are
  required; the original ledger is never replayed.
- A failed Phase B stack can leave retained KMS, DynamoDB and Logs resources.
  They remain quarantined as `FAILED_RETAINED_RESOURCES`; no matching name,
  tag or configuration permits adoption, retry or inferred ownership.
- A single operator remains a governance blocker for independent approval.
- Production remains **NO-GO**.

## Alternatives rejected

- **Direct SSO executor with three Identity Center writes:** bypasses payload,
  sequence, digest and durable replay enforcement.
- **Host-local create-only ledger:** cannot coordinate or resist replay across
  workstations and is not provider-backed.
- **One Lambda/role for Plan, repair and reconcile:** lets read-only recovery or
  Plan creation inherit mutation authority and permits repair to bypass the
  durable Plan gate.
- **Human-supplied repair payload:** turns request data into authority.
- **Unqualified Lambda ARN or function URL:** permits code/version drift or an
  unintended public invocation path.
- **Automatic retry after timeout:** the provider may have completed the write.
- **Treat two sessions held by one person as two approvals:** technical session
  separation is not independent human review.

## Failure, containment and rollback

Before the durable Plan-to-repair transition, any failure is Identity Center
mutation-free. After that transition or a
possibly started provider call, stop all mutation and invoke only the exact
read-only reconcile alias. Preserve the table record and private evidence.

Cloud rollback is not implicit. Assignment deletion, deprovisioning, policy
removal, permission-set deletion, table deletion or stack deletion are separate
destructive operations requiring another issue, authorization and readback.
Repository rollback is a reviewed revert; deployed versioned aliases must not
be repointed without a separately reviewed change.

If Phase B fails after creating a retained KMS key/alias, DynamoDB table or log
group, preserve the stack/Change Set lineage and perform only complete
read-only provider inventory. Mark every discovered candidate quarantined as
`FAILED_RETAINED_RESOURCES`; do not infer ownership from a canonical name,
expected tag or template match, and do not reuse or delete a candidate to
resolve a name collision. Record continuing cost exposure. Any cleanup must be
a separate child package naming the exact KMS, DynamoDB and Logs resources,
their evidence-retention dependencies, destructive authorization and
independent post-cleanup readback.

## Post-merge contract reconciliation

The post-merge review and independent pre-publication review identified seven
fail-closed availability or evidence-integrity defects in the offline
implementation. They did not create a path around the PEP, but they would
block valid readback or accept invalid offline evidence:

- AWS CLI pagination used service-style continuation flags for SSO Admin and
  IAM. All affected collectors now use bounded CLI pages with equal
  `--max-items`/`--page-size`, consume only the CLI `NextToken`, and continue
  only with `--starting-token`; malformed, missing, repeated or excessive
  pagination remains terminal.
- `list-tags-for-resource` has no service page-size member and therefore does
  not accept the AWS CLI `--page-size` option. The shared paginator now makes
  this capability explicit while retaining `--max-items`, `NextToken`, bounded
  pages and replay rejection; both tag-readback call sites bind the exception.
- Lambda `$LATEST` resources and immutable published versions intentionally
  have different descriptions. Runtime validation now binds the exact
  description for each resource class and function kind instead of accepting
  alternatives.
- The semantic evidence validator now recognizes the create-only
  `PLAN_VERIFIED` ledger state and the durable Plan receipt contract already
  required by the JSON schemas, runtime and invoker. Legacy unproven Plan
  evidence remains invalid, and the validator independently recomputes the
  canonical SHA-256 of the immutable Plan binding reconstructed from every
  GUG-221 ledger state before accepting it.

These corrections are repository-only until independently reviewed, merged,
verified on `main`, and separately authorized for live non-production use.
They do not authorize replay of the consumed GUG-220 ledger or any AWS action.

## Evidence classification

| Evidence class | Current status |
|---|---|
| Server-side PEP, IaC, policies, contracts, tests and documentation | **Implemented** only on the exact reviewed repository commit |
| Named local gates | **Locally validated** only when their recorded results pass for that commit |
| Required GitHub checks | **CI validated** only after completion for that exact commit |
| Authority and management stacks | **Not live validated**; no AWS deployment performed by GUG-221 repository work |
| Durable DynamoDB Plan/repair state machine | **Not executed** |
| Final collector SSO/IAM readback | **Not live validated** |
| Candidate A/B validation | **Blocked** until `RECONCILE_VERIFIED` and a dedicated collector SSO session are independently evidenced |
| Independent human approval | **Blocked** while one person is on the roster |
| Production | **NO-GO** |

## References

- [Deployment contract](../docs/deployment/platform-authority-lambda-audit-provisioning-repair.md)
- [Operations runbook](../docs/operations/platform-authority-lambda-audit-provisioning-repair.md)
- [Threat-model delta](../docs/security/gug-221-lambda-audit-provisioning-repair-threat-model-delta.md)
- [ADR-046](ADR-046-lambda-audit-permission-set-provisioning.md)
