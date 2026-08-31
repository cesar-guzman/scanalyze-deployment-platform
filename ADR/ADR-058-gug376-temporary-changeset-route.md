# ADR-058: Attested GUG-376 bootstrap route broker

- **Status:** Proposed repository implementation; live seed not executed
- **Date:** 2026-08-30
- **Implementation issue:** GUG-376
- **AWS live validation:** Bounded read-only inventory only; route not executed
- **AWS mutations:** None
- **Production:** **NO-GO**

## Context

The GUG-376 repair PEP cannot deploy itself. The live predecessor of
`ScanalyzeAuthorityBootstrapPlan` lacks the reviewed `ListChangeSets`
permission that its normal preflight requires. Read-only identities cannot
create the delegation or PEP stacks, while giving a human direct
CloudFormation provider authority would allow the reviewed template parameters
or operation order to be bypassed.

The route also cannot depend on the historical GUG-363/GUG-365 artifact
locations. The connected inventory found no dedicated GUG-376 bucket, KMS
alias, role or tagged resource. Signing-profile inventory was not observable
with the read-only identity, so its absence is not claimed and exact foundation
readback remains mandatory. Treating a legacy bucket as an implicit fallback
would make the live path depend on mutable state that is not closed by the
GUG-376 source review.

An initial management-account administrator is the only existing identity that
can establish a narrower route. That exception must end after the exact route
stack is created. It must not become the actor that deploys the broker,
delegation, PEP, repair, reconciliation or revocations.

CloudFormation IAM conditions can bind a Change Set name and `TemplateURL`, but
cannot close every template parameter. Therefore a human Creator/Executor pair
is still insufficient: either session could submit a different parameter set
to the same reviewed template.

## Decision

### 0. Close the artifact trust root before opening the normal route

The management-account administrator first creates only
`scanalyze-platform-authority-gug376-artifact-bootstrap-bridge`. That stack
contains one `PT1H` IAM Identity Center permission set and, while explicitly
enabled, one assignment to the privately supplied bootstrap principal. Its
inline policy is bounded to `us-east-1`, the absolute route window, the exact
GUG-376 stack and artifact names, CloudFormation forward access and the
specific S3, KMS, Signer and Lambda code-signing operations needed for the
artifact foundation. The initial policy cannot start a signing job because its
Signer profile version is `NOT_CONFIGURED`.

The temporary authority-account session then creates and reads back
`scanalyze-platform-authority-gug376-artifact-foundation`. The retained
foundation contains exactly:

- one rotating symmetric KMS key and exact alias;
- one private, versioned, bucket-key-enabled S3 bucket;
- one AWS Signer profile;
- one enforcing Lambda code-signing configuration; and
- the bucket policy that limits readers to exact GUG-376 roles, object keys and
  object versions.

No connected operation may trust a caller-supplied source receipt. Before each
dispatch, execution, object publication or signing operation, the provider
recomputes the reviewed-source attestation from a clean local `main` whose
`HEAD` and `origin/main` are the exact merged commit. Each mutation has a
separate, at-most-15-minute action authorization, a durable write-once claim,
one zero-retry provider request and an explicit read-only recovery path.
Changing the authorization does not change the mutation claim or provider
idempotency token.

After foundation readback provides the generated Signer profile version, the
bridge is updated to allow `StartSigningJob` only for that exact version. The
reviewed route and delegation templates are then published and read back by
exact S3 version and checksum. A second foundation update opens cross-account
reads only for those two versions. Its exact KMS, S3, Signer, code-signing,
template and source evidence is sealed as
`scanalyze.platform_authority.gug376_artifact_foundation_publish_binding.v1`.

That pre-revocation binding is the sole storage authority accepted by the PEP
and broker artifact attestors, template readbacks, broker configuration and
broker seed materializer. Legacy GUG-363/GUG-365 bindings are available only
behind an internal test-compatibility flag and are never auto-discovered by a
product CLI.

All remaining exact templates and signed artifacts are published and read
back before the bridge assignment is removed. The bridge revocation must then
prove the exact terminal stack, zero assignments and expiry of any credential
that could have been issued during the `PT1H` session. Only after that boundary
may the local materializer seal
`scanalyze.platform_authority.gug376_artifact_bootstrap_route_release.v1`, which binds
the foundation publish binding to the complete template, signed-artifact and
broker-seed receipt set. The normal route seed rejects any input without that
post-revocation release. This two-level contract avoids a circular dependency:
publication requires the live foundation, while opening the normal route
requires proof that the temporary publication authority is gone.

### 1. The administrator creates only the temporary route stack

The management stack
`scanalyze-platform-authority-gug376-temporary-change-set-route` creates:

- `ScanalyzeGug376BrokerSeedCreator` in the authority account;
- `ScanalyzeGug376BrokerSeedExec` in the authority account;
- `ScanalyzeGug376BrokerInvoker` in the authority account; and
- exact management Creator and Executor roles under
  `/scanalyze/platform-authority/`, trusted only by the corresponding broker
  Lambda execution roles in the authority account.

The shortened names are required because an IAM Identity Center permission-set
name is limited to 32 characters. The required flags
`SeedAssignmentsEnabled` and `BrokerInvokerAssignmentEnabled` have no defaults.
The initial route is `true/true`. After the broker is proven, the broker changes
it to `false/true`. Final closeout changes it to `false/false`.
Permission-set definitions and the route stack remain retained evidence; only
assignments convey temporary human access.

Only after the post-revocation bootstrap route release exists may one
separately authorized use of
`839393571433_AWSAdministratorAccess` create, review and execute only that
exact route-stack Change Set. The session ends after exact stack and assignment
readback. It is not reused for any downstream operation.

The seed executor does not accept a caller-supplied attestation as proof of
creation. Before STS it reconstructs the complete seed from the exact private
input and clean merged Git source, reopens the owner-only durable
`CreateChangeSet` result, and requires the attested UUID-bearing stack ARN,
change-set ARN and request ID to match that result. A re-sealed same-name
Change Set from another dispatch cannot reach `ExecuteChangeSet`. After STS,
the executor repeats the unique authoritative `CreateChangeSet` CloudTrail
lookup, `DescribeChangeSet`, `GetTemplate` and exact resource-change projection
and compares every immutable attestation field before the sole effect. It
re-samples the clock after identity validation and immediately before the
write-once claim and provider call, so an authorization that expires during
validation fails closed.

The route parameters contain no credentials or secret material: they are
identifiers, ARNs, immutable versioned-S3 coordinates and bounded
timestamps/flags. They deliberately do not use `NoEcho`. Authoritative
`DescribeChangeSet` and `DescribeStacks` readback must expose and exactly match
every sealed value; `****` or any other mask is rejected rather than treated as
proof.

The downstream delegation and PEP Change Sets follow the same rule. Their
repair principal identifiers, expected permission-set description/tags and
immutable artifact version are causal coordinates supplied by the sealed broker
configuration, not secrets. Those six parameters are not `NoEcho`, and broker
attestation requires one unique key with its exact configured value. A masked,
duplicated, omitted or substituted value cannot authorize execution or
recovery.

For an UPDATE, `UsePreviousValue=true` is not treated as proof of the effective
value. Before execution, the broker reads the stable stack by full ARN, requires
its last update time to be no later than the Change Set creation time, resolves
every previous value and seals the canonical effective-parameter digest. Only
that digest—not the parameter values—is persisted in the private derived
bindings and copied into the execute dispatch. Normal execution and execution
recovery both require the same binding before any effect. `DescribeChangeSet`
may preserve `UsePreviousValue=true` or normalize every previous entry to its
effective `ParameterValue`. The broker accepts either complete representation,
never a mixture; a normalized representation must reproduce the already sealed
effective digest and may not contain a mask. Terminal readback
requires the stack's unique, unmasked String-parameter map to reproduce the
digest and `Stack.ChangeSetId` to equal the executed Change Set ARN. A second
`DescribeStacks` after resource, template, output, control and CloudTrail reads
must reproduce the same stack fingerprint, preventing a mixed snapshot across
a concurrent update. The unique terminal root `StackEvent` must also carry the
exact `ExecuteChangeSet.ClientRequestToken`, stack identity and terminal status,
with its timestamp at or after the execution event. This event is the causal
clock for both CREATE and UPDATE; a CREATE stack's `CreationTime` may correctly
precede execution. Duplicate keys, masks, non-null `ResolvedValue`, event-token
drift or any terminal parameter substitution fail closed.

Every AWS read in a continuation, including each pagination page, rechecks the
shared Lambda remaining-time budget immediately before the provider call. Less
than 15 seconds returns the typed read-only `TIME_BUDGET_PENDING` marker before
another call, CAS or effect; a continuation cannot consume the timeout while
holding an unrecorded terminal result.

#### Finite seed deployment recovery

An ambiguous provider or durability outcome permits readback only and can
never repeat a primary CreateChangeSet or ExecuteChangeSet. One separately
authorized re-entry attempt may be derived from exactly one of these proved
terminal bases:

1. the original primary dispatch, durable claim and result, one exact
   CloudTrail event, a `FAILED`/`UNAVAILABLE` Change Set, a
   `REVIEW_IN_PROGRESS` stack and zero resources;
2. a lane-specific terminal cleanup journal, its one exact DeleteStack event,
   absence of the exact stack and fixed name, and a repeated fixed-resource
   survivor proof; or
3. the broker-protection execution claim and result, its one exact
   ExecuteChangeSet event, `UPDATE_ROLLBACK_COMPLETE` stack/resources and the
   unchanged live ledger state.

It then follows `authorize-reentry`, `materialize-reentry`, `create-reentry`,
`attest-reentry`, `authorize-reentry-execution`,
`materialize-reentry-execution`, and `execute-reentry`. Separately, after a
primary or re-entry CREATE execution, an exact `ROLLBACK_COMPLETE` or
`DELETE_FAILED` stack may be attested from its execution intent, receipt,
durable claim and CloudTrail event and then follow `authorize-cleanup`,
`materialize-cleanup`, `delete-failed-stack`, and `attest-cleanup`.

For `route`, the creator, re-entry executor and failed-CREATE attestor use only
`839393571433_AWSAdministratorAccess`; cleanup uses only
`839393571433_ScanalyzeGug376RouteSeedCleanup`. For `broker`, creation and
re-entry attestation use only
`042360977644_ScanalyzeGug376BrokerSeedCreator`, execution and failed-CREATE
attestation use only `042360977644_ScanalyzeGug376BrokerSeedExec`, and cleanup
uses only `042360977644_ScanalyzeGug376BrokerSeedCleanup`.

Every mutation requires a fresh 60–900-second action-time authorization. The
exact route phrases are
`I_AUTHORIZE_GUG376_ROUTE_SEED_CREATE_REENTRY_1`,
`I_AUTHORIZE_GUG376_ROUTE_SEED_EXECUTE_REENTRY_1`, and
`I_AUTHORIZE_GUG376_ROUTE_SEED_STACK_CLEANUP_1`; the broker phrases replace
`ROUTE` with `BROKER`. Re-entry authorizations expire by
`RouteNotAfter - 1,800 seconds`. Cleanup is bounded by the half-open
`RouteNotBefore <= now < RecoveryNotAfter` interval, where
`RecoveryNotAfter = RouteNotAfter + 24h`; the later bridge
`CleanupNotAfter` horizon does not extend DeleteStack authority.

The causal re-entry chain preserves the primary dispatch, failure attestation,
creation authorization, re-entry intent, re-entry dispatch, re-entry
attestation, execution authorization, execution intent and execution receipt.
`reentry_dispatch` is required independently of the attestation. Before its
first STS call, the re-entry executor reopens the persisted result at
`reentry-create:<target>:<seed-intent-digest>` and requires the supplied
dispatch and attestation to match its full stack ARN, Change Set ARN and
CreateChangeSet request ID. Only after all local causal and grant validation
succeeds may it call STS. After STS, it repeats the unique authoritative
`CreateChangeSet` CloudTrail event, `DescribeChangeSet`, `GetTemplate` and the
exact resource-change projection. Their event, describe, template and change
digests, plus status and execution status, must match the attestation before
execution is reachable. Execution and cleanup are separately write-once at
`reentry-execute:<target>:<seed-intent-digest>` and
`cleanup:<target>:<seed-intent-digest>:<primary|reentry>`. Every lane has
`attempt=1` and `retry_permitted=false`; a new attestation, authorization or
output file does not authorize a second effect. A primary cleanup and a later
re-entry cleanup therefore cannot collide, while neither execution lane can
delete twice. An ambiguous provider response or durable-result write is a
stop.

Cleanup accepts only the attested stack ARN plus its deterministic client
token. It excludes `RoleARN`, `RetainResources` and force deletion. Terminal
attestation binds the lane, DeleteStack claim and CloudTrail event, preserves
the failed-resource projection and its digest, proves the fixed stack name
absent and proves no active fixed-resource survivors before the bridge-owned
cleanup identities may be retired. Both the write-once cleanup claim and its
durable dispatch seal the failed-stack attestation digest and failed-resource
digest; a re-sealed terminal cannot omit a KMS key, code-signing configuration
or any other failed resource and still match that journal. The terminal
`attested_at` is sampled only after STS and all CloudTrail, CloudFormation and
survivor reads complete; clock regression or a closed recovery horizon rejects
the attestation.

Before cleanup STS, the runtime reopens the exact causal ExecuteChangeSet
journal—write-once claim and durable result—for the primary or re-entry lane
and requires its request/token, receipt, caller, timing and digests to match the
failed-CREATE attestation. After STS it repeats the unique ExecuteChangeSet
CloudTrail lookup, requires canonical `responseElements=null` and requires the
event digest to match that attestation, then re-reads the exact stack ARN,
fixed name, attested status and complete resource projection. Any missing
journal, non-unique or changed event, or stack/resource drift blocks
DeleteStack.

Each recovery mutation validates its complete local causal chain and active
60–900-second grant before STS. Every re-entry basis is reopened from its
write-once claim and durable result before STS; after STS, the runtime repeats
the corresponding authoritative CloudTrail, CloudFormation and exact-resource
reads and validates the event caller against the exact target/phase role
pattern, not merely a digest copied from the local journal. It re-samples time
and the same grant after STS, rejects clock regression, and samples again after
live evidence reads and immediately before the O_EXCL claim and sole provider
effect. Expiry at any sample fails closed; neither the recovery horizon nor an
already-open session extends the grant.

### 2. Seed sessions can deploy only one parameterless broker

The seed Creator can create only `gug376-route-broker-create` for
`scanalyze-platform-authority-gug376-route-broker` from one exact versioned S3
`TemplateURL`. The seed Executor can execute only that Change Set. Neither seed
identity can supply a provider target, template body, parameter, role ARN,
notification, import, nested-stack option or alternate failure behavior.

The privately materialized broker template has no `Parameters` section. The
broker ZIP is first built deterministically from an exact clean merged `main`
Git object. A separate read-only attestor then binds that unsigned source
archive to one completed Signer job, signing profile/certificate revocation
state and exact versioned signed output. Only after that receipt exists may the
parameterless template be rendered. It embeds the reviewed source commit,
bounded route window, signed broker-code coordinates and code SHA, compressed
sealed configuration and exact target request projections. Unsigned and signed
archive digests are distinct fields and cannot be substituted for one another.
Every private output is write-once mode `0600` under an owner-only directory;
public receipts expose only sanitized digests.

The broker stack contains:

- Creator and Executor Lambda functions with reserved concurrency one;
- published numeric versions and the exact qualified aliases defined below;
- disjoint Creator and Executor roles;
- zero-retry SDK and asynchronous invocation controls; and
- a retained, encrypted, deletion-protected DynamoDB CAS ledger.

Every invocation event is exactly `{}`. Account, role, stack, Change Set,
template, parameters, artifact, assignment scope and state transition come only
from the sealed broker configuration and invoked alias.

### 3. The durable state machine imposes the operation order

Creator aliases:

```text
seed-revoke-create-v1
delegation-create-v1
pep-create-v1
closeout-gate-v1
delegation-revoke-create-v1
route-revoke-create-v1
```

Executor aliases:

```text
seed-revoke-execute-v1
delegation-execute-v1
pep-execute-v1
delegation-revoke-execute-v1
route-revoke-execute-v1
```

The only successful sequence is:

1. remove both seed assignments and prove zero assignments;
2. create and execute the management delegation Change Set;
3. require terminal delegation stack readback;
4. create and execute the authority PEP Change Set;
5. require terminal PEP stack readback;
6. run Plan, repair and reconcile through the PEP;
7. prove all closeout prerequisites;
8. create and execute delegation revocation and prove zero assignment;
9. create and execute route revocation and prove zero invoker assignment.

Identity Center permission-set ARNs are generated by AWS and therefore cannot
be asserted in the pre-route broker template. The broker derives the two seed
ARNs and broker-invoker ARN only from exact terminal route-stack outputs, and
derives the repair-invoker ARN only from the exact terminal delegation output.
It persists those provider coordinates with their readback digests before
using them for assignment proof or the PEP parameter projection. Operator
input can never supply or override a generated ARN.

Before any provider effect, the broker CASes to the exact `*_ATTEMPTING`
state. It makes one zero-retry request and then records `*_DISPATCHED` without
assuming that an asynchronous CloudFormation operation is already terminal.
A later invocation of that same qualified alias is a CAS-gated, read-only
continuation: it may advance only after exact terminal provider readback and
can never dispatch the mutation again. An ambiguous mutation response or
contradictory terminal readback moves the ledger to `*_UNCERTAIN` when that CAS
is itself provable; either an attempting or uncertain state blocks mutation
replay. No alias can skip or reorder a transition, and continuation never
means effect retry.

The route derives and seals `RecoveryNotAfter = RouteNotAfter + 24h` in the
seed intent, route parameters, broker configuration and parameterless broker
template. Mutation authority is the half-open interval
`RouteNotBefore <= now < RouteNotAfter`; recovery is also half-open and ends
before `RecoveryNotAfter`. The deployed runtime reads and validates the
authority-account ledger before creating any cross-account session. After the
mutation window closes, only the alias whose ledger state is its exact
`*_DISPATCHED` state may continue provider readback and the exact completion or
uncertainty CAS. Closeout, initialization, attempting transitions and all new
Create/Execute or provider mutations stop without assuming the management
role. IAM denies provider writes at `RouteNotAfter` and denies every action at
`RecoveryNotAfter`; the invoker, read APIs, STS readback session and exact
ledger `GetItem`/CAS remain bounded by the recovery horizon only.

The dispatch CAS retains the UUID-bearing Change Set ARN, full stack ARN and
provider request binding in the private broker ledger. Creator continuation
describes that exact ARN, compares the original template bytes, parameters,
capabilities, tags and semantic resource changes, then seals the readback.
For updates it also seals the exact effective-parameter digest derived from the
pre-execution stack snapshot; an executor without that private binding cannot
open a claim or call CloudFormation.
Executor operations derive the full Change Set ARN from that ledger record;
they never execute a same-named Change Set reconstructed from configuration.
An operation that is merely still in progress leaves the dispatched state
unchanged and can be observed again read-only. Only a provider terminal failure
or contradictory evidence is terminal uncertainty.

Authority aliases use authority-account clients. Management aliases assume
only the exact management broker role for that phase, set the reviewed source
identity and verify `sts:GetCallerIdentity` before use. A request field cannot
choose credentials or a role.

### 4. Provider authority remains closed and temporary

Creator roles can create and inspect only their exact versioned Change Sets;
they cannot execute them. Executor roles can execute only their exact Change
Sets; they cannot create them. Target stacks use CloudFormation forward access
and no persistent `RoleARN`. Provider grants require
`aws:CalledVia=cloudformation.amazonaws.com`, exact resources, exact Region and
the route window. Actions that require `Resource: *`, including KMS key and
Lambda code-signing configuration creation, are isolated in their own
statements with the same forward-access, Region and time conditions.

The management provider surface is limited to the two delegation roles, the
repair-invoker permission set and its authority-account assignment. The
authority provider surface is limited to the retained PEP ledger/key/logs,
four PEP roles, signed artifact and three exact functions, versions, aliases
and runtime controls. Direct IAM, Identity Center, KMS, DynamoDB, S3, Logs or
Lambda mutation is explicitly denied outside the CloudFormation path. The
broker's own CAS ledger is the sole direct provider-write exception and is
limited by exact `dynamodb:LeadingKeys`.

### 5. Closeout requires independent terminal evidence

`closeout-gate-v1` is provider-read-only except for its own broker-ledger CAS.
It requires all of the following:

- terminal PEP stack readback bound to the broker execution receipt;
- the original repair ledger at `REPAIR_VERIFIED`,
  `FINAL_READBACK_VERIFIED`, attempted/completed `2/2`;
- the distinct `<repair-id>#reconcile-v1` append-only attestation bound to the
  source commit, intent, repair-ledger digest, final-state digest, invocation
  graph and published reconcile alias/version;
- a later successful `ListChangeSets` CloudTrail event from the exact normal
  Plan assumed-role session and exact review stack; and
- an independent bounded GUG-214 provider readback of the canonical stack ARN
  in `REVIEW_IN_PROGRESS`, absent service role/notifications/nesting, zero
  resources, zero active Change Sets across complete pagination and all four
  account-level S3 Block Public Access controls set to `true`.

CloudTrail is used for caller, request, time and success attribution only.
Read-only CloudTrail records have `responseElements=null`; the broker never
claims that CloudTrail contains `ListChangeSets` results. Provider pagination
and empty-inventory proof are separate.

A public receipt, equivalent provider state, pre-reconcile Plan event,
operator-authored JSON or uncertain repair ledger cannot satisfy closeout.

### 6. Assignment removal and credential expiry are distinct

Every revocation Executor requires both terminal CloudFormation status and a
complete IAM Identity Center readback with zero assignments. Removing an
assignment does not invalidate credentials already issued. The route is
therefore not considered expired until the bounded route window has closed or
all previously issued sessions have otherwise expired. No document may equate
`UPDATE_COMPLETE` alone with revocation.

This rule applies first to the artifact-bootstrap bridge and later to the seed,
repair-invoker and broker-invoker assignments. A successful permission-set
provisioning status is observational evidence only; it is not proof that a
last assignment removal invalidated an already issued session.

## Consequences

- The broad administrator seeds the route but never deploys or operates the
  artifact foundation, broker or PEP.
- The dedicated GUG-376 artifact foundation is created before the normal route,
  is retained as evidence and cannot silently fall back to a legacy bucket or
  signing profile.
- The temporary artifact-bootstrap assignment is removed and its `PT1H`
  credential boundary expires before the normal route can be materialized.
- Bridge-owned cleanup access has a separate sealed outer horizon:
  `CleanupNotAfter = RecoveryNotAfter + 24h`. It survives ArtifactBootstrap
  revocation only to close route/broker seed failure, then a one-way
  `bridge-cleanup-retire` UPDATE removes both cleanup assignments, both cleanup
  permission sets and the read-only management recovery role. `SUCCESS`
  requires just-in-time connected revalidation of route, broker-create and
  broker-protection terminal receipts; otherwise retirement is allowed only
  after the exact cleanup horizon when that access is already inert.
- Human seed identities cannot vary the parameterless broker.
- After seed revocation, the only human authority is invocation of exact
  qualified aliases with `{}`.
- Creator/Executor separation is technical separation, not proof of two-human
  control. Formal production approval remains external to GUG-376.
- No persistent CloudFormation service role is attached to target stacks.
- A repository implementation, successful repair or revoked route does not
  configure GUG-127, implement GUG-128 or authorize production.

## Rollback and uncertainty

Before the administrative seed, rollback is a Git revert. After the route stack
exists but before broker deployment, update the route to `false/false`, prove
zero assignments and wait for session expiry.

After any CreateChangeSet or ExecuteChangeSet dispatch, do not retry. Preserve
the broker attempting/uncertain ledger, inspect the exact provider and
CloudTrail state and require a new reviewed recovery decision. Retained KMS,
DynamoDB, log, function-version and permission-set evidence is not deleted to
make rollback appear clean.

```text
ARTIFACT_FOUNDATION=REPOSITORY_IMPLEMENTATION
ARTIFACT_BOOTSTRAP_BRIDGE=NOT_EXECUTED
FOUNDATION_PUBLISH_BINDING=NOT_MATERIALIZED
BOOTSTRAP_ROUTE_RELEASE=NOT_MATERIALIZED
TEMPORARY_ROUTE=REPOSITORY_IMPLEMENTATION
ADMINISTRATOR_SEED=NOT_EXECUTED
BROKER=NOT_DEPLOYED
TARGET_CHANGE_SETS=NOT_EXECUTED
AWS_CALLS=9
AWS_MUTATIONS=0
PRODUCTION=NO-GO
```

## References

- [ADR-037](ADR-037-founder-bootstrap-single-operator-exception.md)
- [ADR-039](ADR-039-durable-founder-bootstrap-pep.md)
- [ADR-057](ADR-057-bootstrap-plan-permission-repair-pep.md)
- [GUG-376 deployment contract](../docs/deployment/platform-authority-bootstrap-plan-permission-repair.md)
- [GUG-376 operations runbook](../docs/operations/platform-authority-bootstrap-plan-permission-repair.md)
