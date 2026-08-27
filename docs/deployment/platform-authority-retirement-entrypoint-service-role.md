# GUG-365 bounded CloudFormation service-role contract

## Status

GUG-365 is the atomic prerequisite lane for GUG-357. It defines the exact IAM
bundle required by the merged GUG-363 direct entrypoint materializer. This
repository package does not itself authorize an AWS login or mutation.
Production remains **NO-GO**.

The earlier role-only design is unsafe. The final design precreates seven
roles and two inert signed Lambda functions in GUG-365. A dedicated immutable
factory—not a human IAM session—creates the retained DynamoDB ledger with its
resource policy in the same `CreateTable` request. The GUG-363 stack has no
IAM, DynamoDB or Lambda Function resource and cannot submit role,
ledger-policy or function-configuration documents.

## Repository surface

| Surface | Purpose | Live authority |
|---|---|---|
| `ADR/ADR-052-gug357-cloudformation-service-role-boundaries.md` | Architecture and evidence boundary | None |
| `bootstrap/cfn-platform-authority-change-set-retirement-ledger.yaml` | References exact precreated role ARNs and ledger name | Template only |
| `policies/iam/platform-authority-gug365-*-boundary.json` | Service-role and role/class-specific maximum permissions | Policy source only |
| `tooling/platform_authority_retirement_ledger_factory.py` | Immutable one-shot table/PITR factory | No live authority by itself |
| `tooling/platform_authority_retirement_ledger_factory_package.py` | Dedicated reproducible Lambda package | Offline package only |
| `tooling/platform_authority_gug365_phase_execution_ledger.py` | Create-only durable phase ledger, CAS transitions and injected-callback runner enforcement | Library only; no AWS adapter or client |
| `tooling/platform_authority_retirement_entrypoint_service_role_materializer.py` | Deterministic compiler, validator and state classifier | Offline/injected clients only |
| `scripts/deployment/platform-authority-retirement-entrypoint-service-role.py` | Owner-only package/plan wrapper with atomic `0700`/`0600` custody | Offline only; no AWS client |
| `tests/test_deployment/test_gug365_*.py` | Exploit, determinism, drift and one-attempt controls | Synthetic only |
| `docs/operations/platform-authority-retirement-entrypoint-service-role.md` | Owner checkpoint and future live procedure | Documentation only |

## Fixed IAM bundle

All managed policies use path `/scanalyze/platform-authority/`. The bundle has
six managed permissions policies:

- one for the CloudFormation service role;
- one for `ScanalyzeGug215BrokerExecution`;
- one for `ScanalyzeGug215ClassifierInvoker`;
- one for `ScanalyzeGug215ApproverInvoker`; and
- one deny-all boundary shared by the two GUG-217 proof roles; and
- one exact identity/boundary policy for the dedicated ledger-factory role.

The fixed service role is pathless because GUG-363 already binds its exact ARN.
It has:

- one trust statement naming only `cloudformation.amazonaws.com`;
- path `/` and maximum session duration 3600;
- the exact GUG-365 service-role permissions boundary;
- exact repository/source/issue/environment tags;
- zero inline policies; and
- exactly one attached managed identity policy, identical to its boundary.

The main workload managed policies are used both as permissions boundaries and
the only attached identity policies on their exact roles. The factory policy
is attached only during its bounded invocation window; afterward the factory
role is proof-bound and has no attachment. Inline policies are forbidden.
GUG-363 consumes those main role ARNs and the precreated ledger without owning
or mutating them.

## Plan dependency and deterministic projection

The GUG-365 compiler accepts only:

1. a validated private GUG-363 plan;
2. an independently delivered expected GUG-363 plan digest;
3. a separately packaged/signed ledger-factory artifact contract; and
4. repository-owned package/boundary/policy sources from the exact clean
   commit.

No account, Region, role name, boundary name, S3 locator or KMS override is a
CLI input. The compiler imports only the signed deployment destination from the
GUG-363 plan:

- exact bucket;
- exact key;
- exact version ID;
- exact KMS key ARN; and
- exact Lambda Code Signing Config ARN.

It rejects either unsigned source as an effect-capable object. It binds the
GUG-363 durable pre-function projection—not its expiring single-operator
values—the fourteen-resource graph, both signed object versions and both code
digests. Every package manifest, trust/policy, operation list and target
receives a canonical digest. The emitted plan always states
`deployment_authorized=false`.

## Policy boundaries

### Workload roles

The workload boundaries cap effective permissions even if a later IAM
identity policy is broadened. The GUG-363 template cannot submit any role or
policy document:

- broker: only the reviewed retained-shell reads, exact Change Set retirement,
  exact ledger item, exact Identity Center exchange/proof edges, provider
  readback and exact log streams; effectful broker calls require the exact
  Lambda source function;
- classifier: only the exact qualified `single-classify` Function URL path;
- approver: only the exact qualified `single-retire` and `single-reconcile`
  Function URL paths; and
- proof: no action.

A common union boundary is invalid. A missing or swapped boundary is drift.

### CloudFormation service role

The service-role managed policy is both its permissions boundary and its only
identity policy. It allows only the provider calls required to materialize the
reviewed fourteen-resource Version/Alias/URL/Permission/Logs graph. It has no
IAM, DynamoDB, `iam:PassRole`, `lambda:CreateFunction`, S3 or KMS authority and
cannot update the precreated function's code, configuration or role, tag it,
delete it or invoke it.

AWS does not expose request condition keys that bind `PublishVersion` to a
specific version number or `CreateAlias` to a specific alias name. Those two
actions are therefore a declared non-production residual, not an exact-name
server-side control. The service role is activated only for the one reviewed
stack-create window; exact final inventory and separately authorized
proof-bound revocation of the retained service role are mandatory. Extra
versions or aliases are drift and never qualify as completion.

Provider actions and condition keys are a closed reviewed list, not a generic
`service:*` grant. Any required action discovered by simulation or live
readback must return through a new repository review; it must not be added at
runtime.

## GUG-390 guarded live-provider boundary

GUG-390 implements the smallest repository interface needed to connect the
reviewed GUG-365 plan and phase ledger to a separately authorized live
provider. This is a mechanism contract, not a claim that the provider has been
run against AWS. Repository validation uses only injected clients and creates
no AWS session or client.

The implemented closed command surface is:

| Command | Permitted responsibility |
| --- | --- |
| `inventory` | Take two complete, stable, paginated read-only snapshots and compare their canonical IAM/Lambda/Logs/DynamoDB/S3/KMS projections with the plan. |
| `execute-phase` | Execute exactly one named, checkpoint-bound phase in one fresh process; it cannot select or enter a later phase. |
| `reconcile` | Resolve only a recorded ambiguous/in-flight operation with provider reads; it cannot call the write callback. |
| `certify` | Validate the complete causal receipt/readback chain and emit a sanitized manifest; it cannot mutate AWS. |

The entry point is
`scripts/deployment/platform-authority-gug390-live-provider.py`. Repository
and CI validation use injected fakes only and must finish with all of the
following boundaries:

Before any repository module is loaded, the entry point rejects the four
documented Python import/configuration variables, any preloaded or preempting
`tooling` module, and any preloaded boto3/botocore module. It then replaces the
import finder/hook state
with the closed built-in, frozen, path and filesystem loaders and removes every
`sys.path` entry that resolves inside the repository. The package and three
entry modules are loaded explicitly from the Git-blob manifest instead of
through the repository root. The manifest-bound loader always reads and
compiles reviewed `.py` bytes; ignored timestamp bytecode caches, extensions
and sourceless modules are not admissible for `tooling`.
An unimported `tooling` copy installed under the isolated interpreter's exact
`purelib`/`platlib` root may remain discoverable so pinned site dependencies
stay available, but it is never executed: the repository package still enters
`sys.modules` only through the manifest-bound loader. Arbitrary import roots
and every preloaded `tooling` module remain inadmissible. The exact interpreter
site root remains admissible when a clean-clone `.venv` places it below the
repository; sibling repository paths are still removed.
`PYTHONPATH`, `PYTHONHOME`, `_PYTHON_PROJECT_BASE` and
`_PYTHON_SYSCONFIGDATA_NAME` all fail closed before site-root discovery.
Every transitively loaded `tooling` module's `__file__`, import origin and
package path must remain below that root. The Git root, clean tree and exact
`origin/main` commit are validated before provider/executor import.
Operational invocations must therefore unset all four variables and use Python
isolated, no-site mode as shown in the runbook. `-I -S` is required for both
import-inert checks and authorized read-only commands. The reviewed SDK is
loaded only from the separately bound SDK runtime root after the source,
request, and provider gates; ambient site packages are not an authority.

- `AWS_CALLS=0` and `AWS_MUTATIONS=0`;
- `LIVE_PROVIDER_EVIDENCE=false` and `status=LIVE_PROVIDER_NOT_PROVEN`;
- `deployment_authorized=false`, `deployment_status=NOT_DEPLOYED` and
  `production_status=NO-GO`.

### Exact owner, request and runtime bindings

The sanitized public record carries three different bindings and never aliases
them:

- `owner_checkpoint_digest` seals the fresh owner checkpoint;
- `live_request_digest` is the public name for the private live request's
  `request_digest`; and
- `checkpoint_digest` remains the command-result checkpoint (inventory facts,
  terminal ledger state or the independent ACTIVATOR checkpoint).

For an execution claim, the ledger's optional GUG-390 `execution_context`
binds `issue=GUG-390`, `owner_checkpoint_digest`, `live_request_digest`, the
nullable `activator_checkpoint_digest`, and a `context_digest` over those four
fields. Legacy GUG-365 claims omit `execution_context`; omission is visible and
cannot be upgraded to GUG-390 evidence. A completed provider operation may
carry `durable_provider_evidence`, binding its operation/request/result,
identity receipt, transcript, execution context and optional causal receipt.
Legacy outcomes and a hard-crash outcome may omit it, but an omitted evidence
record is never equivalent to a null or complete live receipt and is not
certifiable.

A green test, merge or repository manifest cannot promote any of those values
to live evidence. A separately authorized live process must fail before client
construction unless it has the exact merged commit/tree and private plan digests, an
explicit non-default profile and `us-east-1`, a fresh phase-specific owner
checkpoint and validity window, complete custody bindings, and a stable
before-state. The checkpoint binds the exact STS principal digest and direct
SSO role-name digest in addition to the profile/account/region. STS caller
identity must be the first provider call and must match those bindings. The
validity window is rechecked immediately before initial STS and every later
SDK call/page. Ambient/default/chained credentials, missing pagination,
drift, stale evidence, extra effective authority or an expired checkpoint are
`STOP_NO_MUTATION`.

### GUG-393 private input discovery boundary

GUG-393 closes only the missing-input preflight for the GUG-392 read-only
lane. It does not deploy, mutate, accept staging, or certify production. The
reviewed GUG-363 and GUG-365 plans are revalidated and used only as fixed
selectors; none of their historical classifications is accepted as current
AWS truth. A source contract can be minted only in-process from both complete
validated plans.

The preflight requires two different direct SSO profiles, one per account.
Both profiles are non-default, unchained, read-only, exact-account and
exact-principal bound. Names containing administrator, bootstrap, seed,
deploy, or destroy authority are rejected. Every session performs
`sts:GetCallerIdentity` first, has SDK retries disabled, and is restricted to
the existing closed List/Get/Describe inventory surface in `us-east-1`.

One owner-supplied global budget covers both domains and SSO credential
vending. The implementation hard ceilings are 5,000 provider calls, six
`sso:GetRoleCredentials` attempts, 5,006 total network attempts, 4,300 page
calls, 256 KiB per projected response, and 32 MiB total projected response
bytes. The owner may choose lower limits. The owner also supplies a
digest-bound, time-bounded cost model with fixed, per-attempt, and per-byte
upper bounds; repository code invents no cloud price. Reservation occurs
before a provider call and projected bytes are charged before a response can
enter evidence.

The workflow has two distinct owner approvals:

1. a maximum 15-minute request/checkpoint binds source commit/tree, host,
   private root, reviewed SDK runtime, both exact profiles, and the global
   call/cost budget;
2. after two stable snapshots per domain, a new maximum 15-minute decision
   binds the exact private proposal digest before GUG-392 inputs or plans are
   materialized. Approval must occur within 15 minutes of proposal creation.
   Its `approved_at`/`expires_at` values become a fresh, separate GUG-392 plan
   window rather than reusing the discovery window.

Identity Center exact discovery transitions from its closed discovery policy
to a target-derived exact policy within each capture. This keeps the maximum
session topology at two Authority sessions plus two Identity Center
discovery/exact pairs: six possible SSO credential vends. Absence remains one
Identity Center session per capture. Generated Identity Center roles are
cross-certified against their fresh inline-policy and trust-policy digests;
partial, colliding, inaccessible, unstable, or stale state stops with no
materialization.

The execution capability authorizes each `(domain, capture, stage)` only once
and only after execution starts. Authority and Identity discovery sessions
must use the exact policy digests derived from the sealed request. An Identity
exact policy cannot be registered from caller-supplied targets: the concrete
discovery reader first seals a one-shot attestation over the successful STS
and complete discovery operations and their normalized output. The transition
then recomputes targets from that attested output before authorizing the exact
policy digest.

All requests, checkpoints, claims, snapshots, proposals, decisions, inputs,
plans, and manifests are create-only owner-private artifacts under the
existing 0700-directory/0600-file custody rules. The proposal, decision,
approved inputs, plans, and commit-marker manifest use fixed canonical
filenames; callers cannot select alternate names to replay one approval into
a second materialization. Request/checkpoint names cannot collide with any
reserved lifecycle output, and every fixed downstream target must be absent
before request persistence and again before the executor claims or performs a
provider call. Decision, persistence, and final materialization must remain on
the proposal's exact operational host and exact source commit/tree; moving the
private root to an equivalent path or advancing `origin/main` requires a new
request. Before both the owner decision and final materialization, the library
rereads the canonical persisted proposal, original request/checkpoint, fixed
claim, and all four canonical snapshots. It validates every seal and binding,
then reconstructs the complete proposal at its historical creation time and
requires exact equality. The sealed timeline must also order the claim before
every snapshot identity observation and the latest observation no later than
proposal creation. A caller-supplied or self-resealed proposal, including
one whose plans were recomputed from altered profile/principal inputs, cannot
replace that evidence chain. The public receipt contains
only source and evidence digests, scalar budget counters, the modeled cost
upper bound, and truthful no-mutation/no-production flags. A consumed claim,
expired window, replaced file, copied host binding, budget exhaustion, or
incomplete pagination cannot be retried; create a fresh request instead.

Even a valid GUG-393 receipt and approved GUG-392 plans leave
`two_human_status=NOT_PROVEN`, `deployment_authorized=false`, and
`production_status=NO-GO`. GUG-127 staging certification and GUG-128's
independently authorized production pilot remain separate gates.

### Fresh `origin/main` source custody

The CLI compares `HEAD` with the local `refs/remotes/origin/main`, but that
local comparison is not freshness evidence. Before the owner creates the
checkpoint and within the same maximum 15-minute request window, the operator
must run a successful direct fetch and exact readback:

```console
git fetch --no-tags origin refs/heads/main:refs/remotes/origin/main
git rev-parse --verify HEAD^{commit}
git rev-parse --verify HEAD^{tree}
git rev-parse --verify refs/remotes/origin/main^{commit}
git rev-parse --verify refs/remotes/origin/main^{tree}
test "$(git rev-parse --verify HEAD^{commit})" = "$(git rev-parse --verify refs/remotes/origin/main^{commit})"
test "$(git rev-parse --verify HEAD^{tree})" = "$(git rev-parse --verify refs/remotes/origin/main^{tree})"
git diff --quiet
git diff --cached --quiet
test -z "$(git ls-files --others --exclude-standard)"
```

The fetched `origin/main` commit must equal `HEAD`; its tree must equal the
`source_tree_sha` sealed into both request and checkpoint. Record the fetch
time and exact commit/tree in the private operator evidence. A cached ref,
failed fetch, fetch outside the request window, dirty/untracked file, or any
source change after fetch is `STOP_NO_MUTATION`; refresh and issue a new owner
request rather than reusing the old digest.

Inventory discovery may emit a review-required digest, but it cannot enable a
write until the owner request independently binds both exact snapshot digests
and the complete facts digest and the live semantic projection matches the
sealed plan. Stable-but-wrong S3 content, KMS metadata, code-signing policy,
IAM graph, Lambda configuration, log controls or DynamoDB controls is drift,
not `ABSENT_READY` or `EXACT_PRESENT_NO_TOUCH`.

Each `execute-phase` process accepts one explicit phase, creates one fresh
phase-specific session, consumes one phase ledger root, and exits after that
phase becomes terminal or ambiguous. A phase may contain several ordered
top-level operations, but each top-level provider/SDK operation has one local
invocation with retries disabled and a durable pre-invocation transition.
Every successful mutation is followed by its closed canonical readback
sequence. Create-policy, create-role, create-function and create-log-group
readbacks include their documents/configuration and tags; a missing field or
mismatch after a delivered write is `AMBIGUOUS`, never success.
`LEDGER_FACTORY_INVOKER` is one such top-level invocation; its signed runtime's
internal `CreateTable` and PITR operations remain governed by the separate
causal factory receipt and exact call counts. Provider delivery can still be
ambiguous, so “one invocation” is not proof that an effect occurred exactly
once.

Crash recovery follows the durable boundary, not process memory:

| Last durable boundary | Restart rule |
| --- | --- |
| Before the phase claim or `OPERATION_IN_FLIGHT` CAS | No provider operation may have started. Re-evaluate the exact request and authority window; never infer progress from a missing file. |
| `CLAIMED` after one or more complete outcomes, with no in-flight operation | Resume only the exact `next_operation_sequence` under the same execution context, request, claim nonce, caller/session/authority and still-valid window. Never replay a recorded outcome. Expiry stops with no new effect and requires a recovery issue. |
| `IN_FLIGHT`, or provider response/readback received but outcome/evidence CAS missing | Treat delivery as ambiguous. Do not call the write again or advance; only the closed read-only reconciliation path is admissible. |
| Outcome and `durable_provider_evidence` committed, but private/public output missing | The ledger is authoritative. Recreate no provider effect. A non-terminal claim may continue only under the exact same-context rule above; a terminal record is inspected, not replayed. |
| Outcome exists without `durable_provider_evidence` | Preserve the record as crash evidence. It cannot certify live execution or be silently backfilled from process memory. |

An ambiguous or in-flight result is `UNCERTAIN_RECONCILE_ONLY`. The process
must stop, preserve its artifacts and allow only the read-only `reconcile`
path. Reconciliation cannot replay, repair, adopt, delete, roll back or advance
to another phase. The caller cannot select an unrelated readback: the executor
derives the closed read contract from the ledger's exact ambiguous phase,
operation sequence and request digest, binds both expected state digests, and
requires two equal captures. Fresh STS continuity is checked before reads and
again before CAS. `lambda:InvokeFunction` ambiguity has no sufficient causal
read contract and therefore remains unresolved. Any unstable or
non-conclusive readback requires a new recovery issue and owner decision.

`RECONCILED`, including `EFFECT_PROVEN`, is a terminal recovery classification
only. It does not satisfy predecessor progression, cannot start the next phase,
and is excluded from the certification bundle. A separate recovery issue and
fresh owner decision must define any later action; GUG-390 never converts a
reconciliation receipt into forward authorization. This restriction concerns
the phase-ledger status `RECONCILED`; it does not rename the separate,
independently validated ledger-factory receipt outcome `CREATED_RECONCILED`.

`certify` requires independent digests for all eight `CONSUMED` private
phase-run files, both final inventory snapshots and the GUG-357 ACTIVATOR
checkpoint. It recomputes each private seal, revalidates the ledger-factory
causal receipt and binds the receipt's provider-result digest to the consumed
ledger outcome.

`ACTIVATOR` must fail closed until every predecessor phase is `CONSUMED` with
its complete durable evidence (`RECONCILED` is expressly excluded), the
accepted ledger-factory causal receipt is `CREATED|CREATED_RECONCILED`, the
factory role is proof-bound and detached, and an independently produced
GUG-357 `FUNCTION_CONFIGURATOR` checkpoint and provider readback are supplied.
GUG-390 cannot create that GUG-357 evidence and does not authorize
CloudFormation `CreateStack` or any other GUG-357 effect.

Repository rollback is a revert of the reviewed GUG-390 change. There is no
automatic live rollback: uncertainty and drift are preserved for read-only
reconciliation, while remediation, revocation or deletion requires its own
issue and authorization. Until an exact live checkpoint and conclusive
provider evidence both exist, the deployment decision remains
`production_status=NO-GO`.

## Ordered future prerequisite mutations

After exact-head review/merge, GUG-365 separates all effect capabilities. Each
forward phase has a new checkpoint and a different session; the main
revocator is a forward-disabled emergency contraction path:

1. `POLICY_FACTORY` creates the six fixed managed policies.
2. `FOUNDATION_FACTORY` creates all seven roles under the deny-all proof
   boundary and has zero DynamoDB authority.
3. `FUNCTION_FACTORY` creates only the exact signed broker with an empty
   environment and proof-bound role, then pins runtime/concurrency and
   certifies its closed surface.
4. `LEDGER_FACTORY_FUNCTION_FACTORY` creates the dedicated log group and only
   the exact signed ledger factory with an empty environment and proof-bound
   role, then pins runtime/concurrency and publishes/certifies one immutable
   version. The factory has no alias, URL, resource policy or event source.
5. `LEDGER_FACTORY_ACTIVATOR` attaches the exact factory policy while proof
   remains active, then changes only that role to its final boundary.
6. `LEDGER_FACTORY_INVOKER` can invoke only the exact immutable version with
   synchronous `RequestResponse` and event `{}`. The signed runtime issues at
   most one atomic `CreateTable(ResourcePolicy=...)`, one PITR update and
   bounded read-only certification.
7. `LEDGER_FACTORY_REVOKER` moves the factory role back to proof first and
   detaches its policy second. Main activation is impossible before this
   checkpoint and a causal `CREATED|CREATED_RECONCILED` receipt with call counts
   `1/1`; `ALREADY_EXACT` is not eligible.
8. GUG-357 `FUNCTION_CONFIGURATOR` atomically replaces the complete environment
   under a fresh exception-bound checkpoint and stable provider readback.
9. `ACTIVATOR` attaches each main role's exact managed policy and moves the four
   effect-capable roles from the proof boundary to their final boundary. The
   two proof roles remain deny-all.
10. `REVOCATOR`, if separately authorized, can only move the service, broker,
   classifier and approver roles back to the proof boundary. It cannot attach,
    detach, create, delete or resume activation.

For the GUG-357 handoff, the service-role portion of step 10 is not optional:
after conclusive stack certification it closes the temporary provider window.
If stack creation is ambiguous, only read-only reconciliation may determine
whether revocation is safe; there is no blind retry or automatic rollback.

No authority can reuse another authority's session or hold their union. Final
main-role state has zero inline policies and exactly one attached managed
policy per role, identical to its permissions boundary; the retained factory
role is proof-bound with no attachment. Every
operation is plan-bound, has one attempt and no SDK retry, repair, deletion or
automatic rollback. The proof policy contains an explicit deny-all statement,
not an empty-document convention. Factory readback also requires a consistent
count-only `Scan` proving the new ledger is empty. A partial or
ambiguous bundle is preserved for read-only reconciliation and a separate
recovery issue.

Each phase document must be proved as both the executor's sole identity grant
and its identical maximum-permissions cap, with a complete effective-policy
inventory and zero extra inline, attached or group grants. A normal additive
identity-policy attachment is ineligible. The revocator also verifies the
proof policy is still default `v1`, has only version `v1`, and has the exact
deny-all document digest before its first boundary write and after its last.

### Durable phase execution ledger

Every separately authorized phase is guarded by a create-only durable ledger
whose immutable root binds the exact plan, bundle, target, executor evidence,
host, validity window and ordered request digests. A compare-and-swap claim can
consume that root once. Before an injected provider callback is allowed, the
runner persists a distinct pre-invocation CAS transition for the next exact
operation; after the callback it persists one conclusive or ambiguous outcome
and its digest-linked receipt. Replay, skipped sequence, resealed root drift,
receipt-chain drift and a second write attempt fail closed.

The runner is an enforcement library with an injected callback. It constructs
no AWS client, chooses no profile and grants no live authority. An ambiguous
provider outcome stops the phase and permits only a separately authorized,
read-only reconciliation record; it never permits a blind retry. A downstream
classifier must receive and validate the independently delivered initial-root
binding and the terminal receipt binding, not merely compare naked final
digests. Bundle certification requires the complete ordered causal evidence
for all eight forward phases; one valid phase record cannot stand in for the
bundle.

## State classifications

| Classification | Meaning | Allowed next action |
|---|---|---|
| `ABSENT_READY` | Two stable complete reads prove every target absent; authorization is fresh | Claim ledger, then ordered creates |
| `EXACT_PRESENT_NO_TOUCH` | Every policy/role/readback matches the plan and the causal ledger digest is exact | Emit evidence only |
| `PREEXISTING_NO_TOUCH` | Exact provider state lacks the causal ledger binding | Preserve; owner decision only |
| `DRIFT_BLOCKED_NO_REPAIR` | Any target is partial, foreign, extra or different | Stop; read-only evidence only |
| `UNCERTAIN_RECONCILE_ONLY` | A write was attempted without a conclusive provider result | Reconcile reads only |
| `NOT_AUTHORIZED` | No fresh exact GUG-365 checkpoint | No AWS mutation |

## Handoff to GUG-357

GUG-365 completion can produce a sanitized terminal manifest and a private
provider-backed bundle digest. It does not authorize `CreateStack`. GUG-357
must independently refresh all six managed-policy default versions, all seven
roles' trust/boundary/tags/zero-inline/exact terminal state, both functions,
the retained table/resource-policy/PITR state, and the operator's one-role-only
`PassRole` edge immediately before issuing its own checkpoint.

Repository success is `REPOSITORY_VALIDATED_NO_LIVE_EXECUTION`, not live
certification.

## References

- [ADR-052](../../ADR/ADR-052-gug357-cloudformation-service-role-boundaries.md)
- [Operations runbook](../operations/platform-authority-retirement-entrypoint-service-role.md)
- [Threat model](../security/gug365-retirement-entrypoint-service-role-threat-model.md)
- [GUG-363 deployment contract](platform-authority-retirement-entrypoint-materialization.md)
