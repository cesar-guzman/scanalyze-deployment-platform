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
