# Runbook: GUG-365 bounded CloudFormation service-role prerequisite

## Current status

The fixed GUG-363 CloudFormation service role is live-verified absent. The
repository contract now keeps all seven roles, the retained ledger and two
signed functions outside the GUG-363 stack. No GUG-365 IAM/DynamoDB/Lambda write, GUG-357 CloudFormation call,
broker invocation or GUG-215 effect is authorized by this runbook. Production
is **NO-GO**.

The explicitly supplied `AWSReadOnlyAccess` profile is eligible only for
authorized inventory. `ScanalyzeAuthorityBootstrapPlan` is a GUG-206 Plan duty
and is not an eligible GUG-365 executor. Do not substitute a generic
administrator profile.

## Phase 0 — repository and custody gates

Use the exact GUG-365 issue worktree. The implementation must be reviewed,
merged and revalidated on current `main` before a live plan is eligible.

```bash
git status --short --branch
git diff --check
make platform-authority-retirement-service-role-check
make platform-authority-retirement-entrypoint-check
make platform-authority-bootstrap-check
make docs-check
make security-check
```

The private GUG-363 plan and every GUG-365 artifact must remain outside Git in
an approved owner-only local root. Directories are current-owner `0700`; files
are regular one-link `0600` objects; symlinks, hard links, cloud-synchronized
paths, pre-existing outputs and copied historical plans fail closed.

## Phase 1 — build the GUG-363 plan first

Build a new GUG-363 plan from the exact merged GUG-365-hardened template and
the current signed artifact handoff. The plan remains
`deployment_authorized=false` and no AWS client is constructed.

Do not reuse a historical GUG-363 plan: its template digest and resource graph
predate the external-role-and-ledger pivot. Deliver the expected plan digest
independently from the plan file.

Build the dedicated unsigned factory package only through the offline wrapper:

```bash
python3 scripts/deployment/platform-authority-retirement-entrypoint-service-role.py package \
  --private-root "$APPROVED_PRIVATE_ROOT" \
  --source-commit "$EXACT_SOURCE_COMMIT" \
  --runtime-version-arn "$REVIEWED_RUNTIME_VERSION_ARN"
```

The explicit root must already satisfy the owner-only custody checks. The
wrapper refuses links, cloud/FileProvider paths, pre-existing outputs and
unsafe modes; it writes atomically with `0600` files and performs no AWS call.

## Phase 2 — build the GUG-365 plan offline

The GUG-365 compiler consumes only the validated GUG-363 plan and its separately
reviewed expected digest plus a separately validated factory-package signing
contract and expected digest. It must emit a new owner-only plan whose
projections show:

- the exact six managed policies and their canonical documents;
- the exact CloudFormation-only trust policy;
- all seven fixed roles, their trusts, paths, maximum sessions, tags and exact
  main/factory terminal states;
- zero inline policies, exactly one attached policy per main role and the
  proof-bound/detached terminal factory state;
- the retained table, exact resource policy, deletion protection, KMS
  encryption and 35-day PITR contract;
- both dedicated package manifests and exact signed S3 object version, KMS key,
  code digest and Code Signing Config bindings;
- all ordered, non-overlapping authorization phases plus a forward-disabled
  revocation contract, with one attempt per operation and no
  retry/repair/delete;
- an explicit deny-all proof policy, causal factory receipt and consistent
  count-only ledger `Scan` gate proving zero items before activation;
- complete IAM and DynamoDB readbacks and closed pagination; and
- `deployment_authorized=false`, `production=false` and
  `independent_approval_present=false`.

Keep raw account/caller/ARN/policy data private. Only sanitized classifications
and digests may be copied to Linear.

Compile the exact private plan with independently delivered expected digests:

```bash
python3 scripts/deployment/platform-authority-retirement-entrypoint-service-role.py plan \
  --private-root "$APPROVED_PRIVATE_ROOT" \
  --gug363-plan "$PRIVATE_GUG363_PLAN" \
  --expected-gug363-plan-digest "$EXPECTED_GUG363_PLAN_DIGEST" \
  --ledger-factory-signing-contract "$PRIVATE_FACTORY_SIGNING_CONTRACT" \
  --expected-ledger-factory-signing-contract-digest \
    "$EXPECTED_FACTORY_SIGNING_CONTRACT_DIGEST"
```

This command is create-only and refuses to overwrite an earlier output. A new
attempt requires a new reviewed private root; historical artifacts are never
resumed in place.

## Phase 3 — live read-only before-state

This phase requires an explicitly approved read-only profile and `us-east-1`.
STS caller identity is the first AWS call. Collect two complete, stable IAM and
DynamoDB snapshots with all pagination closed.

For every managed policy target, prove exact absence or read:

- policy ARN/path/tags;
- default version ID and complete default document;
- all policy versions; and
- attachment/use counts.

For every one of the seven roles, prove exact absence or read:

- role ARN/name/path/ID, create date and maximum session;
- trust policy;
- tags and permissions boundary;
- zero inline policy names;
- exactly one attached managed policy identical to a main role's final
  boundary, or proof-bound/zero-attachment for the revoked factory role;
  and
- `RoleLastUsed`.

For the retained table, prove exact absence or read its key schema, billing
mode, KMS configuration, deletion protection, class, tags, exact resource
policy, empty contents and 35-day PITR state.

`AccessDenied`, timeout, truncation, malformed pagination or any error other
than exact `NoSuchEntity` is not absence. A mixed/partial/existing drifted
bundle is `DRIFT_BLOCKED_NO_REPAIR`.

## Phase 4 — mandatory owner checkpoint

Stop before the first AWS mutation. The owner must provide a new GUG-365-only
authorization no longer than fifteen minutes and separately deliver its
expected digest. It must name/bind:

- the exact non-production account and `us-east-1`;
- one newly refreshed short-lived least-privilege GUG-365 executor profile and
  exact caller digest;
- complete authenticated effective-policy inventory proving the phase document
  is the sole identity grant and the identical permissions boundary/session
  cap, with zero extra inline, attached or group policies;
- the reviewed merged commit/tree and fresh GUG-363/GUG-365 plan digests;
- all six policy-document digests, seven trust digests, both signed-function
  contracts and retained-table contract digest;
- each phase's complete ordered operation list, executor-policy digest and
  target digests;
- the stable absent-before-state digest;
- one operator/workstation and private ledger digest;
- issue, not-before, expiry and one-attempt semantics; and
- reconcile-only recovery with no automatic rollback or deletion.

The private phase ledger is a create-only causal guard, not an authorization
artifact. Its immutable root binds the exact plan, bundle, target, phase,
executor evidence, host and ordered requests. Claiming it consumes one attempt
through CAS. The runner must persist the next exact operation as in-flight
before calling the injected provider callback, then persist exactly one
outcome and digest-linked receipt before any later operation. The library has
no AWS adapter, creates no session or client and cannot make this phase live.

Each authority has a separate least-privilege executor policy.
`POLICY_FACTORY` can create only the six policies; `FOUNDATION_FACTORY` can
create only the seven roles under the explicit deny-all proof boundary and has
zero DynamoDB authority; `FUNCTION_FACTORY` creates only the inert signed
broker function, while the separate `LEDGER_FACTORY_FUNCTION_FACTORY` creates
the dedicated log group and only the inert, separately packaged/signed,
empty-environment ledger factory. Each certifies its own function after its
distinct authority expires. `LEDGER_FACTORY_ACTIVATOR` can only attach and
activate the factory role; `LEDGER_FACTORY_INVOKER` can only invoke the exact
qualified immutable version synchronously with event `{}` and read it back;
`LEDGER_FACTORY_REVOKER` moves the role to proof before detaching its policy.
Only a causal `CREATED` or `CREATED_RECONCILED` receipt with exact one-create/
one-PITR counts and final empty-table certification permits progress;
`ALREADY_EXACT` blocks for owner recovery. GUG-357
`FUNCTION_CONFIGURATOR` must atomically replace the entire environment under a
fresh checkpoint before `ACTIVATOR` can attach only the plan-bound policies
and set only the plan-bound final boundaries. `REVOCATOR` is separately
authorized and can only move the four effect-capable roles back to the proof
boundary; it cannot perform a forward operation. No session can hold the union
of these authorities. Every authority except the two narrowly scoped
function-factory sessions denies PassRole; each factory session has only its
one exact proof-bound role edge. Every authority denies CloudFormation,
AssumeRole, service-role assumption, Identity Center mutation, broker
invocation, update, delete, detach and unrelated creation. The GUG-357 and
GUG-206 profiles are not reusable substitutes.

The phase JSON is not safe as an additive identity policy. Before every phase,
provider-backed evidence must prove it is both the sole grant and the maximum
effective-authority cap for a fresh unchained session (or a trusted broker
enforces the identical document as a session cap). Missing, incomplete, stale
or extra policy evidence is `STOP_NO_MUTATION`.

## Phase 5 — future create-only execution

This phase is currently `NOT_AUTHORIZED`. When a later task carries the exact
checkpoint, the implementation must:

1. validate plan, authorization, expected digests, custody and expiry before
   constructing effect-capable clients;
2. call STS first and match the exact caller/account;
3. repeat the complete IAM/Lambda/table absent snapshot for the active phase;
4. consume the private attempt ledger for the authorized phase;
5. revalidate authorization immediately before every ordered write and commit
   the operation-specific pre-invocation CAS transition;
6. call each operation at most once through the injected callback with SDK
   retries disabled, then durably record its single outcome and receipt before
   continuing;
7. immediately perform complete readback after every conclusive response;
8. create each signed function at most once under its separate function-factory
   authority with an empty environment, wait boundedly for Active/Successful,
   pin runtime/concurrency, certify its complete inert state, and expire that
   authority; the ledger-factory phase also creates and certifies only its
   dedicated log group;
9. activate only the factory role, then use a distinct invoke-only session to
   call the exact immutable version with `InvocationType=RequestResponse`,
   payload `{}` and SDK retries disabled; consume the attempt ledger before the
   call and never invoke again after an ambiguous outcome;
10. inside that signed runtime, call `CreateTable` once with the canonical
    resource-policy JSON string in the same request, poll only read APIs until
    exact `ACTIVE`, call `UpdateContinuousBackups` once, and require exact
    controls, policy revision and empty count-only `Scan`;
11. revoke the factory to proof first, detach second, expire the invoker and
    certify the terminal factory state before main activation;
12. require a fresh GUG-357 configuration checkpoint to atomically replace the
    entire environment using the observed RevisionId, then certify and expire
    that authority before any role activation or CreateStack; and
13. close the current session and obtain a fresh checkpoint before the next
   phase.

If any response is ambiguous, stop. Do not infer success, retry, continue to a
dependent write, repair, delete or recreate. Run only the read-only reconcile
path under separately allowed reads. A restart that observes an in-flight
operation also enters read-only reconciliation; it must not call the provider
again. Resealing a modified record, replaying a consumed root or presenting
only equal final digests is not acceptable causal evidence.

## Phase 6 — certification and handoff

Two stable final snapshots must exactly match every policy version/document,
policy tag, trust statement, role tag, boundary, zero-inline state, sole main
attachment, proof-bound/detached factory state, path/session duration, both
function surfaces and expected unused state, plus the complete retained-table/
resource-policy/PITR contract. Provider equivalence without the
causal consumed phase ledgers does not prove that this run created the bundle.
Certification must validate all eight forward-phase ledgers in exact plan
order, including each independently delivered root, claim nonce and terminal
receipt binding; partial phase evidence is not a bundle receipt.

Publish a sanitized terminal manifest to GUG-365 and keep raw receipts private.
The terminal status may be `LIVE_BUNDLE_CERTIFIED_NO_STACK_EXECUTION`; it must
not claim GUG-357, GUG-215, deployment or production completion.

GUG-357 then starts a new continuation, rebuilds its own fresh read-only
checkpoint and revalidates the bundle. It never reuses GUG-365 evidence as a
current identity/session claim.

## Recovery

| Observed state | Classification | Action |
|---|---|---|
| All targets absent, no fresh authorization binding | `NOT_AUTHORIZED` | Await a fresh checkpoint |
| All targets absent, fresh exact authorization binding | `ABSENT_READY` | Claim the phase ledger, then ordered creates |
| Exact full bundle, causal ledger complete | `EXACT_PRESENT_NO_TOUCH` | Certify and return to GUG-357 |
| Exact full bundle without causal ledger | `PREEXISTING_NO_TOUCH` | Preserve; separate owner decision |
| Partial or drifted bundle | `DRIFT_BLOCKED_NO_REPAIR` | Open a new recovery issue |
| Any write attempted with unknown outcome | `UNCERTAIN_RECONCILE_ONLY` | Read-only reconcile; never retry |

This runbook authorizes no cleanup. Deleting a role or managed policy, changing
trust/boundaries, rolling back, repairing, or recreating requires a new atomic
issue and a separately explicit destructive checkpoint.

## References

- [ADR-052](../../ADR/ADR-052-gug357-cloudformation-service-role-boundaries.md)
- [Deployment contract](../deployment/platform-authority-retirement-entrypoint-service-role.md)
- [Threat model](../security/gug365-retirement-entrypoint-service-role-threat-model.md)
