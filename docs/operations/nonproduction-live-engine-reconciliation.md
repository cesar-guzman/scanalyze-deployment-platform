# Non-Production Live Engine Execution and Reconciliation Runbook

## Scope

This runbook governs the explicitly authorized GUG-125 exercise in isolated
non-production accounts. It never authorizes production, customer data,
operator-laptop apply, automatic recovery, force-unlock, migration, redrive, or
destruction outside a separately reviewed cleanup plan.

## Entry gate

Stop before OIDC or Terraform unless every item is proven:

- GUG-121 through GUG-124 are merged and verified on the selected main SHA;
- the shared-services account, OIDC provider, deployment-scoped orchestrator,
  platform-authority record, registry, and execution-ledger table exist;
- each destination has authoritative registry and ACCOUNT_READY v2 records,
  backend/lock/contract infrastructure, a dedicated versioned saved-plan
  bucket, exact terminal roles, and matching KMS/S3/DynamoDB policies;
- the deployment-scoped GitHub Environment is protected, self-review and bypass
  are disabled, and a named independent User reviewer differs from initiator;
- valid short-lived identities exist for shared services and each destination;
- one complete GUG-124 release is signed and addressable by immutable digest;
- synthetic data, cost ceiling, region, environment, cleanup, and destroy scope
  are explicitly authorized;
- local and CI gates pass for the exact commit.

If an SSO session is expired, a platform authority is absent, an account is
empty/unbound, or the independent reviewer cannot be proven, classify the run
`BLOCKED`. Do not substitute a destination account as shared services and do
not infer ACCOUNT_READY from an empty account.

## Protected dispatch and private-input custody

The live path is available only through `nonprod-release.yml` on the protected
`main` ref. It is restricted to `logical_environment=dev`; staging and
production are rejected before credentials. A local invocation of Terraform,
`nonprod-live-controller.py`, or the saved-plan shell runner is unsupported and
cannot be used as deployment evidence.

Before a plan or apply dispatch, record the current authorization tuple:

- exact reviewed `main` SHA and Git-safe request path;
- deployment, DEV destination account, separate platform-authority account,
  Region, protected Environment and target layer;
- release, execution, change and private-claim digests;
- `plan` or `apply`, with exact plan-record and reviewer-packet digests for
  apply only;
- maximum cost, start/expiry, rollback owner and cleanup boundary; and
- initiator plus an independent plan-specific approver for apply.

The workflow accepts only the private claim digest. It never accepts the
private root or individual source paths. The protected Environment supplies the
live-input bundle plus the collector App private-key transport and its public
App ID variable; neither private value is authority without the exact sealed
bindings and verified App installation. The materializer decodes the bundle
only into the canonical `$RUNNER_TEMP/scanalyze-live-inputs` root. The encoded
value is limited to 48,000 bytes (36,000 decoded); oversize input fails closed.

The typed selectors derive only
`deployment/live-input-claims/<deployment_id>/<layer>/<operation>.json`, and
that file must be tracked with working-tree bytes equal to exact `HEAD`.

The unprivileged, Environment-gated pre-OIDC step invokes:

```bash
python scripts/deployment/nonprod-live-input-materializer.py materialize \
  --private-root "$RUNNER_TEMP/scanalyze-live-inputs" \
  --deployment-id "$DEPLOYMENT_ID" \
  --layer "$TARGET_LAYER" \
  --operation "$LIVE_OPERATION" \
  --request-path "$REQUEST_PATH" \
  --claim-digest "$LIVE_INPUT_CLAIM_DIGEST"

python scripts/deployment/nonprod-live-input-materializer.py validate \
  --private-root "$RUNNER_TEMP/scanalyze-live-inputs" \
  --deployment-id "$DEPLOYMENT_ID" \
  --layer "$TARGET_LAYER" \
  --operation "$LIVE_OPERATION" \
  --request-path "$REQUEST_PATH" \
  --claim-digest "$LIVE_INPUT_CLAIM_DIGEST"
```

Continue only if materialization and validation succeed with a well-formed
receipt digest. Within the same protected job, the staging root is deleted and
the protected root is independently rematerialized. It requires the same claim
and stable sealed-authority projection and obtains another complete current
GitHub snapshot before OIDC.
The full receipts are expected to differ by observation time. Missing
transport/source data, digest/schema/tuple drift, backend denial, invalid
contract binding, an existing output or a mismatched stable projection is
`BLOCKED`. Never reconstruct, overwrite or hand-edit the root. Never use a
workflow artifact, repository file, mutable variable or caller-supplied path as
a replacement.

In both passes, require the materialized release, Region, destination and
platform-authority accounts, Environment-configuration digest, terminal roles,
orchestrator role and repository numeric identities to equal the dispatch and
protected Environment values. Stop before OIDC on any mismatch.

Both phases must report `LIVE_INPUTS_MATERIALIZED`, `oidc_authorized=true`, and
`terminal_operation_authorized=false`. Apply also requires
`durable_readback_required=true`, which permits only the controller's exact
durable plan/approval/ledger readback before any possible mutation. It is not an
apply authorization by itself.

Do not place Terraform state in the Environment secret. The Plan terminal role
reads and brackets the exact backend VersionId, lineage, serial, digest, and
size at action time, then records them in the saved plan. Apply must read the
same state again before fetch and immediately before execution. Any difference
is `BLOCKED`; operators never refresh a short-lived state JSON inside the
transport bundle.

Before apply OIDC, the workflow runs `nonprod-live-approval.py materialize` and
`validate`. Through the same verified App token, it performs exactly two
read-only GitHub REST requests: exact workflow-run metadata and that run's
Environment approval history. It stores
one create-only mode-`0600` sanitized record at
`materialized/controller/github-approval.json`. Continue only when
the numeric approver is distinct from the numeric initiator, equals the
configured `SECOND_P0_REVIEWER_ID`, and is the only unique approver represented;
the repository/run/Environment tuple and exact reviewer-packet digest must match
and the five-minute observation evidence must be current. Live execution accepts
only run attempt `1`; start a new workflow run instead of rerunning an earlier
attempt. Never persist the token, raw API responses, reviewer login, comments or
URLs. Revoke the App token with confirmed HTTP 204 and remove its private
material before OIDC; never pass it to Terraform or the controller.
Missing, self-issued, ambiguous, stale, packet-mismatched, or tuple-mismatched
evidence is a pre-OIDC stop.

Before dispatching Apply, review the Plan job's schema-validated sanitized
reviewer packet. Its digest covers the durable plan record, plan hash/size,
complete state-binding digest, cost binding, and canonical resource/output
action manifests. Copy that exact packet digest and the exact plan-record digest
into the Apply dispatch; neither the GitHub summary nor an unbound approval is
durable mutation authority.

The workflow then obtains the exact 3,600-second platform-authority
control-plane OIDC session and vends a separate one-hour destination terminal
role session for one phase. The protected live job has a shorter 45-minute
execution ceiling; the one-hour credential lifetime provides headroom but does
not extend the job. `plan` and `apply` are separate manual dispatches. Apply must
name the immutable approved plan record and reviewer packet, use its own
reviewed `apply.json` claim, share the exact deployment/execution/change/layer/
main/release tuple with plan, and never re-plan. Until the protected transport
and all decoded sources validate in both passes, the expected result is a
pre-OIDC stop, not a request to weaken the gate.

The controller core now treats `APPLIED` as a resumable apply observation, not
as a healthy deployment or permission to start another layer. Reentry from
`APPLIED` or `RECONCILED_APPLIED` skips approval, plan fetch and apply. It can
advance only after a fresh Plan terminal session brackets
`terraform-layer.sh observe` with two identical exact-state reads. The observe
plan uses `-lock=false` and `-detailed-exitcode`; health requires structural
`NO_CHANGE` plus `input_contracts`, `terraform_convergence`, and
`producer_contract_schema`. Sensitive Terraform outputs are discarded. These
are convergence and producer-contract checks, not generic ECS, ALB, API, or
application runtime-health probes.

After the create-only health receipt is durable, a fresh Apply terminal session
builds the canonical catalog-owned layer contract, publishes it create-only to
SSM, and completes exact double parameter/tag readback before the final CAS to
`HEALTHY`. `UNCERTAIN` admits only the Plan-role read-only reconciliation: it
must never publish or retry apply. In that state `contract_verified` means that
the prospective canonical contract validates against its schema; it is not a
publication claim. Reentry after `RECONCILED_APPLIED` performs health and
publication normally. The public Apply path is wired in the repository, but no
connected DEV execution has yet proved it.

The protected job treats the controller exit code as a terminal gate. Only a
durably read-back `HEALTHY` result exits successfully. `APPLIED`, `UNCERTAIN`,
`RECONCILIATION_REQUIRED`, and `RECONCILED_APPLIED` exit nonzero for that
invocation; they must not be reported as a successful deployment. Any later
reentry follows the state-specific read-only or post-apply path above and never
repeats the saved-plan apply.

If a runner disappears while the ledger is `APPLYING`, do not send another
Apply dispatch. The workflow exposes no recovery operation and has no second
protected/OIDC job. Preserve the ledger for read-only diagnosis and a future
separately reviewed recovery design; do not edit it or recreate the removed
privileged path. The normal Apply entry is intentionally read-only when it
observes `APPLYING`: it stops without changing the ledger, even after the
staleness threshold. Only a separately reviewed recovery authority may perform
an `APPLYING -> UNCERTAIN` compare-and-swap.

The complete dispatch templates and evidence-level distinctions are maintained
in `docs/deployment/nonproduction-live-engine.md`.

## Cost and blast-radius gate

The action-time cost ceiling is mandatory. The tracked claim binds integer
`maximum_cost_usd_micros` from 0 through 100,000,000. The sealed request binds an
independently digested USD cost model with integer
`modeled_cost_upper_bound_usd_micros`, `modeled_at`, and `expires_at`. The
validity window cannot exceed 24 hours. Materialization compares the upper bound
to the claim before OIDC and stops if either value is missing, stale, malformed
or exceeded. The receipt binds both values and `cost_model_digest`. Record only
sanitized cost evidence after the run; a budget alarm is not permission to
continue after a breach.

Treat the cost model as a reviewed budget attestation, not as a price derived
from `terraform show` or live AWS pricing. Exact digests prevent switching the
model or lowering its bound between plan and apply; they do not certify the
estimator's accuracy. Stop if the release requires authoritative plan-derived
pricing and that estimator is not bound to the exact saved-plan digest.

One dispatch is bounded to one DEV deployment, account, Region, layer,
operation, execution/change tuple, release and protected Environment. The live
job is capped at 45 minutes, the control-plane OIDC session at 3,600 seconds and
the destination terminal session at one hour. Concurrency does not cancel an
in-flight run, and apply has one attempt. The structural plan classifier denies
destroy, replacement, malformed, or unknown actions before publication and
rejects more than 256 non-no-op resource actions or 128 non-no-op output
actions. A plan containing a resource outside that tuple, an unreviewed IAM
change, another layer, staging or production is an automatic stop.

## Connected sequential execution (not yet executed)

The protected DEV path now implements the post-apply state, no-change,
producer-contract publication, and durable-receipt adapters, but this is not an
executable claim that its connected prerequisites are configured or approved.
Execute one destination at a time only after exact-main review/CI and every
entry gate above passes. Keep the second account untouched until the first has
actually reached `HEALTHY`, completed a no-change rerun, and passed sanitized
evidence review.

For each destination:

1. Re-fetch the registry, external anchors, ACCOUNT_READY, GitHub Environment,
   platform authority, release, and terminal identity contracts.
2. Confirm caller identity before each role transition and compare account and
   role to the authorized contract.
3. Resolve the canonical DAG and acquire the exact deployment execution lock.
4. For each layer, resolve only declared fresh predecessor contracts.
5. Create a bounded plan; deny destroy/replacement in the normal path.
6. Store the exact plan version, create the shared ledger item, and review the
   sanitized packet plus resource/output manifests.
7. Obtain independent plan-specific approval bound to that packet digest.
8. Re-read state VersionId/digest/size and lineage/serial, contracts, release,
   Environment evidence, plan VersionId/digest/size, and ledger immediately
   before apply.
9. Transition once to APPLYING and apply the fetched binary without re-planning.
10. Under Plan authority, bracket `terraform-layer.sh observe` with two exact
    state reads, discard sensitive outputs, and require the three minimum
    convergence/producer-contract checks. Do not claim generic runtime health.
11. Commit the exact health receipt and transition to HEALTHY before continuing.
12. Release the lock only after the ledger and evidence index agree.

After the full DAG, run a new speculative plan from fresh state. The expected
result is `NO_CHANGE`; it is new evidence and never a reason to reuse an old
plan.

## Connected injected-failure exercise (not yet executed)

Use only a defensive synthetic fault at an approved boundary. Do not kill a
database write, corrupt state, delete infrastructure, or interrupt a customer
request.

Do not run this connected exercise until the exact implementation SHA is
reviewed, merged, and all connected entry gates pass. The target scenario is
loss of the Terraform client response after the apply request. Only the
original active controller may
transition `APPLYING -> UNCERTAIN` when it catches that unknown response. A
later or reentered controller is read-only when it observes `APPLYING` and must
not perform that transition. After the original controller records
`UNCERTAIN`, stop downstream layers and perform only:

1. strongly consistent ledger read;
2. read-only state lineage/serial readback;
3. new speculative plan;
4. prospective canonical producer-contract schema verification without
   publication.

Only matching lineage, advanced serial, `NO_CHANGE`, and a valid contract may
produce `RECONCILED_APPLIED`. Anything else becomes
`RECONCILIATION_REQUIRED`. Create a new forward-recovery change and approval;
never retry the old saved plan. A subsequent reentry from
`RECONCILED_APPLIED` must run the normal health and Apply-role contract
publication/readback path before `HEALTHY`.

## Target isolation proof (currently blocked)

Only after both destinations are independently healthy through the connected
path, run negative synthetic checks that attempt to cross customer, deployment,
account, state key, contract path, plan version, approval, role, artifact
destination, and runtime object boundaries. Expected results are explicit
deny/not-found-equivalent responses without enumeration or sensitive logs. No
real document or PII is permitted. Repository tests do not satisfy this proof.

## Cleanup

1. Delete synthetic API data through its owning API and verify absence.
2. Expire/reject every unused ledger execution.
3. Verify the retained plan bucket's one-day current/noncurrent lifecycle; the
   controller has no saved-plan delete API, so do not claim or improvise
   immediate object deletion.
4. Use a reviewed Terraform destroy plan only when its exact environment and
   scope were separately authorized.
5. Verify residual resources, state retention, KMS pending-deletion policy,
   budgets, registry status, and evidence disposition.
6. Never delete shared authority, durable evidence, or another deployment's
   resources as part of destination cleanup.

## Evidence report

Classify every command or gate as PASSED, FAILED, SKIPPED, or BLOCKED. Record
only sanitized identifiers/digests, source commit, workflow run, Environment
configuration digest, plan/reviewer-packet/approval/ledger/health receipt
digests, state binding and serial changes, bounded plan/action-manifest counts,
health codes, failure/reconciliation result, lifecycle cleanup result, cost
observation, and reviewer evidence reference. Never convert SKIPPED or BLOCKED
to PASSED.

## Rollback and stop conditions

Stop on cross-boundary access, unexpected destroy/replace, state mismatch,
unknown apply outcome, failed health, missing contract, unreviewed IAM change,
budget breach, data-loss risk, or any production target. Rollback is a new
signed release selection and a new exact reviewed saved plan; it is never a
rebuild or reuse of the failed plan.

Use the following recovery matrix; do not collapse these states into one
generic rollback:

| Last durable state | Immediate action | Authorized recovery |
|---|---|---|
| Materialization failed, no OIDC | Preserve only sanitized failure code; invalidate the request | Reviewed repository/private-input correction; no AWS cleanup |
| OIDC acquired, no plan object | Stop and verify zero mutation from durable evidence | New authorization after identity and custody review |
| `PLANNED`, apply not started | Start a fresh attempt-1 workflow run if the exact plan is still current | Append fresh approval evidence and perform the normal `PLANNED -> APPROVED` CAS |
| `APPROVED`, `attempt_count=0`, prior run cancelled | Start a fresh attempt-1 workflow run and obtain a new Environment review | Append a digest-addressed approval and CAS-select it without consuming the apply attempt |
| `APPROVED`, selected approval still current in the same run | Resume only the same controller flow | Exact digest readback; no ledger rewrite before `APPLYING` |
| stale `APPLYING` after 3,900 seconds | Preserve the ledger and stop; do not retry Terraform | Read-only diagnosis pending a separately reviewed recovery design; no workflow recovery route exists |
| `APPLYING` with known failure | Stop downstream layers and preserve evidence | New signed forward-recovery release and newly approved saved plan |
| `APPLYING` with an unknown response caught by the original active controller | That controller may CAS to `UNCERTAIN`; do not retry | Read-only state/contract/no-change reconciliation only; a later/reentered controller must not mutate `APPLYING` |
| `HEALTHY` but rollback requested | Keep current evidence and disable promotion | Exact last-known-good signed release plus a new reviewed saved plan |

Reverting repository code never proves cloud rollback. Terraform state restore,
force-unlock, destroy, account cleanup, staging and production recovery each
require their own reviewed authorization and evidence.

## Readiness classification

- Repository tests and CI can establish only `REPOSITORY_READY`.
- One protected plan can establish only `CONNECTED_DEV_PLAN_PROVEN`.
- A separately approved apply plus health, no-change and reconciliation evidence
  can establish only `CONNECTED_DEV_APPLY_PROVEN`.
- GUG-127 must still certify staging after all earlier phase gates.
- GUG-128 must still receive a separate, current human GO for one limited
  production pilot. Nothing in this runbook authorizes that pilot.
