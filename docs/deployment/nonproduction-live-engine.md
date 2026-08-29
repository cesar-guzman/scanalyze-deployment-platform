# Non-Production Live Engine

## Current classification

The current path is
`REPOSITORY_CANDIDATE / CONNECTED_DEV_NOT_PROVEN / PRODUCTION_NO_GO`. It
connects the protected workflow to a typed private-input materializer and a
separate saved-plan controller, but it has not minted an OIDC token, assumed an
AWS role, run a remote Terraform plan, stored or applied a saved plan, performed
a health check, reconciled an uncertain apply, or exercised cloud rollback. No
AWS action was executed while implementing this path. Staging and production
remain blocked by their independent gates.

## Purpose

GUG-125 provides the fail-closed boundary between a reviewed Terraform plan and
one authorized non-production apply. It does not make a laptop, workflow input,
profile name, Environment name, or Terraform output authoritative.

The machine-readable contracts are:

- `schemas/saved-plan.v1.schema.json`;
- `schemas/saved-plan-reviewer-packet.v1.schema.json`;
- `schemas/saved-plan-approval.v1.schema.json`;
- `schemas/live-execution-ledger.v1.schema.json`;
- `schemas/live-health-receipt.v1.schema.json`;
- `schemas/live-reconciliation-receipt.v1.schema.json`;
- `schemas/nonprod-live-input-claim.v1.schema.json`;
- `schemas/nonprod-live-input-sealed-request.v1.schema.json`; and
- `schemas/nonprod-live-github-approval-evidence.v1.schema.json`.

The pure policy core is `tooling/nonprod_live_engine.py`. Destination plan
storage and shared-services ledger storage are deliberately split in
`tooling/nonprod_live_store.py`. `scripts/deployment/nonprod-live-engine.py`
exposes the guarded policy and storage boundary; its legacy
`run-terminal-apply` command is explicitly disabled before private-input or AWS
access while post-apply closure is unwired. `tooling/nonprod_live_orchestrator.py`
builds immutable plan/apply intents bound to one exact main SHA and protected
workflow run. `scripts/deployment/terraform-saved-plan.sh` is the only
allowlisted plan/apply program and remains inaccessible from a local operator
session. `tooling/nonprod_live_input_materializer.py` and
`scripts/deployment/nonprod-live-input-materializer.py` validate the sealed
private inputs before OIDC. `scripts/deployment/nonprod-live-controller.py`
connects only a successful materialization receipt to one protected phase. The
controller core can durably record `PLANNED`, consume one apply attempt, resume
from `APPLIED` without repeating approval/fetch/apply, and finalize only after
state bracketing, a structural `NO_CHANGE` plan, verified input contracts,
non-sensitive outputs, exact contract publication/readback and a durable health
receipt. `UNCERTAIN` permits only the corresponding read-only reconciliation
core. The real protected-workflow adapters for those post-apply callbacks are
not yet connected, so the public Apply CLI returns non-success before it
constructs destination dependencies, assumes a destination role, or consumes
the saved-plan attempt. The core still treats historical or independently wired
`APPLIED` and `UNCERTAIN` records as fail-closed rather than claiming connected
DEV.

In this document, shared-services is not a generic corporate account. It is the
dedicated or formally designated Scanalyze platform-authority account. It owns
only orchestration authority and sanitized registry/ledger state, and it must
not equal either destination account or store customer documents.

## Portable authority factory

`roots/platform-authority` consumes an approved map of deployment bindings and
`modules/platform-authority` creates one exact orchestrator role per entry. The
same source supports any number of clients and AWS destination accounts without
client-specific forks. The authority account, region, globally unique release
bucket, canonical customer/deployment IDs, destination accounts, GitHub numeric
repository IDs, and exact Environment subjects are injected from reviewed
records.

The factory creates no customer workloads. Customer terminal roles, state,
evidence, and `ACCOUNT_READY` are produced separately in each destination by
the account-vending boundary. The authority root also does not create its own
remote backend or IAM Identity Center assignment; those are one-time human
bootstrap prerequisites documented in
`docs/deployment/platform-authority-bootstrap.md`.

## Target authority flow after activation

```text
registry + ACCOUNT_READY + contracts + release + state
                         |
                         v
              Plan terminal role
                         |
        KMS/versioned exact plan object
                         |
                         v
      shared-services create-only ledger
                         |
          independent GitHub approval
                         |
                         v
              Apply terminal role
                         |
        exact-version readback + state check
                         |
                         v
          terraform apply saved binary once
                         |
          state/contract/health readback
                         |
                         v
              HEALTHY or stop
```

The final state/contract/health protocol in this target flow is implemented and
hermetically tested in the controller/engine core. It requires two identical
state observations including VersionId/hash/size, a structural speculative
plan result of `NO_CHANGE`, verified input contracts, explicitly non-sensitive
mode-0600 outputs, a create-only health receipt, and exact publication/readback
evidence before the `HEALTHY` CAS. The protected workflow does not yet provide
the real read-only verification and publication adapters. Its public Apply
entry is therefore disabled before destination access, so repository
implementation is not connected execution evidence.

The Plan role cannot write the shared ledger. The shared orchestrator cannot
write destination infrastructure or the saved plan. Apply cannot generate or
replace a plan. Validation cannot mutate infrastructure.

The shared ledger accepts only the exact per-deployment GUG-123 authority,
`ScanalyzeOrchestrator-<deployment_id>`. The CLI cannot substitute a generic
release role, a role path, or another deployment's orchestrator by supplying a
different ARN.

Plan, approval, health, and reconciliation documents are create-only durable
records in the platform-authority execution table. Consistent readback repeats
schema, digest, and deployment-tuple validation. GitHub artifacts, job outputs,
mutable paths, and caller-supplied JSON are not durable authorization.
Approval records are append-only and content-addressed by their exact
`approval_digest`; the ledger selects the sole authoritative record. A fresh
workflow run may replace that selection by compare-and-swap only while the
ledger is still `APPROVED` with `attempt_count=0`. This recovery does not add a
general `APPROVED -> APPROVED` transition and is forbidden after `APPLYING`.

## Saved-plan apply invariants

Apply is allowed only when all of the following are exactly equal and current:

1. customer, deployment, account, region, environment, execution, change, and
   layer;
2. registry, ACCOUNT_READY, execution-lock, backend, contract-resolution,
   release, source, root-module, and toolchain digests;
3. Terraform state status plus lineage, serial, S3 VersionId, SHA-256, and size
   observed at plan time: `PRESENT` requires every value, while a first
   deployment may use only conclusive `ABSENT` with every state identity field
   null; `AccessDenied`, `403`, or an unknown response is never absence;
4. S3 bucket, derived key, immutable version ID, plan SHA-256, and size;
5. protected Environment configuration and independent approval bound to the
   plan digest;
6. ledger status `APPROVED`, zero prior attempts, unexpired plan and approval.

Any difference creates a new plan and a new approval. Destructive/replacement
plans are a separate reviewed recovery path and are denied by the normal plan
classifier.

Apply repeats the complete intent, approval-expiry, ledger-CAS, plan-version,
state, and cost binding after backend initialization and plan rehash,
immediately before the sole `terraform apply` command.

Before publication, the controller runs `terraform show -json` against the
exact saved binary, rejects delete, replacement, malformed, duplicate, or
unknown actions, then deletes the mode-`0600` raw JSON scratch. Only a sanitized
count summary and its digest enter the durable saved-plan record. At most 256
non-no-op resource actions and 128 non-no-op output actions can enter its
canonical reviewer manifests. The binary is hashed before and after inspection
and again against the immutable upload.

## Protected workflow and CLI boundary

Offline validation is always safe and must run without ambient AWS variables:

```bash
make nonprod-live-engine-check
```

Live subcommands are building blocks for the protected GitHub control plane,
not operator-laptop instructions. They have no profile option. The controller
requires the already assumed exact role. The input materializer itself has no
network access; a bounded GitHub App collector runs twice inside the sole
protected job before OIDC and writes only a short-lived private anchor. The
private root is fixed at
`$RUNNER_TEMP/scanalyze-live-inputs`; it is not a workflow input. The protected
Environment supplies exactly `SCANALYZE_LIVE_INPUT_BUNDLE_B64` and
`SCANALYZE_GITHUB_ENVIRONMENT_COLLECTOR_PRIVATE_KEY` as private transports;
`GITHUB_ENVIRONMENT_COLLECTOR_APP_ID` is a public Environment variable. The
encoded bundle is capped at 48,000 bytes and the decoded sealed
request at 36,000 bytes so every accepted payload fits the GitHub control-plane
limit; larger material must use a separately reviewed private transport design
and is rejected here. Neither private value may be printed or persisted as an
artifact. Never attach the decoded root, generated files, raw plans, state, AWS
responses or credentials to GitHub artifacts, logs, Linear, NotebookLM or a PR.

The workflow shape enforces these boundaries:

1. one manual `dev` dispatch selects exactly one `plan` or `apply` phase and an
   exact protected-main SHA; no recovery operation is exposed;
2. only `live-layer` in `nonprod-release.yml` and the single
   Environment-protected `live_saved_plan` job in the reusable workflow may
   request `id-token: write`; the reusable job contains the pinned AWS
   credential action, while the caller contains none;
3. the only public live-input selector is a lowercase
   `live_input_claim_digest`; the unprivileged Environment-gated job passes it
   with the exact deployment/layer/operation selectors to `materialize` and
   `validate` against the fixed private root;
4. inside that same job, the first staging root is deleted and the protected
   root is rematerialized from the Environment transport. Both passes use the
   same repository-scoped App token, require the reviewed claim and stable
   sealed authority projection, and collect complete current GitHub snapshots;
   full receipt digests intentionally differ because each pass binds its own
   observation time. Both compare release, Region, destination/platform-
   authority accounts, Environment configuration, roles, App installation and
   repository numeric identities; no caller path or artifact may populate the
   roots;
5. a deployment-scoped protected Environment gates the live job;
6. the plan phase creates the exact versioned plan, saved-plan record,
   `PLANNED` ledger, and a schema-validated reviewer packet whose step summary
   contains the packet digest plus bounded resource/output action manifests;
7. independent plan-specific approval occurs after review of that packet; the
   separate apply dispatch must carry both its packet digest and the exact plan
   record digest;
8. before apply OIDC, `nonprod-live-approval.py` uses that same App token for
   two read-only GitHub REST reads: exact workflow-run metadata and its
   Environment approval history.
   It privately binds the reviewer-packet digest and configured
   `SECOND_P0_REVIEWER_ID`, distinct from the initiator, to the repository, run
   and Environment for five minutes;
9. the App token is explicitly revoked with confirmed HTTP 204 and all App
   private material is removed before dependency installation, Terraform, OIDC
   or controller execution;
10. the apply phase consistently reads back the plan and approval, consumes
   `APPROVED -> APPLYING` with compare-and-swap, revalidates after the
   transition, and applies the downloaded binary once without replanning;
11. the controller core can resume `APPLIED` or `RECONCILED_APPLIED` without a
    second approval, fetch or apply, and can advance only after matching health,
    no-change, contract-publication and readback evidence. `UNCERTAIN` can only
    become `RECONCILED_APPLIED` or `RECONCILIATION_REQUIRED` through read-only
    evidence and can never publish or retry apply. The protected workflow
    adapter remains unwired, so the next DAG layer remains blocked until a real
    connected run reaches matching `HEALTHY` evidence.

The typed selectors derive only
`deployment/live-input-claims/<deployment_id>/<layer>/<operation>.json`. Its
working-tree bytes must match exact `HEAD`; the workflow cannot select an
untracked claim, another deployment's claim or an arbitrary path.

The materializer invocation is fixed by the workflow:

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

The tracked request must have working bytes equal to exact `HEAD`, and its
strictly parsed canonical document must equal the request embedded in the claim
and its `deployment_request_digest`. It performs no network or AWS call and
prints no private material. Generated
records are create-only under `materialized/`; `receipt.json` exposes only the
sanitized binding decision and receipt digest. The two passes must agree on the
claim and stable sealed authority projection, while each pass must carry its
own current GitHub anchor. Stable validation failures stop before OIDC. The
controller is never a documented local command: only the protected workflow
may invoke it after materialization, rematerialization and Environment gates
pass.

Both phases require `LIVE_INPUTS_MATERIALIZED`, `oidc_authorized=true`, and
`terminal_operation_authorized=false`. Apply additionally requires
`durable_readback_required=true`; the receipt is not mutation authority. The
controller must read the exact approved saved-plan and ledger records before it
can consume the one apply attempt.

Terraform state is deliberately absent from the pre-OIDC transport. The Plan
terminal role reads the exact versioned backend state immediately before
planning, brackets the plan with an identical second read, and records the
lineage, serial, VersionId, digest, and size in the durable saved plan. Apply
then re-reads that exact state before fetch, authorization, and execution. A
caller-provided or five-minute static state snapshot is never accepted.

For apply only, the protected job then uses
`scripts/deployment/nonprod-live-approval.py materialize` and `validate` before
OIDC. It makes exactly two read-only GitHub REST requests: one for workflow-run
metadata and one for that run's Environment approval history, both through the
already verified App installation token. It stores only
mode-`0600` sanitized evidence under
`materialized/controller/github-approval.json`. The evidence binds the numeric
repository and workflow run, exact Environment, numeric initiator, one distinct
numeric approver, exact reviewer-packet digest, review-set digest, observation
time, and an expiry no later than five minutes after observation or 15 minutes
after the workflow run was created, whichever is earlier. The token, raw
responses, reviewer login, comments and URLs are never persisted. The App token
is revoked and its environment/private material is removed before OIDC; it is
never passed to Terraform or the controller. This evidence is controller
input, not durable saved-plan approval or mutation authority by itself.

The plan job validates
`schemas/saved-plan-reviewer-packet.v1.schema.json` before projecting its
sanitized packet to the GitHub step summary. That packet binds the plan record,
plan hash/size, state-binding digest, cost binding and exact canonical resource
and output action manifests. Reviewers copy its `packet_digest` into the
separate Apply dispatch; the controller rebuilds the packet from the durable
plan record and requires exact digest equality.

Live plan/apply accepts only workflow run attempt `1`. A failed or cancelled
attempt is not rerun in place: start a new workflow run so the protected
Environment review and private evidence belong to a fresh run ID. If apply was
not attempted, that run can append its own approval and select it by exact CAS;
an orphaned approval record grants no authority by itself.

Until the exact Environment secret and every decoded sealed source are present,
the workflow fails closed before OIDC. Configuring them still does not itself
prove a connected DEV execution; only the resulting protected runtime evidence
does.

### Exact protected dispatch shape

The following are execution templates, not standing authorization. Run either
only after an owner authorizes the exact DEV account, Region, deployment,
layer, main SHA, release, claim digest, cost ceiling, change window and
rollback owner. The protected Environment must independently approve the job.

Plan uses a new execution/change tuple and cannot carry a saved-plan digest:

```bash
gh workflow run nonprod-release.yml --ref main \
  -f request_path=<tracked-git-safe-request> \
  -f deployment_id=<dep_ULID> \
  -f logical_environment=dev \
  -f github_environment=scanalyze-<dep_ULID>-dev \
  -f aws_region=<authorized-region> \
  -f release_digest=sha256:<release-digest> \
  -f dry_run=false -f allow_live=true -f live_operation=plan \
  -f target_layer=<one-layer> \
  -f execution_id=<exec_ULID> -f change_id=<chg_ULID> \
  -f main_sha=<reviewed-main-sha> \
  -f live_input_claim_digest=sha256:<private-claim-digest>
```

Apply is a separate dispatch after durable, independent, plan-specific
approval. It uses its own reviewed operation-specific `apply.json` claim,
shares the exact deployment/execution/change/layer/main/release tuple with the
plan, and names the immutable plan record:

```bash
gh workflow run nonprod-release.yml --ref main \
  -f request_path=<tracked-git-safe-request> \
  -f deployment_id=<dep_ULID> \
  -f logical_environment=dev \
  -f github_environment=scanalyze-<dep_ULID>-dev \
  -f aws_region=<authorized-region> \
  -f release_digest=sha256:<release-digest> \
  -f dry_run=false -f allow_live=true -f live_operation=apply \
  -f target_layer=<same-layer> \
  -f execution_id=<same-exec_ULID> -f change_id=<same-chg_ULID> \
  -f main_sha=<same-reviewed-main-sha> \
  -f plan_record_digest=sha256:<approved-plan-record-digest> \
  -f reviewer_packet_digest=sha256:<approved-reviewer-packet-digest> \
  -f live_input_claim_digest=sha256:<approved-apply-claim-digest>
```

Never alter these templates to select `staging` or `production`, bypass the
Environment, supply a local path, retry an uncertain apply, re-plan during
apply, or use a different digest under the same change.

### Expired `APPLYING` recovery

A lost runner never authorizes another apply. This workflow deliberately
exposes no `recover-stale` operation and no second OIDC/Environment job. An
orphaned `APPLYING` ledger remains stopped for read-only diagnosis and a future
separately reviewed recovery design; operators must not edit the ledger,
redispatch apply, or reintroduce an alternate privileged path.

## Cost and blast-radius controls

Every authorization and materialized context binds one DEV destination account,
one separate platform-authority account, one Region, one deployment, one layer,
one operation, one release and one time window. The reviewed claim's integer
`maximum_cost_usd_micros` is limited to 0 through 100,000,000. The sealed
request's independently digested USD `cost_model` carries the integer modeled
upper bound, `modeled_at` and `expires_at`, with a maximum 24-hour window.
Materialization stops before OIDC when the model is missing, malformed, stale or
exceeds the reviewed ceiling. The receipt binds both values and
`cost_model_digest`.

This model is an externally reviewed budget attestation, not a cost calculated
from Terraform actions or current AWS prices. The saved-plan record prevents a
model, ceiling, or modeled bound from being substituted between plan and apply,
but it does not prove the estimator's economic accuracy. Any release that
requires plan-derived pricing remains stopped until an authoritative estimator
is bound to the exact plan digest.

The normal path denies destroy and replacement, rejects more than 256 non-no-op
resource actions or 128 non-no-op output actions, uses a 3,600-second
platform-authority control-plane OIDC session and a separate one-hour
destination terminal role session, caps the protected job at 45 minutes,
serializes the deployment/Region concurrency key without cancelling an
in-flight run, and permits one apply attempt. The 45-minute job timeout is the
execution ceiling; the one-hour credentials provide headroom but never extend
the job. The evidence report records only sanitized cost bounds and counts. The
one-hour contract applies only to the protected OIDC orchestrator and its
plan/apply terminal roles; human diagnostic and state-recovery sessions remain
independently controlled and capped at 900 seconds.

The maximum immediate mutation radius of one authorized apply is the resources
in the exact reviewed saved plan for that single layer and deployment. It does
not include another layer, account, Region, deployment, staging or production.
Any plan that cannot prove that bound is denied rather than partially applied.

## Evidence handling

Raw saved plans are R0 ephemeral execution data. They use the dedicated
destination `scanalyze-<account-id>-tf-plan` bucket's `plan-execution/` prefix,
the exact ACCOUNT_READY `evidence_kms_key`, S3 versioning, create-only write,
no Object Lock, and a one-day current/noncurrent lifecycle expiry. CloudFormation
retains the bucket and policy on stack deletion or replacement; that retention
does not disable object expiry. The controller exposes no saved-plan delete API
and the workflow performs no immediate delete after apply, rejection, expiry,
or reconciliation: lifecycle is the implemented cleanup mechanism. The state
bucket stores only Terraform state, lock and state readback; the evidence bucket
`scanalyze-<account-id>-tf-evidence` keeps only durable sanitized records under
its 90-day COMPLIANCE retention. Neither bucket stores raw plans.

For a present pre-plan state, the durable saved-plan record captures the exact
state object VersionId, SHA-256, and byte size as well as lineage and serial; a
conclusively absent state stores null for all five identity fields. The plan
object separately binds its own VersionId, SHA-256, and byte size. The reviewer
packet exposes a digest of the complete state binding rather than raw state.

Durable evidence contains only sanitized digests and status codes. It must not
contain state, plan JSON, AWS responses, tokens, role sessions, ARNs, bucket
keys, customer payloads, PII, documents, or presigned URLs.

## Current evidence boundary

Implemented and locally validated means the repository contains contracts,
typed materialization, controller and orchestration boundaries, record adapters,
runner guards and offline enforcement. It does not mean that the protected
transport was configured for a connected run or that the controller reached
AWS.

| Evidence level | Minimum proof | What it does not prove |
|---|---|---|
| Repository ready | Exact SHA review/CI plus offline materializer/controller tests | OIDC, AWS, deployment, staging or production |
| Connected DEV plan | Exact protected run, identity readback and immutable saved-plan/ledger evidence | Apply, health, rollback, staging or production |
| Connected DEV apply | Separate approved apply, health, no-change and reconciliation evidence | Staging certification or production GO |
| GUG-127 staging certified | All Phase 1-8 evidence, two isolated non-production environments and exercised rollback/restore | Production authorization |
| GUG-128 production pilot GO | Separate current human authorization for the exact certified release, target and saved plan | Broader rollout or future actions |

The configured and independently reviewed protected Environment transport,
exact separate platform-authority account/backend/orchestrator, destination
baseline and terminal roles, non-overlapping DEV network, protected
Environment, independent reviewer, real protected-workflow adapters for the
implemented post-apply health/no-change/reconciliation core, and connected
plan/apply/health/rollback evidence
remain **NOT_PROVEN** until observed. GUG-127 and GUG-128 remain independent
gates. Production is **NO-GO**.
