# Non-Production Live Engine

## Current classification

GUG-382 is `REPOSITORY_CANDIDATE / LIVE_NOT_PROVEN`. It adds and tests the
repository and CI control shape, but it has not minted an OIDC token, assumed an
AWS role, run a remote Terraform plan, stored or applied a saved plan, performed
a health check, reconciled an uncertain apply, or exercised rollback. No AWS
action was executed for this work package. Staging and production are blocked.

## Purpose

GUG-125 provides the fail-closed boundary between a reviewed Terraform plan and
one authorized non-production apply. It does not make a laptop, workflow input,
profile name, Environment name, or Terraform output authoritative.

The machine-readable contracts are:

- `schemas/saved-plan.v1.schema.json`;
- `schemas/saved-plan-approval.v1.schema.json`;
- `schemas/live-execution-ledger.v1.schema.json`;
- `schemas/live-health-receipt.v1.schema.json`;
- `schemas/live-reconciliation-receipt.v1.schema.json`.

The pure policy core is `tooling/nonprod_live_engine.py`. Destination plan
storage and shared-services ledger storage are deliberately split in
`tooling/nonprod_live_store.py`. `scripts/deployment/nonprod-live-engine.py`
exposes the guarded operational boundary. `tooling/nonprod_live_orchestrator.py`
builds immutable plan/apply intents bound to one exact main SHA and protected
workflow run. `scripts/deployment/terraform-saved-plan.sh` is the only
allowlisted plan/apply program and remains inaccessible from a local operator
session.

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

## Saved-plan apply invariants

Apply is allowed only when all of the following are exactly equal and current:

1. customer, deployment, account, region, environment, execution, change, and
   layer;
2. registry, ACCOUNT_READY, execution-lock, backend, contract-resolution,
   release, source, root-module, and toolchain digests;
3. Terraform state lineage and serial observed at plan time;
4. S3 bucket, derived key, immutable version ID, plan SHA-256, and size;
5. protected Environment configuration and independent approval bound to the
   plan digest;
6. ledger status `APPROVED`, zero prior attempts, unexpired plan and approval.

Any difference creates a new plan and a new approval. Destructive/replacement
plans are a separate reviewed recovery path and are denied by the normal plan
classifier.

## Protected workflow and CLI boundary

Offline validation is always safe and must run without ambient AWS variables:

```bash
make nonprod-live-engine-check
```

Live subcommands are building blocks for the protected GitHub control plane,
not operator-laptop instructions. They have no profile option and require the
already assumed exact role. Operational inputs and outputs must be in an
ephemeral directory outside the repository. Never attach them to GitHub,
Linear, NotebookLM, or a PR.

The workflow shape enforces these boundaries:

1. one manual `dev` dispatch selects exactly one `plan` or `apply` phase and an
   exact protected-main SHA;
2. only `live-layer` in `nonprod-release.yml` and `live_saved_plan` in the
   reusable workflow may request `id-token: write`; only the latter contains
   the pinned AWS credential action;
3. a separate unprivileged prerequisite job currently stops unconditionally
   with `LIVE_INPUT_MATERIALIZATION_NOT_PROVEN`, so the OIDC-capable job is not
   scheduled;
4. a deployment-scoped protected Environment gates the live job;
5. the future plan phase must create the exact versioned plan, saved-plan record
   and `PLANNED` ledger under separated terminal/orchestrator authorities;
6. independent plan-specific approval occurs after that plan run and is stored
   durably before a separate apply dispatch can reference its exact digest;
7. the future apply phase must consistently read back the plan and approval,
   consume `APPROVED -> APPLYING` with compare-and-swap, revalidate after the
   transition, and apply the downloaded binary once without replanning;
8. post-apply readback must persist exact health or reconciliation evidence;
   the next DAG layer remains blocked until matching `HEALTHY` evidence exists.

The materialization stop has no variable-based enablement path. The workflow
therefore describes the protected control topology but cannot yet
reach checkout, OIDC, STS, Terraform, or AWS data-plane operations.

## Evidence handling

Raw saved plans are R0 ephemeral execution data. They use the destination
`scanalyze-<account-id>-tf-state` bucket's `plan-execution/` prefix, KMS
encryption, S3 versioning, create-only write, and no default Object Lock. Delete
only the exact object version after apply, rejection, expiry, or reviewed
reconciliation and no later than 24 hours.

Durable evidence contains only sanitized digests and status codes. It must not
contain state, plan JSON, AWS responses, tokens, role sessions, ARNs, bucket
keys, customer payloads, PII, documents, or presigned URLs.

## Current evidence boundary

Implemented and locally validated means repository building blocks exist:
contracts, typed orchestration intents, record adapters, a canonical workflow
allowlist, runner guards, and offline enforcement. It does not mean those
building blocks form a connected live controller. CI remains pending until the
exact PR checks pass.

The following remain **NOT_PROVEN** and block removal of the materialization
stop: a typed authenticated live-input materializer; the exact separate
platform-authority account, read profile, backend and orchestrator role; the
destination baseline, state resources and terminal roles; a reviewed
non-overlapping CIDR or existing VPC; the exact protected Environment and
verified second P0 reviewer; immutable plan/apply/health evidence; and connected
rollback proof. Production is **NO-GO**.

Activation also requires a separately reviewed controller that connects the
terminal sessions, immutable plan storage, consistent ledger readbacks, CAS,
single-use apply, authenticated GitHub approval provenance, outcome receipts,
and reconciliation. It must bind `github.run_attempt`, consume private
identity-stable file snapshots, use a hash-verified toolchain outside the OIDC
job, and validate the exact KMS key policy needed by all four terminal roles.
None of those activation controls is asserted by this repository candidate.
