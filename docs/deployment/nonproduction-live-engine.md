# Non-Production Live Engine

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
exposes the guarded operational boundary.

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

## Authority flow

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

## CLI boundary

Offline validation is always safe and must run without ambient AWS variables:

```bash
make nonprod-live-engine-check
```

Live subcommands are building blocks for the protected GitHub control plane,
not operator-laptop instructions. They have no profile option and require the
already assumed exact role. Operational inputs and outputs must be in an
ephemeral directory outside the repository. Never attach them to GitHub,
Linear, NotebookLM, or a PR.

The intended protected sequence is:

1. `store-plan` under the exact generic or identity Plan terminal role;
2. `create-ledger` under the exact shared-services orchestrator role;
3. build a saved-plan approval from fresh GitHub API evidence;
4. `transition-ledger` to `APPROVED` with that exact approval;
5. `fetch-plan` under the exact generic or identity Apply terminal role;
6. `authorize-apply`, transition to `APPLYING`, and execute only the fetched
   saved binary;
7. transition to `APPLIED` or `UNCERTAIN`;
8. build and commit an exact health or reconciliation receipt;
9. require HEALTHY evidence before the next DAG layer.

The repository workflow remains dry-run-only until all activation prerequisites
in the runbook are independently proven.

## Evidence handling

Raw saved plans are R0 ephemeral execution data. They use the evidence bucket's
`plan-execution/` prefix, KMS encryption, S3 versioning, create-only write, and
no default Object Lock. Delete only the exact object version after apply,
rejection, expiry, or reviewed reconciliation and no later than 24 hours.

Durable evidence contains only sanitized digests and status codes. It must not
contain state, plan JSON, AWS responses, tokens, role sessions, ARNs, bucket
keys, customer payloads, PII, documents, or presigned URLs.

## Current evidence boundary

Implemented and locally validated means the contracts, portable authority
declarations, and offline enforcement exist. CI remains pending until the PR
checks pass. No live AWS identity,
Terraform plan/apply, deployment, failure injection, health check, two-account
isolation, or cleanup has succeeded for this package. Production is **NO-GO**.
