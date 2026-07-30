# Rollback Procedures

The authoritative distinction between application rollback, infrastructure
rollback, and incident-only Terraform state recovery is defined in
[`rollback-recovery-boundaries.md`](rollback-recovery-boundaries.md). This file
provides the existing release-specific target procedure and remains
non-executable.

> [!CAUTION]
> **TARGET-STATE / LIVE ROLLBACK NO-GO.** This repository does not currently
> implement an executable live deployment rollback. The local `rollback`,
> `validate-live`, and `smoke-e2e` commands are scaffolding only, and the GitHub
> Actions Terraform workflow intentionally rejects live execution. Do not use
> this document as an incident command sequence.

## Current Executable Status

- `scanalyze-deploy.sh rollback --dry-run` can describe the intended operation;
  it does not create or apply a Terraform plan.
- `scanalyze-deploy.sh validate-live` and `smoke-e2e` do not validate deployed
  resources yet.
- No GitHub Actions workflow resolves a rollback record, creates an approved
  saved plan, or applies it.
- Operator-laptop apply remains prohibited by ADR-017.

Live rollback remains blocked until the workflow, deployment registry lookup,
saved-plan approval, apply, and post-change verification are implemented and
tested in non-production. No recovery-time objective has been demonstrated.

## Target-State Principles

These are design requirements for the future implementation, not runnable steps:

1. **Rollback = new Terraform plan, not state revert.**
2. The target is a previously validated set of immutable image digests.
3. Rollback is never automatic and requires explicit GitOps approval.
4. The approved deployment record is authoritative for the known-good release.
5. The exact reviewed saved plan is the only plan eligible for apply.

## Target-State Digest Revert

The planned `digest-revert` flow must:

1. Resolve an approved known-good release from the deployment registry outside
   Git.
2. Create a new `services` layer Terraform plan using those image digests.
3. Reject unexpected changes outside the approved rollback scope.
4. Retain a sanitized plan digest and review evidence.
5. Obtain protected GitHub Environment approval.
6. Apply exactly the reviewed saved plan through the future GitHub orchestrator.
7. Verify running digests and execute a synthetic smoke test before declaring
   recovery.

A Git-safe request may reference the approved release digest, but it must never
contain a real manifest, account bindings, Terraform inputs, plans, state, or
customer data.

## Intended Rollback Coverage

| Component | Target-state method |
|---|---|
| ECS service images | Digest revert via a new Terraform plan |
| ECS task definitions | New revision referencing the approved old digest |
| ALB listener rules | Explicitly reviewed Terraform plan |
| SQS configuration | Explicitly reviewed Terraform plan |

## Components Requiring Separate Assessment

| Component | Reason | Mitigation direction |
|---|---|---|
| DynamoDB schema changes | Additive-only by convention | Keep schema changes append-only |
| S3 object deletions | Versioning is not an instant application rollback | Enable and test version recovery |
| Cognito user pool changes | Some changes are irreversible | Test in non-production first |

## Enablement Evidence Required

Before replacing the NO-GO status, retain evidence of:

- one successful non-production deploy and rollback using immutable digests;
- exact saved-plan identity from review through apply;
- protected Environment approval and registry binding;
- verified running digests after the change;
- a working synthetic smoke test with no sensitive payloads; and
- an exercised incident runbook with measured timings.

## Prohibited Actions

- Reverting Terraform state.
- Force-stopping ECS tasks as a substitute for a plan.
- Running local `apply-layer`, `apply-all`, or a locally invented rollback.
- Treating the current stub commands as live validation.
- Rolling back infrastructure layers without a separate impact assessment.

GitHub branch-protection rollback is a separate repository-governance operation;
it never uses Terraform state. Follow the snapshot and verified restore procedure
in [`github-governance.md`](github-governance.md).
