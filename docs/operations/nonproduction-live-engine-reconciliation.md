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
  backend/lock/evidence/contract infrastructure, exact terminal roles, and
  matching KMS/S3 policies;
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

## Sequential execution

Execute one destination at a time. Keep the second account untouched until the
first reaches HEALTHY, no-change rerun, and sanitized evidence review.

For each destination:

1. Re-fetch the registry, external anchors, ACCOUNT_READY, GitHub Environment,
   platform authority, release, and terminal identity contracts.
2. Confirm caller identity before each role transition and compare account and
   role to the authorized contract.
3. Resolve the canonical DAG and acquire the exact deployment execution lock.
4. For each layer, resolve only declared fresh predecessor contracts.
5. Create a bounded plan; deny destroy/replacement in the normal path.
6. Store the exact plan version and create the shared ledger item.
7. Obtain independent plan-specific approval.
8. Re-read state, contracts, release, Environment evidence, plan version,
   digest, size, and ledger immediately before apply.
9. Transition once to APPLYING and apply the fetched binary without re-planning.
10. Read back state and producer contract; run only sanitized health checks.
11. Commit the exact health receipt and transition to HEALTHY before continuing.
12. Release the lock only after the ledger and evidence index agree.

After the full DAG, run a new speculative plan from fresh state. The expected
result is `NO_CHANGE`; it is new evidence and never a reason to reuse an old
plan.

## Injected-failure exercise

Use only a defensive synthetic fault at an approved boundary. Do not kill a
database write, corrupt state, delete infrastructure, or interrupt a customer
request.

The preferred scenario is loss of the Terraform client response after the
apply request. Transition `APPLYING -> UNCERTAIN`, stop downstream layers, and
perform only:

1. strongly consistent ledger read;
2. read-only state lineage/serial readback;
3. new speculative plan;
4. exact producer-contract verification.

Only matching lineage, advanced serial, `NO_CHANGE`, and a valid contract may
produce `RECONCILED_APPLIED`. Anything else becomes
`RECONCILIATION_REQUIRED`. Create a new forward-recovery change and approval;
never retry the old saved plan.

## Isolation proof

After both destinations are independently healthy, run negative synthetic
checks that attempt to cross customer, deployment, account, state key, contract
path, plan version, approval, role, artifact destination, and runtime object
boundaries. Expected results are explicit deny/not-found-equivalent responses
without enumeration or sensitive logs. No real document or PII is permitted.

## Cleanup

1. Delete synthetic API data through its owning API and verify absence.
2. Expire/reject every unused ledger execution.
3. Delete only exact R0 saved-plan object versions after evidence capture.
4. Use a reviewed Terraform destroy plan only when its exact environment and
   scope were separately authorized.
5. Verify residual resources, state retention, KMS pending-deletion policy,
   budgets, registry status, and evidence disposition.
6. Never delete shared authority, durable evidence, or another deployment's
   resources as part of destination cleanup.

## Evidence report

Classify every command or gate as PASSED, FAILED, SKIPPED, or BLOCKED. Record
only sanitized identifiers/digests, source commit, workflow run, Environment
configuration digest, plan/approval/ledger/health receipt digests, state serial
changes, plan counts, health codes, failure/reconciliation result, cleanup
result, cost observation, and reviewer evidence reference. Never convert
SKIPPED or BLOCKED to PASSED.

## Rollback and stop conditions

Stop on cross-boundary access, unexpected destroy/replace, state mismatch,
unknown apply outcome, failed health, missing contract, unreviewed IAM change,
budget breach, data-loss risk, or any production target. Rollback is a new
signed release selection and a new exact reviewed saved plan; it is never a
rebuild or reuse of the failed plan.
