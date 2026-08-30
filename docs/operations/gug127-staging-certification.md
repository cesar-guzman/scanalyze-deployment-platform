# GUG-127 Staging Certification Runbook

## Entry gate

Stop before dispatch unless all Phase 1-8 evidence is current for the exact
release and both non-production targets. Each target must have a real registry
and ACCOUNT_READY record, backend and lock infrastructure, terminal roles,
deployment-scoped protected GitHub Environment, private transport, cost model,
synthetic-data boundary, rollback owner, on-call owner, and an independently
attested reviewer who differs from the initiator.

Missing GitHub Environments, empty live variables/secrets, absent tracked
requests/claims, an unconfigured signing trust root, an unknown destination
account, or an unavailable reviewer is `BLOCKED`. Do not create an empty
Environment by dispatching with an invented name and do not substitute local
SSO administrator profiles for the workflow's OIDC roles.

The fixed trust root is `governance/staging-certification-trust-anchor.json`.
`configuration_status=NOT_CONFIGURED`, a digest/epoch mismatch, an expired
anchor or policy, or any caller-supplied replacement is a hard stop. Configure
the anchor only through a separately reviewed repository change that binds the
authorized policy digest, monotonic epoch, narrow validity interval, and
distinct certification and approval-authority keys. Never accept the policy's
self-declared digest as its own trust root, and never reuse one key for both
roles.

## Execute and collect

1. Record the exact `main` SHA, release digest, environment, deployment binding,
   Region, target layer, execution/change IDs, private-claim digest, cost and
   expiry.
2. Complete the protected Plan and independently approved Apply sequence for
   every layer in `dev`; require `HEALTHY`, a new no-change rerun, and reviewed
   sanitized evidence.
3. Repeat with a distinct deployment binding in `staging` using the same release
   digest. No saved plan, approval, backend, Environment, contract, or runtime
   identifier may cross environments.
4. Run the positive E2E suite and negative isolation/adversarial suite in both
   environments with synthetic data only.
5. Measure rollback and restore separately, complete the defensive game day,
   and verify alert, backup, on-call, change-window, residual-risk, and
   last-known-good evidence.
6. Authenticate the exact protected-Environment approval history and bind its
   authority, Environment, initiator, reviewer, expiry, release, index, and
   complete reviewed certification body into the sanitized package. Sign that
   binding with the separately pinned approval-authority key.
7. Build the sanitized two-entry evidence index, sign the complete
   decision-bearing certification body with canonical low-S ECDSA under the
   reviewed GUG-127 trust root, and verify it with current system UTC using
   `scripts/deployment/staging-certification.py`.
8. Retain the signed index and decision under the approved R3 evidence policy.
   Retain raw deployment evidence only in its encrypted R2/R4 stores.

## Stop conditions

Stop on a failed or stale check, Critical/High blocker, release mismatch,
reused deployment binding, unexpected Terraform action, non-`HEALTHY` state,
uncertain Apply, failed no-change rerun, self-review, signature failure, or
missing evidence. Evidence older than 72 hours, expired approval, duplicate JSON
keys, a non-canonical ECDSA signature, or an unpinned trust policy also stops the
gate. Preserve evidence and create a forward recovery plan; never weaken the
gate or report partial completion as staging certification.

## Production handoff

Successful GUG-127 verification makes the evidence package reviewable by
GUG-128. It does not enable a workflow, approve a canary, authorize AWS writes,
or establish production readiness. GUG-128 still requires an exact production
target, the certified release and saved plan, current backups/alerts/on-call,
an independent manual GO, and bounded canary/soak/rollback evidence.
