# GUG-127 Protected Staging Certification

## Purpose and boundary

GUG-127 certifies one immutable release across exactly two isolated
non-production environments: `dev` and `staging`. The protected live workflow
uses separate Plan and Apply dispatches, deployment-scoped GitHub Environments,
saved plans, independent approval, and sanitized evidence. Production is not an
accepted input and a GUG-127 certificate never authorizes a production pilot.

This repository revision implements the staging-capable contract and verifier.
It does not claim that either protected Environment, AWS control plane, release,
or connected execution exists. That state advances only after the live evidence
described below is produced and verified.

## Protected execution sequence

For each environment, execute the canonical Terraform layer DAG through
`.github/workflows/nonprod-release.yml` on the exact protected `main` SHA:

1. materialize a tracked Git-safe request and one tracked private claim for the
   exact environment, layer, and operation;
2. dispatch Plan with `logical_environment=dev` or `staging` and
   `github_environment=scanalyze-<deployment_id>-<logical_environment>`;
3. review the sanitized action manifest, cost ceiling, saved-plan digest, state
   binding, and reviewer-packet digest;
4. dispatch Apply separately with those exact digests and an independent
   Environment approval;
5. require a durable `HEALTHY` result, canonical contract publication/readback,
   and a fresh no-change rerun; and
6. preserve only sanitized digests in the evidence index. Raw plan, state,
   protected identifiers, logs, and private inputs remain in their approved
   encrypted stores.

The two environments require different opaque deployment-binding digests and
must use the same immutable release digest. Production, self-review, a wrong
Environment suffix, mixed releases, reused deployment bindings, destroy or
replacement plans, stale evidence, or a missing reviewer fails before a gate
decision. All release, Phase 8, deployment-binding, environment-scoped
workflow, plan, Apply, health, no-change, test, rollback, restore, game-day,
operational, and approval evidence digests must also be globally distinct by
role; one opaque artifact cannot satisfy multiple evidence roles.

## Certification package

`schemas/staging-certification.v1.schema.json` records:

- the exact source revision, release, last-known-good release, Phase 8 evidence,
  observation window, and expiry;
- exactly one `dev` and one `staging` evidence entry;
- saved-plan, apply, health, no-change, positive/negative test, rollback,
  restore, and game-day digests for each environment;
- operational confirmation digests for residual risk, on-call, change window,
  alerts, and backups;
- a distinct, human-attested reviewer tuple plus authenticated approval,
  approval-authority, protected-Environment, expiry, and exact-reviewed-body
  binding digests, signed by the independently pinned approval authority; and
- a detached canonical low-S ECDSA P-256 signature over every decision-bearing
  claim in the certification body (excluding only the signature value and the
  derived certificate digest).

The trust policy is separately bound by
`schemas/staging-certification-trust-policy.v1.schema.json`. Its digest and
monotonic epoch must match the independently reviewed, repository-pinned
`governance/staging-certification-trust-anchor.json`; supplying a trust policy
on the command line cannot establish trust. The pinned anchor is intentionally
`NOT_CONFIGURED` in this revision, so operational certification remains
fail-closed until a separate reviewed change records the authorized digest,
epoch, and validity window. Verification recomputes the policy, approval,
index, signed-body, and certificate digests before checking the current system
UTC time, evidence age, two-environment isolation, release equality, reviewer
separation, approval expiry, and cryptographic signature. Duplicate JSON keys,
non-canonical ECDSA signatures, and caller-controlled verification time are
rejected.

The trust policy pins separate certification and approval-authority key sets.
The same key or signer identity cannot satisfy both roles. The approval
authority signs the exact reviewed-body binding; the certification signer then
signs the complete package, including that independent signature. Recomputing
hashes or holding only the certifier key therefore cannot reauthorize changed
Phase 8, release, operational, expiry, or decision claims.

Run the verifier only against sanitized files:

```bash
python3 scripts/deployment/staging-certification.py \
  --certification /approved/sanitized/gug127-certification.json \
  --trust-policy /approved/sanitized/gug127-trust-policy.json
```

A successful result is `STAGING_CERTIFIED` with
`production_authorized=false`. It is only entry evidence for a separate,
exact-target GUG-128 manual decision.

The approval authority must authenticate the exact protected GitHub Environment
approval history before signing: initiator and reviewer identities,
MFA/independence attestations, approval authority, Environment anchor, release,
evidence index, complete reviewed body, certification ID, and expiry all
participate in the approval binding. Arbitrary IDs or a detached approval
screenshot are not sufficient evidence.

## Rollback

Repository rollback reverts the GUG-127 staging-support change. A connected
environment rollback must use a separately reviewed saved rollback plan for the
exact environment; restore validation is a different exercise and must not be
reported as rollback. Never rerun an uncertain Apply or use a local Terraform
apply as a substitute for the protected workflow.
