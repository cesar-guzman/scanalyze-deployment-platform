# GitHub OIDC and terminal IAM rollout/rollback

Production: **NO-GO**. This is a target runbook. Do not execute it without a
separate approved change naming the GitHub repository, non-production
deployment, AWS accounts, profiles, region, operators, evidence location,
budget, and rollback owner.

## Stop conditions

Stop without mutation if any of these is unknown or inconsistent:

- registry target or independent target anchor;
- ACCOUNT_READY v2 digest or role/resource tags;
- immutable GitHub owner/repository IDs;
- exact workflow path/ref/event;
- deployment-specific Environment protections;
- full inventory of existing repository OIDC consumers;
- ability to prevent self-review/admin bypass;
- exact OIDC trust and terminal role policies;
- anchored platform identity authority for the shared-services account,
  provider, repository IDs, orchestrator role, and role tags;
- independent reviewer or rollback operator; or
- GUG-124 immutable plan/supply-chain binding or GUG-125 live engine readiness.

Never solve a stop condition with static AWS keys, long-lived PATs, wildcard
subjects, dual generic Environments, repository variables, or temporary broad
IAM.

## Phase A — read-only plan

1. Confirm repository and AWS identities using approved read-only sessions.
2. Read the deployment target, independent anchor, ACCOUNT_READY v2, platform
   identity authority, and its independent version/digest anchor from their
   authoritative stores without printing payloads.
3. Inventory every workflow and external consumer that requests GitHub OIDC.
4. Read repository OIDC customization, Environment protection/variables, and
   relevant IAM trust/policies.
5. Produce a redacted diff containing only control state and canonical digests.
6. Run repository gates and IAM policy analysis offline. Live Access Analyzer or
   STS evaluation requires the separately authorized account context.

If an existing consumer depends on the default subject, the rollout is not
ready. Updating repository subject customization can break every OIDC consumer.

At the GUG-123 repository baseline, no workflow is allowed to request OIDC or
invoke the AWS credential action. The legacy microservices publication path is
an explicit NO-GO while validation remains available. Re-enabling it requires
the reviewed GUG-124 evidence chain and the GUG-125 live engine; restoring its
former variable-selected role path is forbidden.

## Phase B — prepare exact trust before customization

1. Derive every new exact customized subject from immutable IDs, exact
   Environment, workflow ref, and event.
2. Add only those complete subjects to their intended role trusts. A temporary
   transition may contain multiple complete exact subjects; it may not contain a
   wildcard, name-only repository prefix, branch-only trust, or pull-request
   subject.
3. Apply deployment/resource tags and 900-second maximum sessions.
4. Verify generic Plan/Apply exclude `identity-control-plane`, the dedicated
   Identity-Plan/Identity-Apply roles accept only that layer, Promotion and
   Validation retain their exact stages, and break-glass can target only
   Diagnostic/StateRecovery.
5. Re-read and compare the remote trust digest before proceeding.

## Phase C — configure GitHub control plane

1. Create or reconcile the exact deployment Environment.
2. Configure `main`-only deployment, independent named user review,
   prevent-self-review, and no bypass.
3. Set only the six non-secret deployment variables. Confirm reserved names are
   absent at repository and organization scope. Store no AWS keys or role
   credentials in GitHub.
4. Configure the repository OIDC subject template with the five reviewed claim
   keys in exact order.
5. Use a separate read-only collector to retrieve the new configuration and
   create a maximum-ten-minute digest anchor.
6. Run the GUG-123 authorizer against the registry/baseline/anchor chain.

The workflow being governed must not create, modify, or attest its own
Environment or OIDC configuration.

## Phase D — negative proof before positive proof

Prove denial for each synthetic attempt without revealing tokens or ARNs:

- pull request and fork;
- wrong repository owner ID or repository ID;
- wrong workflow, branch, event, or generic Environment;
- wrong customer, deployment, account, region, or logical stage;
- wrong operation or layer;
- missing/expired/altered GitHub anchor;
- missing tag, extra tag, long session, or changed source identity;
- absent `aws:TagKeys` context against a multivalued allowlist;
- orchestrator to Diagnostic/StateRecovery; and
- break-glass to Plan/Apply/Promotion/Validation.

Only then execute the single authorized non-production identity request. GUG-123
does not authorize Terraform or a deployment; GUG-125 owns that proof.

## Evidence

Retain outside Git and NotebookLM:

- approved change and independent reviewer;
- exact commit/workflow run and immutable repository IDs;
- sanitized GitHub/IAM configuration digests;
- target, baseline, and anchor digests;
- allow/deny test matrix with timestamps;
- CloudTrail event identifiers without credential or payload content; and
- rollback verification.

Classify repository tests, CI, GitHub configuration, AWS identity evaluation,
and deployment validation separately.

## Rollback

1. Disable or remove the privileged job entry point.
2. Revoke the new exact OIDC trust subjects.
3. Restore the prior reviewed exact subject customization/trust pair only if all
   previous consumers remain known and independently verified.
4. Re-read GitHub and IAM state and prove that the failed/new path cannot obtain
   identity.
5. Preserve control-plane evidence; do not delete customer resources, state,
   locks, registry records, or audit evidence as part of identity rollback.
6. Open a new reviewed change for any third-party drift or unknown outcome.

Rollback never enables the default subject, wildcard trust, static keys,
generic Environment reuse, self-review, or admin bypass.
