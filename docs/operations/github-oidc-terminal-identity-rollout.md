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

Under the current protected-live design, only the sole Environment-gated
`live_saved_plan` job may request OIDC or invoke the pinned AWS credential
action. The legacy microservices publication path must remain disabled and
non-OIDC; it must not be re-enabled after later gates. Future publication work
must extend the single privileged job or adopt a separately reviewed terminal
identity architecture. Restoring the former variable-selected role path is
forbidden.

## Phase B — prepare exact trust before customization

1. Derive every new exact customized subject from immutable IDs, exact
   Environment, workflow ref, and event.
2. Add only those complete subjects to their intended role trusts. A temporary
   transition may contain multiple complete exact subjects; it may not contain a
   wildcard, name-only repository prefix, branch-only trust, or pull-request
   subject.
3. Apply deployment/resource tags and exact session requests: 3,600 seconds for
   the protected orchestrator and Plan/Apply terminal path, and 900 seconds for
   the separately controlled human Diagnostic/StateRecovery paths. Negatively
   test any other duration.
4. Verify generic Plan/Apply exclude `identity-control-plane`, the dedicated
   Identity-Plan/Identity-Apply roles accept only that layer, Promotion and
   Validation retain their exact stages, and break-glass can target only
   Diagnostic/StateRecovery.
5. Re-read and compare the remote trust digest before proceeding.

## Phase C — configure GitHub control plane

1. Create or reconcile the exact deployment Environment.
2. Configure `main`-only deployment, independent named user review,
   prevent-self-review, and no bypass.
3. Set exactly these 16 non-secret deployment variables, with no extras:
   `CUSTOMER_ID`, `DEPLOYMENT_ID`, `AWS_ACCOUNT_ID`, `AWS_REGION`,
   `LOGICAL_ENVIRONMENT`, `OIDC_ORCHESTRATOR_ROLE_ARN`,
   `ORCHESTRATOR_ROLE_ARN`, `GENERIC_PLAN_ROLE_ARN`,
   `GENERIC_APPLY_ROLE_ARN`, `IDENTITY_PLAN_ROLE_ARN`,
   `IDENTITY_APPLY_ROLE_ARN`, `PLATFORM_AUTHORITY_ACCOUNT_ID`, `REPOSITORY_ID`,
   `REPOSITORY_OWNER_ID`, `SECOND_P0_REVIEWER_ID`, and
   `GITHUB_ENVIRONMENT_COLLECTOR_APP_ID`. Confirm reserved names are absent at
   repository and organization scope.
4. Configure exactly two Environment secret names:
   `SCANALYZE_LIVE_INPUT_BUNDLE_B64` and
   `SCANALYZE_GITHUB_ENVIRONMENT_COLLECTOR_PRIVATE_KEY`. Never record, print or
   expose their values in inventory or evidence. Configure no additional
   secret names and store no AWS keys or role credentials in GitHub.
5. Configure the repository OIDC subject template with the five reviewed claim
   keys in exact order.
6. Install the collector App on exactly the intended repository with exactly
   read-only `actions`, `environments`, `metadata`, `secrets`, and `variables`
   permissions. Do not add a PAT or partial token-action permission inputs.
7. Use the sole protected job to verify the App installation with an App JWT,
   create one repository-scoped installation token, take two complete stable
   snapshots, and revoke the token before OIDC.
8. Run the GUG-123 authorizer against the registry/baseline/anchor chain.

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
- missing tag, extra tag, a duration other than the path's exact 3,600- or
  900-second request, or changed source identity;
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
