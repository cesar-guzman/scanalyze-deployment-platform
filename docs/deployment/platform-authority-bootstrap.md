# Platform-Authority Bootstrap and Customer Onboarding

## Purpose

The Scanalyze platform authority is a dedicated control-plane AWS account. It
is neither a customer account nor a generic corporate shared-services account.
It stores only deployment control metadata and immutable release material:

- one GitHub OIDC provider;
- one exact `ScanalyzeOrchestrator-<deployment_id>` role per deployment;
- the deployment registry and live execution ledger;
- a versioned, KMS-encrypted release bucket.

It must never store customer documents, PII, Terraform state for a customer
deployment, processing queues, ECS workloads, Cognito tenants, or extracted
payloads.

## Identity planes

IAM Identity Center is the human bootstrap and recovery plane. A short-lived,
audited permission-set session establishes the authority backend and reviews the
first plan. GitHub OIDC is the machine runtime plane after bootstrap. Static
access keys, copied SSO credentials, long-lived IAM users, and a customer
account acting as the authority are forbidden.

The authority does not create or manage the organization's Identity Center
instance. The organization's identity team assigns two disjoint, time-bound
plan and apply permission sets to non-overlapping groups in the authority
account. Neither is trusted by customer terminal roles during normal deployment
execution.

## Required onboarding record

Each new client supplies an independently approved record containing:

| Field | Authority |
|---|---|
| `customer_id` | Scanalyze customer registry; canonical `cust_` ULID |
| `deployment_id` | Scanalyze deployment registry; canonical `dep_` ULID |
| destination account and region | verified STS and account-vending evidence |
| environment | `sandbox`, `dev`, or `staging` for GUG-125 |
| repository owner/repository numeric IDs | fresh GitHub API evidence; enforced as immutable OIDC trust claims |
| GitHub OIDC subject | exact protected Environment subject, legacy or immutable-ID format, never a wildcard |
| release bucket | globally unique authority-owned name |
| backend binding | independently bootstrapped authority state bucket/key/KMS |

Request payloads, profile names, account aliases, repository names, environment
names, customer slugs, and the last digits of an account never establish
authority.

## Bootstrap sequence

1. Allocate or formally designate a third AWS account for Scanalyze platform
   authority. Verify that it is different from every destination account.
2. Follow the dedicated GUG-206
   [`platform-authority-account-bootstrap.md`](platform-authority-account-bootstrap.md)
   procedure. Through IAM Identity Center, obtain a short-lived plan session
   whose scope is limited to Change Set creation and cancellation.
3. Create and review the exact CloudFormation Change Set, obtain approval from
   a different attributable SSO principal, and execute it only under explicit
   authorization. Record only sanitized digests; never store backend files,
   plans, approvals, credentials, state, or AWS responses in Git, Linear, or
   NotebookLM.
4. Render the root inputs from the approved onboarding records. The root and
   module reject missing, malformed, production, duplicated, wildcard, or
   authority-equals-destination bindings.
5. Produce and review a saved Terraform plan. Confirm the exact account guard,
   resources, KMS key, two protected DynamoDB tables, release bucket, OIDC
   provider, permissions boundary, one role per deployment, and runtime decrypt
   access limited to the exact authority KMS key.
6. Only after explicit non-production authorization, execute that exact saved
   plan with the short-lived Identity Center session. Capture sanitized digests
   and resource counts, not identifiers or payloads.
7. Run the customer account-vending flow separately in each destination. It
   creates customer-owned terminal roles, state/evidence backends, and
   `ACCOUNT_READY`; the platform-authority root does not.
8. Configure one protected GitHub Environment per deployment with independent
   review, the exact OIDC subject recorded in the authority contract, immutable
   `repository_owner_id` and `repository_id` trust conditions, and an explicit
   900-second role-duration request. Existing legacy-format subjects and newer
   immutable-ID subjects are both accepted only when their separately verified
   numeric claims match. IAM role configuration has a
   one-hour minimum ceiling; relying on its default would issue a one-hour
   session and is not the accepted GUG-123 contract.
9. Exercise GUG-125 sequentially: deployment A plan/apply/health, idempotent
   no-change rerun, deployment B plan/apply/health, then negative cross-customer
   and cross-deployment attempts.
10. Reconcile and clean synthetic customer resources under their separately
    authorized destroy roles. The platform authority is retained unless a
    separately reviewed decommission is approved.

## Minimum human permission boundary

The state bootstrap uses two permission sets rendered from
`policies/iam/platform-authority-bootstrap-plan-role.json` and
`policies/iam/platform-authority-bootstrap-apply-role.json`. They are assigned
only to the dedicated authority account and to non-overlapping initiator and
approver/executor groups. The plan role cannot execute; the apply role cannot
create/cancel Change Sets or delete the stack. Its execution resource is
rendered after plan review to the exact Change Set name and UUID, then disabled
after the bootstrap window. The later Terraform apply permission is derived
separately from the reviewed saved plan and must be limited to:

- the exact platform-authority state bucket, state key, and KMS key;
- `ScanalyzePlatformAuthority*` policies and
  `ScanalyzeOrchestrator-<deployment_id>` roles;
- the single GitHub OIDC provider;
- the two canonical DynamoDB tables;
- the exact configured release bucket and authority KMS alias;
- read-only identity and tagging APIs required by Terraform.

Creation APIs that cannot be resource-scoped remain constrained by the exact
authority account, region, permission boundary, required request tags, and an
explicit deny for IAM users/access keys, `iam:PassRole`, Organizations, customer
workloads, and production. The final permission set must be generated from and
reviewed against the provider plan; a generic administrator policy is not an
acceptable bootstrap shortcut.

## Fail-closed stops

Stop before any AWS mutation when the authority profile/account is absent,
identity differs from the approved account, the backend is not independently
bound, any destination equals the authority, a customer/deployment binding is
ambiguous, a GitHub subject contains a wildcard, repository numeric claims do
not match, the plan is not an exact saved binary, or independent approval is
missing.

## Evidence classification

Repository declarations and synthetic tests are **Implemented** and **Locally
validated** only after their named gates pass. CI, reviewed merge, main
verification, authority bootstrap, two-client isolation, cleanup, and live AWS
validation remain separate evidence classes. Production remains **NO-GO**.
