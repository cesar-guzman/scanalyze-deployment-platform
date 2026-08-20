# ADR-031: GitHub OIDC and Terminal Deployment Identity

- **Status:** Proposed; accepted only after reviewed merge and main verification
- **Date:** 2026-07-14
- **Work package:** GUG-123
- **Baseline:** `5bbb9c932b32dbb30457c7fdbdc47b4eb1d7ccf4`
- **Program:** GUG-115
- **Upstream:** GUG-121, GUG-122, ADR-004, ADR-017, ADR-030
- **Downstream gates:** GUG-124, GUG-125, GUG-117
- **Live validation:** No
- **AWS or GitHub mutation:** None

Production: **NO-GO**

## Context

GUG-121 made the release graph and contract digests strict. GUG-122 made the
deployment registry, account baseline, Terraform backend, and execution lock
authoritative. Neither package proved which GitHub execution could consume
those contracts or which IAM identity could enter each terminal operation.

A repository name, branch name, Environment name, workflow input, or default
GitHub OIDC subject is not sufficient authority. Reusable workflows, forks,
pull requests, dry-runs, generic Environments, mutable names, or a forged
Environment snapshot must not obtain deployment identity. A shared
orchestrator must not become diagnostic or state-recovery authority.

## Decision

### 1. One exact GitHub identity contract per deployment execution

The v1 identity contract binds exact customer, deployment, AWS account,
region, logical environment, immutable GitHub owner/repository numeric IDs,
repository name, workflow path, `refs/heads/main`, event, deployment-specific
GitHub Environment, OIDC subject, orchestrator role, terminal roles, and role
resource tags. All values are assertions until they agree with the GUG-122
registry target, independent registry anchor, and ACCOUNT_READY v2.

Missing, malformed, legacy, partial, ambiguous, foreign, or conflicting
contracts are denied. The request cannot choose a role, account, Environment,
layer, subject, or session duration.

A separately anchored platform identity authority binds the immutable GitHub
IDs to the approved shared-services account, OIDC provider, deployment-scoped
orchestrator ARN, and its exact deployment/customer/account/region/environment
role tags. This prevents an Environment administrator from substituting a
self-consistent role in an unapproved shared-services account.

### 2. GitHub OIDC uses one customized exact subject

The repository OIDC subject template contains, in order:

1. `repository_owner_id`;
2. `repository_id`;
3. `context` (rendered as the deployment-specific Environment);
4. `workflow_ref` (exact workflow path and `refs/heads/main`); and
5. `event_name`.

AWS trust uses exact `StringEquals` for `aud=sts.amazonaws.com` and the complete
derived subject. Wildcards, default subjects, pull-request events, feature
branches, arbitrary reusable workflows, and dry-run execution are forbidden.
The identity contract requires the first-hop caller to request exactly
`DurationSeconds=900`. IAM role `MaxSessionDuration` cannot be configured below
one hour, so the role setting alone does not prove a 15-minute session. The
broker/caller must enforce and negatively test the 900-second request before
live use.

The subject template is repository-wide. Its live rollout must first inventory
every existing OIDC consumer and install each new exact trust subject before
changing the GitHub customization. GUG-123 performs no such live mutation.

### 3. Environment configuration requires independent, fresh evidence

The deployment identity contains an expected Environment snapshot, but it
cannot attest to itself. A separate `github_environment_anchor` must be fetched
through an approved read-only GitHub API adapter outside the release workflow.
It binds immutable repository IDs, exact Environment name, and a canonical
digest covering reviewer, branch/tag protection, bypass/self-review posture,
reserved variable scope, deployment variables, secret-name inventory, and OIDC
subject customization.

The anchor is integrity-protected, non-future, and valid for no more than ten
minutes. Only named `User` reviewers are accepted because a team reviewer does
not prove that the initiator is not a team member. The initiator must differ
from every reviewer. Generic Environments, repository/organization overrides,
Environment secrets, tag deployment, admin bypass, and self-review are denied.

### 4. The orchestrator and terminal roles are disjoint

The GitHub OIDC role can assume only the generic Plan/Apply roles, the dedicated
Identity-Plan/Identity-Apply roles, Promotion, and Validation. Generic
Plan/Apply explicitly exclude `identity-control-plane`; the dedicated identity
roles accept only that layer, preserving the GUG-93 state boundary. Each
terminal trust has separate statements for `sts:AssumeRole`,
`sts:TagSession`, and `sts:SetSourceIdentity`. It requires exact resource-bound
customer, deployment, account, region, environment, operation, and layer tags,
an approved change ID, a fixed tag allowlist, a non-null `aws:TagKeys` context,
and `exec_<ULID>` source identity.

Plan cannot become Apply. Promotion is limited to artifact publication writes.
Validation remains read-only and is limited to the two validation entrypoints:
artifact-publication input validation and synthetic validation. The operation is
always `validate`; Validation never inherits Promotion's publication authority.
Customer roles are terminal and cannot assume further roles. The child sets the
minimum supported IAM role maximum of 3,600 seconds, while the identity contract
requires each AssumeRole request to set `DurationSeconds=900`. That caller-side
enforcement is downstream and not live-proven; the template by itself does not
cap a session at 15 minutes.

The dedicated identity roles have a read-only upper bound on objects in
`scanalyze-shared-releases`; they receive no list, write, or publication action.
The exact immutable release-digest prefix must be reduced by the per-execution
session policy. Until that downstream session-policy wiring is implemented and
verified, identity plan/apply is not deployable or live-ready.

Generic Apply service mutations that still require `Resource: "*"` are an
account-level upper bound, not proof of resource or layer isolation. A dedicated
one-deployment account reduces cross-deployment exposure, but session layer tags
alone do not prevent mutation of manually created or cross-layer resources.
Per-layer session policies and service-specific ARN/resource-tag bindings are
downstream requirements for data/runtime/edge execution. Until those controls
are implemented and negatively tested, no terminal-role assumption or live
deployment is authorized and this candidate remains `DEPLOYMENT_NO_GO`.

Generic Apply deliberately cannot create roles or policies, attach policies,
or rewrite trust. The current `modules/global/iam.tf` and
`modules/cicd/main.tf` still declare those IAM resources, while neither the
parent nor the terminal-role companion preprovisions the three exact PassRole
targets. AccountVending must materialize the reviewed roles/policies or those
modules must be redesigned before global or CI/CD can run. Re-adding IAM create
authority to generic Apply is not an accepted compatibility path.

IdentityApply likewise cannot create roles, write inline role policies, change
trust, or retag roles. It may read and pass only the two exact preprovisioned
identity runtime roles to their exact Lambda functions, with partition-portable
service binding. The current identity-control-plane Terraform still declares
those roles and inline policies, so AccountVending must preprovision reviewed
Lambda-only trusts and policies and the module must migrate to consuming them.
Identity-control-plane execution remains `DEPLOYMENT_NO_GO` until that work is
implemented and negatively tested; restoring persistent IAM mutation is not a
compatibility option.

The closed KMS ownership-tag contracts also intentionally fail against current
Terraform callers: identity adds `managed_by` and `purpose`, data-foundation
omits `customer_id`, and CI/CD supplies only `Name` and `layer`. Those modules
must adopt the exact reviewed customer/deployment/layer request-tag contract
before KMS create, tag, alias, or grant paths can run. The policies are not
relaxed to preserve compatibility; identity, data-foundation, and CI/CD remain
`DEPLOYMENT_NO_GO` until caller tags and negative tests agree.

IAM separates saved-plan and evidence paths but cannot attest object content.
Apply and IdentityApply therefore have no evidence-bucket PutObject or evidence
key encrypt/data-key authority, and their boundaries explicitly deny those
operations. A future evidence publisher must be separately trusted and must
prove runtime sanitization, evidence-schema validation, and negative content
tests before it can write COMPLIANCE WORM storage.

Diagnostic remains a human break-glass path with separate trust, reviewed
approval, MFA, exact ownership tags, incident/operator evidence, and no
orchestrator principal. StateRecovery is materialized with its future
least-privilege permissions boundary, but its deployed trust is deliberately
deny-only. The current break-glass role could otherwise self-assert
`recovery_approved=true`, which is not independent approval. GUG-123 must wire
and prove a distinct approval issuer before StateRecovery can gain any Allow
trust. Until then it is not assumable and cannot perform recovery.

The parent intentionally applies `Retain` to the nested terminal-role stack.
Deleting or replacing the parent therefore does not revoke the seven live
Allow trusts or remove the roles. Any future decommission must first revoke or
replace those trusts, verify that no usable sessions remain, and only then
retire the retained child through a separately reviewed forward operation.
Parent deletion alone is never accepted as IAM revocation evidence.

### 5. Repository workflows remain unprivileged until the live engine exists

The current non-production release and reusable Terraform workflows remain
offline/dry-run. The pre-existing microservices publisher selected a role,
account, and Environment from workflow inputs or mutable variables and could
therefore bypass this authorization chain. Its validation jobs remain intact,
but its cloud publication job is now an explicit fail-closed NO-GO with empty
permissions and no credential action. Repository validation rejects
`id-token: write` or AWS credential actions in every workflow, not only known
dry-run paths. Enabling a privileged workflow belongs to GUG-125 after GUG-124
binds immutable plan and supply-chain evidence.

## Consequences

- A wrong repository, fork, workflow, branch, event, Environment, customer,
  deployment, account, region, operation, or layer fails before cloud identity.
- Environment variables are defense in depth, never authority.
- Numeric GitHub IDs prevent a renamed or transferred repository from silently
  inheriting name-based trust.
- `ACCOUNT_READY` v2 records lacking the two GUG-93 identity roles or any of the
  five required role resource tags are migration-required and denied; GUG-123
  performs no automatic inference or live migration.
- A forged self-consistent snapshot fails the independent anchor comparison.
- Repository-wide OIDC customization requires a staged compatibility rollout.
- A request to use the legacy microservices publisher fails explicitly instead
  of minting a variable-selected identity.
- GitHub plan/API limitations and live IAM evaluation remain GUG-125 evidence,
  not locally proven facts.

## Rollout and rollback

Follow the dedicated runbook. Rollout is plan-first, inventory-first, and
requires independent approval. Update exact AWS trusts before the repository
subject template, verify the intended non-production path, then retire any old
exact subject. Never introduce a wildcard compatibility window.

Rollback disables privileged workflow entry first, restores the previous
reviewed exact trust/template pair, and verifies that no workflow can mint a
usable identity. It never falls back to static keys, generic Environments,
default subjects, or broad role trust.

## Evidence classification

- **Implemented:** candidate schemas, validator, exact trust/policy fixtures,
  synthetic tests, Make gate, ADR, runbook, threat delta, and sanitized source.
  The fixture-to-CloudFormation union is an offline structural guarantee only.
- **Locally validated:** only named offline commands for the candidate tree.
- **CI validated:** pending the exact PR commit.
- **Live validated:** no.
- **Blocked:** per-execution release-digest session-policy reduction,
  independent StateRecovery approval issuance and trust activation, reviewed
  PR/main verification, authorized GitHub configuration, IAM Access
  Analyzer/live STS denial evidence, GUG-124, GUG-125, and GUG-117.
- **Production:** **NO-GO**.

## References

- [GitHub OIDC reference](https://docs.github.com/en/actions/reference/security/oidc)
- [GitHub OIDC with AWS](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-aws)
- [AWS IAM GitHub OIDC trust guidance](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html)
