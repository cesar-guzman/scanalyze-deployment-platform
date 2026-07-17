# ADR-034: Dedicated Platform-Authority Account Bootstrap

- **Status:** Proposed; accepted only after reviewed merge and main verification
- **Date:** 2026-07-16
- **Work package:** GUG-206
- **Parent / phase gate:** GUG-125 / GUG-117
- **Baseline:** `daf010d3c6cc17d1885b6c0627b9c06bc73d849d`
- **AWS live validation:** Read-only account inventory only; bootstrap not applied
- **Production:** **NO-GO**

## Context

GUG-125 introduced a portable Terraform root for the Scanalyze machine control
plane, but correctly required its state and human recovery plane to pre-exist.
The original repository bootstrap template was designed for customer
deployments. It permitted production, created a legacy DynamoDB lock table,
derived resources from a deployment ID, and did not prove that the current AWS
account was the dedicated platform authority. Reusing it would collapse the
control-plane/customer boundary and conflict with the native S3 lockfile
contract established by GUG-122.

A newly vended authority account was inventoried read-only. It contained only
the organization baseline and no Scanalyze storage, workloads, IAM identities,
OIDC provider, or state. Organization security services remain owned by their
delegated administrators; this package must not create competing member-level
administration.

## Decision

### 1. The authority account is a distinct ownership boundary

The platform authority must be different from every customer destination
account. It stores deployment control metadata, releases, approvals, and
execution state only. It never stores customer documents, PII, extracted
payloads, customer Terraform state, processing queues, or runtime workloads.

Human bootstrap and recovery use short-lived IAM Identity Center sessions.
Normal machine execution later uses the exact GitHub OIDC roles declared by
`roots/platform-authority`. IAM users, access keys, copied SSO credentials, and
a customer or corporate audit account acting as the authority are forbidden.

### 2. A dedicated bootstrap owns only the Terraform state boundary

`cfn-platform-authority-state-backend.yaml` creates one retained, rotating KMS
key, one alias, one versioned S3 bucket, and one restrictive bucket policy. The
template rejects a supplied account or bucket that does not equal the current
account and region. The fixed state key is:

```text
platform-authority/terraform.tfstate
```

Terraform uses `use_lockfile = true`. No DynamoDB lock table, workspace prefix,
customer/deployment prefix, production selector, or request-supplied key is
accepted.

The bucket is bucket-owner-enforced, KMS-encrypted with a bucket key, versioned,
private, retained on stack deletion/replacement, and limited to the state and
lockfile keys. Bucket policy denies insecure transport, cross-account access,
wrong/missing encryption, unexpected object keys, and direct state deletion.

### 3. Account-level S3 public access is one explicit planned step

CloudFormation does not expose a native resource that changes the S3 account
public-access-block setting. The bootstrap orchestrator therefore binds the
current setting and the all-true desired setting into the same short-lived plan
record. Immediately before executing the reviewed change set, it writes the
all-true account control. A later stack failure does not roll back that safe
account-wide setting.

Bucket-level public access remains independently enforced by CloudFormation.
Organization SCPs and Control Tower controls remain additional layers, not
substitutes for either control.

### 4. Planning, approval, execution, and verification are separate

`plan` validates STS identity and template, creates a CloudFormation Change Set
plus its empty `REVIEW_IN_PROGRESS` stack record, and records the exact resource
changes and template digest. It cannot execute the change set or create template
resources. The plan expires within one hour and is written mode 0600 outside
the repository.

`approve` requires a different live AWS principal in the same authority account
and binds both principal digests to the exact plan. `apply` revalidates account,
region, template, change-set contents, plan/approval digests, lifetimes, and the
current executor principal before the first write. It then enables account S3
public blocking, executes the exact change set once, and verifies every storage
control before emitting a backend configuration.

Request fields, profile names, aliases, last-four digits, local usernames, and
plain approval labels never establish authority. Operational plans, approvals,
backend files, AWS responses, and verification receipts stay outside Git,
Linear, NotebookLM, and general CI artifacts.

### 5. Bootstrap permissions are two disjoint permission sets

`platform-authority-bootstrap-plan-role.json` is the intended inline policy for
the time-bound IAM Identity Center plan permission set. It can create, inspect,
and cancel only the exact unexecuted Change Set. It cannot execute the Change
Set, change the account S3 public-access block, or create S3/KMS resources.

`platform-authority-bootstrap-apply-role.json` is the intended inline policy
for the independently assigned apply permission set. After plan review, its
Change Set ARN placeholders are rendered to the exact name and UUID from the
plan before assignment. It can execute only that Change Set and
provision/verify only the bound S3/KMS backend controls. It cannot create or
cancel Change Sets, delete the stack, create identities, `iam:PassRole`, access
Organizations, or create customer workloads.

The organization administrator creates the two permission sets and assigns
them to non-overlapping initiator and approver/executor groups only in the
authority account. This repository does not create an Identity Center instance
or a standing IAM role. A broad administrator session may inventory and
validate, but it is not accepted evidence of the final least-privilege
operating boundary. The live adapter verifies an `AWSReservedSSO_*` STS
principal and requires the canonical Plan or Apply permission-set role before
each corresponding mutation; a profile name alone never establishes authority.
The exact Apply policy is provisioned only after the Change Set exists and is
removed or disabled after the bootstrap window.

## Consequences

- A customer account can never silently become the deployment authority.
- Backend creation is recoverable without static credentials or local state.
- State and lock ownership agree with the GUG-122/GUG-125 contracts.
- Initial bootstrap needs two independently attributable SSO principals.
- The account-wide S3 control is explicit because it is outside the
  CloudFormation resource graph.
- Security Hub, GuardDuty, organization trails, and delegated Config controls
  remain organization responsibilities and are verified separately.

## Alternatives rejected

- **Reuse the customer backend template:** wrong ownership, production option,
  deployment-derived naming, and legacy DynamoDB locking.
- **Bootstrap with local Terraform state:** the recovery boundary would reside
  on an operator workstation and could be lost or altered.
- **Use an audit or customer account:** combines evidence/customer authority
  with deployment authority and breaks independent isolation proof.
- **Execute a template directly:** skips exact change review and independent
  approval.
- **Treat a profile name as identity:** profile configuration is local and
  request-controlled; STS account/principal evidence is authoritative.

## Rollback and recovery

Before execution, delete only the unexecuted Change Set after recording its
sanitized digest. After an uncertain execution, do not create or execute a new
plan; use read-only `verify` and CloudFormation events. Retained state storage
is never automatically emptied or deleted. Decommission requires a separately
approved change, an empty-state/evidence inventory, KMS retention decision, and
explicit rollback procedure.

## Evidence classification

| Class | Status |
|---|---|
| Implemented | Template, typed plan/approval/verification contracts, pure authorization core, live CLI boundary, minimum permission policy, tests and documentation |
| Locally validated | Pending named offline gates on this branch |
| CI validated | Pending PR checks for the exact commit |
| Live validated | No; only read-only account inventory exists |
| Blocked | Reviewed merge; disjoint minimum permission sets; second SSO principal; authorized Change Set and apply; live verification; platform-authority root plan/apply |
| Production | **NO-GO** |
