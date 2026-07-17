# Dedicated Platform-Authority Account Bootstrap

## Scope

This runbook creates only the remote Terraform state boundary required by
`roots/platform-authority`. It does not deploy Scanalyze, customer workloads,
GitHub OIDC, terminal roles, registries, ledgers, releases, Cognito, or any
destination-account resource.

The authority account must be newly approved or formally dedicated, different
from every destination account, and governed through IAM Identity Center.
Examples below use placeholders only. Never commit operational receipts,
backend files, account inventories, credentials, or real bindings.

## Identity Center permission sets

Create two dedicated permission sets:

- `ScanalyzePlatformAuthorityBootstrapPlan`, rendered from
  `policies/iam/platform-authority-bootstrap-plan-role.json`, for the initiator;
- `ScanalyzePlatformAuthorityBootstrapApply`, rendered from
  `policies/iam/platform-authority-bootstrap-apply-role.json`, for the
  independent approver/executor after the exact Change Set exists.

Both permission sets require:

- a short session duration;
- no managed `AdministratorAccess` policy;
- assignment only to the dedicated platform-authority account;
- independently attributable, non-overlapping groups; no principal receives
  both permission sets during the same bootstrap window;
- organization audit retention and the standard emergency revocation path.

The plan policy cannot execute a Change Set or create backend resources. The
apply policy cannot create/cancel a Change Set or delete the stack, and its
`${change_set_name}` and `${change_set_id}` placeholders must be rendered from
the reviewed plan to one exact ARN before assignment. Backend-mutating S3 and
KMS actions additionally require the multivalued `aws:CalledVia` context to
contain `cloudformation.amazonaws.com`; a direct S3/KMS API call therefore does
not receive those permissions. The only direct mutation is the separately
planned all-true account-level S3 public-access block, which the CLI binds to
the current authority account and verifies immediately. Remove or disable the
Apply assignment after the bootstrap window.

Render the initial Plan policy offline into the controlled evidence directory;
do not substitute policy placeholders by hand:

```bash
umask 077
mkdir -p '<private-evidence-dir>'

python3 scripts/deployment/platform-authority-bootstrap.py render-plan-policy \
  --authority-account-id '<authority-account-id>' \
  --region '<authority-region>' \
  --destination-account-id '<customer-a-account-id>' \
  --destination-account-id '<customer-b-account-id>' \
  --policy-out '<private-evidence-dir>/bootstrap-plan-policy.json'
```

The identity administrator validates that file with IAM Access Analyzer and
uses the governed IAM Identity Center process to create or update only the
canonical Plan permission set. The command performs no AWS call.

Identity Center creates the account-local `AWSReservedSSO_*` role. Do not
create a manual IAM role or IAM user for this workflow. The policy template is
rendered from the exact account, region, and bucket binding under change
control; placeholders must never be submitted to AWS. The CLI checks the live
STS principal: `plan`/`cancel` require the canonical
`ScanalyzePlatformAuthorityBootstrapPlan` permission set, while
`approve`/`apply`/`verify` require
`ScanalyzePlatformAuthorityBootstrapApply`. `AWS_PROFILE` text is not trusted
as proof of either role.

## Preflight: read-only

Use an SSO profile for the authority account. Do not export access keys or
session tokens.

```bash
export AWS_PROFILE='<authority-bootstrap-plan-sso-profile>'
export AWS_REGION='<authority-region>'
export AWS_DEFAULT_REGION="$AWS_REGION"

python3 scripts/deployment/platform-authority-bootstrap.py preflight \
  --authority-account-id '<authority-account-id>' \
  --region "$AWS_REGION" \
  --destination-account-id '<customer-a-account-id>' \
  --destination-account-id '<customer-b-account-id>'
```

The command fails if STS, region, destination separation, stack absence,
template validation, or the current S3 account setting is ambiguous. It prints
no ARN or AWS response and performs no writes.

## Plan: metadata write only

Choose a private directory outside every repository with permissions 0700. The
CLI creates the receipt with mode 0600 and refuses existing paths or symlinks.

```bash
umask 077
mkdir -p '<private-evidence-dir>'

python3 scripts/deployment/platform-authority-bootstrap.py plan \
  --authority-account-id '<authority-account-id>' \
  --region "$AWS_REGION" \
  --destination-account-id '<customer-a-account-id>' \
  --destination-account-id '<customer-b-account-id>' \
  --initiator-id '<approved-operator-id>' \
  --plan-out '<private-evidence-dir>/bootstrap-plan.json' \
  --allow-change-set-write
```

This creates one CloudFormation Change Set and an empty
`REVIEW_IN_PROGRESS` stack record; it creates no template resources and does not
execute the Change Set. Review the sanitized resource-type/action inventory,
template digest, expiry, account public-access transition, and plan digest. The
raw receipt remains controlled operational evidence.

At this point, the identity administrator renders the Apply inline policy with
the exact Change Set binding from the controlled plan:

```bash
python3 scripts/deployment/platform-authority-bootstrap.py render-apply-policy \
  --authority-account-id '<authority-account-id>' \
  --region "$AWS_REGION" \
  --destination-account-id '<customer-a-account-id>' \
  --destination-account-id '<customer-b-account-id>' \
  --plan '<private-evidence-dir>/bootstrap-plan.json' \
  --policy-out '<private-evidence-dir>/bootstrap-apply-policy.json'
```

The renderer derives the exact `change_set_name` and UUID from the
digest-validated, unexpired plan, rejects foreign or incomplete ARNs, and
writes mode 0600. The identity administrator validates the output with IAM
Access Analyzer, provisions or updates the canonical Apply permission set, and
assigns it only to the independent approver/executor group for the approved
window. Do not publish either ARN component in Git, Linear, NotebookLM, or
general CI artifacts.

## Approval: a different SSO principal

The approver signs in through a distinct, attributable Identity Center session
in the same account. Merely changing a profile name is insufficient; the CLI
compares hashed STS principal evidence.

```bash
export AWS_PROFILE='<independent-authority-apply-sso-profile>'
aws sso login --profile "$AWS_PROFILE"

python3 scripts/deployment/platform-authority-bootstrap.py approve \
  --authority-account-id '<authority-account-id>' \
  --region "$AWS_REGION" \
  --destination-account-id '<customer-a-account-id>' \
  --destination-account-id '<customer-b-account-id>' \
  --plan '<private-evidence-dir>/bootstrap-plan.json' \
  --approver-id '<approved-reviewer-id>' \
  --approval-out '<private-evidence-dir>/bootstrap-approval.json'
```

Approval expires no later than the plan. If the plan, template, account,
principal, or time binding changes, create a new plan and obtain new approval.

## Apply and verify

Apply is authorized separately. The exact command must be reviewed with its
account, region, plan digest, approval digest, cost boundary, and change window.
Keep the independent apply profile active; the plan profile is technically
unable to execute the Change Set.

```bash
python3 scripts/deployment/platform-authority-bootstrap.py apply \
  --authority-account-id '<authority-account-id>' \
  --region "$AWS_REGION" \
  --destination-account-id '<customer-a-account-id>' \
  --destination-account-id '<customer-b-account-id>' \
  --plan '<private-evidence-dir>/bootstrap-plan.json' \
  --approval '<private-evidence-dir>/bootstrap-approval.json' \
  --verification-out '<private-evidence-dir>/bootstrap-verification.json' \
  --backend-config-out '<private-evidence-dir>/platform-authority.backend.hcl' \
  --allow-bootstrap-apply
```

Success requires all of the following:

- account-level and bucket-level S3 public access blocked;
- bucket owner enforced;
- versioning enabled;
- default SSE-KMS with the exact key and S3 Bucket Key enabled;
- KMS rotation enabled;
- every mandatory bucket-policy deny present;
- exact stack/account/region/bucket/state-key outputs;
- native Terraform lockfile enabled and no DynamoDB lock table.

After success, initialize only `roots/platform-authority` with the generated
backend file. A separate saved Terraform plan, independent approval, and exact
GUG-125 apply are still required to create the platform-authority resources.

## Evidence and status

Publish only sanitized digests, resource-type counts, gate results, commit/PR,
and evidence classification to Linear/GitHub. Do not publish principal IDs,
Change Set ARNs, bucket/KMS identifiers, backend config, AWS responses, stack
events, plans, approvals, or receipts.

Repository and CI evidence are not live evidence. Backend live verification is
not a Scanalyze deployment and does not establish two-customer isolation.
Production remains **NO-GO**.
