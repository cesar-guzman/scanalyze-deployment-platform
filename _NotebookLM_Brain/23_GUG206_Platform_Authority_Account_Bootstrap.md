# GUG-206 — Dedicated Platform-Authority Account Bootstrap

## Problem

The portable platform-authority Terraform root cannot safely create its own
remote state. The repository's older bootstrap belongs to customer deployments,
uses deployment-derived naming and legacy DynamoDB locking, and therefore must
not be reused for the machine control plane.

## Implemented design

GUG-206 defines an independent, recoverable state bootstrap for a dedicated AWS
account:

- exact authority account and region equality;
- explicit inequality with every customer destination;
- one retained rotating KMS key and one retained versioned state bucket;
- fixed `platform-authority/terraform.tfstate` key;
- native S3 lockfile and no DynamoDB lock table;
- bucket-owner enforcement and public-access blocking at bucket and account;
- deny policies for insecure, cross-account, wrongly encrypted, arbitrary-key,
  and state-delete operations;
- CloudFormation Change Set review without execution during plan;
- independent Identity Center principal approval and exact apply;
- read-only verification after an uncertain result;
- private operational receipts outside Git and sanitized evidence elsewhere.

## Identity model

IAM Identity Center is the human bootstrap/recovery plane. Two dedicated,
time-bound and non-overlapping permission sets separate Change Set
creation/cancellation from exact execution and backend provisioning. The Apply
policy is rendered after review to one exact Change Set ARN and disabled after
the bootstrap window. Backend-mutating S3 permissions and required KMS
key-side permissions require an `aws:CalledVia` chain containing
CloudFormation, preventing their direct use; the exact alias-resource grant is
condition-free because KMS requires that shape. The explicit all-true account
S3 public block is the sole direct mutation.
Identity Center creates the account-local roles; no
manual IAM user or standing bootstrap role is created. GitHub OIDC remains the
later machine execution plane created by `roots/platform-authority`.

Profile names, aliases, last-four digits, request values, and local operator
labels are not authority. The live STS principal must be an Identity Center
session and protected operations require the canonical Plan or Apply
permission-set role. Exact records and independent assignments are required.

## Execution sequence

1. Read-only STS/account/template preflight.
2. Create one unexecuted Change Set and short-lived plan record.
3. Review template/resource/control digests.
4. A different SSO principal approves that exact plan.
5. Under explicit authorization, enable account S3 public blocking and execute
   the exact Change Set once.
6. Verify every bucket/KMS/native-lock control before rendering backend config.
7. Separately plan and apply the platform-authority Terraform root.
8. Only then continue sequential GUG-125 customer deployment/isolation proof.

## Evidence state

- **Implemented:** repository contracts, template, core, CLI, policy, tests,
  ADR, runbook, and threat-model delta when present in the reviewed commit.
- **Locally validated:** only after named offline gates pass.
- **CI validated:** only after required checks pass for the exact commit.
- **Live validated:** no; read-only inventory is not bootstrap execution.
- **Blocked:** disjoint minimum permission sets, independent reviewer,
  authorized Change Set/apply, post-verification, platform-authority Terraform,
  and two-customer isolation proof.
- **Production:** **NO-GO**.

## Post-merge correction

GUG-207 supersedes the original key-side `kms:RequestAlias` condition. Alias
management requires exact permissions on both the alias and affected key;
conditions are unsupported on the alias resource, and `kms:RequestAlias` is not
valid for those operations. Refer to sanitized source 24 for the corrected
split authorization boundary. GUG-206 is not complete
until that hotfix is merged and verified on main.

## Ingestion boundary

Ingest this sanitized source only. Never ingest account IDs, principals,
permission-set assignments, Change Set identifiers, plans, approvals, backend
files, bucket/KMS identifiers, state, AWS responses, stack events, screenshots,
logs, credentials, or customer evidence.
