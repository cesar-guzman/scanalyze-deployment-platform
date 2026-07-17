# GUG-208 — Identity Center Permission-Set Name Contract

## Problem

The original platform-authority Plan and Apply permission-set names exceeded
the IAM Identity Center maximum of 32 characters. The service rejected the
first Plan create before creating a resource; Apply was not attempted. This is
not live bootstrap evidence.

## Implemented model

- canonical Plan name: `ScanalyzeAuthorityBootstrapPlan`;
- canonical Apply name: `ScanalyzeAuthorityBootstrapApply`;
- portable ASCII allowlist and 1-to-32-character validation;
- exact account-local `AWSReservedSSO_*` role matching;
- no truncation, alias, legacy fallback, customer suffix, environment suffix,
  profile-name authority, or manual IAM role;
- Plan/Apply separation remains mandatory.

## Evidence state

- **Implemented:** local GUG-208 worktree only until the reviewed commit merges;
- **Locally validated:** 29 focused tests, security 6/6, repository 1,136,
  contract matrix 114/114, and provider validate 12/12 passed with Python
  3.11.14 and Terraform 1.14.6;
- **CI validated:** pending the exact commit;
- **Live validated:** no;
- **AWS changes:** one rejected request, zero resources or assignments;
- **Production:** **NO-GO**.

After merge and `main` verification, creating or assigning the corrected
permission sets requires fresh, explicit authorization and independent group
membership. The exact Change Set, apply, backend, customer accounts, and
deployments remain separate gates.

## Ingestion boundary

This source is sanitized. Do not ingest real account IDs, group members,
principal identities, permission-set ARNs, assignments, Change Set IDs, AWS
responses, credentials, or operational evidence.
