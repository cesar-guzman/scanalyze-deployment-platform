# GUG-207 — KMS Alias Authorization Repair

## Problem

The merged platform-authority bootstrap used `kms:RequestAlias` to restrict
key-side `CreateAlias` and `UpdateAlias` permissions. AWS KMS does not supply
that condition for alias-management operations. The policy was structurally
valid but unusable when CloudFormation attempted to create the state alias.

## Implemented model

- exact alias ARN for the platform-authority state alias;
- exact authority account and region for affected KMS keys;
- canonical `service`, `data_class`, `account_id`, and `region` key tags;
- `CreateAlias`, `UpdateAlias`, and `DeleteAlias` on both required resource
  sides;
- no condition on the exact alias-resource statement, as required by KMS;
- `aws:CalledVia` CloudFormation enforcement on the required key-side grant;
- no `kms:RequestAlias`, alias wildcard, direct API fallback, or inferred
  ownership;
- negative tests for semantic condition compatibility.

KMS evaluates permissions for the exact alias and each affected key. The alias
statement prevents another alias from being managed; the key statement prevents
the exact alias from being attached to an unbound key and denies direct calls.

## Evidence state

- **Implemented:** local worktree contains the policy, tests, ADR, runbook and
  threat-model delta; reviewed commit remains pending.
- **Locally validated:** focused 20-test gate, security gate and pinned M2B
  preflight passed; the repository suite reported 1128 passed and provider
  validation 12/12.
- **CI validated:** only for the exact hotfix commit.
- **Live validated:** no.
- **AWS changes:** none.
- **Production:** **NO-GO**.

## Ingestion boundary

This source is sanitized. Do not ingest account IDs, principal identities,
permission-set assignments, Change Set identifiers, key/alias ARNs, backend
coordinates, AWS responses, stack events, plans, approvals, credentials, or
customer evidence.
