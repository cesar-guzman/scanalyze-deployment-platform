# ADR-035: KMS Alias Authorization Boundary

- **Status:** Proposed; accepted only after reviewed merge and main verification
- **Date:** 2026-07-16
- **Work package:** GUG-207
- **Parent:** GUG-206
- **Baseline:** `5d7ff57483658fbcc271284cec519944be961df7`
- **AWS live validation:** None
- **Production:** **NO-GO**

## Context

PR #21 added a CloudFormation bootstrap for the dedicated platform-authority
state boundary. Its Apply policy separated the exact alias ARN from the
associated KMS key, but conditioned the key-side alias operations on
`kms:RequestAlias`. AWS KMS does not make that condition key available to
alias-management operations. It applies only when an alias identifies a key in
cryptographic operations, `DescribeKey`, or `GetPublicKey`.

KMS authorizes `CreateAlias`, `UpdateAlias`, and `DeleteAlias` against both the
alias and every affected KMS key. The unsupported condition therefore made the
key-side Allow unusable. Access Analyzer and CI accepted the policy syntax, but
the first live `AWS::KMS::Alias` operation would have been denied.

## Decision

Alias management uses two complementary statements:

1. The alias-side statement grants `CreateAlias`, `UpdateAlias`, and
   `DeleteAlias` only on the exact
   `alias/scanalyze-platform-authority-state` ARN for the bound account and
   region.
2. The alias-side statement has no `Condition`. AWS KMS does not support
   condition keys when an alias is the statement resource; the exact ARN is
   the complete alias-side restriction.
3. The key-side statement grants the same three actions only on keys in the
   bound account and region whose `service`, `data_class`, `account_id`, and
   `region` resource tags exactly match the platform-authority state contract,
   and only when `aws:CalledVia` contains `cloudformation.amazonaws.com`.

KMS must authorize every affected resource. The exact alias statement prevents
use of another alias, while the tagged-key statement prevents association with
an unbound key and denies a direct request because `aws:CalledVia` is absent.
`kms:RequestAlias` and every other condition are forbidden on the alias-resource
statement.

The template key policy continues to delegate account IAM authorization. No
direct KMS mutation, wildcard alias ARN, wildcard account/region, request-
supplied alias, or alias-based inference establishes authority.

## Alternatives rejected

- **Keep `kms:RequestAlias`:** syntactically valid but absent from alias
  operation request context, so the key-side Allow never applies.
- **Use `kms:ResourceAliases`:** a new key does not yet have the alias during
  `CreateAlias`; using the future alias as the initial binding is circular.
- **Grant `kms:*` or alias/key wildcards:** would allow authority over unrelated
  keys or aliases.
- **Permit direct CLI fallback:** bypasses the reviewed CloudFormation Change
  Set and destroys the Plan/Apply separation.
- **Put `aws:CalledVia` on the alias resource:** contradicts the KMS alias
  authorization contract, which does not support condition keys on that
  resource type. The required key-side authorization is the forward-access
  enforcement point.

## Consequences

- CloudFormation can create, update, delete, and roll back the exact alias.
- The Apply principal still cannot manage an unrelated alias or untagged key.
- Regression tests must validate semantic condition compatibility in addition
  to IAM policy syntax.
- PR #21 CI evidence remains historical, but it does not establish usable live
  alias authorization.

## Rollback

Before merge, discard the hotfix branch. After merge but before any bootstrap,
revert the hotfix commit and keep GUG-206 blocked. After a partially attempted
bootstrap, do not retry or mutate KMS directly; inspect the exact Change Set and
stack events read-only, preserve retained resources, and follow the reviewed
forward-recovery runbook.

## Evidence classification

| Class | Status |
|---|---|
| Implemented | Local hotfix worktree; commit and review pending |
| Locally validated | `platform-authority-bootstrap-check` (20 passed), `security-check`, and pinned `preflight-m2b` (1128 repository tests; provider validate 12/12) passed |
| CI validated | Pending exact hotfix commit |
| Live validated | No |
| AWS writes | None |
| Production | **NO-GO** |
