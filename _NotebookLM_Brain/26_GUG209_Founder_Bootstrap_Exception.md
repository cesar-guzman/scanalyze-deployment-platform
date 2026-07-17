# GUG-209 — Bounded Founder Bootstrap Exception

## Problem

The normal platform-authority bootstrap requires two independently attributable
IAM Identity Center principals: one creates/reviews the Change Set and another
approves/executes it. A new authority account can temporarily have a single
founder operator. Treating that situation as ordinary self-approval would make
the normal separation-of-duties control disappear exactly when the first
durable state boundary is created.

## Offline-only target model

GUG-209 defines a separate, fail-closed, single-operator exception rather than
altering the normal approval flow:

- it is bound to one pre-designated dedicated authority account, one Region,
  and `non-production`; those live identifiers stay outside this sanitized
  source;
- the record explicitly says that independent approval is absent and has no
  approver identifier;
- it applies to one fresh reviewed backend Change Set with `CREATE` semantics,
  one offline record format, and one intended future attempt;
- Plan and Apply are temporary, non-overlapping windows with separate
  permission sets and a recorded gap;
- AWS evaluates policy `Deny` conditions against its own request time, rather
  than trusting an operator-local clock;
- policy rendering privately binds the one approved Identity Center subject;
- the time-bound deny remains after expiry for a full session-safety retention
  period, while assignments and memberships are removed and read back;
- absent cleanup proof is `REVOCATION_REQUIRED`, not success;
- BreakGlass, production, customer destinations, retries, direct storage/key
  mutation, and normal-flow self-approval remain prohibited.

The exception is an explicit risk acceptance. It never claims that an
independent approval occurred and it cannot be reused for later customer
deployments or normal Terraform plans.

Local JSON records, digests, and rendered policies are not durable
authorization, trusted AWS evidence, or an exactly-once ledger. GUG-209 is
**OFFLINE-ONLY — LIVE EXECUTION BLOCKED**. A future separately reviewed policy
enforcement point must use durable compare-and-swap, trusted identity/event
evidence, and immediate readback of the exact Change Set, template, and
resource inventory before any AWS execution.

## Normal flow remains authoritative

The normal Plan/Apply process is unchanged: independent people, non-overlapping
roles, an exact reviewed Change Set, and separate verification remain
mandatory. GUG-209 is only a bounded bridge for a documented single-founder
condition. When independent operators exist, the exception is unavailable.

## Evidence and safety boundary

This source describes repository intent and testable contracts. It does not
authorize AWS execution. A future live PEP additionally needs exact
CloudFormation Change Set-name binding, bounded KMS alias creation, separate
live approval, read-only reconciliation, and verified revocation. It does not
prove customer isolation, a Scanalyze deployment, or production readiness.

- **Implemented:** only when the reviewed commit includes the separate
  contracts, policies, ledger/revocation logic, tests, ADR, runbook, and threat
  model.
- **Locally validated / CI validated:** only with named passing gates for the
  exact commit.
- **Live validated:** no; live execution is blocked until the future PEP and
  its durable evidence boundary exist.
- **Production:** **NO-GO**.

## Ingestion boundary

Ingest this sanitized source only. Do not ingest account IDs, user IDs, emails,
principal or permission-set ARNs, group memberships, Change Set identifiers,
plan/approval/ledger/revocation records, policy renderings, state/backend
files, AWS responses, credentials, logs, screenshots, customer evidence, or
any raw operational artifact.
