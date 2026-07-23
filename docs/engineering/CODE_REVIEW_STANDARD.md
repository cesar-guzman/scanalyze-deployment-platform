# Scanalyze Code Review Standard

## Document control

| Field | Value |
|---|---|
| Owner | Platform Engineering |
| Status | CURRENT |
| Audience | Pull request authors, reviewers, code owners, and maintainers |
| Review cadence | Quarterly and after a material review escape |
| Last verified | 2026-07-23 |

This document supplements [`CONTRIBUTING.md`](../../CONTRIBUTING.md). It defines
how humans review changes and communicate findings. It does not reduce the
approval requirements in the contribution policy.

## Review objectives

A review should establish that:

1. the pull request solves the linked Linear issue and nothing materially wider;
2. behavior is correct in success, failure, retry, and rollback paths;
3. authentication, authorization, tenant isolation, and data boundaries remain
   fail-closed;
4. contracts, migrations, queues, workers, and infrastructure preserve
   compatibility and ownership;
5. tests prove the change rather than mock away its core behavior;
6. logs and evidence exclude secrets, PII, customer content, and raw plans/state;
7. documentation, rollout, recovery, and ownership are operationally complete;
8. the final head SHA—not an older revision—has the required evidence.

## Reviewer preparation

Before commenting:

- read the Linear issue, acceptance criteria, and risk class;
- confirm the repository, base branch, and pull request head SHA;
- read the PR description, files changed, and relevant ADRs;
- identify trust boundaries and stateful or irreversible operations;
- confirm whether generated files or dependency locks are present;
- review the highest-risk paths first;
- avoid spending the review budget on style already enforced by tools.

Reviewers MUST disclose when they lack the context or independence required to
approve a P0 change.

## Severity model

Prefix actionable comments with one of these labels:

| Label | Meaning | Merge effect |
|---|---|---|
| `[P0]` | Exploitable security/tenant failure, likely data loss, destructive cloud path, production-control bypass | Immediate blocker; escalate |
| `[P1]` | Material correctness, authorization, reliability, rollback, or operational defect | Blocker |
| `[P2]` | Bounded defect, missing regression evidence, maintainability problem likely to cause future failure | Fix or reviewer-approved follow-up |
| `[question]` | Context or decision is unclear | Non-blocking unless converted explicitly |
| `[suggestion]` | Optional improvement | Non-blocking |
| `[praise]` | Specific positive feedback | Non-blocking |

Do not inflate severity to win a preference. If impact is uncertain, ask a
question and explain the potential risk.

## Actionable comment format

A blocking comment should contain:

1. **Observation**: what the current code does.
2. **Impact**: the failure, threat, or operational consequence.
3. **Request**: the required outcome, not necessarily a forced implementation.
4. **Evidence**: a path, line, test, contract, or documented invariant.

Example:

```text
[P1] The export query is scoped by document ID but not by the authenticated
customer binding. A user who learns another tenant's ID could receive its ZIP.
Please include the verified customer ID in the repository lookup and add a
negative cross-tenant test.
```

Avoid:

```text
This looks wrong. Please rewrite it.
```

Comments MUST NOT contain copied tokens, logs with customer content, credentials,
signed URLs, raw Terraform plans/state, or exploit details inappropriate for a
public repository.

## What to inspect by change type

### Authentication and authorization

- issuer, audience, signature, expiry, and claim validation;
- server-side tenant/customer resolution;
- object-level authorization on every read/write;
- service-to-service versus human identity separation;
- negative tests for missing, forged, stale, and cross-tenant identity;
- no authorization based only on UI visibility or caller-controlled headers.

### Workers and event-driven processing

- event schema and version;
- customer/tenant binding through every hop;
- FIFO group and deduplication semantics;
- idempotency and partial failure behavior;
- retry limits, poison messages, and DLQ ownership;
- timeouts, throttling, cost, and redacted observability.

### Terraform, IAM, and GitHub Actions

- one declarative owner per resource;
- least privilege and exact resource/condition binding;
- no state, plan, or credential leakage;
- disabled backend for local validation;
- saved-plan identity and apply separation;
- pinned third-party actions and read-only default permissions;
- stable aggregate required checks;
- explicit environment and production boundaries.

### APIs, contracts, and migrations

- backward compatibility and explicit versioning;
- strict input validation and safe error responses;
- producer/consumer fixtures;
- up/down or forward-only migration plan;
- rollback compatibility across mixed versions;
- documentation and changelog impact.

### Frontend

- backend remains the authorization point;
- runtime configuration fails closed;
- loading, empty, error, unauthorized, and unavailable states;
- no token/PII leakage through telemetry or browser storage;
- accessibility and end-to-end behavior.

### Documentation-only

- current versus target state is explicit;
- links resolve to canonical sources;
- commands are safe, scoped, and use placeholders;
- claims match verified code/runtime evidence;
- owners, status, review cadence, and last verification are present where needed.

## Author responsibilities

The author MUST:

- acknowledge every actionable thread;
- push focused fixes instead of unrelated rewrites;
- identify the fixing commit;
- rerun and report relevant validation;
- update the PR summary when scope or risk changes;
- request re-review after material changes;
- avoid dismissing a concern because CI is green.

Acceptable responses:

```text
Fixed in abc1234. Added the cross-tenant negative test and reran:
python -m pytest ... -q (12 passed).
```

```text
I propose keeping the current API because ADR-021 requires compatibility with
v1. I added a fail-closed adapter and a test. Does that resolve the concern?
```

```text
Agreed this is valid but outside the approved issue. Follow-up GUG-000 has an
owner and acceptance criteria. Requesting reviewer approval to defer.
```

## Thread resolution

- The author may resolve non-blocking questions and suggestions after answering.
- The originating reviewer should resolve or explicitly accept the disposition
  of P0/P1/P2 findings.
- Security, tenant isolation, data loss, destructive infrastructure, and
  production-control findings require reviewer revalidation on the final SHA.
- A stale approval does not survive a material push.
- A discussion is not resolved by moving it to chat without a durable summary.

## Approval standard

Approval means the reviewer:

- reviewed the final relevant diff;
- understands the issue and risk class;
- found no unresolved blocker;
- accepts the test and documentation evidence;
- believes rollback/recovery is credible;
- is independent from the author;
- is willing to be named in the audit trail.

Approval does not authorize deployment or production.

## Review anti-patterns

Do not:

- rubber-stamp because the author is senior or the change is urgent;
- ask the author to silence a check instead of fixing root cause;
- combine architecture redesign with an unrelated bug fix;
- rely only on generated summaries without inspecting critical code;
- request personal style preferences as blockers;
- expose sensitive data in examples;
- approve an old SHA after a material last push;
- treat merge as runtime verification.

## Review completion checklist

- [ ] Linear issue and pull request scopes match.
- [ ] Risk class and required reviewers are correct.
- [ ] Highest-risk files and trust boundaries were inspected.
- [ ] Acceptance criteria have code/tests/evidence.
- [ ] Failure, retry, rollback, and negative paths were reviewed.
- [ ] Documentation and operations are updated.
- [ ] Sensitive-data hygiene is preserved.
- [ ] All blocking threads are resolved on the final SHA.
- [ ] Approval count and CODEOWNERS requirements are satisfied.

