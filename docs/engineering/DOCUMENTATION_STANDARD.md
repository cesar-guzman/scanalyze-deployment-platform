# Scanalyze Engineering Documentation Standard

## Document control

| Field | Value |
|---|---|
| Owner | Platform Engineering |
| Status | CURRENT |
| Audience | Authors, reviewers, operators, architects, security, and auditors |
| Review cadence | Quarterly and when behavior changes |
| Last verified | 2026-07-23 |

Documentation is part of the implementation. It must be source-traceable,
reviewable, and explicit about what is current, proposed, verified, and approved.

## Canonical locations

| Content | Location |
|---|---|
| Repository purpose and entrypoints | `README.md` |
| Human contribution policy | `CONTRIBUTING.md` |
| GitHub access and contributor onboarding | `docs/engineering/GITHUB_CONTRIBUTOR_WALKTHROUGH.md` |
| Security reporting | `SECURITY.md` |
| Component setup and operation | nearest component `README.md` |
| Architecture decisions | `ADR/` |
| Engineering standards | `docs/engineering/` |
| Deployment design | `docs/deployment/` |
| Operator and recovery procedures | `docs/operations/` and `playbooks/` |
| Threat-model deltas | `docs/security/` |
| Production-readiness gates | `docs/production-readiness/` |
| Historical evidence | `reports/`, clearly labeled and never used as current state |

Link to a canonical source instead of copying it into multiple documents.

## Required document metadata

Normative standards, runbooks, and current-state assessments should identify:

- title and purpose;
- owner;
- audience;
- status;
- scope and explicit exclusions;
- last verified date and, when relevant, commit/environment;
- review cadence;
- approval or review path;
- related ADR, issue, runbook, or evidence.

Short component READMEs do not need a formal control table when ownership and
scope are obvious from their location.

## Status vocabulary

Use these terms consistently:

- **CURRENT**: implemented and verified in the stated source/environment.
- **TRANSITIONAL**: currently used but scheduled for replacement.
- **TARGET STATE**: proposed or accepted direction not fully implemented.
- **DEPRECATED**: existing behavior that new changes must not adopt.
- **NO-GO**: explicitly unauthorized.
- **HISTORICAL EVIDENCE**: a past observation that may not describe current state.

Do not label a target design as current. Always include the verification basis
for a current-state claim.

## Evidence vocabulary

Keep these facts separate:

| State | Meaning |
|---|---|
| Documented | Written in a reviewed source |
| Implemented | Present in a referenced commit |
| Evidenced | Supported by retained, sanitized evidence |
| Tested | A named check passed against a named revision/environment |
| Approved | An authorized human accepted the named action |
| Deployed | The named artifact/change reached the named environment |

Examples:

- “CI passed for `abc1234`” does not mean “deployed.”
- “PR merged” does not mean “production approved.”
- “Terraform plan succeeded” does not mean “Terraform apply ran.”
- “Resource name observed” does not prove the intended policy is effective.

## Writing requirements

Documentation MUST:

- use clear, direct language;
- define acronyms and domain terms;
- distinguish required rules from recommendations;
- use placeholders for accounts, profiles, regions, ARNs, tenants, and secrets;
- include safe failure, rollback, and recovery behavior for operational commands;
- show read-only commands before mutation commands;
- state authorization prerequisites for cloud or production operations;
- use synthetic examples;
- link relative repository paths with valid Markdown links;
- identify unresolved gaps, risks, and owners.

Documentation MUST NOT:

- contain credentials, tokens, customer data, PII, raw production logs, state, or
  unsanitized plans;
- claim approval on behalf of a human;
- hide uncertainty behind polished language;
- describe a destructive command as routine;
- use real account/customer identifiers in examples;
- duplicate a long source without a maintenance reason.

## Change triggers

Update documentation in the same pull request when changing:

- public or internal API/event/schema contracts;
- environment variables or runtime configuration;
- auth, authorization, tenant, or data boundaries;
- Terraform modules, ownership, inputs, outputs, or layer order;
- GitHub Actions, required checks, environments, or OIDC;
- deployment, rollback, recovery, or break-glass procedures;
- dependencies, local setup, test commands, or supported versions;
- logging, metrics, alarms, DLQ, or on-call behavior;
- feature flags, entitlements, migration, or deprecation behavior.

An ADR is required for a material, durable decision with alternatives or
cross-component impact. A threat-model delta is required when a trust boundary,
actor, asset, abuse path, or security control changes.

## Commands and examples

Commands must:

- be copyable without hidden prerequisites;
- start with a safe/read-only or local mode;
- use explicit repository directories;
- avoid default AWS profiles;
- use `<PLACEHOLDER>` values;
- explain expected output and failure behavior;
- state whether the command writes files, remote systems, or cloud resources.

Never show `terraform apply`, destructive AWS operations, or production actions
without an explicit authorization gate and rollback/recovery context.

## Diagrams and tables

Use a diagram when it materially clarifies three or more relationships, trust
boundaries, owners, or dependent stages. Keep diagrams source-controlled as text
when possible. Tables are appropriate for mappings, matrices, and current versus
target comparisons.

All diagrams must have text that remains understandable without rendering.

## Review checklist

- [ ] Owner, scope, status, and verification basis are clear.
- [ ] Current and target state are separated.
- [ ] Claims link to code, ADR, tests, or sanitized evidence.
- [ ] Links and commands are valid and safe.
- [ ] No secret, PII, customer, state, or raw-plan data is present.
- [ ] Rollback, recovery, and failure behavior are documented where relevant.
- [ ] Duplicated content has a justified owner and maintenance path.
- [ ] Related Linear issue and pull request are linked.
