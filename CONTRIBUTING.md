# Contributing to Scanalyze

## Document control

| Field | Value |
|---|---|
| Owner | Platform Engineering |
| Audience | Human contributors, reviewers, code owners, maintainers, and release operators |
| Status | CURRENT policy; enforcement gaps are identified explicitly |
| Scope | `cesar-guzman/scanalyze-deployment-platform` |
| Work tracking | Linear project `Scanalyze — Product & Platform Delivery` |
| Review cadence | Quarterly and after a material incident or governance change |
| Last verified | 2026-07-23 against `main@0f3dc10` |

This is the canonical human contribution policy for the Scanalyze repository.
The words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are normative.

The repository is currently public. Treat every committed line, GitHub comment,
workflow log, and uploaded artifact as externally visible. Never use Git as a
document store for customer or operational data.

## Quick start

Before changing code:

1. Read this guide, [`README.md`](README.md), and the documentation for the
   component you will change. New contributors also complete the
   [`GitHub contributor walkthrough`](docs/engineering/GITHUB_CONTRIBUTOR_WALKTHROUGH.md).
2. Confirm that the work has one Ready Linear issue with an owner, acceptance
   criteria, risk class, repository, environment boundary, and rollback plan.
3. Start from the current `origin/main`, not an old local checkout.
4. Use one issue, one branch, one worktree, and one pull request.
5. Make the smallest change that satisfies the issue. Keep unrelated cleanup
   out of the pull request.
6. Run focused validation first and the applicable broader gates before review.
7. Open a draft pull request early and complete every section of the template.
8. Obtain the required independent review. Passing CI is not approval.
9. Merge only after the issue, review, checks, documentation, and rollback
   evidence agree.
10. Treat merge, deployment, runtime validation, and production approval as
    separate facts.

No step in this guide authorizes AWS mutation or production activity.

## 1. Sources of truth and precedence

| Domain | Authoritative source |
|---|---|
| Work scope, owner, priority, and status | Linear issue |
| Code and configuration | GitHub `main` |
| Architecture decisions | Accepted files under [`ADR/`](ADR/) |
| Repository ownership | [`CODEOWNERS`](CODEOWNERS) |
| Required CI contexts | [`governance/github-policy.json`](governance/github-policy.json) |
| Deployment topology and contracts | `deployment/`, `schemas/`, and reviewed Terraform |
| Runtime state | Read-only evidence from the exact environment |
| Production authorization | Explicit human approval through the approved production control |

If sources conflict, stop and resolve the conflict in the owning source. A
Linear status cannot override code, CI, GitHub protection, an ADR, runtime
evidence, or production authorization. A polished document cannot prove that a
capability is deployed.

The following evidence states MUST remain distinct:

- **Documented**: described in a reviewed source.
- **Implemented**: present in the referenced commit.
- **Evidenced**: supported by retained, sanitized evidence.
- **Tested**: the stated check completed against the stated revision/environment.
- **Approved**: an authorized human accepted the stated action.
- **Deployed**: applied to the stated environment.

## 2. Roles and separation of duties

### Contributor or author

- Owns the Linear issue and pull request from intake through handoff.
- Protects tenant isolation, secrets, customer data, and existing behavior.
- Produces tests, documentation, and sanitized evidence.
- Responds to every review thread.
- Does not approve or merge their own change.

### Reviewer

- Reviews the change, not the author.
- Verifies scope, behavior, tests, failure modes, security, and rollback.
- Uses the severity and comment format in
  [`docs/engineering/CODE_REVIEW_STANDARD.md`](docs/engineering/CODE_REVIEW_STANDARD.md).
- Rechecks material fixes after the last push.

### Code owner

- Is accountable for the owned surface in [`CODEOWNERS`](CODEOWNERS).
- Confirms architectural consistency and operational ownership.
- Does not treat CODEOWNER status as permission to self-approve.

### Maintainer

- Confirms required checks, reviews, conversation resolution, and issue state.
- Selects the approved merge strategy.
- Does not bypass a gate to accelerate delivery.

### Release or cloud operator

- Is separate from code authorship for high-risk changes.
- Confirms the exact repository, commit, environment, AWS profile, account, and
  region before any authorized operation.
- Retains sanitized execution and rollback evidence.

## 3. Human onboarding

Before the first technical issue is assigned, a team member MUST complete:

- named GitHub account; shared accounts are prohibited;
- MFA enabled and organization/repository access granted with least privilege;
- protected workstation with supported OS updates, disk encryption, screen
  lock, and endpoint protection;
- Git identity configured with the corporate address;
- SSH or HTTPS authentication using an approved short-lived or managed method;
- no long-lived AWS, GitHub, or application credentials stored in the repo;
- repository cloned from the canonical GitHub URL;
- local toolchain versions reconciled with `.tool-versions`,
  `.terraform-version`, workflow pins, and component instructions;
- read-through of this guide, `SECURITY.md`, relevant ADRs, and component docs;
- one low-risk onboarding pull request completed under independent review.

The end-to-end access, GitHub interface, clone, worktree, pull request, checks,
and first-day exercise are documented in
[`docs/engineering/GITHUB_CONTRIBUTOR_WALKTHROUGH.md`](docs/engineering/GITHUB_CONTRIBUTOR_WALKTHROUGH.md).

Signed commits are strongly recommended. Any future signature requirement MUST
be evaluated with the repository merge strategy, automation identities, and
recovery process before enforcement. Never weaken signature, MFA, or branch
controls locally.

## 4. Work intake and Definition of Ready

Linear is the durable delivery tracker. Chat and meetings can clarify work, but
decisions, blockers, scope changes, and closure evidence MUST be written back to
the issue.

An issue is Ready only when it contains:

- one repository and one intended component or bounded cross-component scope;
- problem statement and business/security impact;
- explicit in-scope and out-of-scope items;
- testable acceptance criteria;
- assignee and reviewer or review group;
- risk class: P0, P1, or P2;
- dependencies and blockers;
- required ADR or threat-model decision for high-risk changes;
- validation plan and expected evidence;
- rollout and rollback/recovery plan;
- environment boundary, including an explicit `no cloud` statement when local
  work is sufficient.

If implementation reveals a materially different problem, stop, update or split
the issue, and obtain review before expanding the pull request.

### Work-in-progress limit

The default contributor WIP limit is **one implementation issue**. A second item
may be accepted only for an urgent review or a documented blocker, and it MUST
use a separate branch, worktree, and pull request.

## 5. Risk classification and required review

| Class | Typical scope | Minimum independent approval |
|---|---|---|
| P0 | Authentication, authorization, tenant isolation, IAM, encryption, Terraform/CDK, CI/CD authority, schemas/contracts, migrations, customer data, production behavior | Two humans, including the applicable code/security/architecture owner |
| P1 | Bounded product behavior, frontend, non-sensitive operational tooling, backward-compatible API behavior | One applicable code owner |
| P2 | Documentation-only, tests-only, or low-risk maintenance with no runtime/security effect | One reviewer |

Self-approval never counts. A review made before a material last push MUST be
revalidated. If the required independent reviewer is unavailable, the change
waits or follows the exception process; urgency does not reduce the review bar.

The repository does not yet enforce all human-review requirements technically.
See
[`docs/engineering/GITHUB_ENFORCEMENT_BASELINE.md`](docs/engineering/GITHUB_ENFORCEMENT_BASELINE.md).
The policy remains mandatory during that gap.

## 6. Branch and worktree model

Every issue maps to exactly one branch, one worktree, and one pull request.

Allowed branch patterns:

```text
feat/gug-123-short-topic
fix/gug-123-short-topic
chore/gug-123-short-topic
review/gug-123-short-topic
```

Use lowercase ASCII, hyphens, and the Linear identifier. Do not use customer
names, account identifiers, personal names, secrets, or environment credentials
in branch names.

Recommended setup:

```bash
git fetch origin main
git rev-parse origin/main
git worktree add \
  -b fix/gug-105-ocr-worker-get-logger \
  ../scanalyze-gug-105-ocr-worker-get-logger \
  origin/main
cd ../scanalyze-gug-105-ocr-worker-get-logger
git status -sb
```

Before editing, confirm:

- repository root;
- branch name;
- exact base SHA;
- clean worktree;
- absence of unrelated work;
- expected component and acceptance criteria.

Never develop directly on `main`. Never reuse another issue's worktree. Never
mix a recovered, dirty, or stale checkout into a new package.

## 7. Implementation rules

Contributors MUST:

- inspect existing code, tests, ADRs, and component docs before editing;
- follow existing patterns before introducing abstractions or dependencies;
- keep functions small, typed where supported, and explicit about errors;
- validate all untrusted inputs and fail closed at authorization boundaries;
- preserve tenant/customer binding across APIs, events, storage, queues, and
  background processing;
- preserve FIFO, idempotency, retry, poison-message, and DLQ semantics;
- use synthetic fixtures; real customer documents and production payloads are
  prohibited;
- emit structured observability without tokens, document content, PII, financial
  payloads, raw OCR, or credentials;
- update tests and documentation in the same change when behavior changes;
- avoid unrelated formatting, generated churn, and dependency upgrades.

Contributors MUST NOT:

- bypass authentication, authorization, WAF, CI, scanners, or branch controls;
- add customer-specific forks or `if customer == ...` behavior;
- hardcode accounts, regions, ARNs, secrets, or tenant identifiers;
- swallow exceptions or convert failures into broad skips;
- weaken tests to make CI green;
- modify Terraform for a service-only issue unless the issue explicitly scopes
  the infrastructure change;
- create a new dependency without explaining ownership, license, security,
  maintenance, and rollback impact.

## 8. Security and sensitive data

Never commit, paste into a pull request, attach to an issue, or print in CI:

- `.env` files or environment exports;
- AWS keys, tokens, cookies, JWTs, private keys, certificates, or passwords;
- Terraform state or raw plans;
- customer documents, production logs, PII, bank/financial data, or extracted
  document content;
- database dumps, queue payloads, signed URLs, or session data;
- local archives, Finder duplicates, debug bundles, or credentialed config.

Use placeholders such as `<AWS_PROFILE>`, `<AWS_REGION>`, `<ACCOUNT_ID>`, and
synthetic identifiers. Evidence MUST be sanitized before upload.

Suspected vulnerabilities or accidental disclosure MUST follow
[`SECURITY.md`](SECURITY.md). Do not open a public issue with exploit details.

## 9. Local validation

Run the narrowest relevant check first. Before review, run the broader checks
appropriate to the changed surface.

### Documentation and governance

```bash
make contributor-docs-check
make docs-check
make github-governance-check
make git-safety
```

### Python, platform tooling, and workers

```bash
python -m pytest <focused-test-path> -q
make microservices-check
make security-check
```

For a changed worker, run its component suite with the documented `PYTHONPATH`
and a no-push image build when relevant. See
[`backend/workers/README.md`](backend/workers/README.md).

### Frontend

```bash
cd frontend/scanalyze-frontend-ui
npm ci
npm run check
npm run audit
npm run test:e2e
```

### Terraform or deployment contracts

```bash
make terraform-fmt-check
make provider-check
make schema-check
make security-check
make gitops-orchestrator-check
```

Local Terraform validation MUST use disabled backends and MUST NOT perform an
apply. A successful local or CI check is repository evidence only.

Record every command and outcome in the pull request. If a check was not run,
state why, the residual risk, and who must run it.

### Validation not run

An omitted check is not a silent success. The pull request MUST name the check,
reason it was not run, residual risk, and the person or gate that must complete
it. A required check cannot be waived only because it is slow or unavailable.

## 10. Documentation standard

Follow
[`docs/engineering/DOCUMENTATION_STANDARD.md`](docs/engineering/DOCUMENTATION_STANDARD.md).

Behavior changes require updates to the closest durable source:

- component `README.md` for setup or local operation;
- ADR for a material architectural/security decision;
- schema/API documentation for contract changes;
- runbook for deployment, rollback, recovery, or operational changes;
- threat-model delta for a changed trust boundary or abuse path;
- changelog/release notes when the repository adopts them.

Do not copy large documents into multiple locations. Link to the canonical
source, state its owner/status, and distinguish current behavior from target
state.

## 11. Commit standard

Commits MUST be reviewable and build toward one issue. Use an imperative
Conventional Commit subject when practical:

```text
fix(ocr-worker): restore the canonical logger import
docs(contributing): define the human review contract
test(auth): cover cross-tenant export denial
```

Include the Linear identifier in the commit body or trailer:

```text
Linear: GUG-105
```

Do not include secrets, customer names, account identifiers, or unverified
claims in commit messages. Do not rewrite shared history or force-push without a
maintainer-approved recovery plan.

## 12. Pull request standard

Open a draft pull request when the approach is ready for early feedback. A pull
request MUST:

- target `main`;
- reference exactly one primary Linear issue;
- use the repository pull request template without deleting sections;
- explain why the change is needed and what is intentionally excluded;
- declare P0/P1/P2 risk;
- identify auth, tenant, data, IAM, Terraform, CI/CD, and production impact;
- include focused and broad validation with exact outcomes;
- include documentation, rollout, rollback, and recovery notes;
- contain only sanitized evidence;
- be small enough to review confidently.

Prefer fewer than 400 non-generated changed lines. Larger changes require a
written decomposition rationale and reviewer agreement. Generated files,
lockfiles, schemas, and fixtures still require review even when excluded from
the size heuristic.

The pull request is Ready for Review only when:

- acceptance criteria are implemented or explicitly deferred;
- the branch is current with `main`;
- required local checks have passed;
- CI is green or every failure is classified;
- no unresolved author TODO remains;
- documentation and rollback are complete;
- the author performed a self-review of the final diff.

## 13. Review and comment etiquette

The full standard is in
[`docs/engineering/CODE_REVIEW_STANDARD.md`](docs/engineering/CODE_REVIEW_STANDARD.md).

Every actionable comment should state:

1. the observed behavior;
2. why it matters;
3. the requested outcome or a concrete option;
4. severity when the impact is not obvious.

Use respectful, technical language. Review the code, not the person. Questions
are not automatically blockers. Preferences must be labeled as non-blocking.

Authors respond with one of:

- `Fixed in <commit>` plus the validation performed;
- a reasoned alternative and supporting evidence;
- a follow-up Linear issue accepted by the reviewer;
- an explicit request for a decision.

Do not resolve a blocking security, authorization, data-loss, or production
thread without reviewer revalidation.

## 14. CI, merge, and branch hygiene

The required static checks are defined in
[`governance/github-policy.json`](governance/github-policy.json). Dynamic matrix
jobs provide evidence but MUST NOT become unstable branch-protection API names.

Before merge, verify:

- the exact head SHA;
- required checks are successful for that SHA;
- required human approvals are current;
- all blocking conversations are resolved;
- CODEOWNERS were included;
- no new secret, binary, state, plan, or sensitive artifact is present;
- the Linear issue and pull request describe the same scope;
- rollback and residual risks are recorded.

Squash merge is the default for one-issue branches. Another merge strategy
requires maintainer rationale. Delete the remote branch after merge when it is
no longer needed. Do not delete a worktree until evidence and any recovery need
have been reviewed.

## 15. Post-merge and release boundaries

A merged pull request proves only that the reviewed repository change reached
`main`. It does not prove:

- image publication;
- Terraform plan or apply;
- non-production deployment;
- runtime correctness;
- customer enablement;
- production readiness or production approval.

After merge:

1. verify the commit exists on `main`;
2. verify post-merge CI separately;
3. update Linear with the exact PR, merge SHA, checks, and remaining gates;
4. perform non-production validation only when separately authorized;
5. attach sanitized runtime evidence;
6. close the issue only when its stated Definition of Done is satisfied.

Production remains **NO-GO** unless an explicit current authorization states the
exact environment and action. Green CI, a merge, or a Linear `Done` status does
not grant that authority.

## 16. AWS and production safety

Local development uses no AWS profile by default.

For an explicitly authorized read-only cloud assessment:

1. obtain the approved profile and region from the issue or task owner;
2. set `AWS_PROFILE` and `AWS_REGION` explicitly;
3. run `aws sts get-caller-identity`;
4. record the account/profile/region without exposing credentials;
5. use `list`, `describe`, and `get` operations only.

Cloud writes require a separate, current approval for the exact account,
environment, action, and rollback. Production is read-only by default.

Prohibited without explicit approval include Terraform apply/destroy, IAM
changes, ECS operations, Step Functions execution, queue purge/redrive, database
writes, S3 deletion, CloudFront invalidation, Route 53 changes, pipeline release,
and destructive migration.

## 17. Exceptions and break-glass

No rule is skipped implicitly. An exception requires a linked issue containing:

- rule and scope affected;
- business reason and risk class;
- named owner and independent approver;
- compensating controls;
- exact start and expiration time;
- monitoring and evidence plan;
- rollback and permanent remediation;
- confirmation that production remains blocked when separation of duties or
  evidence cannot be maintained.

Break-glass is an incident procedure, not a shortcut. Preserve evidence, limit
authority and duration, and complete retrospective review.

## 18. Offboarding and transfer

When a contributor changes role or leaves the team:

- revoke repository, organization, cloud, and environment access promptly;
- remove or transfer CODEOWNERS and review assignments;
- transfer active Linear issues and document branch/worktree/PR state;
- invalidate exposed or personal credentials through the owning system;
- preserve company-owned commits and sanitized evidence;
- do not copy repository data, customer information, or credentials to personal
  storage;
- review unmerged branches for required recovery or deletion.

## 19. Enforcement and continuous improvement

Policy text is not equivalent to technical enforcement. The verified baseline
and target controls are documented in
[`docs/engineering/GITHUB_ENFORCEMENT_BASELINE.md`](docs/engineering/GITHUB_ENFORCEMENT_BASELINE.md).

If practice and this document diverge:

1. fail closed for security, tenant, data, IAM, CI/CD, and production risk;
2. open or update a Linear issue;
3. change the guide, automation, or protection through a reviewed pull request;
4. add a regression test when the rule can be automated;
5. record the owner and verification date.

Questions and proposed improvements belong in GUG-111 or a scoped successor
issue. Security reports follow `SECURITY.md`.

## External references

This repository-specific contract is informed by:

- [NIST SP 800-218, Secure Software Development Framework (SSDF) 1.1](https://csrc.nist.gov/pubs/sp/800/218/final)
- [GitHub: helping others review changes](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/getting-started/helping-others-review-your-changes)
- [GitHub: protected branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
- [GitHub: issue and pull request templates](https://docs.github.com/en/communities/using-templates-to-encourage-useful-issues-and-pull-requests/about-issue-and-pull-request-templates)
- [GitHub: repository security advisories](https://docs.github.com/en/code-security/concepts/vulnerability-reporting-and-management/repository-security-advisories)

GitHub issue forms are currently documented as public preview. Treat the form
as an intake convenience, keep Linear as the durable work tracker, and
revalidate the form schema during each governance review.
