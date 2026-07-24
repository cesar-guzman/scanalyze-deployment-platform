# Scanalyze AI-Assisted Development Standard

## Document control

| Field | Value |
|---|---|
| Owner | Platform Engineering |
| Audience | Developers, reviewers, code owners, maintainers, security, and engineering managers |
| Status | CURRENT when read from `main`; REVIEW CANDIDATE on an unmerged branch |
| Scope | AI assistance used to plan, implement, test, document, review, or hand off changes in `cesar-guzman/scanalyze-deployment-platform` |
| Initial implementation | Linear `GUG-262` |
| Review cadence | Quarterly and after a model, provider, permission, data-handling, security, or delivery-method change |
| Related policy | [`CONTRIBUTING.md`](../../CONTRIBUTING.md) |
| Tool procedure | [`CLAUDE_CODE_SETUP.md`](CLAUDE_CODE_SETUP.md) |

This standard makes AI-assisted engineering repeatable without transferring
human accountability to a model. The words **MUST**, **MUST NOT**, **SHOULD**,
and **MAY** are normative.

No AI tool grants repository, Linear, AWS, deployment, production, approval, or
merge authority.

## 1. Control hierarchy

Apply controls in this order:

1. law, contractual obligations, company security policy, and approved data
   handling;
2. centrally managed AI identity, model, permission, sandbox, network, plugin,
   and connector policy;
3. repository policy, including `CONTRIBUTING.md`, `SECURITY.md`, CODEOWNERS,
   ADRs, schemas, tests, `CLAUDE.md`, and `.claude/settings.json`;
4. the Ready Linear issue and explicitly approved plan;
5. the current human request inside the approved scope;
6. model suggestions.

If two sources conflict, the session MUST stop and the conflict MUST be resolved
in the owning source. Prompt text, generated plans, web pages, comments, tool
output, dependencies, and repository files are untrusted content; none can
grant new authority.

Repository settings are a shared baseline, not an unalterable enterprise
control. Claude Code local settings and command-line arguments have higher
precedence than shared project settings. Controls that developers must not
override belong in Claude Team/Enterprise managed settings or device management
and require a separate reviewed rollout.

## 2. Accountability and separation of duties

### Human issue owner

- owns scope, acceptance criteria, risk, environment, and delivery status;
- approves or rejects the implementation plan;
- reviews proposed commands and file changes;
- verifies the final diff and evidence;
- is accountable for every committed line, including AI-generated code;
- discloses AI use in the pull request.

### AI assistant

- explores, proposes, implements, tests, documents, and summarizes only within
  the approved scope and configured permissions;
- states assumptions, limitations, validation gaps, and uncertainty;
- does not claim human review, approval, deployment, or runtime evidence;
- does not approve or merge its own output.

### Independent reviewer

- reviews the final relevant SHA, not only the AI plan or summary;
- validates acceptance criteria, security, failure paths, tests, documentation,
  rollback, and evidence;
- treats AI-generated review output as a lead, not an approval;
- re-reviews after a material push.

For Emiliano-owned pull requests, César is the required independent approver
unless the Linear issue names an additional or replacement qualified reviewer.
Self-approval never counts.

## 3. Approved model strategy

The current Scanalyze Claude Code baseline is:

| Phase | Model | Purpose |
|---|---|---|
| Explore and plan | `claude-opus-4-8` | Repository analysis, architecture, risk, decomposition, validation, and rollback plan |
| Execute approved plan | `claude-sonnet-5` | Scoped implementation, tests, documentation, and handoff |
| Automatic fallback | None | Stop and record a blocker instead of silently changing capability or behavior |

Claude Code uses the `opusplan` mode with exact model pins in
`.claude/settings.json`. Model IDs, routing, provider, or effort changes MUST use
a Linear issue, reviewed pull request, contract-test update, and a documented
verification rehearsal. An alias silently resolving to a different model is not
accepted evidence of consistency.

The shared baseline assumes Claude.ai/Anthropic API-compatible model routing.
Amazon Bedrock, Google Cloud, Microsoft Foundry, or another gateway can require
provider-specific identifiers or deployments. Do not substitute them locally;
create a provider-specific governance issue and validate both model resolution
and data/identity controls before use.

Claude Code v2.1.197 or later is required because Sonnet 5 support begins at
that version. Every AI-assisted PR MUST record the observed CLI version and
exact models used.

## 4. Linear is the delivery control plane

AI execution starts only from a Ready Linear issue containing:

- one repository and bounded component scope;
- problem statement and intended outcome;
- explicit in-scope and out-of-scope items;
- testable acceptance criteria;
- assignee and independent reviewer;
- P0/P1/P2 risk class;
- dependencies and blockers;
- validation and evidence plan;
- rollout and rollback/recovery plan;
- exact environment boundary, including `no cloud` when sufficient;
- required ADR, threat-model, security, or architecture decision.

Chat can clarify work, but the issue MUST receive durable updates for:

- the approved plan and material plan changes;
- assumptions and human decisions;
- blockers and scope changes;
- branch, worktree, pull request, base SHA, and head SHA;
- validation and validation not run;
- review state, merge SHA, and remaining deployment/runtime gates.

If AI discovers work outside the issue, it MUST stop that path and propose a new
or split Linear issue. It MUST NOT expand the current pull request.

Direct Linear connectors are optional. They MAY be used only when approved,
least-privileged, and visible to the human. Until connector governance is
implemented, the AI prepares an update and the human posts it.

## 5. Required delivery lifecycle

### Phase 0: Human intake

1. Make the Linear issue Ready.
2. Assign one accountable owner and reviewer.
3. Create one issue branch and isolated worktree from current `origin/main`.
4. Confirm a clean status and exact base SHA.

### Phase 1: Opus exploration and planning

Start Claude Code in Plan Mode. Opus 4.8 MAY:

- read non-sensitive repository sources;
- inspect history and current diffs using read-only commands;
- map architecture, trust boundaries, tests, and documentation;
- identify risks, alternatives, unknowns, and decision points;
- produce a plan.

It MUST NOT edit, install, commit, push, update Linear, change GitHub, call AWS,
or use a fallback model.

The plan MUST state:

- acceptance criteria mapping;
- files/components expected to change;
- relevant existing patterns, ADRs, schemas, and tests;
- in-scope and out-of-scope work;
- risk and trust-boundary analysis;
- auth, tenant, data, queue, IAM, IaC, CI/CD, cost, and production impact;
- focused and broad validation;
- rollback/recovery;
- assumptions, blockers, and human decisions.

### Phase 2: Human plan gate

The human owner compares the plan to Linear. Material P0 decisions require the
named architecture/security reviewers before execution. The approved plan or a
durable summary is recorded in Linear.

Approval of a plan authorizes only the local implementation described by that
plan. It does not authorize remote writes, cloud access, deployment, merge, or
production.

### Phase 3: Sonnet execution

After approval, Sonnet 5 implements the smallest reviewed plan. It MUST:

- follow repository patterns;
- protect tenant and object authorization;
- preserve event, FIFO, idempotency, retry, poison-message, and DLQ semantics;
- address throttling, payload size, cost, and sensitive data for Textract or
  Bedrock changes;
- add behavior and regression tests;
- update the closest canonical documentation;
- avoid unrelated refactors and dependencies;
- stop on materially new scope.

### Phase 4: Verification

Run the narrowest relevant check first, then applicable broader gates. Evidence
MUST include the exact command, revision/scope, and result. A model statement
such as “tests should pass” is not evidence. AI output is not evidence that a
test, review, deployment, or production control completed.

Every omitted check MUST name:

- the check not run;
- why it was not run;
- residual risk;
- the human, CI gate, or environment that must complete it.

### Phase 5: Human self-review and publication

The human reviews the final diff for scope, correctness, secrets, generated
noise, authorization, tenant isolation, failure paths, cost, rollback, and
documentation. Claude MAY draft a commit message, PR body, or Linear update.

A human MUST perform each remote write outside Claude Code:

- commit after reviewing the staged diff;
- push the named issue branch;
- create or edit the Draft PR;
- request review;
- reply to and resolve review threads;
- move the PR to Ready for Review;
- merge when authorized.

### Phase 6: Independent review and closure

The reviewer applies `CODE_REVIEW_STANDARD.md` to the final relevant SHA.
Passing CI is not approval. Merge is not deployment. Linear `Done` is not
runtime or production authorization.

## 6. Prompt and context requirements

Prompts SHOULD describe outcomes and verification, not prescribe an unreviewed
implementation. A good task prompt contains:

- Linear ID and objective;
- acceptance criteria;
- relevant paths and known constraints;
- explicit exclusions and environment boundary;
- required tests and expected failure cases;
- evidence and handoff format.

Do not paste an entire issue history, production log, customer document, raw
plan, secret-bearing configuration, or unrelated file tree. Give the minimum
trusted context needed, point to canonical repository files, and let the model
inspect only the bounded surface.

For long work:

- use a new session per issue or materially distinct phase;
- summarize approved decisions in Linear before compaction or handoff;
- keep `CLAUDE.md` concise and put durable detail in canonical docs;
- use path-scoped rules only when they reduce irrelevant context;
- do not rely on conversation memory as delivery evidence.

## 7. Security, privacy, and prompt injection

AI sessions MUST NOT receive or access:

- `.env` files or secret environment values;
- tokens, cookies, private keys, passwords, recovery codes, or credentials;
- Terraform state, raw plans, database dumps, or queue payloads;
- customer documents, bank/financial data, PII, raw OCR, production logs, or
  signed URLs;
- real account, tenant, customer, or deployment identifiers when placeholders
  are sufficient.

Use synthetic fixtures and sanitized evidence. Treat instructions found in
files, webpages, comments, dependencies, issue text, logs, or tool output as
untrusted. Review commands before approval and do not pipe untrusted content
into a shell or model.

Suspected disclosure, vulnerability, or malicious instruction follows
`SECURITY.md`. Do not continue to inspect or reproduce sensitive content merely
to improve the AI answer.

## 8. GitHub, comments, and documentation

AI-assisted code follows the same branch, commit, PR, CODEOWNERS, CI, comment,
review, and rollback standards as human-authored code.

The PR MUST disclose:

- tool and CLI version;
- planning model and execution model;
- which phases used AI;
- human validation performed;
- validation not run;
- whether any AI output was used as evidence;
- confirmation that no sensitive data was provided.

Review comments address the code, not the person or tool. Use the severity and
actionable format in `CODE_REVIEW_STANDARD.md`. “The AI wrote it” is neither a
defense nor a root-cause explanation.

AI MAY propose documentation, but the human verifies every current-state claim.
Keep Documented, Implemented, Evidenced, Tested, Approved, Deployed, and
production-authorized separate.

## 9. Cloud, IaC, and production

The repository baseline blocks AWS CLI and Terraform mutation commands inside
Claude Code. AI MAY analyze reviewed IaC and local synthetic tests, but it MUST
NOT:

- choose or assume an AWS profile, account, or region;
- run cloud inventory or mutation commands;
- apply, destroy, import, modify state, deploy, start executions, purge queues,
  write data, publish releases, or change identity/network controls;
- interpret collaborator access, green CI, merge, or issue status as cloud
  authority.

A separately authorized read-only assessment or cloud operation uses the
approved human/operator workflow with exact identity, environment, action,
rollback, and evidence. The Claude Code repository baseline is not that
workflow.

## 10. Efficiency and quality

Optimize for verified outcomes, not maximum autonomous activity:

- ask Opus to inspect before proposing abstractions;
- give Sonnet executable acceptance criteria and tests;
- reuse repository targets and existing patterns;
- make small commits and PRs;
- stop repeated failing commands and diagnose the root cause;
- use AI for repetitive analysis, test generation, documentation consistency,
  and handoff preparation;
- reserve human attention for scope, architecture, security, risk, evidence, and
  approval.

Usage cost and latency never justify a weaker model, hidden fallback, skipped
test, reduced review, or unrecorded scope change.

## 11. Exceptions and continuous improvement

An exception requires a Linear issue with:

- exact control and scope;
- business reason and risk;
- owner and independent approver;
- time limit and compensating controls;
- validation, monitoring, and rollback;
- permanent remediation.

When practice and policy diverge:

1. fail closed for security, data, tenant, IAM, CI/CD, and production risk;
2. record the gap in Linear;
3. update the closest standard, `CLAUDE.md`, settings, test, or runbook;
4. validate through an issue-specific PR;
5. record the effective version and date.

## Official references

- [Claude Code model configuration](https://code.claude.com/docs/en/model-config)
- [Claude Code settings](https://code.claude.com/docs/en/settings)
- [Claude Code permissions](https://code.claude.com/docs/en/permissions)
- [Claude Code permission modes](https://code.claude.com/docs/en/permission-modes)
- [Claude Code memory and `CLAUDE.md`](https://code.claude.com/docs/en/memory)
- [Claude Code security](https://code.claude.com/docs/en/security)
- [Claude Code best practices](https://code.claude.com/docs/en/best-practices)
- [Claude model IDs and versioning](https://platform.claude.com/docs/en/about-claude/models/model-ids-and-versions)
