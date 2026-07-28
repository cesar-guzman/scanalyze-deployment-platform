# Contributor Guide

> Status: CURRENT
> Owner: Emiliano Díaz
> Approver: César Guzmán (@cesar-guzman)

This is the end-to-end walkthrough for contributing to the Scanalyze
Deployment Platform, for both human and AI-assisted work. It is the canonical
process document; when it disagrees with habit, this document wins.

Companion documents:

- [AI-Assisted Development Standard](ai-assisted-development.md)
- [Claude Code Setup & Daily Workflow](claude-code-setup.md)
- [Onboarding Rehearsal Checklist](onboarding-rehearsal-checklist.md)

## Delivery model

One unit of work flows through exactly four aligned artifacts:

```text
1 Linear issue  =  1 branch  =  1 isolated worktree  =  1 pull request
```

- **Linear** is the durable source of delivery state (what, why, status).
- **GitHub** is the source of code and review evidence (how, proof).
- Never batch unrelated changes into one branch or one PR. If the scope grows,
  split the Linear issue.

## Roles

| Role | Person | Responsibility |
|---|---|---|
| Author / Owner | Emiliano Díaz | Plans, implements, tests, opens the PR, drives it to merge |
| Independent Approver | César Guzmán (@cesar-guzman) | Required review; no self-approval by the author |

AI (Claude Code) assists the author. It does **not** replace human
accountability, independent review, tests, or production authorization. See the
[AI-Assisted Development Standard](ai-assisted-development.md).

## Definition of Ready (DoR)

An issue is ready to start when:

- [ ] The Linear issue has a clear problem statement and acceptance criteria.
- [ ] Scope fits one branch / one PR.
- [ ] No blocking dependency is open.
- [ ] The change does **not** require AWS or production mutation to be validated
      locally (all gates in this repo are offline).

## Definition of Done (DoD)

A PR is done when:

- [ ] Acceptance criteria in the Linear issue are all met.
- [ ] Local validation gates pass (see [Validation](#8-run-local-validation)).
- [ ] Documentation is updated and, where applicable, marked `Status: CURRENT`.
- [ ] Evidence is attached to the Linear issue (branch, commit SHA, gate output).
- [ ] The independent approver (@cesar-guzman) has approved the PR.
- [ ] No secrets, state, plans, credentials, or client material are in the diff.
- [ ] No AWS or production change was made.

---

## The workflow, step by step

### 1. Access

- GitHub access to `cesar-guzman/scanalyze-deployment-platform` (write for the
  author; review rights for the approver via [`CODEOWNERS`](../../CODEOWNERS)).
- Linear access to the delivery team/project.
- Toolchain pinned by [`.tool-versions`](../../.tool-versions) /
  [`.terraform-version`](../../.terraform-version): Terraform 1.14.6,
  Python 3.11.x. Verify with `make toolchain-check`.
- AWS credentials are **not** required to contribute. They are only needed by
  operators running a real deployment, out of band from this workflow.

### 2. Clone

```bash
git clone https://github.com/cesar-guzman/scanalyze-deployment-platform.git
cd scanalyze-deployment-platform
make toolchain-check
```

Verify a clean clone reproduces (offline):

```bash
make clone-check
```

### 3. Branch and isolated worktree

One issue → one branch → one worktree. Branch naming: `<type>/<slug>` where
`<type>` is `feat`, `fix`, `docs`, `chore`, or `refactor`.

```bash
# From an up-to-date main:
git fetch origin
git worktree add ../scanalyze-<slug> -b feat/<slug> origin/main
cd ../scanalyze-<slug>
```

Working in a dedicated worktree keeps each Linear issue physically isolated and
lets you keep `main` clean. When the PR is merged, remove the worktree:

```bash
git worktree remove ../scanalyze-<slug>
```

### 4. Implement the fix or feature

- Respect one declarative owner per resource (see the repo Safety principles in
  the [README](../../README.md)).
- Terraform owns ECS/infra; Python workers under `backend/workers/` own runtime
  behavior. Do not encode the same fact in two places.
- Keep changes minimal and reviewable. Match the style of surrounding code.
- Never introduce customer-specific forks; customer behavior is injected through
  reviewed contracts, safe Terraform inputs, and SSM parameters.

### 5. Documentation

- Update the relevant doc in the same PR as the code it describes.
- If a document is authoritative, mark it `Status: CURRENT` at the top; mark
  superseded material `Status: SUPERSEDED` with a pointer to the replacement.
- If you change the contributor workflow, Claude Code baseline, or model
  routing, update this guide and its companions.

### 6. Commits

- Small, logical commits. Conventional prefixes: `feat:`, `fix:`, `docs:`,
  `chore:`, `refactor:`, `test:`.
- Never commit secrets, `*.tfstate`, plans, local deployment inputs,
  credentials, or client material. `make git-safety` enforces this.
- Reference the Linear issue in the branch and PR (not necessarily every commit).

### 7. Pull request

- The PR is authored by **Emiliano** (the owner). The author never
  self-approves.
- PR description must include: link to the Linear issue, summary, exact branch
  and commit SHA, commands run and results, risks, rollback path, and any
  validation not run.
- Request review from **@cesar-guzman** (required by `CODEOWNERS`).
- Keep the branch in one-issue scope; if scope grows, open a new issue/PR.

> Publishing is a human step. The repository Claude Code baseline denies
> `git push` and `gh pr create`; the author performs push and PR creation
> deliberately from their own shell.

### 8. Run local validation

Run the narrowest relevant gate first, then broaden before review:

```bash
make docs-check              # docs presence
make contributor-check       # this workflow's contract (docs + Claude baseline)
make preflight-core          # lint, policy, contract, security, microservices
make preflight-m1            # broader module/root/supply-chain/tests
```

No validation target authorizes AWS mutation. Passing local gates does not
replace a real image build and reviewed Terraform plan in non-production before
any production release.

### 9. Comments and review

- Address every review comment explicitly (resolve or reply with rationale).
- Push follow-up commits to the same branch; do not force-push over review
  history unless the approver asks.
- Re-run the relevant gates after changes and note the new results.

### 10. Merge

- Merge only after the independent approver has approved and checks are green.
- Squash or merge per repo convention; keep the Linear issue link in the merge.
- Remove the worktree and delete the branch after merge.

### 11. Rollback

- Terraform state is **not** a release rollback mechanism.
- To revert code: open a new branch/PR that reverts the change (`git revert`),
  following this same workflow. See
  [`docs/operations/rollback.md`](../operations/rollback.md) for the
  deployment-level rollback procedure.

### 12. Linear updates

- Move the Linear issue through its states as work progresses:
  `Todo → In Progress → In Review → Done`.
- On opening the PR, set the issue to **In Review** and attach the PR URL.
- Attach evidence (branch, commit SHA, redacted gate output, and — for
  onboarding rehearsals — the redacted transcript/checklist).
- Close the issue only when the PR is merged and the DoD is fully met.

---

## Evidence & handoff

Every delivery attaches to its Linear issue:

- Exact branch and commit SHA.
- Commands run and a summary of results.
- Claude Code `/status` model/config verification, **redacted** (no tokens, no
  account data).
- PR checks and human review state.
- Risks, rollback path, and any validation not run.

Handoff of operational responsibility follows
[`docs/operations/handoff.md`](../operations/handoff.md).
