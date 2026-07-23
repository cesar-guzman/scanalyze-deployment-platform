# Scanalyze GitHub Contributor Walkthrough

## Document control

| Field | Value |
|---|---|
| Owner | Platform Engineering |
| Audience | New contributors, reviewers, code owners, maintainers, and access administrators |
| Status | REVIEW DRAFT; becomes CURRENT only after approval and merge to `main` |
| Scope | `cesar-guzman/scanalyze-deployment-platform` |
| Last verified | 2026-07-23 against `main@0f3dc10` and GitHub repository metadata |
| Review cadence | Quarterly and after an access, ownership, branch-protection, or GitHub UI change |
| Related policy | [`CONTRIBUTING.md`](../../CONTRIBUTING.md) |
| Related controls | [`CODE_REVIEW_STANDARD.md`](CODE_REVIEW_STANDARD.md), [`GITHUB_ENFORCEMENT_BASELINE.md`](GITHUB_ENFORCEMENT_BASELINE.md), and [`SECURITY.md`](../../SECURITY.md) |

This walkthrough explains how a human contributor obtains access, recognizes
the repository's sources of truth, navigates GitHub, works locally, opens and
reviews a pull request, and interprets completion signals.

It supplements the normative rules in `CONTRIBUTING.md`. If the two documents
conflict, `CONTRIBUTING.md` controls. No step in this walkthrough authorizes an
AWS mutation, deployment, production activity, branch-protection change, merge,
or release.

## 1. The operating model in one page

Scanalyze uses four distinct working surfaces:

| Surface | Purpose | It does not prove |
|---|---|---|
| Linear | Scope, owner, priority, acceptance criteria, blockers, and durable delivery status | That code exists, passed CI, merged, or deployed |
| GitHub | Versioned source, pull requests, review history, checks, and merge record | That a change is deployed or production-approved |
| Local worktree | Isolated implementation and local validation for one issue | That CI or another human accepted the change |
| Runtime/AWS evidence | Observed state of an explicitly named environment | That source, governance, or production authorization is correct |

The required work unit is:

```text
one Ready Linear issue
        |
        v
one branch + one isolated worktree
        |
        v
one pull request
        |
        v
independent review + required checks
        |
        v
merge
```

Merge, deployment, runtime validation, and production approval remain separate
facts.

## 2. Current repository access model

The currently verified repository state is:

| Property | Current state |
|---|---|
| Canonical URL | `https://github.com/cesar-guzman/scanalyze-deployment-platform` |
| Visibility | Public |
| Owner type | Personal GitHub account |
| Default branch | `main` |
| Contribution model | Named collaborators push issue branches and use pull requests |

Because the repository is public, anyone can read and clone its public content.
That does not grant permission to push, approve on behalf of Scanalyze, merge,
change settings, use cloud credentials, or represent the company.

A personal-account repository has a broad collaborator permission model.
Collaborators can push and can perform several repository actions that exceed a
developer's normal day-to-day need. GitHub UI capability is therefore not
business authorization. Contributors MUST follow the narrower policy in this
repository even when GitHub presents a button.

### Enterprise target

For durable separation of duties and least privilege, the target model is an
organization-owned repository with:

- named organization membership;
- team-based access;
- least-privilege repository roles;
- at least two independent code owners for critical surfaces;
- required reviews and CODEOWNER review;
- stale-approval dismissal and conversation-resolution enforcement;
- audited onboarding, quarterly access review, and immediate offboarding;
- protected environments for any deployment authority.

Repository transfer, role changes, and protection changes are separate
governance work. This document does not perform or authorize them.

## 3. Before access is granted

Every contributor MUST use a named GitHub account. Shared human accounts are
prohibited.

The onboarding owner records the following in the private Linear onboarding
issue:

- team member and manager/sponsor;
- GitHub username;
- requested capability and business justification;
- repository and expected component;
- employment or engagement boundary;
- access start date and review/expiry date;
- required reviewer or code owner;
- completion of security and repository onboarding;
- offboarding owner.

Do not put personal contact data in a public GitHub issue or pull request.

The contributor completes:

- verified GitHub account;
- two-factor authentication with an approved primary and recovery method;
- recovery codes stored in an approved private location;
- supported and protected workstation;
- disk encryption, screen lock, current security updates, and endpoint
  protection;
- individual Git identity;
- read-through of `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, and this guide.

Never send passwords, tokens, recovery codes, SSH private keys, or session
cookies to an administrator. Access administrators need only the GitHub
username.

## 4. Granting and accepting current access

### Repository owner procedure

The repository is currently owned by a personal account. The owner:

1. Opens the repository on GitHub.
2. Selects **Settings**.
3. Under **Access**, selects **Collaborators**.
4. Selects **Add people**.
5. Searches for the exact GitHub username from the Linear onboarding issue.
6. Verifies the displayed account with the team member through an approved
   channel.
7. Sends the repository invitation.
8. Records the invitation date in Linear.

Do not invite an email address or similarly named account without verifying the
exact GitHub username. Do not add deploy keys or shared automation credentials
as a substitute for a named collaborator.

### Contributor procedure

The contributor:

1. Signs in to the intended GitHub account.
2. Opens the invitation from GitHub.
3. Confirms that the repository is exactly
   `cesar-guzman/scanalyze-deployment-platform`.
4. Accepts the invitation.
5. Records acceptance in the Linear onboarding issue.
6. Performs the read-only verification below.

If the repository returns `404`, first verify the signed-in GitHub account and
invitation status. Do not ask another team member to share credentials or clone
contents through an unapproved channel.

## 5. Secure command-line authentication

Install Git and the GitHub CLI through the approved workstation software
channel. Prefer the GitHub CLI browser flow over manually creating or copying a
personal access token.

The following command opens GitHub authentication in a browser and configures
HTTPS Git access:

```bash
gh auth login --hostname github.com --web --git-protocol https
```

This changes local GitHub CLI authentication state. Complete it only on the
contributor's assigned workstation. If the CLI warns that credentials will be
stored in plain text instead of the operating-system credential store, stop and
ask Platform Engineering to correct credential storage.

Verify the active account without printing a token:

```bash
gh auth status --hostname github.com
```

Never run `gh auth token`, print authentication environment variables, paste
authentication output containing secrets, or embed a token in a Git remote URL.

## 6. Read-only access verification

These commands do not change the repository:

```bash
gh repo view cesar-guzman/scanalyze-deployment-platform \
  --json nameWithOwner,visibility,defaultBranchRef,viewerPermission
```

Expected interpretation:

- `nameWithOwner` is
  `cesar-guzman/scanalyze-deployment-platform`;
- `visibility` is `PUBLIC`;
- the default branch is `main`;
- `viewerPermission` indicates the authenticated user's effective repository
  permission.

Open the canonical repository:

```bash
gh repo view cesar-guzman/scanalyze-deployment-platform --web
```

If the contributor is expected to push and the permission output does not
provide collaborator write capability, stop and update the Linear onboarding
issue. Do not solve access failures with another person's token.

## 7. What contributors see in GitHub

The tabs shown by GitHub depend on repository features and the viewer's
permission. The primary repository views are:

| View | What it shows | How Scanalyze uses it |
|---|---|---|
| **Code** | Default branch, branch selector, files, README, commits, tags, and clone options | Inspect the current versioned source; never edit `main` directly |
| **Issues** | GitHub issue forms and discussion | A structured mirror or public coordination surface; Linear remains the delivery source of truth |
| **Pull requests** | Proposed branch changes and their review/merge state | Mandatory path for integrating human changes into `main` |
| **Actions** | Repository-wide workflow runs and logs | CI evidence and diagnosis; logs are public in a public repository |
| **Security** | Security policy and permission-dependent alerts | Security posture and private-reporting instructions; never disclose a vulnerability publicly |
| **Insights** | Repository activity and history | Supporting metrics, not delivery approval |
| **Settings** | Access, branches, Actions, security, webhooks, and repository controls | Owner/maintainer administration only |

GitHub may collapse tabs into an overflow menu on smaller screens.

### The Code view

Before trusting what is displayed, check:

- the owner and repository name at the top of the page;
- the selected branch;
- whether the branch is `main`, an issue branch, or a tag;
- the commit SHA and commit date;
- the path of the file being viewed.

Reading a file on an old branch is not evidence of current behavior.

### Issues versus Linear

A GitHub issue does not replace the Linear issue. When a GitHub issue exists:

- it MUST link or name the primary Linear identifier;
- its scope MUST match the Linear issue;
- decisions and blockers MUST be written back to Linear;
- closing the GitHub issue does not prove Definition of Done;
- no secret, customer data, PII, raw plan/state, or production log may be
  attached.

## 8. How to read a pull request

A pull request proposes merging a **head/compare branch** into a **base branch**.
For normal Scanalyze work, the base is `main`.

Verify the following before reviewing:

1. Repository is `cesar-guzman/scanalyze-deployment-platform`.
2. Base branch is `main`.
3. Head branch contains the expected Linear identifier.
4. PR title and description identify the same issue and scope.
5. Risk class, environment boundary, validation, and rollback are complete.
6. The PR is **Draft** until the author requests formal review.

The main PR views are:

| PR view | Purpose | Reviewer question |
|---|---|---|
| **Conversation** | Description, review events, comments, decisions, and merge box | Does the narrative match the issue and current diff? |
| **Commits** | History added by the head branch | Are commits attributable, scoped, and free of unrelated work? |
| **Checks** | Automated tests, builds, scans, annotations, and results | Did the required checks finish successfully on the current SHA? |
| **Files changed** | Exact diff between base and head | Is the implementation correct, safe, tested, and documented? |
| **Merge box** | Conflicts, review requirements, checks, and merge controls | Are all policy and technical gates satisfied? |

GitHub can display a green merge button even when a manual Scanalyze policy gap
exists. Green UI is not permission to self-approve, bypass an independent
review, deploy, or perform a production action.

## 9. Reviewer walkthrough

The reviewer follows this sequence:

1. Open the linked Linear issue and read acceptance criteria, exclusions, risk,
   environment, and rollback.
2. Read the PR description and confirm it describes the same work.
3. Record or inspect the current head SHA.
4. Open **Files changed**.
5. Review the highest-risk files first.
6. Review one file at a time and mark it **Viewed**.
7. Inspect tests, negative cases, docs, and failure/recovery behavior.
8. Open **Checks** and confirm required checks ran on the current SHA.
9. Submit one of:
   - **Comment** for non-decision feedback;
   - **Approve** when the final relevant diff satisfies the policy;
   - **Request changes** when blocking findings remain.
10. Re-review after a material push.

Use the labels and actionable format in
[`CODE_REVIEW_STANDARD.md`](CODE_REVIEW_STANDARD.md):

```text
[P1] Observation: ...
Impact: ...
Request: ...
Evidence: path/to/file:line or named test/contract
```

The originating reviewer resolves or explicitly accepts P0/P1/P2 findings.
Approval means the code is acceptable for merge; it does not authorize
deployment or production.

## 10. Clone and create an isolated issue worktree

Choose a local parent directory approved for source code. The example uses a
placeholder and writes only to the local workstation:

```bash
cd <APPROVED_SOURCE_PARENT>
gh repo clone cesar-guzman/scanalyze-deployment-platform
cd scanalyze-deployment-platform
```

Configure identity for this repository. Use the contributor's own name and
verified work email; do not copy another developer's identity:

```bash
git config --local user.name "<CONTRIBUTOR_NAME>"
git config --local user.email "<VERIFIED_WORK_EMAIL>"
git config --local --get user.name
git config --local --get user.email
```

Inspect the clone before making changes:

```bash
git rev-parse --show-toplevel
git remote -v
git status -sb
git fetch --prune origin
git rev-parse origin/main
```

Create one isolated worktree from the current remote `main`:

```bash
git worktree add \
  -b chore/gug-123-short-topic \
  ../scanalyze-gug-123-short-topic \
  origin/main
cd ../scanalyze-gug-123-short-topic
git status -sb
```

Replace `GUG-123` and the topic with the Ready Linear issue. Use `feat/`,
`fix/`, `chore/`, or `review/` according to `CONTRIBUTING.md`.

Do not work directly on `main`. Do not reuse a worktree from another issue. If
the clone or target worktree is dirty, stop and identify the owner of the
existing changes; do not reset, clean, overwrite, or delete them.

## 11. Implement and validate locally

Before editing:

```bash
git branch --show-current
git status --short
git rev-parse HEAD
```

During implementation:

- change only files required by the issue;
- preserve existing repository patterns;
- add tests for behavior and regressions;
- update documentation in the same PR when behavior changes;
- never place customer data, PII, credentials, `.env` files, Terraform state,
  raw plans, production logs, or tokens in the worktree.

Run the narrowest relevant check first. For this contributor-governance package:

```bash
make contributor-docs-check
python3 -m pytest tests/test_contributor_contract.py -q
git diff --check
```

Then inspect exactly what changed:

```bash
git status --short
git diff --stat
git diff
```

Passing local validation is evidence for the named local revision only. It is
not CI, approval, merge, deployment, or production authorization.

## 12. Stage and commit safely

Staging and committing write only to the local repository. List explicit paths;
do not use `git add .` for a controlled package:

```bash
git add <EXPECTED_FILE_1> <EXPECTED_FILE_2>
git diff --cached --check
git diff --cached --stat
git diff --cached
```

If the staged diff contains an unexpected file or value, stop and correct the
staging selection before committing.

Create an attributable commit:

```bash
git commit \
  -m "docs: add contributor onboarding walkthrough" \
  -m "Linear: GUG-123"
```

Use `git commit -S` only when commit signing is already configured and verified.
Do not weaken a signing policy to make a commit succeed.

Verify the local result:

```bash
git status -sb
git log -1 --show-signature --stat
```

## 13. Push the issue branch

`git push` changes GitHub. Run it only when the issue scope is approved, local
validation is recorded, the branch is correct, and the contributor has
collaborator access.

First perform read-only confirmation:

```bash
git remote get-url origin
git branch --show-current
git status -sb
git log -1 --oneline
```

Then push only the named issue branch:

```bash
git push --set-upstream origin chore/gug-123-short-topic
```

Never push directly to `main`, use `--force`, expose credentials in a remote
URL, or push a second issue into the same branch.

## 14. Open a Draft pull request

Open the browser-based PR form so the repository template is visible:

```bash
gh pr create \
  --draft \
  --base main \
  --head chore/gug-123-short-topic \
  --web
```

In GitHub:

1. Use title `[GUG-123] Short outcome`.
2. Complete every PR-template section.
3. Link the primary Linear issue.
4. Identify risk, environment, validation, validation not run, rollback, and
   reviewer focus.
5. Confirm base `main` and the expected head branch.
6. Keep the PR as **Draft** until the author checklist is complete.
7. Request the independent reviewer required by the risk class.

The PR updates automatically when new commits are pushed to the same branch.
After a material push, update the description and request re-review.

## 15. Interpret checks and failures

Check states are evidence for a specific commit:

| State | Meaning | Required action |
|---|---|---|
| Queued/in progress | Validation has not finished | Wait; do not claim success |
| Success | That named check completed successfully | Confirm all required checks and current SHA |
| Failure | Validation found a problem or infrastructure failed | Read annotations/logs, reproduce safely, fix root cause |
| Cancelled/timed out | No passing evidence exists | Diagnose; rerun only with a reason |
| Skipped/neutral | The check did not necessarily execute its core behavior | Confirm whether branch policy treats it as acceptable |

Do not repeatedly rerun a failing workflow hoping for green. Do not change,
delete, skip, or weaken a check merely to make a PR mergeable.

Workflow logs in this public repository are externally visible. If a log
contains a possible secret, customer datum, PII, signed URL, state, or raw plan,
stop sharing it and follow the incident path in `SECURITY.md`.

## 16. Address review feedback

For every actionable thread:

1. Understand the observation and intended outcome.
2. Reproduce or inspect the evidence.
3. Make the smallest scoped correction.
4. Add or update the regression test.
5. Rerun relevant validation.
6. Push a focused commit.
7. Reply with the fixing commit and validation result.
8. Ask the reviewer to revalidate blocking findings.

Example:

```text
Fixed in abc1234. Added the negative authorization case and reran the focused
suite: 12 passed. Requesting re-review on the current head SHA.
```

Do not resolve a blocking reviewer thread yourself unless the originating
reviewer explicitly accepted the disposition.

## 17. Merge and post-merge interpretation

A maintainer merges only when:

- Linear scope and PR scope agree;
- the PR is no longer Draft;
- required independent approvals apply to the final relevant SHA;
- blocking conversations are resolved;
- required checks completed successfully;
- documentation and rollback/recovery are complete;
- no unresolved security or production-control concern exists.

The default strategy for one-issue branches is squash merge unless a maintainer
records a reason for another supported strategy.

After merge, record:

- pull request URL;
- merge commit SHA;
- validation and review summary;
- follow-up issues;
- explicit deployment status;
- explicit remaining production gate.

Do not write “done” when only merge is complete. Use precise status such as:

```text
Merged to main at <SHA>. CI passed. Not deployed. No runtime validation or
production approval was performed.
```

## 18. Actions prohibited without separate authorization

Contributors MUST NOT:

- edit or commit directly on `main`;
- self-approve or self-merge;
- use force push or rewrite shared history;
- bypass, skip, delete, or weaken required checks;
- change repository visibility, access, branch protection, Actions permissions,
  environments, secrets, webhooks, or CODEOWNERS outside an approved issue;
- publish releases or packages outside an approved release workflow;
- paste secrets, customer information, PII, state, raw plans, or production
  logs into GitHub;
- approve an old SHA after a material push;
- treat collaborator permission as cloud or production permission;
- use GitHub Actions to mutate AWS without exact environment authorization.

## 19. Troubleshooting

| Symptom | Safe response |
|---|---|
| Repository returns `404` | Confirm the signed-in account and accepted invitation |
| `gh auth status` shows the wrong account | Stop; switch through the approved GitHub CLI flow before cloning or pushing |
| Clone works but push is denied | Verify collaborator access and branch name; update the Linear blocker |
| Push to `main` is rejected | Expected; use the issue branch and PR workflow |
| Worktree is dirty before starting | Stop and identify existing work; do not reset or clean |
| PR contains unrelated files | Remove or split them locally before review; do not hide them in the description |
| Branch is behind `main` | Fetch `origin/main`, assess conflicts, and follow maintainer guidance; never force push |
| Check fails | Inspect the failing check and reproduce safely; fix the root cause |
| Check is green but merge is blocked | Inspect required review, conversations, branch currency, and policy gaps |
| Possible secret or PII appears | Stop, avoid copying it, and follow `SECURITY.md` immediately |
| GitHub button permits an unapproved action | Do not use it; repository policy is narrower than current UI permissions |

Never use `git reset --hard`, `git clean -fd`, force push, branch deletion, or
history rewriting as a troubleshooting shortcut.

## 20. First-day supervised exercise

A new contributor completes this sequence before receiving a runtime change:

1. Access onboarding is recorded in Linear.
2. The contributor verifies 2FA, invitation, authenticated identity, repository,
   visibility, default branch, and effective permission.
3. The contributor clones the repository and configures local identity.
4. The contributor reads:
   - `README.md`;
   - `CONTRIBUTING.md`;
   - `SECURITY.md`;
   - this walkthrough;
   - `CODE_REVIEW_STANDARD.md`.
5. The contributor creates a P2 documentation issue worktree from current
   `origin/main`.
6. The contributor runs `make contributor-docs-check`.
7. The contributor opens a Draft PR using the template.
8. The contributor practices one structured review comment on another safe PR.
9. An independent reviewer validates the final SHA.
10. The onboarding owner records completion and the contributor's permitted
    component scope in Linear.

For Emiliano, reviewing the GUG-111 contributor-governance PR is an appropriate
first supervised activity once that branch has been pushed and the Draft PR
exists. It exercises navigation, issue/PR scope comparison, documentation
review, checks, comment structure, and approval boundaries without granting
runtime or cloud authority.

## 21. Offboarding and periodic review

When access is no longer required:

1. record the effective date and owner in Linear;
2. remove repository collaborator access;
3. revoke or rotate affected credentials through their owning systems;
4. transfer open issues and PRs;
5. inspect unmerged branches for recovery needs;
6. retain only sanitized, required audit evidence;
7. confirm completion independently.

Quarterly access review confirms:

- every collaborator is still an active, named team member;
- access still matches current responsibilities;
- open branches and PRs have owners;
- code-owner and reviewer coverage is adequate;
- GitHub protection matches
  `GITHUB_ENFORCEMENT_BASELINE.md`;
- no personal token, deploy key, or shared identity has replaced normal human
  access.

## 22. Official references

- [GitHub: about repositories](https://docs.github.com/en/repositories/creating-and-managing-repositories/about-repositories)
- [GitHub: inviting collaborators to a personal repository](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/repository-access-and-collaboration/inviting-collaborators-to-a-personal-repository)
- [GitHub: permissions for a personal-account repository](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/repository-access-and-collaboration/permission-levels-for-a-personal-account-repository)
- [GitHub: two-factor authentication](https://docs.github.com/en/authentication/securing-your-account-with-two-factor-authentication-2fa/about-two-factor-authentication)
- [GitHub CLI: authentication](https://cli.github.com/manual/gh_auth_login)
- [GitHub: pull requests](https://docs.github.com/en/pull-requests/reference/pull-requests)
- [GitHub: reviewing proposed changes](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/reviewing-changes-in-pull-requests)
- [GitHub: status checks](https://docs.github.com/en/pull-requests/reference/status-checks)
- [GitHub CLI: create a pull request](https://cli.github.com/manual/gh_pr_create)
