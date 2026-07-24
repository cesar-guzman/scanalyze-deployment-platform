# Scanalyze Claude Code Setup and Daily Workflow

## Document control

| Field | Value |
|---|---|
| Owner | Platform Engineering |
| Audience | Emiliano and future Scanalyze developers using Claude Code |
| Status | CURRENT when read from `main`; REVIEW CANDIDATE on an unmerged branch |
| Scope | Local Claude Code CLI setup and use for `cesar-guzman/scanalyze-deployment-platform` |
| Required models | Plan: `claude-opus-4-8`; execute: `claude-sonnet-5` |
| Minimum Claude Code | v2.1.197 |
| Initial implementation | Linear `GUG-262` |
| Review cadence | Quarterly and after a Claude Code/model/provider/security change |
| Human workflow | [`GITHUB_CONTRIBUTOR_WALKTHROUGH.md`](GITHUB_CONTRIBUTOR_WALKTHROUGH.md) |
| AI policy | [`AI_ASSISTED_DEVELOPMENT_STANDARD.md`](AI_ASSISTED_DEVELOPMENT_STANDARD.md) |

This guide configures a consistent local environment and shows the complete
Linear-to-plan-to-code-to-PR workflow. It does not grant repository, cloud,
deployment, merge, or production authority.

## 1. What the repository provides

After cloning current `main`, the contributor receives:

| Artifact | Purpose |
|---|---|
| `CLAUDE.md` | Concise instructions loaded at every project session |
| `.claude/settings.json` | Shared model, permission, sandbox, and safety baseline |
| `AI_ASSISTED_DEVELOPMENT_STANDARD.md` | Normative governance and lifecycle |
| This guide | Installation, verification, prompts, and daily operation |
| `validate_contributor_contract.py` | Offline checks for the shared baseline |

The shared settings are a repository baseline. They can be superseded by local
settings or command-line arguments. Organization-wide, non-overridable controls
require Claude Team/Enterprise managed settings or MDM and are described in
Section 12.

## 2. Prerequisites

Before installation:

- named corporate workstation and OS account;
- supported OS with current security updates, disk encryption, screen lock, and
  endpoint protection;
- named GitHub and Linear accounts;
- accepted access to the Scanalyze repository and project;
- Git and GitHub CLI installed through the approved software channel;
- one Ready Linear onboarding or implementation issue;
- no customer data, production logs, Terraform state, or credentials in the
  source directory.

Complete the access and clone steps in
`GITHUB_CONTRIBUTOR_WALKTHROUGH.md` before AI execution.

## 3. Install one supported Claude Code distribution

Platform Engineering SHOULD deploy Claude Code through managed software. On an
approved macOS workstation, the stable Homebrew cask is the preferred
self-service path:

```bash
brew install --cask claude-code
```

Do not keep multiple native, Homebrew, or legacy npm installations. Verify the
selected binary and version:

```bash
which -a claude
command -v claude
claude --version
claude doctor
```

Required result:

- exactly one intended binary is selected;
- Claude Code is v2.1.197 or later;
- `claude doctor` reports no unresolved installation, configuration, or
  credential-storage problem.

Sonnet 5 requires Claude Code v2.1.197 or later; Opus 4.8 requires v2.1.154 or
later. If the version is older, update through the same approved channel:

```bash
brew upgrade --cask claude-code
claude --version
claude doctor
```

Do not switch to an unapproved latest/beta channel only to bypass a model or
configuration failure. Record the version in the Linear issue and PR.

## 4. Authenticate without copying tokens

Start the CLI from a neutral local directory and use the invited
Team/Enterprise account:

```bash
claude auth login
claude auth status --text
```

On macOS, Claude Code stores supported credentials in the encrypted Keychain.
Never run a command that prints a token, paste a token into chat, add an API key
to `.env`, or commit authentication configuration.

If a shell already exports `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, or a
cloud-provider selector, it can take precedence over the intended account.
Do not print its value. Stop, remove the unintended environment configuration
through the approved workstation process, and verify again with:

```bash
claude auth status --text
```

The expected account/provider must match the approved Scanalyze AI service. If
it does not, stop and update Linear.

This baseline assumes Claude.ai/Anthropic API-compatible model routing. A
Bedrock, Google Cloud, Microsoft Foundry, or custom-gateway setup requires a
separate reviewed provider configuration; do not replace the pinned model IDs
ad hoc on one workstation.

## 5. Clone and create the issue worktree

Follow the full human guide. The abbreviated flow is:

```bash
cd <APPROVED_SOURCE_PARENT>
gh repo clone cesar-guzman/scanalyze-deployment-platform
cd scanalyze-deployment-platform
git fetch --prune origin
git rev-parse origin/main
git status -sb
```

Create exactly one isolated worktree for the Ready Linear issue:

```bash
git worktree add \
  -b chore/gug-262-claude-code-baseline \
  ../scanalyze-gug-262-claude-code-baseline \
  origin/main
cd ../scanalyze-gug-262-claude-code-baseline
git branch --show-current
git status --short
git rev-parse HEAD
```

For a different issue, replace the ID and topic. Never start Claude Code on
`main`, in another issue's worktree, in a dirty checkout, or from the home
directory.

## 6. Inspect before trusting project configuration

Claude Code asks the contributor to trust a new project. Before accepting,
inspect the versioned configuration as untrusted code:

```bash
git status --short
git log -1 --oneline
git diff --exit-code origin/main -- CLAUDE.md .claude/settings.json
python3 -m json.tool .claude/settings.json >/dev/null
```

On a feature branch, replace `origin/main` with the reviewed base or inspect the
actual diff explicitly. Confirm:

- `model` is `opusplan`;
- Opus is pinned to `claude-opus-4-8`;
- Sonnet is pinned to `claude-sonnet-5`;
- default permission mode is `plan`;
- fallback is empty;
- Auto, bypass, Remote Control, and Artifact publication are disabled;
- secret paths, AWS, destructive Git, remote GitHub writes, Terraform
  apply/destroy, and deletion commands are denied;
- no plugin, hook, MCP server, URL, or credential source was added unexpectedly.

If the configuration differs, stop and ask the code owner to review the exact
diff. Do not accept trust first and investigate later.

## 7. Start and verify the session

Launch from the root of the issue worktree:

```bash
claude --model opusplan --permission-mode plan
```

Inside Claude Code, run:

```text
/status
/model
/permissions
/memory
```

Verify:

- project `.claude/settings.json` is listed as a settings source;
- root `CLAUDE.md` is listed as project memory;
- the configured session is `opusplan`;
- Plan Mode is active;
- planning resolves to `claude-opus-4-8`;
- available execution resolves to `claude-sonnet-5`;
- effort is `high`;
- no settings error, fallback model, unapproved MCP server, plugin, or hook is
  active.

If the exact model cannot be verified, a fallback notice appears, or the project
configuration is missing, stop. Record the CLI version, provider, non-sensitive
status summary, and blocker in Linear. Do not silently continue on another
model.

## 8. Phase A — plan with Opus 4.8

Use this prompt template in Plan Mode:

```text
Linear issue: GUG-<ID>
Objective: <OUTCOME>
Acceptance criteria:
- <CRITERION>

In scope:
- <BOUNDED_SCOPE>

Out of scope:
- AWS or production mutations
- <OTHER_EXCLUSIONS>

First inspect the relevant code, tests, ADRs, schemas, and documentation.
Do not edit files or run write-capable commands.

Produce a plan containing:
1. current-state findings and source paths;
2. acceptance-criterion mapping;
3. proposed files and minimal changes;
4. P0/P1/P2 risk plus auth, tenant, data, IAM, IaC, CI/CD, cost, and
   production impact;
5. focused and broad validation;
6. rollback/recovery;
7. assumptions, blockers, and decisions required from the human.
```

Review the plan against Linear. Copy a durable, sanitized plan summary to the
issue and obtain the named human approval. For Emiliano-owned work, César is the
independent approver unless Linear names another qualified reviewer.

Do not treat the model asking to proceed as approval. Do not approve P0
execution until required security/architecture decisions are recorded.

## 9. Phase B — execute with Sonnet 5

After plan approval, leave Plan Mode using the Claude Code mode selector and
choose the normal manual mode that asks before edits. The `opusplan` model then
routes execution to the pinned `claude-sonnet-5`.

Do not select Auto or bypass-permissions mode. Do not pass
`--fallback-model`, `--settings`, or a different `--model`.

Verify the execution model in the session header or `/model`, then use:

```text
The plan for GUG-<ID> was approved by <HUMAN> and recorded in Linear.
Implement only that plan.

Constraints:
- preserve existing repository patterns and tenant/security boundaries;
- do not expand scope;
- use synthetic data only;
- do not call AWS or perform remote GitHub/Linear writes;
- run the focused tests first, then the approved broader gates;
- update canonical documentation with behavior changes;
- stop and ask if implementation contradicts the approved plan.

At handoff, report exact files, commands/results, validation not run, risks,
rollback, and the final diff summary. Do not commit or push.
```

Approve edits and commands individually after reading their exact target and
effect. A familiar command can still be wrong for the current branch.

## 10. Human verification, commit, and Draft PR

Exit or pause Claude Code. The human verifies:

```bash
git status --short
git diff --stat
git diff
git diff --check
```

Run the repository checks required by the issue. For contributor/AI governance:

```bash
make contributor-docs-check
python3 -m pytest tests/test_contributor_contract.py -q
git diff --check
```

List explicit paths when staging:

```bash
git add <EXPECTED_FILE_1> <EXPECTED_FILE_2>
git diff --cached --check
git diff --cached --stat
git diff --cached
```

After human approval, create an attributable local commit:

```bash
git commit \
  -m "docs(ai): establish Claude Code contributor baseline" \
  -m "Linear: GUG-<ID>"
```

The repository baseline denies remote writes from Claude Code. From the human
terminal, recheck identity, branch, status, and remote, then push only the issue
branch:

```bash
git remote get-url origin
git branch --show-current
git status -sb
git log -1 --oneline
git push --set-upstream origin <ISSUE_BRANCH>
```

Create a Draft PR using the human walkthrough. Complete every template section,
including AI assistance, models, human validation, validation not run, risk,
rollback, reviewer focus, and cloud/production boundary.

## 11. Required handoff and clean-room rehearsal

The issue owner records:

- Linear ID, branch, worktree, base SHA, and head SHA;
- Claude Code version and provider;
- planning model `claude-opus-4-8`;
- execution model `claude-sonnet-5`;
- approved plan summary and approver;
- files changed;
- exact validation and outcomes;
- validation not run and residual risk;
- PR URL and CI state;
- security, tenant, cloud, production, and rollback impact;
- confirmation that no sensitive input or unauthorized remote/cloud action was
  used.

For GUG-262, Emiliano completes a clean-room rehearsal from a fresh clone or
new worktree, attaches only redacted status/checklist evidence to Linear, fixes
guide/config defects in the same issue branch, and moves the Draft PR to Ready
for Review. César reviews and approves the final relevant SHA.

## 12. Enterprise managed-settings target

The checked-in configuration improves consistency but is developer-editable.
Platform Engineering SHOULD open a separate governance issue before declaring
enterprise enforcement. The managed rollout should evaluate:

- Team/Enterprise identity and organization lock;
- managed exact model allowlist and organization default;
- managed `opusplan` routing and no fallback chain;
- `allowManagedPermissionRulesOnly`;
- sandbox `failIfUnavailable: true` and
  `allowUnsandboxedCommands: false`;
- managed read/network allowlists and credential denial;
- Auto and bypass mode disabled;
- Remote Control and Artifact publication disabled unless separately approved;
- managed-only plugins, hooks, skills, and MCP servers;
- blocked sideload flags and unapproved marketplaces;
- auditable version rollout, emergency rollback, and quarterly access review.

Do not copy an organization UUID, API key, token, or provider credential into
the repository. Managed policy deployment is a separate administrative change,
not part of local onboarding.

## 13. Troubleshooting

| Symptom | Safe response |
|---|---|
| `claude` is not found | Stop; install through the approved channel and reopen the terminal |
| Multiple binaries appear | Stop; ask Platform Engineering to select and remove conflicting installations |
| Version is below v2.1.197 | Update through the approved stable channel; do not continue with Sonnet 5 claims |
| Wrong account/provider is active | Stop; correct authentication without printing credentials |
| Project settings are absent from `/status` | Check JSON and repository root; do not continue |
| Planning is not Opus 4.8 | Stop and record a model-routing blocker |
| Execution is not Sonnet 5 | Stop and record a model-routing blocker |
| A fallback notice appears | Stop; do not accept silent model drift |
| A denied command is required | Do not weaken settings ad hoc; update Linear and use the separately approved human/operator path |
| Sandbox prevents a test | Record the exact blocked requirement; review a narrow exception through Linear instead of disabling the sandbox |
| Claude requests sensitive data | Deny the request and follow `SECURITY.md` if exposure may have occurred |
| Generated change exceeds scope | Stop, discard only the AI-owned proposed change safely, and split/update Linear |
| PR checks fail | Diagnose the root cause; do not weaken, skip, or rerun blindly |

## Official references

- [Claude Code quickstart](https://code.claude.com/docs/en/quickstart)
- [Claude Code authentication](https://code.claude.com/docs/en/iam)
- [Claude Code model configuration](https://code.claude.com/docs/en/model-config)
- [Claude Code settings](https://code.claude.com/docs/en/settings)
- [Claude Code permissions](https://code.claude.com/docs/en/permissions)
- [Claude Code permission modes](https://code.claude.com/docs/en/permission-modes)
- [Claude Code memory and `CLAUDE.md`](https://code.claude.com/docs/en/memory)
- [Claude Code security](https://code.claude.com/docs/en/security)
- [Claude Code best practices](https://code.claude.com/docs/en/best-practices)
- [Claude model IDs and versioning](https://platform.claude.com/docs/en/about-claude/models/model-ids-and-versions)
