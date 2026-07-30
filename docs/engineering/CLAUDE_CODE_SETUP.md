# Claude Code Setup & Daily Workflow

## Document control

| Field | Value |
|---|---|
| Owner | Platform Engineering |
| Audience | Contributors using Claude Code on this repository |
| Status | CURRENT |
| Scope | `cesar-guzman/scanalyze-deployment-platform` |
| Review cadence | Quarterly and after a change to the Claude Code baseline |
| Last verified | 2026-07-30 against `main@66007de` |
| Related policy | [`CONTRIBUTING.md`](../../CONTRIBUTING.md) |
| Related controls | [`AI_ASSISTED_DEVELOPMENT_STANDARD.md`](AI_ASSISTED_DEVELOPMENT_STANDARD.md), [`CLAUDE_CODE_ONBOARDING_REHEARSAL.md`](CLAUDE_CODE_ONBOARDING_REHEARSAL.md), [`GITHUB_CONTRIBUTOR_WALKTHROUGH.md`](GITHUB_CONTRIBUTOR_WALKTHROUGH.md) |

How to install Claude Code, confirm it resolves the pinned models under the
repository baseline, and use it day to day. Read alongside the
[`AI-Assisted Development Standard`](AI_ASSISTED_DEVELOPMENT_STANDARD.md). No step
here authorizes an AWS mutation, deployment, or production activity.

## 1. Install

- Install Claude Code (CLI, or the VS Code / JetBrains extension).
- Authenticate with your Anthropic account.
- Confirm the CLI runs: `claude --version`.

## 2. The repository baseline

The shared baseline is committed at
[`.claude/settings.json`](../../.claude/settings.json). It applies automatically
when you launch Claude Code from the repository root. It sets:

- `model: opusplan` with pinned identifiers `ANTHROPIC_DEFAULT_OPUS_MODEL=claude-opus-4-8`
  (planning) and `ANTHROPIC_DEFAULT_SONNET_MODEL=claude-sonnet-5` (execution);
- `permissions.defaultMode: plan`;
- `deny` / `ask` rules for secrets, destructive Git, remote publish, and
  Terraform / AWS mutation (full list in the
  [`AI-Assisted Development Standard`](AI_ASSISTED_DEVELOPMENT_STANDARD.md));
- exact-target `make` allowances only (no global `Bash(make:*)`).

Do **not** edit `.claude/settings.json` to loosen protections for convenience.
Personal, non-shared preferences belong in `.claude/settings.local.json`, which
is git-ignored.

## 3. Verify model routing (`/status`)

Inside a Claude Code session at the repo root, run `/status` and confirm:

- Plan mode is the default (you start in plan mode).
- The planning model resolves to **Opus 4.8** (`claude-opus-4-8`).
- The execution model resolves to **Sonnet 5** (`claude-sonnet-5`).

If either model differs, stop — that is a silent-fallback condition. Re-launch
from the repo root, confirm no personal override in `settings.local.json` is
shadowing the baseline, and re-check. Capture the corrected `/status` (redacted:
no tokens, no account data) as onboarding evidence.

Confirm the static contract without a live session:

```bash
make contributor-docs-check
```

This fails if the committed baseline drifts from the pinned routing or drops a
required denial.

## 4. Daily workflow

1. **Start in the issue's worktree.** One Linear issue → one branch → one
   worktree (see `CONTRIBUTING.md`).
2. **Open Claude Code from the repo root** so the baseline loads. You begin in
   plan mode.
3. **Give it the issue.** Paste the Linear acceptance criteria; ask it to
   analyze first, then plan.
4. **Review the plan, then approve.** Execution switches to Sonnet 5 only after
   you accept.
5. **Let it run gated.** Denied actions are blocked; `ask` actions pause for your
   confirmation. Never approve an AWS or `terraform apply/destroy` action.
6. **Run gates yourself.** `make contributor-docs-check`, `make docs-check`,
   `make preflight-core`, and any narrower gate relevant to the change.
7. **You publish.** Push and open the PR from your own shell — the baseline
   deliberately blocks the agent from `git push` and `gh pr create`.
8. **Attach evidence to Linear.** Branch, commit SHA, gate output, redacted
   `/status`.

## 5. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `/status` shows a different model | Personal override or wrong launch dir | Remove/adjust `settings.local.json`; launch from repo root |
| Agent tries `git push` / `aws` and is blocked | Working as intended | Perform the action yourself, deliberately, in your shell |
| `make contributor-docs-check` fails on routing | Baseline drift | Restore `.claude/settings.json` pinned values |
| Agent edits a `.tfvars`/state file | Should be denied by baseline | Verify the `deny` list is intact |

## 6. Never

- Never paste secrets, tokens, or temporary credentials into a session.
- Never commit `.claude/settings.local.json`.
- Never weaken the shared baseline to unblock a task; fix the task instead.
