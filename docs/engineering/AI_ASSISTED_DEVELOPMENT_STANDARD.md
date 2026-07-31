# AI-Assisted Development Standard

## Document control

| Field | Value |
|---|---|
| Owner | Platform Engineering |
| Audience | Contributors, reviewers, code owners, and maintainers using AI assistance |
| Status | CURRENT |
| Scope | `cesar-guzman/scanalyze-deployment-platform` |
| Review cadence | Quarterly and after a change to the Claude Code baseline or model routing |
| Last verified | 2026-07-30 against `main@66007de` |
| Related policy | [`CONTRIBUTING.md`](../../CONTRIBUTING.md) |
| Related controls | [`CLAUDE_CODE_SETUP.md`](CLAUDE_CODE_SETUP.md), [`CLAUDE_CODE_ONBOARDING_REHEARSAL.md`](CLAUDE_CODE_ONBOARDING_REHEARSAL.md), [`CODE_REVIEW_STANDARD.md`](CODE_REVIEW_STANDARD.md), [`GITHUB_ENFORCEMENT_BASELINE.md`](GITHUB_ENFORCEMENT_BASELINE.md), [`SECURITY.md`](../../SECURITY.md) |
| Tracking | [GUG-262](https://linear.app/guguce/issue/GUG-262/establish-and-validate-claude-code-contributor-baseline) |

This standard supplements the normative rules in `CONTRIBUTING.md`. If the two
documents conflict, `CONTRIBUTING.md` controls. The words **MUST**, **MUST NOT**,
**SHOULD**, and **MAY** are normative. No step in this standard authorizes an AWS
mutation, deployment, or production activity.

## 1. Principle: AI assists, humans remain accountable

AI (Claude Code) assists a human contributor. It **MUST NOT** replace:

- human accountability for the change;
- independent review by the required approver;
- tests and local validation gates;
- authorization for any AWS or production action.

The human author owns every AI-assisted change and signs off by opening the pull
request under their own name. Passing CI is not approval, and an AI-generated
plan is not evidence.

## 2. Model routing (pinned, no silent fallback)

The repository baseline [`.claude/settings.json`](../../.claude/settings.json)
routes models by phase:

| Phase | Model | Model ID |
|---|---|---|
| Exploration / planning (plan mode) | Claude Opus 4.8 | `claude-opus-4-8` |
| Approved execution | Claude Sonnet 5 | `claude-sonnet-5` |

This is expressed with `"model": "opusplan"` and the pinned identifiers in the
`env` block:

- `ANTHROPIC_DEFAULT_OPUS_MODEL=claude-opus-4-8`
- `ANTHROPIC_DEFAULT_SONNET_MODEL=claude-sonnet-5`

No silent fallback is accepted. If the resolved models drift from the pinned
values, `make contributor-docs-check` MUST fail. Contributors verify the live
resolution with `/status` (redacted) and attach it as onboarding evidence.

## 3. Plan-first, permission-gated

- The baseline sets `permissions.defaultMode: plan`. Every session starts in
  plan mode: it explores and proposes before it edits.
- Execution happens only after the human approves the plan.
- The baseline denies dangerous actions outright (Section 4). Denials are a
  floor, not a substitute for judgment.

## 4. What the baseline blocks

The baseline MUST deny, at minimum:

- **Secrets & protected data paths**: reading/editing `*.tfstate`, `*.tfvars`,
  `*.pem`/`*.key`, `.env*`, `credentials`, `*secret*`, and `~/.aws/**`.
- **Destructive Git**: `git push --force`, `git reset --hard`, `git clean`,
  branch deletion.
- **Remote publish**: `git push`, `gh pr create`, `gh repo`, `gh release`,
  `gh secret`, adding or altering remotes.
- **Infrastructure mutation**: `terraform apply`/`destroy`/`import`/`state`
  mutations, `tofu apply`/`destroy`, `cdk deploy`/`destroy`, `sam deploy`.
- **AWS CLI**: the `aws` CLI is denied to the agent entirely. AWS inspection or
  action is performed by a human operator in their own shell, never through the
  assistant, and never as part of this contribution workflow.
- **`docker push`** and recursive force-delete.

Actions that are sometimes legitimate but need a human decision — `git commit`,
`git checkout`, `terraform plan`, `docker build`, web fetches — are set to
**ask**, so the agent MUST request confirmation. Bash `make` access is limited
to exact validation targets; a global `Bash(make:*)` allow MUST NOT be used.

Personal overrides go in `.claude/settings.local.json` (git-ignored) and MUST
NOT loosen the shared denials for shared work.

## 5. Using AI responsibly

- **Prompt with the issue in view.** Give Claude the Linear acceptance criteria;
  keep one issue per session where practical.
- **Read the plan.** Approve plans deliberately; do not rubber-stamp.
- **Verify outputs.** Run the gates yourself; AI passing a gate is not evidence
  until you have seen the output.
- **Never paste secrets** into a session. Temporary credentials, tokens, and
  account data do not belong in prompts or transcripts.
- **Redact evidence.** When attaching a transcript or `/status` output to Linear,
  remove tokens and account identifiers.

## 6. Evidence expected from AI-assisted work

Same as any change (see `CONTRIBUTING.md`), plus:

- a redacted `/status` capture confirming Opus 4.8 (plan) / Sonnet 5 (execute);
- confirmation that the session ran under the repository baseline (plan mode
  default, denials in force).
