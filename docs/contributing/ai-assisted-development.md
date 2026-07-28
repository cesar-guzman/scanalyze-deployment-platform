# AI-Assisted Development Standard

> Status: CURRENT
> Owner: Emiliano Díaz
> Approver: César Guzmán (@cesar-guzman)

This standard governs how AI tools — specifically Claude Code — are used to
contribute to the Scanalyze Deployment Platform. It exists so AI assistance is
reproducible, safe, and accountable.

## Principle: AI assists, humans remain accountable

AI does **not** replace:

- Human accountability for the change.
- Independent review by the required approver.
- Tests and local validation gates.
- Authorization for any AWS or production action.

A human author owns every AI-assisted change and signs off on it by opening the
PR under their own name.

## Model routing (pinned, no silent fallback)

Claude Code is configured by the repository baseline
([`.claude/settings.json`](../../.claude/settings.json)) to route models by
phase:

| Phase | Model | Model ID |
|---|---|---|
| Exploration / planning (plan mode) | Claude Opus 4.8 | `claude-opus-4-8` |
| Approved execution | Claude Sonnet 5 | `claude-sonnet-5` |

This is expressed with `"model": "opusplan"` plus the pinned model IDs in the
`env` block. **No silent fallback is accepted**: if the resolved models drift
from the pinned values, the contributor contract check
(`make contributor-check`) fails. Contributors verify the live resolution with
`/status` (redacted) and attach it as onboarding evidence.

## Plan-first, permission-gated

- The baseline sets `defaultMode: plan`. Claude Code starts every session in
  plan mode: it explores and proposes before it edits.
- Execution happens only after the human approves the plan.
- The baseline denies dangerous actions outright (see below). These denials are
  a floor, not a substitute for judgment.

## What the baseline blocks

The repository baseline denies, at minimum:

- **Secrets & protected data paths**: reading/editing `*.tfstate`, `*.tfvars`,
  `*.pem`/`*.key`, `.env*`, `credentials`, `*secret*`, and `~/.aws/**`.
- **Destructive Git**: `git push --force`, `git reset --hard`, `git clean`,
  branch deletion.
- **Remote publish**: `git push`, `gh pr create`, `gh repo`, `gh release`,
  `gh secret`, adding/altering remotes.
- **Infrastructure mutation**: `terraform apply`/`destroy`/`import`/`state`
  mutations, `tofu apply`/`destroy`, `cdk deploy`/`destroy`, `sam deploy`.
- **AWS CLI**: the `aws` CLI is denied to the agent entirely. AWS inspection or
  action is performed by a human operator in their own shell, never through the
  assistant, and never as part of this contribution workflow.
- **`docker push`** and recursive force-delete.

Actions that are sometimes legitimate but need a human decision — `git commit`,
`git checkout`, `terraform plan`, `docker build`, web fetches — are set to
**ask**, so the agent must request confirmation.

Personal overrides go in `.claude/settings.local.json` (git-ignored) and must
never loosen the shared denials for shared work.

## Using AI responsibly

- **Prompt with the issue in view.** Give Claude the Linear acceptance criteria;
  keep one issue per session where practical.
- **Read the plan.** Approve plans deliberately; do not rubber-stamp.
- **Verify outputs.** Run the gates yourself; AI passing a gate is not evidence
  until you have seen the output.
- **Never paste secrets** into a session. Temporary credentials, tokens, and
  account data do not belong in prompts or transcripts.
- **Redact evidence.** When attaching a transcript or `/status` output to Linear,
  remove tokens and account identifiers.

## Evidence expected from AI-assisted work

Same as any change (see the [Contributor Guide](contributor-guide.md)), plus:

- A redacted `/status` capture confirming Opus 4.8 (plan) / Sonnet 5 (execute).
- Confirmation that the session ran under the repository baseline (plan mode
  default, denials in force).
