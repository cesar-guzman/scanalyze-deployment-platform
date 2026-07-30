# Claude Code Onboarding Rehearsal Checklist

## Document control

| Field | Value |
|---|---|
| Owner | Platform Engineering |
| Audience | Onboarding contributors and their reviewers |
| Status | CURRENT |
| Scope | `cesar-guzman/scanalyze-deployment-platform` |
| Review cadence | Quarterly and after a change to the Claude Code baseline |
| Last verified | 2026-07-30 against `main@66007de` |
| Related policy | [`CONTRIBUTING.md`](../../CONTRIBUTING.md) |
| Related controls | [`AI_ASSISTED_DEVELOPMENT_STANDARD.md`](AI_ASSISTED_DEVELOPMENT_STANDARD.md), [`CLAUDE_CODE_SETUP.md`](CLAUDE_CODE_SETUP.md) |
| Tracking | [GUG-262](https://linear.app/guguce/issue/GUG-262/establish-and-validate-claude-code-contributor-baseline) |

A clean-room rehearsal of the contributor workflow. The onboarding contributor
runs this end to end, records evidence, fixes any gaps **in the same branch**,
and moves the PR to Ready for Review. Attach the completed, **redacted** copy to
the Linear issue.

> Redaction rule: remove all tokens, session credentials, and account
> identifiers before attaching anything. Never paste secrets into the transcript.

## Environment

| Field | Value |
|---|---|
| Contributor | _e.g. Emiliano Díaz_ |
| Date | _YYYY-MM-DD_ |
| Branch | _feat/<slug>_ |
| Commit SHA (start) | _<sha>_ |
| Commit SHA (end) | _<sha>_ |
| PR URL | _<url>_ |
| Linear issue | GUG-262 |

## Access & toolchain

- [ ] GitHub access confirmed (author write / reviewer rights).
- [ ] Linear access confirmed.
- [ ] `make toolchain-check` passes (Terraform 1.14.6, Python 3.11.x).

## Clone & reproducibility

- [ ] Fresh clone completed.
- [ ] `make clone-check` passes.

## Branch & worktree

- [ ] Isolated worktree created for one Linear issue.
- [ ] Branch named `<type>/<slug>`.

## Claude Code baseline

- [ ] Claude Code launched from repo root; started in **plan mode**.
- [ ] `/status` shows plan → Opus 4.8, execute → Sonnet 5 (redacted capture
      attached).
- [ ] `make contributor-docs-check` passes.
- [ ] Verified a denied action (e.g. attempted `git push` / `aws`) is blocked by
      the baseline.

## Change, docs, commits

- [ ] Implemented the scoped change.
- [ ] Updated relevant docs; authoritative docs marked `Status: CURRENT`.
- [ ] Commits use conventional prefixes; `make git-safety` clean.

## Validation

- [ ] `make contributor-docs-check` — result: ____
- [ ] `make docs-check` — result: ____
- [ ] `make preflight-core` — result: ____
- [ ] `make preflight-m1` — result: ____ (or reason not run)

## PR & review

- [ ] Draft PR opened by the author (not self-approved).
- [ ] PR body includes branch, commit SHA, commands + results, risks, rollback
      path, validation not run.
- [ ] Review requested from @cesar-guzman.
- [ ] All review comments addressed.

## Gaps found & fixed (same branch)

| Gap | Fix | Commit SHA |
|---|---|---|
| | | |

## Linear

- [ ] Issue kept In Progress until the updated head is green.
- [ ] Evidence (this checklist, redacted `/status`, gate output, PR URL) attached.

## Sign-off

- [ ] Definition of Done met.
- [ ] Independent approval by @cesar-guzman recorded.
- [ ] No AWS or production change was made.
