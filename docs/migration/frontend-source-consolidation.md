# Frontend Source Consolidation Runbook

## Status and boundary

This is a local, report-only source migration prerequisite for GUG-95. It does
not fetch AWS CodeCommit, mutate AWS, publish assets, deploy, migrate users, or
retire the legacy repository. Production remains **NO-GO**.

| Item | Value |
|---|---|
| Target baseline | `e9daaaaa19f5e58505b642a06213588178d212b8` |
| Target branch | `chore/gug-95-prereq-frontend-source-consolidation` |
| Canonical target | `frontend/scanalyze-frontend-ui` |
| Source ref observed locally | `refs/remotes/origin/main` |
| Source commit | `959b52e57fc0a6f70cc57725ced3dae07a6bf2db` |
| Source tree | `fcee267a7cce115cfe8ab377335885e03f65a821` |
| Live source verification | No |

## Inventory decision

Allowed import classes:

- committed `src/` and synthetic `tests/`;
- `package.json` and `package-lock.json`;
- TypeScript, Vite, ESLint, Tailwind, PostCSS, Playwright, and HTML source
  configuration.

Denied import classes:

- `.env*`, credentials, tokens, keys, customer data, logs, HAR files, and dumps;
- `public/config.json` or any live/customer runtime binding;
- build output, test output, archives, reports, screenshots, or operational
  evidence;
- imperative deploy/generate scripts and legacy CodeBuild configuration; and
- all modified, deleted, or untracked material from the source checkout.

The allowlist was exported from the cached Git object, not copied from the
working tree. `SOURCE_PROVENANCE.v1.json` is the durable machine-readable record.

## Validation procedure

From a clean clone with Node 22 and the repository Python/Terraform pins:

```bash
make frontend-check
cd frontend/scanalyze-frontend-ui
npx playwright install chromium
npm run test:e2e
```

Repository validation then runs `git diff --check`, `make git-safety`,
`make security-check`, schema/contracts, documentation, governance,
microservices, and the applicable preflight/reproducibility gates. Playwright
uses only synthetic configuration, identity state, documents, and API results.

Before any future asset publication, verify the edge response-headers policy
emits the reviewed CSP including `frame-ancestors`, HSTS,
`X-Content-Type-Options`, and the clickjacking control. The HTML meta policy is
defense in depth only and is not acceptable evidence for those headers.

## Divergence and quarantine

If a later authorized read-only CodeCommit fetch differs from the recorded
commit, classify each path as:

- already imported;
- reviewed upstream change;
- sensitive/runtime evidence to retain outside GitHub;
- generated/obsolete; or
- ambiguous and quarantined.

Never automatically select the newest timestamp, merge a dirty tree, infer
customer bindings, or delete the legacy repository. A reconciler must produce a
dry-run file/digest report and require explicit review before another PR.

## Rollback

Before any consumer cutover, revert the consolidation commit. Preserve both
histories and all external runtime assets. After a future authorized cutover,
rollback means restoring the prior immutable frontend artifact/config pair; it
never means restoring Terraform state, copying live config into Git, or
re-enabling a source build in a customer account without review.

## Linear publication fallback

Linear write tools were unavailable during implementation. Publish a child or
blocking prerequisite under GUG-95 without duplicating an existing issue:

> **P1 — Consolidar scanalyze-frontend-ui como fuente GitHub canónica y portable**
>
> Baseline `e9daaaaa...`; branch
> `chore/gug-95-prereq-frontend-source-consolidation`; isolated worktree;
> source is cached CodeCommit `origin/main` `959b52e...` and is not live-
> verified. Scope: allowlisted source import, closed provenance, runtime config
> v2 fail-closed, Node/CI/reproducibility gates, synthetic tests and docs.
> Excludes AWS/CodeCommit live, deploy, asset publish, migration, repository
> retirement, GUG-95 UI features, merge and production. Production NO-GO.
