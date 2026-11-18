# Frontend audit exceptions

`npm run audit` in `frontend/scanalyze-frontend-ui` runs
`scripts/audit-gate.mjs`. The gate keeps `npm audit --audit-level=low` as the
source of truth. It adds one narrow, time-boxed path for advisories that have no
fixed release, so a single unfixable build-tool advisory does not block every
pull request.

## Rules

- **Production dependencies get no exceptions.** `npm audit --omit=dev` must
  report no advisory at all.
- **The full tree may report only listed advisories.** Each entry in
  `audit-exceptions.json` names one GitHub advisory and one package, has scope
  `development`, and lasts at most 30 days from `granted`. A grant cannot be
  dated in the future.
- **An expired entry fails the gate.** Renewing it needs a new review: a new
  `granted` date, an updated reason and code-owner approval.
- **Stale entries are reported.** An entry that no longer matches an advisory
  prints a warning. Remove it in the change that updates the lockfile.
- **Everything else fails.** Any other advisory, an npm error or an unreadable
  report fails the gate, as before.

`tests/unit/audit-gate.test.mjs` covers these rules, and
`tests/test_gug95_frontend_source_contract.py` pins the audit arguments, the
30-day limit and the closed format of the exception file.

## Current exceptions

| Advisory | Package | Granted | Expires | Why |
| --- | --- | --- | --- | --- |
| GHSA-fc5q-39xc-vjpf (high, ReDoS) | picomatch 4.0.5 | 2026-11-17 | 2026-12-17 | No fixed release exists. The advisory was widened on 2026-11-17 to every version up to 4.0.7, with no patched version. picomatch is reached only through build and lint tooling: vite, @vitejs/plugin-react, fdir, tinyglobby and the typescript-eslint packages. It is not in the SPA bundle, and `npm audit --omit=dev` reports nothing. |

Before this change, the frontend audit on `main` reported 11 high-severity
entries. All of them came from this one advisory: picomatch itself and 10
packages that depend on it.

## Removing an exception

When a fixed release ships, update the lockfile as in PR #133, run
`npm run audit`, and delete the entry and its row here in the same change.

## Rollback

Revert the change. `npm run audit` then runs `npm audit --audit-level=low`
again and fails until picomatch ships a fix.
