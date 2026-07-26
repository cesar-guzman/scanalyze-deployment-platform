# GUG-263 Frontend Dependency Remediation

## Scope and evidence boundary

GUG-263 restores the frontend dependency-security baseline that blocked both
`PR validation` and `Reproducibility check`. The change is repository-only,
uses synthetic browser fixtures, performs no AWS operation, and does not change
GUG-121 or GUG-124.

The baseline on `main@1c779bf5ce090d8139b754c2c867e9fd1da1689a` installed
`react-router@7.18.1`, `brace-expansion@1.1.16`, and
`brace-expansion@5.0.7`. `npm audit --audit-level=low` reported seven high
severity vulnerability paths and exited nonzero.

## Remediation decision

| Vulnerable path | Decision | Compatibility boundary |
| --- | --- | --- |
| `react-router-dom@7.18.1 -> react-router@7.18.1` | Replace the removed v8 compatibility package with `react-router@8.3.0` and migrate declarative imports to `react-router`. | React Router v8 requires Node 22.22+ and React/React DOM 19.2.7+. The repository uses Node 22 in CI and moves React/React DOM to 19.2.8. |
| `eslint@9 -> minimatch@3 -> brace-expansion@1` | Move to ESLint 10 and its compatible `@eslint/js` and React Hooks plugin releases. | The existing flat configuration is retained. Bounded source annotations preserve intentional external synchronization and upload state-machine effects exposed by ESLint 10 analysis. |
| `typescript-eslint -> minimatch@10.2.4 -> brace-expansion@5.0.7` | Regenerate the lockfile so the compatible range resolves to `minimatch@10.2.5` and `brace-expansion@5.0.8`. | No override is used. Forcing `brace-expansion@5` into `minimatch@3` was rejected because the major versions expose different CommonJS APIs. |

No `npm audit fix --force`, audit-level reduction, warning-only conversion,
permanent advisory allowlist, or workflow exception is used.

## React Router advisory applicability

The React Router advisory concerns unstable React Server Components APIs.
Scanalyze does not use those APIs:

- the application is a client-side Vite SPA;
- routing uses declarative `BrowserRouter`, `Routes`, and `Route`;
- no React Router framework plugin or server entry exists;
- no RSC router, server request handler, route loader, route action, or
  `unstable_*` React Router API is imported.

The vulnerable RSC path was therefore not shown reachable in Scanalyze.
Dependency remediation is still required because the global audit gate is
fail-closed and must contain no affected effective version.

React Router v8 removes `react-router-dom`. All current Scanalyze imports are
non-DOM-specific declarative APIs and move to `react-router`; the application
does not use `RouterProvider` or `HydratedRouter`, which would move to
`react-router/dom`.

## Required validation

Run from `frontend/scanalyze-frontend-ui` with Node 22:

```bash
npm ci
npm explain brace-expansion
npm explain react-router
npm audit --audit-level=low
npm run check
npx playwright install --with-deps chromium
npm run test:e2e
```

The router/authentication boundary suite must preserve:

- unauthenticated protected-route denial;
- login authorization parameters and callback URI;
- authenticated callback routing;
- logout post-redirect binding;
- authenticated deep links and primary navigation.

Repository `docs-check`, `security-check`, `git-safety`, and clean-clone
reproducibility remain required before publication.

## Rollback

Rollback is a repository revert of the complete GUG-263 commit. The dependency
manifest, lockfile, React Router imports, lint-compatibility annotations,
router/authentication tests, and this decision record must be reverted
together. A partial downgrade to `react-router-dom@7`, ESLint 9, or vulnerable
`brace-expansion` versions is not an acceptable production workaround; after a
revert, the frontend audit and dependent pull requests remain NO-GO.
