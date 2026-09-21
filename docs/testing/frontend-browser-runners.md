# Frontend browser test runners

The frontend has two browser test runners with different test APIs. Playwright
discovers only `tests/**/*.spec.ts`. Node discovers `tests/browser/*.test.mjs`;
those files use `node:test` while driving Chromium through Playwright's library.
Importing a Node test file from Playwright registers tests with the wrong runner
and does not establish that CI executed their assertions correctly.

From `frontend/scanalyze-frontend-ui`, use the repository-supported Node version
(CI uses Node 22), install the locked dependencies and Chromium, then run both:

```sh
npm ci
npx playwright install --with-deps chromium
npm run check
npm run audit
npm run test:browser
npm run test:e2e
```

`test:browser` runs files sequentially to bound simultaneous browser/server
fixtures. Test and hook failures propagate through Node and npm. PR validation
runs this command after Chromium installation, followed by the existing
Playwright step. No failure suppression or replacement of existing checks is
introduced. A failed Node step fails its job and may prevent subsequent steps
from running; it cannot produce a successful job by skipping Playwright.
The clean-clone workflow still runs its existing frontend check/audit commands;
it does not acquire browser-suite coverage from this PR workflow change.

`esbuild` is a direct development dependency at the version already present in
the lockfile because these browser harnesses import it directly. No runtime
package version or transitive resolution changes are required.

## Admitted recovery coverage

The two admitted harnesses exercise the integrated GUG-423 recovery sources:

- `bulk-upload-recovery.test.mjs`: original-key reconciliation, uncertain
  responses, bounded file concurrency, retained references and mounted bank/bulk
  recovery. Bank expectations preserve Historial alongside Resultados del lote.
- `bulk-recovery-review.test.mjs`: journal replacement, configuration changes,
  pending batch reconciliation and recovery ownership across React remounts.

They use real Chromium, native sessionStorage, React and Axios, with synthetic
configuration/auth-context/client boundaries and a local HTTP ledger. External
requests are blocked or fulfilled by test fixtures. They do not validate the
pending session-manager implementation, live identity, server authorization,
cloud resources or production processing. Existing Playwright history/CSV cases
remain in their original suite.

This is partial GUG-422 integration. The other four candidate harnesses
(`dashboard-export-contract`, `document-polling-recovery`, `passkey-registration`
and `session-continuity`) and their source dependencies require separate review
before admission. The runner scripts discover admitted files; they do not certify
the candidate's completeness. GUG-422 must remain open until its full acceptance
criteria and source concerns are resolved. GUG-424 transport deadlines remain
separate.

## Validation and rollback

Record the exact base commit, Node/browser versions, unique per-runner counts and
skips when validating. `npm run test:e2e -- --list` verifies discovery, not test
execution. Also verify each runner returns a failing process status for an
intentional isolated failing test; do not place such fixtures in committed test
directories or weaken assertions to make the check pass.

Rollback must keep runner configuration and admitted files consistent: reverting
only `testMatch` while retaining Node harnesses restores mixed discovery. Revert
the runner script, PR step, admitted harnesses and dependency declaration together
through a reviewed change. This test-only integration changes no application
runtime and requires no production rollback or recovery-journal cleanup.
