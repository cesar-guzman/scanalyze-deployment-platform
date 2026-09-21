# Document polling hook recovery (GUG-428)

GUG-428 is the document-polling increment under GUG-422. This increment does not
close the parent issue or establish connected-runtime or production readiness.

This increment changes only the document-status polling hook and its component
coverage. It retains the existing public hook methods and automatic start for a
new document. UI pages, status/result envelope validation, application identity,
and transport timeout/cancellation remain separate concerns.

## Behavior

- One in-flight status GET per document within one hook instance, retained across
  option changes. A different document can be fetched while an older read settles.
- StrictMode cleanup discards obsolete work; callback identities remain stable.
- Explicit start/stop during consumer mount takes precedence over deferred startup.
- Stop and terminal results stay stopped when options change for the same document.
  Explicit start or changing documentId may resume polling.
- Interval must be an integer from 1 through 2147483647 milliseconds; other values
  use the existing 3000ms default. Attempt limit must be a positive safe integer;
  other values use the existing three-attempt default.
- Exponential backoff preserves its deadline across visibility changes. Both the
  computed backoff and the final native timer argument are capped at 2147483647ms,
  including floating-point rounding in deadline subtraction.

## Validation

Run `npm run test:browser` from the frontend directory. The additional file
`tests/browser/document-polling-hook.test.mjs` defines 30 component cases. It bundles
real React, hook, documentApi, Axios and Chromium. Only the API client boundary is
synthetic, with loopback GET/status requests. The bundle excludes application
identity/config/bootstrap and DocumentPage. One maximum-delay case uses a fixed
fractional monotonic-clock reading; other timers run on the native browser clock.

Coverage includes StrictMode, stable callbacks, visibility/backoff, start/stop,
reconfiguration while a read is pending, unmount, changing documents, malformed
numeric options, stopped/terminal intent, and the native timer limit. The original
standalone packet established component evidence. The cases are now included in
the ordinary browser suite against the integrated frontend source tree.

Local integration validation on 2026-09-21 used Node 22.23.1, dependencies installed
with `npm ci` from the existing lockfile, and the existing Chromium installation:

| Command | Observed result |
| --- | --- |
| `npm run check` | Typecheck, lint, 82 unit tests, and production build passed. |
| `npm run test:browser` | 55 passed: 25 existing browser cases and 30 polling cases. |
| `CI=1 SCANALYZE_E2E_PORT=5298 npm run test:e2e -- --workers=1 --retries=0 --reporter=line` | 79 Playwright cases passed without retries. |

These results use synthetic fixtures and local loopback services. Hosted CI and
connected-runtime behavior remain separate validation requirements after review
and publication; no deployed processing or production-readiness claim follows.

## Remaining limits and rollback

A read that never settles can still hold the same-document slot indefinitely:
transport deadlines and cancellation belong to the pending transport increment.
This hook does not validate complete response envelopes or coordinate separate
hook instances. No actor/session or deployed document processing claim follows.

Revert the hook and its added component test together if the increment is rejected.
Do not revert the already integrated browser-runner separation or bank-history
recovery, and do not remove recovery journals or remote document data.
