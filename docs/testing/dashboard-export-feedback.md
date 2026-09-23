# Dashboard Export Feedback Regression Tests

Synthetic browser tests to validate CSV export error handling and modal lifecycle concurrency in the main Dashboard component.

## Scope
Validates that:
1. Failed exports keep the modal open and restore its download button; an explicit retry clears the previous feedback.
2. User's parameters, filters, and selections are exactly preserved on failure and retry.
3. Downloads are suppressed when an error occurs.
4. Auto-retries are not triggered by the frontend.
5. Error response payload text is intentionally kept hidden and replaced by an accessible `role="alert"` Spanish message.
6. The UI correctly recovers if the user explicitly retries the export, waiting for the download payload and checking its CSV contents.
7. Deferred HTTP responses from cancelled attempts cannot change fresh modal state: a late error does not show an alert, and a late CSV response does not trigger a stale download or close the new modal.

## Execution

From `frontend/scanalyze-frontend-ui`, with the repository's Node dependencies
and Playwright Chromium installed:

```bash
node --test tests/browser/dashboard-export-feedback.test.mjs
```

## Scenarios

The suite contains 13 cases:

- Six failure/retry cases: `403` and `503` for each of filters, manual selection,
  and batch selection. Each checks preserved inputs and exact GET parameters,
  generic feedback without the response body, no download on failure, and no
  automatic retry during a 500 ms observation window. An explicitly requested,
  held retry clears the error, shows the busy state, and verifies the eventual
  CSV bytes and filename.
- Three initial-success cases, one per mode, checking parameters, CSV bytes,
  filename, and modal closure.
- One case clearing visible feedback when the user cancels and reopens.
- Two cases delivering a cancelled attempt's late failure or success while a
  newer export is pending. The old response must not replace the busy state,
  show feedback, download a file, or close the new modal.
- One case delivering a cancelled late failure into a fresh idle modal, which
  must remain ready for use.

## Evidence boundary

The harness mounts the actual Dashboard in React StrictMode, uses Axios against
a synthetic HTTP server bound to `127.0.0.1`, and drives Chromium. Authentication,
the shared API-client factory, and employee-profile status are replaced at the
test boundary. Fixtures and CSV content are synthetic.

These tests validate UI behavior; they do not establish deployed authentication,
backend authorization, connected export correctness, or production readiness.
The absence of automatic retries is observed for the bounded interval above.
Cancelling invalidates the attempt's UI effects; it does not abort its underlying
HTTP request. This change does not modify shared authentication or API-client
behavior.

## Rollback

Revert the Dashboard change together with this suite and its documentation.
The prior behavior silently handled export errors. No backend, data migration,
or cloud resource rollback is involved in this change.
