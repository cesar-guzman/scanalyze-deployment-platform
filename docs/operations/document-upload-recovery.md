# Browser document-upload recovery

## Supported flow

The single-document `/upload` page retains an operation reference before sending
CREATE and reconciles that original operation after an uncertain response. It
does not issue another CREATE from the recovery button. This behavior uses the
canonical document-journey v1 contract over API v2.

The browser stores an opaque UUID, a file fingerprint, the operation phase and,
once confirmed, the durable document ID. The storage namespace includes API,
issuer/client, customer, deployment and user subject. It is a browser UX boundary;
the backend independently authorizes every request and document.

The journal contains no file, filename, token, signed upload URL or raw error
body. File comparison hashes bounded chunks and request metadata; reselecting a
different file, content type or filename cannot replace the original intent.
The page accepts the canonical PDF, PNG, JPEG and TIFF types up to 512 MiB and
enforces the request's filename limit before CREATE.

## User-visible recovery

| Observed failure | Recovery behavior |
| --- | --- |
| CREATE response is lost | Keep the original idempotency key and call CREATE reconciliation. After success, continue with that durable document. |
| Reconciliation is pending | Keep the operation and offer an explicit delayed retry. No replacement CREATE is sent. |
| Reconciliation is failed, unknown/quarantined or expired | Stop for operator review. The backend currently provides no executable client retry path for `FAILED_RETRYABLE` CREATE records. |
| PUT fails or its response is uncertain | Read the existing document status, renew its upload capability if needed, require the original file and continue with the same document. |
| SUBMIT response is lost | Read status first. Active/completed processing redirects to tracking without another PUT or submit. Only the canonical retryable enqueue-failure state permits submit retry. |
| Status is unavailable or malformed | Keep the operation for another status check; do not infer that the previous write failed. |
| Browser storage fails | Stop before the next write. Keep any already-persisted original key available for reconciliation. |
| Session expires or another user signs in | Stop the previous user's network sequence. Each API dispatch checks the expected subject; a new user cannot continue the previous journal. |
| Navigation leaves an upload request in flight | The old view cannot continue its sequence. Journal key comparisons prevent a late response from replacing or clearing a newer operation. |

The recovery button is **Recuperar carga**. A missing file can be selected again
without changing the operation. Errors use bounded application messages; raw
provider responses and capability URLs are not displayed.

## Operational limits

Recovery uses `sessionStorage`: it survives reloads in the same tab, but it is not
a cross-device or cross-tab recovery catalog. Closing the tab, clearing browser
storage or losing the browser session can remove the local reference. Preserve
the tab while resolving an uncertain operation. Do not instruct users to clear
storage, open a new tab or repeatedly upload the file to resolve uncertainty.

This patch does not change bulk upload, the backend ledger retention policy,
operator permissions or production storage retention. An operator-assisted
reconciliation path still needs the approved environment and identity; never
request a JWT, signed capability URL or a document attachment for diagnostics.

Browser tests use synthetic files and simulated transport. They do not prove
real S3 CORS, Cognito sign-in, worker processing, ledger durability, or production
readiness. Before admitting initial users, run the connected checks in the
[express production preparation packet](../deployment/express-production-execution-plan.md).

## Validation and rollback

From `frontend/scanalyze-frontend-ui`, use the repository-compatible Node 22:

```sh
npm run check
SCANALYZE_E2E_PORT=5187 CI=1 npx playwright test tests/upload_recovery.spec.ts tests/recovery_ux.spec.ts tests/document_journey.spec.ts
```

The regression suite checks lost CREATE/PUT/SUBMIT responses, original-key and
file continuity, pending/stopped ledger states, malformed status/journal,
persistence failures and changes of user. The release record lists the latest
completed full-suite results. It also covers navigating away while CREATE is in
flight, reconciling the first operation and starting another before the first
response arrives; the new journal must remain intact.

Before deployment, revert only this local patch to withdraw it. After deployment,
retain compatibility with the `scanalyze.upload.v1` journal until active loads
have been reconciled: reverting to a client that creates a new key on every retry
can recreate documents. Closing admission while resolving pending operations is
safer than deleting recovery references or documents.
