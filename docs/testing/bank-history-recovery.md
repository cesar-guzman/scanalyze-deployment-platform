# Bank history, CSV and durable batch recovery

[GUG-423](https://linear.app/guguce/issue/GUG-423/reconcile-bank-history-acceptance-with-document-result-recovery-ui)
preserves **Historial** and access to previous bank statement results. The owner
confirmed that product contract on September 21, 2026 UTC. Current-tab batch
references are a separate view and do not replace account history.

## Supported behavior

- **Subir** and **Carga Masiva** use the same actor/deployment-scoped recovery
  journal. A lost CREATE response is reconciled with its original idempotency
  key. A lost submit response is followed by a status read before any retry.
  Reloading or changing pages does not automatically restart an operation.
- **Resultados del lote** shows opaque references retained in this tab. A
  confirmed submission does not mean extraction has completed. Files, names,
  signed upload URLs, tokens and result payloads are not persisted in the journal.
- **Historial** queries the backend independently of that journal and opens the
  canonical result for the selected document. Errors and denied access are
  displayed as failures, not as an empty history. Actor changes discard the
  previous view and late responses cannot publish another actor's data.
- **Exportar CSV** exports the selected historical statement through the backend
  export policy. Denial leaves a visible error and creates no download. Unknown
  amounts stay empty, while known zero amounts stay zero.

The historical frontend referenced `/analytics/docs` and `/analytics/export-bank`,
but neither route existed in the baseline backend. Browser mocks alone had hidden
that gap. This change adds the two service routes as well as their UI integration.

## API and authorization

The application facade maps `/api/analytics/...` to the existing v1 router.

`GET /analytics/docs?classRoute=bank-extract&limit=50&cursor=...` returns
`{ "documents": [...], "nextCursor": null | "..." }`. The closed metadata DTO
contains `documentId`, `filename` (nullable), `status` and `createdAt`. Limits are
1 through 100 evaluated records per request. The backend makes one bounded query
against the existing `OwnershipIndex`; it never scans the table or reads all
pages to fill a filtered page. A page can be empty with a non-null continuation.
The UI keeps offering **Cargar más** in that case. The index has no chronological
sort key, so the UI does not promise globally sorted results.

The route requires `DOCUMENTS_READ_METADATA` and revalidates record ownership.
Only canonical document-journey bank records belonging to the authenticated actor,
customer and deployment are projected. Legacy records without those bindings are
not silently admitted. The cursor is a bounded continuation position bound to the
current scope; it is not an authorization capability or a client-supplied DynamoDB
key. A missing ownership index is a deployment prerequisite, not a reason to
fall back to a scan.

Opening a result retains the existing `RESULTS_READ_FULL` operation. CSV uses
`GET /analytics/export-bank?documentIds=<id>[,<id>...]`, accepts at most ten distinct
canonical IDs and requires `EXPORTS_EXECUTE`. The backend checks every selected
record before reading result contents. It then reuses the canonical journey result
reader, preserving actor binding, supported lifecycle, worker checkpoint, object
provenance, byte bounds and result projection. Permission catalogs and grants are
not broadened.

CSV is buffered before responding, so a denied or invalid document cannot become
a partially successful export. It is bounded to 50,000 rows and 20 MiB, neutralizes
spreadsheet formulas through the existing CSV helper and exposes only selected
canonical result fields. History and exports use `Cache-Control: no-store`.
No raw provider payload, full account locator or credential is included.

## Recovery integrity

A local validation failure before the journal exists returns the upload form to
an editable state. Corrupt or uncertain journals remain blocked and retained.
The controller rejects contradictory item/intent states, including `DONE` paired
with `CREATE_UNKNOWN`, and validates every retained intent before clearing a
completed batch. Normal retries preserve the original operation rather than
generating replacement CREATE requests.

The shared recovery source was extracted from the preserved production-readiness
candidate after per-file SHA-256 verification. Only the reviewed dependency closure
was imported. The original checkout was not edited. Authentication/session rewrites,
other candidate UI changes and infrastructure changes are outside this patch.

## Validation and evidence limits

Use the repository Node version range and install locked dependencies in the
frontend directory. Run `npm run check`, followed by the normal Playwright suite.
The focused suites are `document_result_contract.spec.ts`,
`bank_upload_recovery.spec.ts` and `bulk_recovery_integrity.spec.ts`.

Backend coverage exercises the two actual routes, typed operation bindings,
customer/deployment/actor isolation, cursor validation, bounded repository queries,
CSV integrity and export denial. Existing journey, ownership and authorization
suites remain part of the regression check. All data is synthetic; local test
adapters replace AWS and identity providers.

Recorded local validation on September 21, 2026 UTC:

| Check | Result |
| --- | --- |
| Complete ingest API test directory | 1,139 passed, including 66 new bank history/export cases |
| Frontend unit suite | 82 passed |
| Complete Playwright suite using the existing command | 79 passed |
| Frontend source/ownership contracts | 7 passed |
| Typecheck, ESLint, production build, diff whitespace | Passed |
| Independent automated review | Two recovery regressions reproduced and fixed; no remaining P1/P2 findings in the reviewed change |

The backend runner blocked network sockets and disabled AWS credential/config file
resolution and instance metadata. One initial fixture required an explicit
synthetic default region; adding that runner setting produced the final complete
pass without changing the test or weakening its assertions. The only remaining
warning was an existing Starlette/httpx deprecation. Focused and independent runs
are subsets of these totals and are not additional test cases.

These checks demonstrate local source behavior, not a deployed authenticated
document journey. Exact-head CI and review remain prerequisites for integration.
Installed index/IAM permissions, a live identity session, deployed API routing,
HTTPS, processing, durable storage, operational alarms and rollback still require
separate connected evidence. Production remains NO-GO at this checkpoint.

[GUG-422](https://linear.app/guguce/issue/GUG-422/separate-node-browser-harnesses-from-playwright-discovery-and-enforce)
still owns runner separation and the remaining candidate harness integration.
[GUG-424](https://linear.app/guguce/issue/GUG-424/bound-document-api-and-upload-requests-without-duplicating-ambiguous)
still owns finite transport deadlines and cancellation. This patch does not claim
either issue complete.

## Rollback

Rollback is a reviewed revert of this bounded source change; no cloud resources,
schema migration, permission grants or stored documents are changed here. Keep
pending browser journals intact. Reverting to the earlier UI removes its ability
to recover a pending batch, so do not instruct users to erase browser storage or
recreate uncertain documents. Reconcile pending operations before intentionally
switching clients. CSV exports are read-only and require no data rollback.
