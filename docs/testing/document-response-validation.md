# Document response validation (GUG-429)

GUG-429 is a bounded response-validation increment under GUG-422. It does not
complete the parent issue or establish connected processing or production readiness.

The pure `src/domain/documentResponseValidation.ts` module validates public
document status and bank-result responses before consumers receive typed values.
Its authority is the current `schemas/scanalyze-document-journey.openapi.v1.json`
and `schemas/scanalyze-document-journey-result.v1.schema.json`, including their
document identity, timestamp, progress and statement-period invariants. Runtime
enums are reused from `src/contracts/documentJourney.v1.ts`.

## Validation behavior

- Require the requested document identity, exact contract/schema versions,
  required fields and closed objects. Result IDs bind to the same document.
- Enforce the six allowed lifecycle/stage combinations, progress bounds and
  created/terminal/updated timestamp order.
- Preserve valid nulls, zeros, negative finite amounts, empty collections and
  duplicate warning codes. Reject nonfinite numbers and numeric strings.
- Enforce the schema's masks, enums, collection limits and Unicode code-point
  string limits. Do not add trimming, balance equations, transaction-period
  restrictions or country/currency membership requirements.
- Validate real Gregorian dates and timezone-aware date-times. Years 0001–9999,
  seconds 00–59 and mandatory timezone match the existing public backend's
  supported range. Date-times accept T/t, Z/z and signed HH:MM offsets through
  23:59. Compare complete fractional seconds without millisecond truncation.

Invalid status and result responses raise fixed messages suitable for the UI:
`La respuesta de estado del documento no es válida.` and
`La respuesta de resultado del documento no es válida.` The separate `code`
properties are `DOCUMENT_STATUS_RESPONSE_INVALID` and
`DOCUMENT_RESULT_RESPONSE_INVALID`. Errors contain no received payload or cause.
Valid input objects are returned without mutation or cloning.

## Unit runner

From `frontend/scanalyze-frontend-ui`, the existing runner discovers
`tests/unit/document-response-validation.test.mjs`:

```sh
npm run test:unit
```

To run only this file:

```sh
node --test tests/unit/document-response-validation.test.mjs
```

The test uses the existing esbuild dependency. Its `before` hook bundles the
actual validator and public contract into a temporary directory, checks that
those are the only source inputs, and imports that bundle. Cleanup removes the
temporary directory after the suite and on setup failure. Public schemas are
read from repository-relative paths. No new package script or dependency is
required. All inputs are synthetic; no application client or browser is loaded.

## Integrated validation

The dedicated worktree is based on reviewed PR125 merge
`4b59040aa9d119943b76424bda0bb6a0abf898dc`; its main reproducibility run
`35634068118` completed successfully before integration. On Node 22.23.1,
the integrated frontend passed **418 distinct test cases** on 2026-09-21:

- `npm ci --no-audit --no-fund` from the unchanged lockfile: PASS.
- `npm run check`: TypeScript, lint, **267 unit cases** and production build PASS.
- `npm run test:browser`: **72 cases** PASS, including the 17 new response cases.
- `CI=1 SCANALYZE_E2E_PORT=5299 npm run test:e2e -- --workers=1 --retries=0
  --reporter=line`: **79 cases** PASS, using the existing Chromium installation
  and an isolated local dev server.

The 185 new unit cases are included in 267; their earlier standalone execution
is not added again. Independent static review of the eight-file increment found
no P1/P2 issues. TypeScript and lint were rerun after test-compatibility edits.

One of those tests compares 6,720 discriminator combinations against the public
OpenAPI branches; 25 are valid. The combinations are assertions within one test
and must not be added to the 185-test count. Coverage also includes nested
required/closed fields, null versus zero, Unicode limits, real dates, offsets,
sub-millisecond ordering, enums and collection boundaries.

The mounted-page harness bundles the actual DocumentPage, polling hook, API,
validator and public contract. It uses a synthetic Axios client and loopback
server, checks exact source imports and request headers, and rejects external
network requests. Two positive cases preserve canonical results and null/zero
rendering. Ten malformed-result cases show a fixed error without a renderer
crash; five malformed-status cases never request a result. Status-error
expectations allow 22 seconds for the real 2-second polling interval's 4+8-second
backoff, without shortening production timers.

The first Playwright run exposed three old-test incompatibilities (76 passed,
3 failed). `recovery_ux.spec.ts` now derives its terminal FAILED response from
the canonical fixture and uses the allowed OCR_FAILED code, while retaining
error/retry assertions. Two malformed-status cases in `upload_recovery.spec.ts`
now expect the existing unconfirmed-load message because validation rejects the
response before recovery policy runs. The valid PROCESSING case still expects
the policy refusal. All three retain one CREATE/PUT/submit and the durable
SUBMIT_UNKNOWN journal. The complete final 79-case run passed without retries;
these runs are not added together.

Publication, exact-head hosted CI and human review of GUG-429 remain separate
gates. No connected document processing, application identity or production
readiness is established by synthetic responses. GUG-422's other acceptance and
GUG-424 transport integration remain open.

The integration retains existing API method signatures, client-selection
arguments, request routes and headers. The polling component test's exact
bundle-input allowlist now includes the validator and public contract.
Transport deadlines and lifecycle coordination remain separate concerns.

Strict validation intentionally rejects nonconforming successful HTTP responses;
a future contract version needs a coordinated parser/test update. Rollback
should revert the API guards, validator, test compatibility updates and this
documentation together. Preserve existing bank-history recovery and runner
separation; no migration or data removal is needed.
