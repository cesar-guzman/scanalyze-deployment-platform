# Synthetic document journey smoke

## Scope and evidence boundary

`scripts/validation/document-journey-smoke.py` implements one positive, synthetic
bank-document API journey against an explicitly selected DEV or STAGING target.
It is not a deployment command. Adding or testing this driver makes no connected
application call and does not establish production readiness.

The existing infrastructure `HEALTHY` result is Terraform convergence and contract
evidence, not an application-processing result. This driver is separate from the
`scanalyze-deploy.sh smoke-e2e` scaffold and does not change that entrypoint. See
[the nonproduction engine](../deployment/nonproduction-live-engine.md) and
[staging certification](gug127-staging-certification.md) for the broader gates.

The driver follows the authoritative document-journey OpenAPI and result schemas:

1. POST `/api/v2/documents` with a new UUIDv4 idempotency key.
2. PUT the fixed synthetic PDF to the returned, explicitly allowed S3 host.
3. POST the ingest stage to `/api/v2/documents/{documentId}/submit`.
4. GET that document until a valid completed status, within the request budget.
5. GET its canonical bank result and compare the expected fictional values.
6. Repeat CREATE with the original key and identical payload; require a replay
   with the original durable response and document identity.

Every response must meet the canonical schema and runtime identity/timestamp
checks. The original CREATE response remains the replay baseline even after the
document completes. A failed processing state, non-active processing condition,
unexpected HTTP status, schema mismatch, journal failure, or exhausted budget
stops execution. There are no automatic HTTP retries, including for throttling.

## Before any connected run

Obtain explicit authorization for the exact environment, deployment, API origin,
upload bucket, synthetic document writes and possible processing charges. This
tool performs application writes; AWS read-only approval does not cover them.
There is no production mode.

The operator must independently verify the target's deployed identity and release,
including `processing_domain=bank` and its bank route. Config labels, a deployment
ID, an authorization reference, or a hostname do **not** prove the target's AWS
account, environment, release, or permission to execute. The driver has no target
attestation endpoint and must not be used as one.

Use a fresh, reviewed `main` whose exact commit passed the required CI. The CLI
requires a clean local `main` equal to local `origin/main`; it does not fetch or
prove that this tracking ref is current. An isolated development branch can run
the hermetic tests, but cannot run the connected CLI.

The same authorized principal is used for the entire journey. Human access needs
the live membership/capability checks and appropriate read/write/admin authority;
full-result access also requires the backend's recent phishing-resistant step-up.
For M2M, use server-bound granted actions, not invented scope strings. No token is
minted or authorization weakened here. If processing outlasts the step-up window
or the token expires, a rejection stops this attempt; do not bypass reauthentication.

Supply the access token through an approved environment injection mechanism as
`SCANALYZE_SMOKE_ACCESS_TOKEN`. Never put its value in command arguments, config,
shell history, documentation, logs, or receipts. The CLI does not load an env file,
read an AWS profile, or print the token. Do not use real customer or bank documents.

## Private configuration

Use an existing owner-only `0700` directory outside Git and synced storage, with
an owner-only, regular, single-link `0600` JSON config. Paths must be absolute,
without symlink components. Use the real `/private/tmp` path instead of its `/tmp`
symlink on macOS if selecting a temporary private directory. Keep receipts outside
OneDrive/SharePoint as well; only a separately reviewed, sanitized report belongs
in shared documentation. No private directory is created automatically.

The config has exactly these fields. The following is a fictional shape example,
**not an executable target or an authorization**:

```json
{
  "schema_version": 1,
  "environment": "dev",
  "processing_domain": "bank",
  "api_origin": "https://api.example.invalid",
  "upload_host": "synthetic-example.s3.us-east-1.amazonaws.com",
  "deployment_id": "dep_01ARZ3NDEKTSV4RRFFQ69G5FAV",
  "region": "us-east-1",
  "authorization_reference": "5fba4872-34fb-48d3-bcc2-fbd96abf8f20",
  "timeout_seconds": 180,
  "poll_interval_seconds": 2,
  "max_requests": 96
}
```

`environment` is `dev` or `staging`. The API origin has no path, trailing slash,
query, credentials, or explicit port. The upload host is one exact regional S3
hostname in `us-east-1`. Both are operator-verified inputs, not discovery results.
The authorization reference is a canonical UUIDv4 linked to the operator's actual
approval record. The time budget is 30–600 seconds, poll interval 1–30 seconds,
and total HTTP request budget 6–256; booleans are not accepted as numbers.

## Offline validation and authorized command shape

Safe, hermetic validation from the implementation branch:

```sh
make document-journey-smoke-check
python3 scripts/validation/document-journey-smoke.py --help
```

The tests inject transports or synthetic CLI modules and never invoke a live
application. They do not produce connected evidence.

Only after the recovery integration is implemented and reviewed, and the
prerequisites above are satisfied, from the reviewed clean `main`, the command
shape for one separately approved connected attempt is:

```sh
env -u PYTHONPATH -u PYTHONHOME PYTHONDONTWRITEBYTECODE=1 \
  python3 scripts/validation/document-journey-smoke.py run \
  --config /absolute/private-directory/smoke-config.json \
  --receipt /absolute/private-directory/new-attempt.jsonl \
  --authorize-application-writes
```

Use the repository's validated Python environment and dependencies. The flag is
an explicit local operator acknowledgement, not a substitute for approval or
server-side controls. Omitting it fails before source, config, token, or network
access. No command here should be run merely because a PR merged.

## Transport and synthetic assertions

The fixed PDF declares all content fictional: `Scanalyze Synthetic Bank`, January
2026, currency MXN, opening balance zero, and one credit of 100 with a closing
balance of 100. The result must contain exactly that transaction, its date and
reference, matching totals, no warnings, and overall confidence at least 90. This
is a fixture-specific assertion, not a statistical production-quality threshold.

The HTTPS transport rejects private/non-global DNS results, including mixed DNS
answers, and pins the selected public address while preserving TLS hostname
verification. It neither follows redirects nor forwards Bearer or API headers to
the upload URL. Only PDF Content-Type accompanies the PUT. Ambient proxy and CA
override variables are rejected; no cookie jar or alternate endpoint is used.
Responses are bounded to 2 MiB and compressed responses are rejected.

Requests have socket timeouts and deadline checks, with a cumulative time budget
and finite polling/request count. System DNS resolution itself is synchronous;
this is not a process-level hard deadline guarantee. A stalled resolver or slowly
delivered response headers may require operator interruption. Interruption cannot
prove that an in-flight application write had no effect.

## Receipt, uncertainty, and rollback

The CLI creates a new `0600` JSONL receipt exclusively and fsyncs each event before
continuing. It records STARTED (source commit and config digest), BEFORE_REQUEST,
STEP_PASSED, and a final SUMMARY or a sanitized failure code when writing remains
possible. It refuses to reopen or overwrite an existing receipt. A partial journal
is preserved and cannot be resumed by this tool.

The CLI persists a private CREATE_PREPARED event containing
the original UUIDv4 idempotency key and request digest before CREATE. After a
validated CREATE response, a private DOCUMENT_CREATED event persists the
synthetic document ID before any upload.
Neither identifier is an authentication credential, but both are restricted
operational data and must remain in private custody with the original config.
The config digest ties that separately retained config to the receipt.

Receipts never contain access tokens, signed upload URLs, raw response bodies,
extracted records, or target locators. The public summary contains only the PDF
digest, a hashed document ID, request count, completed steps, and elapsed time;
it excludes both raw recovery identifiers. It is local observation, not a signed
or tamper-proof deployment attestation.

The intended effects are one document, one upload, one ingest submission and a
CREATE replay, plus status/result reads. A server replay defect can create another
document before the driver detects it. The tool does not delete any artifact,
undo processing, or reconcile failed requests automatically. After an unknown
CREATE outcome, preserve the receipt and original config; use the canonical CREATE
reconciliation endpoint with the original idempotency key only under separately
authorized service operations and the original principal context. For later-stage
uncertainty, the stored document ID supports authorized status observation. This
driver does not perform either recovery action or resume an attempt. Do not
blindly rerun with a new key or claim zero side effects.

`APPLICATION_SMOKE_PASSED` proves only this positive synthetic API journey. It does
not prove browser login, negative authorization/tenant isolation, performance,
rollback/restore, DEV-to-STAGING promotion, signed staging certification, or
production readiness. `production_authorized` is always false.

The local implementation can be reverted without any cloud rollback when no
connected run has occurred. Artifacts from a later approved run need a separate,
exactly scoped retention/cleanup decision; reverting code does not remove them.
