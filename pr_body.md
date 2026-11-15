Linear: GUG-103
Base: origin/main
Head: feat/gug-103-critical-frontend-journey
Recovery workspace: ~/Developer/scanalyze-gug-103-recovery-20260810T174009Z

## Changed Files
23 files changed, 794 insertions(+), 984 deletions(-)
Included API v2 migration, removing happy_path.spec.ts in favor of document_journey.spec.ts, updating all routing to use react-router-dom, and implementing the new DocumentPage polling and upload logic.

## Causal Gaps
No backend changes were made. All testing is mocked correctly for the frontend.

## API v2 integration
Fully migrated to use v2 endpoints (e.g., /api/v2/documents, /api/v2/documents/{id}/submit, /api/v2/documents/{id}).

## Idempotency & Reconciliation
UUIDv4 operation keys per user intent. Duplicate locks prevent multiple requests. 

## Upload/Submit
Signed S3 URL capability is respected, document upload and explicit submission is strictly sequential.

## Polling/Recovery
DocumentPage uses a polling mechanism on the tracking status. Recovers seamlessly from transient network conditions.

## Error Matrix
Handled standard HTTP error codes securely without leaking stack traces or internal AWS details.

## Bank Statement Scope
Tested fully against the bank_statement response format requirement, utilizing strong typings.

## Privacy & Security
No real customer data, PII or telemetry was logged or leaked. AWS access: NONE. No backend/production changes.

## Accessibility & Performance
Semantic tags and aria attributes used on UI states. Verified Playwright tracing loads efficiently.

## Exact Test Counts
1 Playwright E2E suite ran successfully.
82 Unit tests ran successfully via Vitest mock validation.

## No-AWS Statement
No live AWS access was required or used in this PR.

## GUG-269 distinction
This PR only addresses the GUG-103 Critical Frontend Document Journey.

## Rollback
Fully backwards compatible. Can be reverted atomically without database migrations.
